using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.RateLimiting;
using Api.Auth;
using Api.Data;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Api.Mcp;

/// <summary>
/// A small OAuth 2.1 authorization server for the MCP connector (claude.ai): discovery metadata (RFC 9728, RFC 8414),
/// dynamic client registration (RFC 7591), authorization code + PKCE S256, refresh tokens, resource-bound access tokens (RFC 8707).
/// Employees sign in with their Acme HR email and password. Tokens are signed JWTs; the signing secret is stored in the database
/// so tokens survive restarts. Registered clients are stateless (the client_id is a signed list of its redirect URIs).
/// </summary>
public static class McpOAuth
{
    public const string Scheme = "McpJwt";
    public const string Policy = "mcp";
    public const string Scope = "hr.self.read";
    const string RateLimit = "oauth";
    static readonly TimeSpan AccessLifetime = TimeSpan.FromHours(1);
    static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(30);
    static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    static readonly TimeSpan ClientLifetime = TimeSpan.FromDays(365);

    /// <summary>Exact redirect URIs allowed besides loopback (http://localhost or 127.0.0.1 on any port, for MCP Inspector).</summary>
    static readonly string[] AllowedRedirects = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"];

    // ---------- signing key (persisted) ----------

    static SymmetricSecurityKey? _key;
    static SymmetricSecurityKey Key => _key ?? throw new InvalidOperationException("MCP OAuth key not loaded. Call McpOAuth.EnsureKey at start-up.");

    /// <summary>Creates the key table if missing (works on an existing Postgres database and on SQLite) and loads the signing secret.</summary>
    public static void EnsureKey(AcmeDb db)
    {
        db.Database.ExecuteSqlRaw("""CREATE TABLE IF NOT EXISTS "McpOAuthKeys" ("Id" INTEGER PRIMARY KEY, "Secret" TEXT NOT NULL)""");
        var fresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        db.Database.ExecuteSqlRaw("""INSERT INTO "McpOAuthKeys" ("Id", "Secret") VALUES (1, {0}) ON CONFLICT ("Id") DO NOTHING""", fresh);
        var secret = db.Database.SqlQueryRaw<string>("""SELECT "Secret" AS "Value" FROM "McpOAuthKeys" WHERE "Id" = 1""").AsEnumerable().First();
        _key = new SymmetricSecurityKey(Convert.FromBase64String(secret));
    }

    // ---------- URLs ----------

    /// <summary>The public base URL: PUBLIC_BASE_URL if set, else the request's scheme and host (behind Render's proxy via forwarded headers).</summary>
    static string Base(HttpContext ctx)
    {
        var configured = ctx.RequestServices.GetRequiredService<IConfiguration>()["PUBLIC_BASE_URL"];
        return !string.IsNullOrWhiteSpace(configured) ? configured.TrimEnd('/') : $"{ctx.Request.Scheme}://{ctx.Request.Host}";
    }
    static string Resource(HttpContext ctx) => Base(ctx) + "/mcp";

    // ---------- services ----------

    public static IServiceCollection AddMcpOAuth(this IServiceCollection services)
    {
        services.Configure<ForwardedHeadersOptions>(o =>
        {
            o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            o.KnownNetworks.Clear(); // Render's proxy address is not fixed
            o.KnownProxies.Clear();
        });
        services.AddAntiforgery(o => { o.Cookie.Name = "acme.oauth.af"; o.FormFieldName = "__af"; });
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddPolicy(RateLimit, ctx => RateLimitPartition.GetFixedWindowLimiter(
                ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) }));
        });

        services.AddAuthentication().AddJwtBearer(Scheme, o =>
        {
            o.MapInboundClaims = false;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeyResolver = (_, _, _, _) => [Key],
                ValidateIssuer = false, // the audience check below binds the token to this server's /mcp URL
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
                NameClaimType = "name",
                RoleClaimType = "role",
            };
            o.Events = new JwtBearerEvents
            {
                OnTokenValidated = ctx =>
                {
                    var p = ctx.Principal!;
                    var audOk = p.FindAll("aud").Any(a => a.Value == Resource(ctx.HttpContext));
                    if (p.FindFirstValue("token_use") != "access" || !audOk) ctx.Fail("Token is not an access token for this MCP server.");
                    return Task.CompletedTask;
                },
                OnChallenge = ctx =>
                {
                    ctx.HandleResponse();
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    var err = ctx.AuthenticateFailure is null ? "" : ", error=\"invalid_token\"";
                    ctx.Response.Headers.WWWAuthenticate = $"Bearer resource_metadata=\"{Base(ctx.HttpContext)}/.well-known/oauth-protected-resource\"{err}";
                    return Task.CompletedTask;
                },
            };
        });
        services.AddAuthorization(o => o.AddPolicy(Policy, p => p
            .AddAuthenticationSchemes(Scheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(c => (c.User.FindFirstValue("scope") ?? "").Split(' ').Contains(Scope))));
        return services;
    }

    // ---------- endpoints (anonymous: approved OAuth endpoints only) ----------

    public static void MapMcpOAuth(this WebApplication app)
    {
        app.MapGet("/.well-known/oauth-protected-resource", ProtectedResource).AllowAnonymous().ExcludeFromDescription();
        app.MapGet("/.well-known/oauth-protected-resource/mcp", ProtectedResource).AllowAnonymous().ExcludeFromDescription();
        app.MapGet("/.well-known/oauth-authorization-server", (HttpContext ctx) =>
        {
            var b = Base(ctx);
            return Results.Json(new Dictionary<string, object>
            {
                ["issuer"] = b,
                ["authorization_endpoint"] = b + "/oauth/authorize",
                ["token_endpoint"] = b + "/oauth/token",
                ["registration_endpoint"] = b + "/oauth/register",
                ["response_types_supported"] = new[] { "code" },
                ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
                ["token_endpoint_auth_methods_supported"] = new[] { "none" },
                ["scopes_supported"] = new[] { Scope },
            });
        }).AllowAnonymous().ExcludeFromDescription();

        // Cast so it binds as a minimal API (the IResult is written), not as a raw RequestDelegate.
        app.MapPost("/oauth/register", (Func<HttpContext, Task<IResult>>)Register).AllowAnonymous().RequireRateLimiting(RateLimit).ExcludeFromDescription();
        app.MapGet("/oauth/authorize", AuthorizeGet).AllowAnonymous().ExcludeFromDescription();
        app.MapPost("/oauth/authorize", AuthorizePost).AllowAnonymous().RequireRateLimiting(RateLimit).ExcludeFromDescription();
        app.MapPost("/oauth/token", TokenPost).AllowAnonymous().RequireRateLimiting(RateLimit).ExcludeFromDescription();
    }

    static IResult ProtectedResource(HttpContext ctx) => Results.Json(new Dictionary<string, object>
    {
        ["resource"] = Resource(ctx),
        ["authorization_servers"] = new[] { Base(ctx) },
        ["scopes_supported"] = new[] { Scope },
        ["bearer_methods_supported"] = new[] { "header" },
        ["resource_name"] = "Acme HR",
    });

    static IResult OAuthError(string error, string description, int status = 400) =>
        Results.Json(new { error, error_description = description }, statusCode: status);

    // ---------- dynamic client registration (RFC 7591) ----------

    record RegistrationRequest(string[]? redirect_uris, string? client_name, string? token_endpoint_auth_method);

    static bool RedirectAllowed(string uri)
    {
        if (AllowedRedirects.Contains(uri, StringComparer.Ordinal)) return true;
        return Uri.TryCreate(uri, UriKind.Absolute, out var u) && u.Scheme == "http" && (u.Host == "localhost" || u.Host == "127.0.0.1")
            && string.IsNullOrEmpty(u.UserInfo) && string.IsNullOrEmpty(u.Fragment);
    }

    static async Task<IResult> Register(HttpContext ctx)
    {
        RegistrationRequest? req;
        try { req = await ctx.Request.ReadFromJsonAsync<RegistrationRequest>(); }
        catch (System.Text.Json.JsonException) { return OAuthError("invalid_client_metadata", "The body is not valid JSON."); }
        if (req?.redirect_uris is not { Length: > 0 } uris) return OAuthError("invalid_redirect_uri", "redirect_uris is required.");
        if (uris.FirstOrDefault(u => !RedirectAllowed(u)) is { } bad) return OAuthError("invalid_redirect_uri", $"Redirect URI not allowed: {bad}");
        if (req.token_endpoint_auth_method is { } m && m != "none") return OAuthError("invalid_client_metadata", "Only public clients (token_endpoint_auth_method \"none\") are supported.");

        var name = string.IsNullOrWhiteSpace(req.client_name) ? "MCP client" : req.client_name.Trim()[..Math.Min(req.client_name.Trim().Length, 100)];
        var now = DateTimeOffset.UtcNow;
        var clientId = Sign(ctx, new() { ["token_use"] = "client", ["redirect_uris"] = uris.ToList(), ["client_name"] = name }, ClientLifetime, null);
        return Results.Json(new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["client_id_issued_at"] = now.ToUnixTimeSeconds(),
            ["client_name"] = name,
            ["redirect_uris"] = uris,
            ["grant_types"] = new[] { "authorization_code", "refresh_token" },
            ["response_types"] = new[] { "code" },
            ["token_endpoint_auth_method"] = "none",
        }, statusCode: StatusCodes.Status201Created);
    }

    // ---------- authorize: Acme HR login + consent ----------

    record AuthRequest(string ClientId, string ClientName, string RedirectUri, string CodeChallenge, string State, string Scope, string Resource);

    /// <summary>Checks the request. Errors about the client or redirect URI are shown on the page (never redirect to an unknown URI);
    /// other errors go back to the client's redirect URI.</summary>
    static async Task<(AuthRequest? Req, IResult? Error)> ReadAuthRequest(HttpContext ctx, Func<string, string?> get)
    {
        var clientId = get("client_id") ?? "";
        var redirect = get("redirect_uri") ?? "";
        var client = await Validate(clientId, "client");
        if (client is null) return (null, Page("Unknown app", "<p>This app is not registered. Add the connector again.</p>", 400));
        var uris = client.FindAll("redirect_uris").Select(c => c.Value).ToList();
        if (!uris.Contains(redirect, StringComparer.Ordinal)) return (null, Page("Unknown redirect", "<p>The redirect address does not match the registered app.</p>", 400));

        var state = get("state") ?? "";
        IResult Back(string error, string desc) =>
            Results.Redirect($"{redirect}{(redirect.Contains('?') ? '&' : '?')}error={error}&error_description={Uri.EscapeDataString(desc)}&state={Uri.EscapeDataString(state)}");

        if (get("response_type") != "code") return (null, Back("unsupported_response_type", "response_type must be code"));
        var challenge = get("code_challenge") ?? "";
        if (challenge.Length < 43 || get("code_challenge_method") != "S256") return (null, Back("invalid_request", "PKCE with code_challenge_method S256 is required"));
        var scope = string.IsNullOrWhiteSpace(get("scope")) ? Scope : get("scope")!;
        if (scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(s => s != Scope)) return (null, Back("invalid_scope", $"Only {Scope} is available"));
        var resource = string.IsNullOrWhiteSpace(get("resource")) ? Resource(ctx) : get("resource")!.TrimEnd('/');
        if (resource != Resource(ctx)) return (null, Back("invalid_target", "Unknown resource"));

        return (new AuthRequest(clientId, client.FindFirstValue("client_name") ?? "MCP client", redirect, challenge, state, Scope, resource), null);
    }

    static async Task<IResult> AuthorizeGet(HttpContext ctx, IAntiforgery af)
    {
        var (req, error) = await ReadAuthRequest(ctx, k => ctx.Request.Query[k].FirstOrDefault());
        return error ?? LoginPage(ctx, af, req!, null);
    }

    static async Task<IResult> AuthorizePost(HttpContext ctx, IAntiforgery af, UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn)
    {
        try { await af.ValidateRequestAsync(ctx); }
        catch (AntiforgeryValidationException) { return Page("Session expired", "<p>Please go back to the app and connect again.</p>", 400); }

        var form = await ctx.Request.ReadFormAsync();
        var (req, error) = await ReadAuthRequest(ctx, k => form[k].FirstOrDefault());
        if (error is not null) return error;
        if (form["action"] == "deny")
            return Results.Redirect($"{req!.RedirectUri}{(req.RedirectUri.Contains('?') ? '&' : '?')}error=access_denied&state={Uri.EscapeDataString(req.State)}");

        var user = await users.FindByEmailAsync(form["email"].FirstOrDefault() ?? "");
        var check = user is null ? Microsoft.AspNetCore.Identity.SignInResult.Failed
            : await signIn.CheckPasswordSignInAsync(user, form["password"].FirstOrDefault() ?? "", lockoutOnFailure: true);
        if (!check.Succeeded)
            return LoginPage(ctx, af, req!, check.IsLockedOut ? "Too many attempts. Try again in 15 minutes." : "Wrong email or password.");

        // The code carries only the user id: roles and employee id are read again when the token is issued.
        var code = Sign(ctx, new()
        {
            ["token_use"] = "code",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["sub"] = user!.Id,
            ["cid"] = ClientHash(req!.ClientId),
            ["redirect_uri"] = req.RedirectUri,
            ["code_challenge"] = req.CodeChallenge,
            ["scope"] = req.Scope,
            ["resource"] = req.Resource,
        }, CodeLifetime, null);
        var sep = req.RedirectUri.Contains('?') ? '&' : '?';
        return Results.Redirect($"{req.RedirectUri}{sep}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(req.State)}&iss={Uri.EscapeDataString(Base(ctx))}");
    }

    // ---------- token endpoint ----------

    static readonly ConcurrentDictionary<string, DateTimeOffset> UsedCodes = new();

    static async Task<IResult> TokenPost(HttpContext ctx, UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        if (!ctx.Request.HasFormContentType) return OAuthError("invalid_request", "Use application/x-www-form-urlencoded.");
        var form = await ctx.Request.ReadFormAsync();
        string? F(string k) => form[k].FirstOrDefault();
        var clientId = F("client_id") ?? "";
        if (await Validate(clientId, "client") is null) return OAuthError("invalid_client", "Unknown client.", 401);

        switch (F("grant_type"))
        {
            case "authorization_code":
            {
                var code = await Validate(F("code") ?? "", "code");
                if (code is null) return OAuthError("invalid_grant", "The code is invalid or expired.");
                if (code.FindFirstValue("cid") != ClientHash(clientId)) return OAuthError("invalid_grant", "The code was issued to another client.");
                if (code.FindFirstValue("redirect_uri") != F("redirect_uri")) return OAuthError("invalid_grant", "redirect_uri does not match.");
                var verifier = F("code_verifier") ?? "";
                if (verifier.Length < 43 || Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) != code.FindFirstValue("code_challenge"))
                    return OAuthError("invalid_grant", "PKCE verification failed.");
                if (F("resource") is { Length: > 0 } r && r.TrimEnd('/') != code.FindFirstValue("resource")) return OAuthError("invalid_target", "Unknown resource.");
                var jti = code.FindFirstValue("jti")!;
                foreach (var old in UsedCodes.Where(kv => kv.Value < DateTimeOffset.UtcNow).Select(kv => kv.Key).ToList()) UsedCodes.TryRemove(old, out _);
                if (!UsedCodes.TryAdd(jti, DateTimeOffset.UtcNow + CodeLifetime + TimeSpan.FromMinutes(1))) return OAuthError("invalid_grant", "The code was already used.");
                return await Issue(ctx, users, signIn, code.FindFirstValue("sub")!, clientId, code.FindFirstValue("scope")!, code.FindFirstValue("resource")!);
            }
            case "refresh_token":
            {
                var rt = await Validate(F("refresh_token") ?? "", "refresh");
                if (rt is null || rt.FindFirstValue("cid") != ClientHash(clientId)) return OAuthError("invalid_grant", "The refresh token is invalid or expired.");
                return await Issue(ctx, users, signIn, rt.FindFirstValue("sub")!, clientId, rt.FindFirstValue("scope")!, rt.FindFirstValue("resource")!);
            }
            default:
                return OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
        }
    }

    /// <summary>Issues an access + refresh token. The user is loaded again, so a locked-out or deleted account gets nothing,
    /// and the current roles and employee id are used.</summary>
    static async Task<IResult> Issue(HttpContext ctx, UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn, string userId, string clientId, string scope, string resource)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || await users.IsLockedOutAsync(user)) return OAuthError("invalid_grant", "The account is not available.");
        var principal = await signIn.CreateUserPrincipalAsync(user);
        var employeeId = principal.FindFirstValue(ClaimsPrincipalExtensions.EmployeeIdClaim);
        if (string.IsNullOrEmpty(employeeId)) return OAuthError("invalid_grant", "This account is not linked to an employee.");
        var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

        var access = Sign(ctx, new()
        {
            ["token_use"] = "access", ["sub"] = user.Id, ["cid"] = ClientHash(clientId),
            [ClaimsPrincipalExtensions.EmployeeIdClaim] = employeeId, ["name"] = user.Email ?? "", ["role"] = roles, ["scope"] = scope,
        }, AccessLifetime, resource);
        var refresh = Sign(ctx, new()
        {
            ["token_use"] = "refresh", ["jti"] = Guid.NewGuid().ToString("N"), ["sub"] = user.Id, ["cid"] = ClientHash(clientId), ["scope"] = scope, ["resource"] = resource,
        }, RefreshLifetime, null);
        return Results.Json(new { access_token = access, token_type = "Bearer", expires_in = (int)AccessLifetime.TotalSeconds, refresh_token = refresh, scope });
    }

    // ---------- tokens ----------

    static readonly JsonWebTokenHandler Jwt = new() { SetDefaultTimesOnTokenCreation = true };

    static string Sign(HttpContext ctx, Dictionary<string, object> claims, TimeSpan lifetime, string? audience)
    {
        var now = DateTime.UtcNow;
        return Jwt.CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            Issuer = Base(ctx),
            Audience = audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now + lifetime,
            SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256),
        });
    }

    /// <summary>Validates one of our own tokens and checks what it is for (client, code, refresh). Null when invalid.</summary>
    static async Task<ClaimsPrincipal?> Validate(string token, string use)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        var r = await Jwt.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = Key, ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = true, ClockSkew = TimeSpan.FromSeconds(30),
        });
        return r.IsValid && r.ClaimsIdentity.FindFirst("token_use")?.Value == use ? new ClaimsPrincipal(r.ClaimsIdentity) : null;
    }

    static string ClientHash(string clientId) => Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(clientId)))[..22];
    static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ---------- pages ----------

    static IResult LoginPage(HttpContext ctx, IAntiforgery af, AuthRequest r, string? error)
    {
        var tokens = af.GetAndStoreTokens(ctx);
        string H(string s) => HtmlEncoder.Default.Encode(s);
        string Hidden(string n, string v) => $"<input type=\"hidden\" name=\"{n}\" value=\"{H(v)}\">";
        var body = $"""
            <p><b>{H(r.ClientName)}</b> wants to read your Acme HR data as you:</p>
            <ul><li>your name, roles and leave balance (<code>{Scope}</code>)</li></ul>
            <p class="note">It can only read. It cannot change anything.</p>
            {(error is null ? "" : $"<p class=\"error\">{H(error)}</p>")}
            <form method="post" action="/oauth/authorize">
              {Hidden(tokens.FormFieldName, tokens.RequestToken!)}
              {Hidden("client_id", r.ClientId)}{Hidden("redirect_uri", r.RedirectUri)}{Hidden("response_type", "code")}
              {Hidden("code_challenge", r.CodeChallenge)}{Hidden("code_challenge_method", "S256")}{Hidden("state", r.State)}
              {Hidden("scope", r.Scope)}{Hidden("resource", r.Resource)}
              <label>Work email <input name="email" type="email" autocomplete="username" required></label>
              <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
              <div class="row"><button name="action" value="allow">Sign in and allow</button>
              <button name="action" value="deny" class="secondary" formnovalidate>Deny</button></div>
            </form>
            """;
        return Page("Connect to Acme HR", body, 200);
    }

    static IResult Page(string title, string body, int status) => Results.Content($$"""
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>{{HtmlEncoder.Default.Encode(title)}}</title>
        <style>
        body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#E3F4EE;color:#1F1147}
        main{max-width:420px;margin:48px auto;padding:20px 24px;background:#FFFEF9;border:3px solid #1F1147;border-radius:16px}
        h1{font-size:1.4em;margin:0 0 12px}label{display:grid;gap:4px;font-weight:600;margin:10px 0}
        input{padding:8px;border:2px solid #1F1147;border-radius:8px;font:inherit}.row{display:flex;gap:8px;margin-top:14px}
        button{background:#FFCE32;border:2px solid #1F1147;border-radius:10px;padding:8px 14px;font-weight:700;cursor:pointer}
        button.secondary{background:#fff}.error{color:#B8321A;font-weight:700}.note{opacity:.8;font-size:.9em}code{font-size:.9em}
        </style></head><body><main><h1>{{HtmlEncoder.Default.Encode(title)}}</h1>{{body}}</main></body></html>
        """, "text/html; charset=utf-8", Encoding.UTF8, status);
}
