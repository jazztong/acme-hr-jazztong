using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using Api.Auth;
using Api.Data;
using Api.Services;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace Api.Mcp;

/// <summary>
/// Read-only Acme HR tools for the MCP connector. Who is asking always comes from the OAuth access token
/// (employee_id claim), never from a tool argument, so a tool can only return the signed-in employee's own data.
/// </summary>
[McpServerToolType]
public class HrTools(IHttpContextAccessor http, AcmeDb db, LeaveService leave)
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    ClaimsPrincipal User => http.HttpContext?.User ?? throw new McpException("Not signed in.");

    int EmployeeId()
    {
        var id = User.EmployeeId();
        return id > 0 ? id : throw new McpException("This sign-in is not linked to an employee.");
    }

    [McpServerTool(Name = "whoami", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Who is signed in to Acme HR through this connector: employee id, name, email, department and roles.")]
    public async Task<string> WhoAmI()
    {
        var id = EmployeeId();
        var e = await db.Employees.FindAsync(id) ?? throw new McpException($"Employee {id} was not found.");
        var roles = User.FindAll("role").Select(r => r.Value).ToArray();
        return JsonSerializer.Serialize(new { employeeId = e.Id, e.Name, e.Email, e.Department, roles }, Json);
    }

    [McpServerTool(Name = "get_my_leave_balance", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("The signed-in employee's annual leave balance in working days: entitlement, used (approved), pending and available. Half days count 0.5.")]
    public async Task<string> GetMyLeaveBalance()
    {
        var id = EmployeeId();
        var b = await leave.GetBalanceAsync(id) ?? throw new McpException($"Employee {id} was not found.");
        return JsonSerializer.Serialize(b, Json);
    }
}
