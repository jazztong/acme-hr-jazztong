using System.Net;
using System.Net.Http.Json;
using Api.Models;
using Api.Services;

namespace Api.Tests;

/// <summary>Days taken this year: only Approved leave counts (same rule as the balance, POL-02).</summary>
public class DaysTakenThisYearTests
{
    const int Employee = 9; // seed: no leave of their own

    static DateOnly Monday(int week) =>
        Api.Data.Seed.MondayOnOrAfter(new DateOnly(DateTime.UtcNow.Year, 2, 2)).AddDays(7 * week);

    static async Task<decimal?> DaysTakenWith(LeaveStatus status)
    {
        using var db = TestDb.Create();
        db.LeaveRequests.Add(new LeaveRequest { EmployeeId = Employee, StartDate = Monday(1), EndDate = Monday(1).AddDays(1), Status = status, Reason = "Test" }); // Mon-Tue: 2 days
        await db.SaveChangesAsync();
        return await new LeaveService(db).DaysTakenThisYearAsync(Employee);
    }

    [Fact]
    public async Task Approved_leave_counts_as_taken() => Assert.Equal(2m, await DaysTakenWith(LeaveStatus.Approved));

    [Fact]
    public async Task Pending_leave_is_not_taken() => Assert.Equal(0m, await DaysTakenWith(LeaveStatus.Pending));

    [Fact]
    public async Task Rejected_leave_is_not_taken() => Assert.Equal(0m, await DaysTakenWith(LeaveStatus.Rejected));

    [Fact]
    public async Task Unknown_employee_has_no_summary()
    {
        using var db = TestDb.Create();
        Assert.Null(await new LeaveService(db).DaysTakenThisYearAsync(999));
    }
}

/// <summary>GET /employees/{id}/summary over HTTP: same access rules as the balance.</summary>
public class EmployeeSummaryApiTests(ApiFactory api) : IClassFixture<ApiFactory>
{
    record Summary(int EmployeeId, decimal DaysTakenThisYear);

    [Fact]
    public async Task Employee_sees_own_summary()
    {
        var gopal = await api.SignedInAs(People.Gopal); // id 7, seed: one approved half day this year
        var res = await gopal.GetAsync("/employees/7/summary");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var s = await res.Content.ReadFromJsonAsync<Summary>();
        Assert.Equal(7, s!.EmployeeId);
        Assert.Equal(0.5m, s.DaysTakenThisYear);
    }

    [Fact]
    public async Task Another_employee_gets_403()
    {
        var farah = await api.SignedInAs(People.Farah); // id 6
        var res = await farah.GetAsync("/employees/7/summary");
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Unknown_employee_id_gets_404()
    {
        var dina = await api.SignedInAs(People.Dina); // HR: may see everyone, so the id itself decides
        var res = await dina.GetAsync("/employees/999/summary");
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
        Assert.Equal("application/problem+json", res.Content.Headers.ContentType?.MediaType);
    }
}
