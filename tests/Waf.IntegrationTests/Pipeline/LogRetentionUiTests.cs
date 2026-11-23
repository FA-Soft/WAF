using System.Net;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>The log retention settings page and the cleanup job, against a running gateway.</summary>
public sealed class LogRetentionUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)]).ToArray();
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/"));
        var monitor = gateway.App.Services.GetRequiredService<IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (monitor.Statistics!.Written < 1)
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }

        return gateway;
    }

    [Fact]
    public async Task Settings_page_shows_the_log_and_saves_new_limits()
    {
        await using var gateway = await StartAsync();

        var page = await gateway.GetPageAsync("/logs/settings");
        Assert.Contains("of at most 1,024 MB", page, StringComparison.Ordinal);
        Assert.Contains("<meter", page, StringComparison.Ordinal);
        Assert.Contains("value=\"30\"", page, StringComparison.Ordinal);

        var saved = await gateway.PostAsync("/logs/settings", "log-retention", new()
        {
            ["Model.BaseVersion"] = "1",
            ["Model.MaxAgeDays"] = "7",
            ["Model.MaxDatabaseSizeMb"] = "200",
        });

        Assert.Contains("Log retention saved (version 2).", saved, StringComparison.Ordinal);
        Assert.Contains("of at most 200 MB", saved, StringComparison.Ordinal);
        var retention = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.LogRetention;
        Assert.Equal((7, 200), (retention.MaxAgeDays, retention.MaxDatabaseSizeMb));

        var invalid = await gateway.PostAsync("/logs/settings", "log-retention", new()
        {
            ["Model.BaseVersion"] = "2",
            ["Model.MaxAgeDays"] = "7",
            ["Model.MaxDatabaseSizeMb"] = "5",
        });
        Assert.Contains("Use at least 10 MB.", invalid, StringComparison.Ordinal);
        Assert.Equal(2, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version);
    }

    [Fact]
    public async Task Clean_up_now_removes_entries_beyond_the_age_limit()
    {
        await using var gateway = await StartAsync();

        // Entries from before the age limit (as if the gateway had run for months).
        var paths = new StoragePaths(gateway.DataDirectory, gateway.DataDirectory);
        await new SqliteRequestLogStore(paths).WriteAsync(
        [
            .. Enumerable.Range(0, 100).Select(i => new RequestLogEntry(
                DateTimeOffset.UtcNow.AddDays(-60).AddMinutes(i), "203.0.113.7", "GET", "old.example.com", $"/old/{i}", null,
                RequestAction.NoRoute, null, null, null, null, 404, 1)),
        ], Ct);

        var html = await gateway.PostAsync("/logs/settings", "cleanup-now", []);

        Assert.Contains("Cleanup finished: 100 entries removed.", html, StringComparison.Ordinal);
        var retention = gateway.App.Services.GetRequiredService<ILogRetention>();
        Assert.Equal((100L, 0L), (retention.LastRun!.DeletedByAge, retention.LastRun.DeletedBySize));
        var info = await gateway.App.Services.GetRequiredService<RequestLogMaintenance>().GetInfoAsync(Ct);
        Assert.Equal(1, info!.Entries); // the request of this test stays
    }
}
