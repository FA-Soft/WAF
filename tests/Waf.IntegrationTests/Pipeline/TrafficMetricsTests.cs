using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>The traffic counts in metrics.db, against running gateways.</summary>
public sealed class TrafficMetricsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A route for www.example.com to backend A and one with no backend at all.</summary>
    private sealed class Gateway(params string[] extra) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            [.. new RouteArgs()
                .Add("website", [("http", A.Port)], hosts: ["www.example.com"])
                .Add("dead", [("http", ClosedPort())], hosts: ["dead.example.com"])
                .ToArray(), .. extra];

        /// <summary>A local port nothing listens on.</summary>
        private static int ClosedPort()
        {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }

    private static async Task<HttpStatusCode> SendAsync(Gateway gateway, string path, string host = "www.example.com")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
        request.Headers.Host = host;
        using var response = await gateway.Public.SendAsync(request, Ct);
        return response.StatusCode;
    }

    [Fact]
    public async Task The_counts_per_second_match_the_request_log()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "no-secret",
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/secret" } } },
        });
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        for (var i = 0; i < 20; i++)
        {
            Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, $"/page/{i}"));
        }

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/secret/x"));
        }

        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"));
        Assert.Equal(HttpStatusCode.NotFound, await SendAsync(gateway, "/", host: "unknown.example.com"));
        Assert.Equal(HttpStatusCode.BadGateway, await SendAsync(gateway, "/", host: "dead.example.com"));

        // Everything counted so far, written now (as on shutdown); and the request log has caught up.
        var writer = gateway.App.Services.GetRequiredService<RequestMetricsWriter>();
        await writer.FlushAsync(all: true, Ct);
        var monitor = gateway.App.Services.GetRequiredService<IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (monitor.Statistics!.Written < 26)
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }

        var store = gateway.App.Services.GetRequiredService<SqliteMetricsStore>();
        Assert.Equal(Path.Combine(gateway.DataDirectory, "metrics.db"), store.DatabasePath);
        var counts = await store.ReadCountsAsync(MetricsTier.Second, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddMinutes(1), Ct);

        var options = new DbContextOptionsBuilder<EventDbContext>()
            .UseSqlite(SqliteRequestLogStore.ConnectionString(new StoragePaths(gateway.DataDirectory, gateway.DataDirectory)))
            .Options;
        await using var db = new EventDbContext(options);
        var rows = await db.RequestEvents.AsNoTracking().ToListAsync(Ct);

        // Per second, the same totals as the request log.
        var fromLog = rows.GroupBy(r => r.TimestampMs / 1000).ToDictionary(g => g.Key, g => (long)g.Count());
        var fromCounts = counts.GroupBy(c => c.BucketStart).ToDictionary(g => g.Key, g => g.Sum(c => c.Count));
        Assert.Equal(fromLog.OrderBy(p => p.Key), fromCounts.OrderBy(p => p.Key));

        long Count(TrafficKind kind, string name = "") => counts.Where(c => c.Kind == kind && c.Name == name).Sum(c => c.Count);
        Assert.Equal(20, Count(TrafficKind.Forwarded));
        Assert.Equal(3, Count(TrafficKind.RuleBlocked, "no-secret"));
        Assert.Equal(1, Count(TrafficKind.AttackBlocked, "SqlInjection"));
        Assert.Equal(1, Count(TrafficKind.NoRoute));
        Assert.Equal(1, Count(TrafficKind.BackendError));
        Assert.All(counts.Where(c => c.Kind == TrafficKind.NoRoute), c => Assert.Equal(string.Empty, c.Route));
        Assert.All(counts.Where(c => c.Kind == TrafficKind.BackendError), c => Assert.Equal("dead", c.Route));

        // Bad requests per minute by source.
        var sources = await store.ReadSourcesAsync(MetricsTier.Minute, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddMinutes(1), Ct);
        Assert.All(sources, s => Assert.Equal("127.0.0.1", s.Source));
        Assert.Equal(5, sources.Sum(s => s.Count));

        var statistics = gateway.App.Services.GetRequiredService<IRequestMetricsMonitor>().Statistics!;
        Assert.Equal(26, statistics.Counted);
        Assert.Equal(0, statistics.Dropped);

        // The dashboard shows them.
        var dashboard = await gateway.GetPageAsync("/");
        Assert.Contains("Traffic counts", dashboard, StringComparison.Ordinal);
        Assert.Contains("requests counted since start", dashboard, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Counting_can_be_switched_off()
    {
        await using var gateway = new Gateway("--Gateway:Metrics:Enabled=false");
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/"));

        Assert.Null(gateway.App.Services.GetRequiredService<IRequestMetricsMonitor>().Statistics);
        Assert.False(File.Exists(Path.Combine(gateway.DataDirectory, "metrics.db")));
        Assert.Contains("Gateway:Metrics:Enabled", await gateway.GetPageAsync("/"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_settings_stop_the_start()
    {
        await using var gateway = new Gateway("--Gateway:Metrics:FlushIntervalSeconds=0");
        var error = await Assert.ThrowsAnyAsync<Exception>(async () => await gateway.InitializeAsync());
        Assert.Contains("Gateway:Metrics:FlushIntervalSeconds", error.ToString(), StringComparison.Ordinal);
    }
}
