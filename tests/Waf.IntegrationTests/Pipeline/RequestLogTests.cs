using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;
using Waf.IntegrationTests.Proxy;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>The request log in events.db, against running gateways.</summary>
public sealed class RequestLogTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>One route for www.example.com to backend A; optional extra arguments (e.g. queue size).</summary>
    private sealed class Gateway(params string[] extra) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            [.. new RouteArgs().Add("website", [("http", A.Port)], hosts: ["www.example.com"]).ToArray(), .. extra];
    }

    private static async Task<HttpStatusCode> SendAsync(Gateway gateway, string pathAndQuery, string host = "www.example.com", Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{pathAndQuery}"));
        request.Headers.Host = host;
        configure?.Invoke(request);
        using var response = await gateway.Public.SendAsync(request, Ct);
        return response.StatusCode;
    }

    private static RequestLogStatistics Statistics(Gateway gateway) =>
        gateway.App.Services.GetRequiredService<IRequestLogMonitor>().Statistics!;

    private static async Task WaitUntilAsync(Func<bool> condition, int seconds = 20)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }
    }

    private static async Task<List<RequestEvent>> RowsAsync(Gateway gateway)
    {
        var options = new DbContextOptionsBuilder<EventDbContext>()
            .UseSqlite(SqliteRequestLogStore.ConnectionString(new StoragePaths(gateway.DataDirectory, gateway.DataDirectory)))
            .Options;
        await using var db = new EventDbContext(options);
        return await db.RequestEvents.AsNoTracking().OrderBy(e => e.Id).ToListAsync(Ct);
    }

    [Fact]
    public async Task Every_request_is_recorded_with_its_outcome_and_without_secrets()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "no-secret",
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/secret" } } },
        });
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, "test", null, Ct)).Succeeded);

        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/hello?token=query-secret", configure: r =>
        {
            r.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "auth-secret");
            r.Headers.Add("Cookie", "session=cookie-secret");
        }));
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/secret/x"));
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"));
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/account", configure: r => r.Headers.Add("Cookie", "id=1' OR '1'='1; session=other-cookie-secret")));
        Assert.Equal(HttpStatusCode.NotFound, await SendAsync(gateway, "/", host: "unknown.example.com"));

        await WaitUntilAsync(() => Statistics(gateway).Written >= 5);
        var rows = await RowsAsync(gateway);

        var forwarded = rows[0];
        Assert.Equal(("GET", "www.example.com", "/hello", "website", "Forwarded", 200), (forwarded.Method, forwarded.Host, forwarded.Path, forwarded.RouteName, forwarded.Action, forwarded.StatusCode));
        Assert.Equal("127.0.0.1", forwarded.ClientIp);
        Assert.Equal($"http://127.0.0.1:{gateway.A.Port}", forwarded.Destination!.TrimEnd('/'));
        Assert.True(forwarded.LatencyMs > 0);
        Assert.InRange(DateTimeOffset.FromUnixTimeMilliseconds(forwarded.TimestampMs), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow);

        Assert.Equal(("Blocked", "RuleBlocked", "no-secret", 403), (rows[1].Action, rows[1].Event, rows[1].RuleName, rows[1].StatusCode));
        Assert.Null(rows[1].Destination);
        Assert.Equal(("Blocked", "AttackBlocked", "/search"), (rows[2].Action, rows[2].Event, rows[2].Path));
        Assert.StartsWith("SqlInjection in Query", rows[2].Detail, StringComparison.Ordinal);
        Assert.Contains("(cookie value not logged)", rows[3].Detail, StringComparison.Ordinal);
        Assert.Equal(("NoRoute", 404, (string?)null), (rows[4].Action, rows[4].StatusCode, rows[4].RouteName));

        // Nothing secret in the database: no query strings, authorization headers or cookie values.
        SqliteConnection.ClearAllPools();
        var bytes = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(Path.Combine(gateway.DataDirectory, "events.db"), Ct))
            + (File.Exists(Path.Combine(gateway.DataDirectory, "events.db-wal")) ? Encoding.UTF8.GetString(await File.ReadAllBytesAsync(Path.Combine(gateway.DataDirectory, "events.db-wal"), Ct)) : string.Empty);
        foreach (var secret in new[] { "query-secret", "auth-secret", "cookie-secret", "token=" })
        {
            Assert.DoesNotContain(secret, bytes, StringComparison.Ordinal);
        }

        // The admin UI is not part of the request log.
        await gateway.GetPageAsync("/");
        await Task.Delay(300, Ct);
        Assert.Equal(5, (await RowsAsync(gateway)).Count);
    }

    /// <summary>
    /// Load test: while events.db is locked (as if the disk stalls), a burst of requests is served without delay;
    /// what does not fit in the queue is dropped and counted, and everything else is written once the lock is gone.
    /// </summary>
    [Fact]
    public async Task Requests_are_not_slowed_down_while_the_log_database_is_locked()
    {
        await using var gateway = new Gateway("--Gateway:EventLog:QueueCapacity=200", "--Gateway:EventLog:BatchSize=50");
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/warm-up"));
        await WaitUntilAsync(() => Statistics(gateway).Written == 1);

        // Hold a write lock on events.db: the writer's next batch waits for it (busy timeout) and then fails.
        await using var locker = new SqliteConnection(SqliteRequestLogStore.ConnectionString(new StoragePaths(gateway.DataDirectory, gateway.DataDirectory)));
        await locker.OpenAsync(Ct);
        await using (var begin = locker.CreateCommand())
        {
            begin.CommandText = "BEGIN EXCLUSIVE;";
            await begin.ExecuteNonQueryAsync(Ct);
        }

        const int Total = 3000;
        const int Concurrency = 32;
        var latencies = new double[Total];
        var next = -1;
        var watch = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, Concurrency).Select(async _ =>
        {
            int i;
            while ((i = Interlocked.Increment(ref next)) < Total)
            {
                var started = Stopwatch.GetTimestamp();
                Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, $"/load/{i}"));
                latencies[i] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            }
        }));
        watch.Stop();

        var during = Statistics(gateway);
        Array.Sort(latencies);
        var p99 = latencies[(int)(Total * 0.99)];
        TestContext.Current.TestOutputHelper!.WriteLine(
            $"{Total} requests in {watch.ElapsedMilliseconds} ms while events.db was locked; p50 {latencies[Total / 2]:F1} ms, p99 {p99:F1} ms, max {latencies[^1]:F1} ms; queued {during.Queued}, dropped {during.Dropped}.");

        // A blocking logger would hold requests for the busy timeout (5 s); here even the slowest is far below it.
        Assert.True(latencies[^1] < SqliteRequestLogStore.BusyTimeoutSeconds * 1000 / 2, $"Slowest request took {latencies[^1]:F0} ms.");
        Assert.True(during.Dropped > 0, "The queue (200) cannot hold 3000 entries; the rest must be dropped, not waited for.");
        Assert.True(during.Queued <= 200);

        // Release the lock: everything is accounted for, as written or dropped.
        await using (var rollback = locker.CreateCommand())
        {
            rollback.CommandText = "ROLLBACK;";
            await rollback.ExecuteNonQueryAsync(Ct);
        }

        await WaitUntilAsync(() => Statistics(gateway) is { Queued: 0 } s && s.Written + s.Dropped == Total + 1, seconds: 30);
        var after = Statistics(gateway);
        Assert.Equal(after.Written, (await RowsAsync(gateway)).Count);
        Assert.True(after.Written > 1);
    }

    [Fact]
    public async Task Logging_can_be_switched_off()
    {
        await using var gateway = new Gateway("--Gateway:EventLog:Enabled=false");
        await gateway.InitializeAsync();

        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/"));

        Assert.Null(gateway.App.Services.GetRequiredService<IRequestLogMonitor>().Statistics);
        Assert.False(File.Exists(Path.Combine(gateway.DataDirectory, "events.db")));
        Assert.Contains("Switched off in the host settings", await gateway.GetPageAsync("/"), StringComparison.Ordinal);
    }
}
