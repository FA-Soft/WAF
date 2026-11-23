using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.Proxy;

namespace FASoft.Waf.UnitTests.Logging;

public class RequestLogWriterTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static RequestLogEntry Entry(int i = 0) => new(
        DateTimeOffset.UnixEpoch.AddSeconds(i), "203.0.113.7", "GET", "www.example.com", $"/page/{i}", "website",
        RequestAction.Forwarded, null, null, null, "http://10.0.0.5:8080/", 200, 1.5);

    /// <summary>A store that can be stalled (like a locked database) or made to fail.</summary>
    private sealed class TestStore : IRequestLogStore
    {
        public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int FailuresLeft { get; set; }

        public List<RequestLogEntry> Stored { get; } = [];

        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public async Task WriteAsync(IReadOnlyList<RequestLogEntry> entries, CancellationToken cancellationToken)
        {
            await Gate.Task;
            if (FailuresLeft > 0)
            {
                FailuresLeft--;
                throw new IOException("disk full");
            }

            lock (Stored)
            {
                Stored.AddRange(entries);
            }
        }
    }

    private static RequestLogWriter Writer(IRequestLogStore store, int capacity = 100, int batch = 10) =>
        new(store, new EventLogOptions { QueueCapacity = capacity, BatchSize = batch }, TimeProvider.System, NullLogger<RequestLogWriter>.Instance);

    [Fact]
    public async Task Write_never_waits_for_a_stalled_database_and_counts_what_it_drops()
    {
        var store = new TestStore(); // stalled until the gate opens
        using var writer = Writer(store);
        await writer.StartAsync(Ct);

        const int Total = 200_000;
        var watch = Stopwatch.StartNew();
        for (var i = 0; i < Total; i++)
        {
            writer.Write(Entry(i));
        }

        watch.Stop();

        // 200,000 writes against a database that does not move: far below a millisecond each.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"Writing took {watch.Elapsed}.");
        var stats = writer.Statistics!;
        Assert.True(stats.Queued <= 100);
        Assert.True(stats.Dropped >= Total - 100 - 10, $"Dropped {stats.Dropped}.");

        store.Gate.SetResult();
        await writer.StopAsync(Ct);

        stats = writer.Statistics!;
        Assert.Equal(Total, stats.Written + stats.Dropped);
        Assert.Equal(stats.Written, store.Stored.Count);
    }

    [Fact]
    public async Task Queued_entries_are_written_in_order_and_drained_on_shutdown()
    {
        var store = new TestStore();
        store.Gate.SetResult();
        using var writer = Writer(store, capacity: 1000, batch: 7);
        await writer.StartAsync(Ct);

        for (var i = 0; i < 500; i++)
        {
            writer.Write(Entry(i));
        }

        await writer.StopAsync(Ct);

        Assert.Equal(Enumerable.Range(0, 500).Select(i => $"/page/{i}"), store.Stored.Select(e => e.Path));
        Assert.Equal((500L, 0L, 0), (writer.Statistics!.Written, writer.Statistics.Dropped, writer.Statistics.Queued));
    }

    [Fact]
    public async Task A_failing_batch_is_dropped_and_counted_and_writing_continues()
    {
        var store = new TestStore { FailuresLeft = 1 };
        store.Gate.SetResult();
        using var writer = Writer(store, capacity: 1000, batch: 10);
        await writer.StartAsync(Ct);

        for (var i = 0; i < 10; i++)
        {
            writer.Write(Entry(i));
        }

        // The first batch fails; wait until the writer reports it, then send more.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (writer.Statistics!.Dropped < 10 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, Ct);
        }

        Assert.Equal("disk full", writer.Statistics.LastError);
        for (var i = 10; i < 20; i++)
        {
            writer.Write(Entry(i));
        }

        await writer.StopAsync(Ct);

        Assert.Equal((10L, 10L), (writer.Statistics!.Written, writer.Statistics.Dropped));
        Assert.Null(writer.Statistics.LastError);
        Assert.Equal("/page/10", store.Stored[0].Path);
    }

    [Fact]
    public async Task Entries_written_after_shutdown_are_counted_as_dropped()
    {
        var store = new TestStore();
        store.Gate.SetResult();
        using var writer = Writer(store);
        await writer.StartAsync(Ct);
        await writer.StopAsync(Ct);

        writer.Write(Entry());

        Assert.Equal(1, writer.Statistics!.Dropped);
    }

    [Theory]
    [InlineData(99, 500, "QueueCapacity")]
    [InlineData(10_000, 0, "BatchSize")]
    public void Options_are_validated(int capacity, int batch, string expected)
    {
        var errors = new EventLogOptions { QueueCapacity = capacity, BatchSize = batch }.Validate();

        Assert.Contains(expected, Assert.Single(errors), StringComparison.Ordinal);
        Assert.Empty(new EventLogOptions().Validate());
    }

    [Fact]
    public void The_most_important_waf_event_is_kept()
    {
        var feature = new RequestLogFeature(DateTimeOffset.UnixEpoch, 0);
        static WafEvent Event(WafEventKind kind, string rule) =>
            new(DateTimeOffset.UnixEpoch, kind, System.Net.IPAddress.Loopback, "GET", "h", "/", null, rule, 200);

        feature.Record(Event(WafEventKind.RuleLogged, "watch"));
        feature.Record(Event(WafEventKind.RuleLogged, "watch-2"));
        Assert.Equal("watch", feature.RuleName);

        feature.Record(Event(WafEventKind.RuleDetected, "try-out"));
        feature.Record(Event(WafEventKind.RuleBlocked, "block"));
        feature.Record(Event(WafEventKind.AttackDetected, "sqli"));

        Assert.Equal((WafEventKind.RuleBlocked, "block"), (feature.Event, feature.RuleName));
    }

    [Fact]
    public async Task Sqlite_store_writes_every_field()
    {
        var directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
        var paths = new StoragePaths(directory, directory);
        try
        {
            var store = new SqliteRequestLogStore(paths);
            await store.InitializeAsync(Ct);
            await store.WriteAsync(
            [
                Entry(1),
                new RequestLogEntry(DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_123), "2001:db8::1", "POST", "api.example.com", "/login",
                    null, RequestAction.Blocked, WafEventKind.AttackBlocked, "sqli-union", "SqlInjection in Query 'q': union select", null, 403, 0.25),
            ], Ct);

            var options = new DbContextOptionsBuilder<EventDbContext>().UseSqlite(SqliteRequestLogStore.ConnectionString(paths)).Options;
            await using var db = new EventDbContext(options);
            var rows = await db.RequestEvents.OrderBy(e => e.Id).ToListAsync(Ct);

            Assert.Equal(2, rows.Count);
            Assert.Equal(("Forwarded", (string?)null, "http://10.0.0.5:8080/", "website"), (rows[0].Action, rows[0].Event, rows[0].Destination, rows[0].RouteName));
            var blocked = rows[1];
            Assert.Equal(
                (1_700_000_000_123L, "2001:db8::1", "POST", "api.example.com", "/login", "Blocked", "AttackBlocked", "sqli-union", 403, 0.25),
                (blocked.TimestampMs, blocked.ClientIp, blocked.Method, blocked.Host, blocked.Path, blocked.Action, blocked.Event, blocked.RuleName, blocked.StatusCode, blocked.LatencyMs));
            Assert.Null(blocked.Destination);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }
}
