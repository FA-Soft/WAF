using System.Diagnostics;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class RequestLogReaderTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private StoragePaths Paths => new(_directory, _directory);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private static RequestLogEntry Entry(
        int minutesAgo, string path = "/", string ip = "203.0.113.7", string host = "www.example.com", RequestAction action = RequestAction.Forwarded,
        WafEventKind? wafEvent = null, string? rule = null, int status = 200, string? detail = null, string? route = "website") =>
        new(Now.AddMinutes(-minutesAgo), ip, "GET", host, path, route, action, wafEvent, rule, detail,
            action == RequestAction.Forwarded ? "http://10.0.0.5:8080/" : null, status, 1.25);

    private async Task<RequestLogReader> WithAsync(params RequestLogEntry[] entries)
    {
        var store = new SqliteRequestLogStore(Paths);
        await store.InitializeAsync(Ct);
        await store.WriteAsync(entries, Ct);
        return new RequestLogReader(Paths);
    }

    private static async Task<List<string>> PathsAsync(RequestLogReader reader, RequestLogFilter filter) =>
        [.. (await reader.ReadPageAsync(filter, null, null, 100, Ct)).Items.Select(e => e.Path)];

    [Fact]
    public async Task An_absent_database_reads_as_empty()
    {
        var reader = new RequestLogReader(Paths);

        Assert.False(reader.DatabaseExists);
        Assert.Empty((await reader.ReadPageAsync(new RequestLogFilter(), null, null, 50, Ct)).Items);
        Assert.Equal(0, await reader.GetLatestIdAsync(Ct));
        Assert.Null(await reader.GetAsync(1, Ct));
    }

    [Fact]
    public async Task A_fixed_period_shows_only_the_requests_that_started_in_it()
    {
        var reader = await WithAsync(Entry(90, "/old"), Entry(50, "/start"), Entry(30, "/middle"), Entry(11, "/before-end"), Entry(10, "/end"), Entry(5, "/after"));

        var filter = new RequestLogFilter { From = Now.AddMinutes(-50), To = Now.AddMinutes(-10) };
        Assert.Equal(["/before-end", "/middle", "/start"], await PathsAsync(reader, filter));
        Assert.Equal(["/before-end", "/middle", "/start", "/old"], await PathsAsync(reader, new RequestLogFilter { To = Now.AddMinutes(-10) }));
        Assert.Empty(await PathsAsync(reader, new RequestLogFilter { To = Now.AddMinutes(-100) }));
    }

    [Fact]
    public async Task A_slow_request_written_after_later_ones_is_still_in_its_period()
    {
        // Written in completion order: the slow request started first but was logged last.
        var reader = await WithAsync(Entry(29, "/quick-1"), Entry(28, "/quick-2"), Entry(31, "/slow"));

        Assert.Equal(["/slow"], await PathsAsync(reader, new RequestLogFilter { To = Now.AddMinutes(-30) }));
    }

    [Fact]
    public async Task Views_select_what_happened()
    {
        var reader = await WithAsync(
            Entry(9, "/ok"),
            Entry(8, "/blocked", action: RequestAction.Blocked, wafEvent: WafEventKind.RuleBlocked, rule: "no-admin", status: 403),
            Entry(7, "/limited", action: RequestAction.RateLimited, wafEvent: WafEventKind.RateLimited, rule: "per-client", status: 429),
            Entry(6, "/would", wafEvent: WafEventKind.AttackDetected, rule: "sqli-1"),
            Entry(5, "/logged", wafEvent: WafEventKind.RuleLogged, rule: "watch"),
            Entry(4, "/missing", action: RequestAction.NoRoute, status: 404, route: null),
            Entry(3, "/down", action: RequestAction.BackendUnavailable, status: 503),
            Entry(2, "/closed", action: RequestAction.FailClosed, wafEvent: WafEventKind.FailClosed, status: 503, route: null));

        Assert.Equal(8, (await PathsAsync(reader, new RequestLogFilter())).Count);
        Assert.Equal(["/closed", "/limited", "/blocked"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.Blocked }));
        Assert.Equal(["/would"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.WouldBlock }));
        Assert.Equal(["/logged"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.Logged }));
        Assert.Equal(["/logged", "/would", "/ok"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.Forwarded }));
        Assert.Equal(["/missing"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.NoRoute }));
        Assert.Equal(["/closed", "/down"], await PathsAsync(reader, new RequestLogFilter { Show = LogView.Errors }));
    }

    [Fact]
    public async Task Exact_filters_and_time_range()
    {
        var reader = await WithAsync(
            Entry(120, "/old"),
            Entry(30, "/other-client", ip: "198.51.100.1"),
            Entry(20, "/api", host: "API.example.com", route: "api"),
            Entry(10, "/blocked", action: RequestAction.Blocked, rule: "No-Admin", status: 403));

        Assert.Equal(["/other-client"], await PathsAsync(reader, new RequestLogFilter { ClientIp = "198.51.100.1" }));
        Assert.Equal(["/api"], await PathsAsync(reader, new RequestLogFilter { Host = "api.EXAMPLE.com" }));
        Assert.Equal(["/api"], await PathsAsync(reader, new RequestLogFilter { Route = "API" }));
        Assert.Equal(["/blocked"], await PathsAsync(reader, new RequestLogFilter { Rule = "no-admin" }));
        Assert.Equal(["/blocked"], await PathsAsync(reader, new RequestLogFilter { Status = 403 }));
        Assert.Equal(["/blocked", "/api", "/other-client"], await PathsAsync(reader, new RequestLogFilter { From = Now.AddHours(-1) }));
        Assert.Empty(await PathsAsync(reader, new RequestLogFilter { From = Now.AddMinutes(1) }));
    }

    [Fact]
    public async Task Search_is_case_insensitive_and_literal()
    {
        var reader = await WithAsync(
            Entry(5, "/Products/100%_Cotton"),
            Entry(4, "/products/1000-cotton"),
            Entry(3, "/x", detail: "SqlInjection in Query 'q': UNION select"),
            Entry(2, "/y", ip: "192.0.2.55"));

        Assert.Equal(["/products/1000-cotton", "/Products/100%_Cotton"], await PathsAsync(reader, new RequestLogFilter { Search = "PRODUCTS/100" }));
        Assert.Equal(["/Products/100%_Cotton"], await PathsAsync(reader, new RequestLogFilter { Search = "100%_" }));
        Assert.Equal(["/x"], await PathsAsync(reader, new RequestLogFilter { Search = "union" }));
        Assert.Equal(["/y"], await PathsAsync(reader, new RequestLogFilter { Search = "192.0.2" }));
    }

    [Fact]
    public async Task Pages_walk_every_entry_once_in_both_directions()
    {
        var reader = await WithAsync([.. Enumerable.Range(0, 23).Select(i => Entry(100 - i, $"/{i}", action: i % 2 == 0 ? RequestAction.Forwarded : RequestAction.Blocked))]);
        var filter = new RequestLogFilter { Show = LogView.Forwarded }; // 12 entries: /0, /2, ... /22

        var pages = new List<RequestLogPage>();
        var page = await reader.ReadPageAsync(filter, null, null, 5, Ct);
        pages.Add(page);
        while (page.HasOlder)
        {
            page = await reader.ReadPageAsync(filter, page.Items[^1].Id, null, 5, Ct);
            pages.Add(page);
        }

        Assert.Equal([5, 5, 2], pages.Select(p => p.Items.Count));
        Assert.Equal(Enumerable.Range(0, 12).Select(i => $"/{22 - (2 * i)}"), pages.SelectMany(p => p.Items).Select(e => e.Path));
        Assert.Equal([false, true, true], pages.Select(p => p.HasNewer));

        // Back up from the last page.
        var newer = await reader.ReadPageAsync(filter, null, pages[2].Items[0].Id, 5, Ct);
        Assert.Equal(pages[1].Items.Select(e => e.Id), newer.Items.Select(e => e.Id));
        Assert.True(newer.HasNewer);
        Assert.True(newer.HasOlder);
    }

    [Fact]
    public async Task Live_view_reads_entries_after_an_id_up_to_a_bound()
    {
        var reader = await WithAsync(Entry(3, "/a"), Entry(2, "/b", action: RequestAction.Blocked), Entry(1, "/c"), Entry(0, "/d"));
        var latest = await reader.GetLatestIdAsync(Ct);

        var newer = await reader.ReadNewerAsync(new RequestLogFilter { Show = LogView.Forwarded }, latest - 3, 10, Ct, upTo: latest - 1);

        Assert.Equal(["/c"], newer.Select(e => e.Path)); // /b does not match, /d is beyond the bound
        Assert.Equal("/d", (await reader.GetAsync(latest, Ct))!.Path);
    }

    /// <summary>
    /// A million entries: every kind of query must stay fast, because reading stops as soon as a page is full and
    /// pages are found by id, not by offset. Timings are written to the test output.
    /// </summary>
    [Fact]
    public async Task Viewer_stays_fast_with_a_million_entries()
    {
        const int Total = 1_000_000;
        var store = new SqliteRequestLogStore(Paths);
        await store.InitializeAsync(Ct);
        var batch = new List<RequestLogEntry>(50_000);
        for (var i = 0; i < Total; i++)
        {
            // 2% blocked; one rare client (every 100,000th); timestamps spread over 30 days, oldest first.
            var minutesAgo = (int)((long)(Total - i) * 43_200 / Total);
            batch.Add(i % 50 == 0
                ? Entry(minutesAgo, $"/admin/{i}", action: RequestAction.Blocked, wafEvent: WafEventKind.RuleBlocked, rule: "no-admin", status: 403)
                : Entry(minutesAgo, $"/page/{i}", ip: i % 100_000 == 7 ? "192.0.2.99" : $"10.0.{i % 250}.{i % 200}"));
            if (batch.Count == batch.Capacity)
            {
                await store.WriteAsync(batch, Ct);
                batch.Clear();
            }
        }

        var reader = new RequestLogReader(Paths);
        var latest = await reader.GetLatestIdAsync(Ct);
        var last24h = Now.AddHours(-24);
        var queries = new (string Name, Func<Task<int>> Run)[]
        {
            ("newest 50", async () => (await reader.ReadPageAsync(new RequestLogFilter(), null, null, 50, Ct)).Items.Count),
            ("newest 200, last 24 h", async () => (await reader.ReadPageAsync(new RequestLogFilter { From = last24h }, null, null, 200, Ct)).Items.Count),
            ("blocked only", async () => (await reader.ReadPageAsync(new RequestLogFilter { Show = LogView.Blocked }, null, null, 50, Ct)).Items.Count),
            ("rare client IP", async () => (await reader.ReadPageAsync(new RequestLogFilter { ClientIp = "192.0.2.99" }, null, null, 50, Ct)).Items.Count),
            ("deep page (middle)", async () => (await reader.ReadPageAsync(new RequestLogFilter(), latest / 2, null, 50, Ct)).Items.Count),
            ("oldest page", async () => (await reader.ReadPageAsync(new RequestLogFilter(), 60, null, 50, Ct)).Items.Count),
            ("search, last 24 h", async () => (await reader.ReadPageAsync(new RequestLogFilter { From = last24h, Search = "admin/99" }, null, null, 50, Ct)).Items.Count),
            ("search without matches, last 24 h", async () => (await reader.ReadPageAsync(new RequestLogFilter { From = last24h, Search = "no-such-thing" }, null, null, 50, Ct)).Items.Count),
            ("search without matches, everything (worst case: reads all 1,000,000)", async () => (await reader.ReadPageAsync(new RequestLogFilter { Search = "no-such-thing" }, null, null, 50, Ct)).Items.Count),
            ("live poll", async () => (await reader.ReadNewerAsync(new RequestLogFilter { Show = LogView.Blocked }, latest - 1000, 200, Ct)).Count),
        };

        foreach (var (name, run) in queries)
        {
            await run(); // warm the page cache like a real viewer
            var watch = Stopwatch.StartNew();
            var count = await run();
            watch.Stop();
            TestContext.Current.TestOutputHelper!.WriteLine($"{name}: {count} rows in {watch.Elapsed.TotalMilliseconds:F1} ms");
            Assert.True(count > 0 || name.Contains("without", StringComparison.Ordinal), name);
            var limit = name.Contains("worst case", StringComparison.Ordinal) ? TimeSpan.FromSeconds(5) : TimeSpan.FromSeconds(1);
            Assert.True(watch.Elapsed < limit, $"{name} took {watch.Elapsed.TotalMilliseconds:F0} ms.");
        }
    }
}
