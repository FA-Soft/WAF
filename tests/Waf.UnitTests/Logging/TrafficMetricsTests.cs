using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.UnitTests.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class TrafficMetricsTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static RequestLogEntry Entry(
        RequestAction action, WafEventKind? wafEvent = null, string? rule = null, string? detail = null, int status = 200,
        string? route = "website", string ip = "203.0.113.7", DateTimeOffset? at = null) =>
        new(at ?? Start, ip, "GET", "www.example.com", "/", route, action, wafEvent, rule, detail, null, status, 1.0);

    public static TheoryData<RequestLogEntry, bool, TrafficKind, string> Classifications => new()
    {
        { Entry(RequestAction.Forwarded), false, TrafficKind.Forwarded, "" },
        { Entry(RequestAction.Forwarded, status: 500), false, TrafficKind.Forwarded, "" }, // the backend's own answer
        { Entry(RequestAction.Redirected, status: 308), false, TrafficKind.Redirected, "" },
        { Entry(RequestAction.Answered), false, TrafficKind.Answered, "" },
        { Entry(RequestAction.Forwarded, WafEventKind.RuleDetected, "no-admin"), false, TrafficKind.WouldBeBlocked, "no-admin" },
        { Entry(RequestAction.Forwarded, WafEventKind.RateLimitDetected, "per-ip"), false, TrafficKind.WouldBeBlocked, "per-ip" },
        { Entry(RequestAction.Forwarded, WafEventKind.AttackDetected, "sqli-1", "SqlInjection in QueryString 'q': ' or 1=1"), false, TrafficKind.WouldBeBlocked, "SqlInjection" },
        { Entry(RequestAction.Forwarded, WafEventKind.RuleLogged, "watch"), false, TrafficKind.Forwarded, "" },
        { Entry(RequestAction.Blocked, WafEventKind.RuleBlocked, "no-admin", status: 403), false, TrafficKind.RuleBlocked, "no-admin" },
        { Entry(RequestAction.Blocked, WafEventKind.AttackBlocked, "xss-2", "CrossSiteScripting in Path: <script>", 403), false, TrafficKind.AttackBlocked, "CrossSiteScripting" },
        { Entry(RequestAction.Blocked, WafEventKind.AttackBlocked, "tool-1", "BadUserAgent in Header 'User-Agent': sqlmap", 403), false, TrafficKind.AttackBlocked, "BadUserAgent" },
        { Entry(RequestAction.RateLimited, WafEventKind.RateLimited, "per-ip", status: 429), false, TrafficKind.RateLimited, "per-ip" },
        { Entry(RequestAction.FailClosed, WafEventKind.FailClosed, status: 503), false, TrafficKind.FailClosed, "" },
        { Entry(RequestAction.NoRoute, status: 404, route: null), false, TrafficKind.NoRoute, "" },
        { Entry(RequestAction.BackendUnavailable, status: 503), false, TrafficKind.NoBackend, "" },
        { Entry(RequestAction.BackendUnavailable, status: 502), false, TrafficKind.BackendError, "" },
        { Entry(RequestAction.BackendUnavailable, status: 504), false, TrafficKind.BackendTimeout, "" },
        { Entry(RequestAction.Forwarded, status: 500), true, TrafficKind.GatewayError, "" },
        { Entry(RequestAction.Answered, status: 500), true, TrafficKind.GatewayError, "" },
    };

    [Theory]
    [MemberData(nameof(Classifications))]
    public void Every_outcome_is_classified(RequestLogEntry entry, bool failed, TrafficKind kind, string name)
    {
        Assert.Equal((kind, name), TrafficClassifier.Classify(entry, failed));
    }

    [Theory]
    [InlineData(TrafficKind.Forwarded, TrafficOutcome.Good)]
    [InlineData(TrafficKind.WouldBeBlocked, TrafficOutcome.Good)]
    [InlineData(TrafficKind.RuleBlocked, TrafficOutcome.Bad)]
    [InlineData(TrafficKind.NoRoute, TrafficOutcome.Bad)]
    [InlineData(TrafficKind.NoBackend, TrafficOutcome.Failed)]
    [InlineData(TrafficKind.GatewayError, TrafficOutcome.Failed)]
    public void Kinds_belong_to_an_outcome(TrafficKind kind, TrafficOutcome outcome)
    {
        Assert.Equal(outcome, TrafficClassifier.OutcomeOf(kind));
    }

    [Fact]
    public void Every_kind_has_a_known_outcome()
    {
        Assert.All(Enum.GetValues<TrafficKind>(), kind => Assert.True(Enum.IsDefined(TrafficClassifier.OutcomeOf(kind))));
    }

    [Fact]
    public void Counts_are_kept_per_second_and_taken_only_when_the_second_is_over()
    {
        var counter = new TrafficCounter();
        counter.Add(Start, TrafficKind.Forwarded, "", "website", "203.0.113.7");
        counter.Add(Start.AddMilliseconds(900), TrafficKind.Forwarded, "", "website", "203.0.113.7");
        counter.Add(Start.AddSeconds(1), TrafficKind.Forwarded, "", "website", "203.0.113.7");
        counter.Add(Start.AddSeconds(1), TrafficKind.Forwarded, "", "api", "203.0.113.7");

        var (counts, _, _) = counter.TakeCompleted(Start.AddSeconds(1.5), TimeSpan.Zero);
        var only = Assert.Single(counts);
        Assert.Equal(new TrafficCount(Start.ToUnixTimeSeconds(), TrafficKind.Forwarded, "", "website", 2), only);

        (counts, _, _) = counter.TakeCompleted(Start.AddSeconds(2), TimeSpan.Zero);
        Assert.Equal(2, counts.Count);
        Assert.Equal(0, counter.Pending);
    }

    [Fact]
    public void Sources_are_counted_per_minute_for_bad_requests_only()
    {
        var counter = new TrafficCounter();
        counter.Add(Start.AddSeconds(5), TrafficKind.Forwarded, "", "website", "198.51.100.1");
        counter.Add(Start.AddSeconds(5), TrafficKind.RuleBlocked, "no-admin", "website", "198.51.100.2");
        counter.Add(Start.AddSeconds(59), TrafficKind.RuleBlocked, "no-admin", "website", "198.51.100.2");
        counter.Add(Start.AddSeconds(30), TrafficKind.NoBackend, "", "website", "198.51.100.3");

        // Not yet: the minute ended less than the grace period ago.
        Assert.Empty(counter.TakeCompleted(Start.AddSeconds(70), TimeSpan.FromSeconds(30)).Sources);

        var sources = counter.TakeCompleted(Start.AddSeconds(90), TimeSpan.FromSeconds(30)).Sources;
        Assert.Equal([new SourceCount(Start.ToUnixTimeSeconds(), "198.51.100.2", TrafficKind.RuleBlocked, 2)], sources);
    }

    [Fact]
    public void Requested_destinations_are_counted_per_minute_for_bad_requests_only()
    {
        var counter = new TrafficCounter();
        counter.Add(Start.AddSeconds(5), TrafficKind.Forwarded, "", "website", "198.51.100.1", "www.example.com/");
        counter.Add(Start.AddSeconds(5), TrafficKind.NoRoute, "", null, "198.51.100.2", "probe.example.net/.env");
        counter.Add(Start.AddSeconds(50), TrafficKind.NoRoute, "", null, "198.51.100.3", "probe.example.net/.env");
        counter.Add(Start.AddSeconds(51), TrafficKind.RuleBlocked, "no-wp", "website", "198.51.100.3", "www.example.com/wp-login.php");

        var (_, sources, destinations) = counter.TakeCompleted(Start.AddMinutes(2), TimeSpan.Zero);

        Assert.Equal(3, sources.Count);
        Assert.Equal(
            [
                new SourceCount(Start.ToUnixTimeSeconds(), "probe.example.net/.env", TrafficKind.NoRoute, 2),
                new SourceCount(Start.ToUnixTimeSeconds(), "www.example.com/wp-login.php", TrafficKind.RuleBlocked, 1),
            ],
            destinations);
    }

    [Fact]
    public void A_scan_of_many_paths_is_counted_as_other_beyond_the_limit()
    {
        var counter = new TrafficCounter(maxCells: 1000, maxSourceCells: 3);
        for (var i = 0; i < 10; i++)
        {
            counter.Add(Start, TrafficKind.NoRoute, "", null, "198.51.100.1", $"www.example.com/probe-{i}");
        }

        var destinations = counter.TakeCompleted(Start.AddMinutes(5), TimeSpan.Zero).Destinations;
        Assert.Equal(10, destinations.Sum(d => d.Count));
        Assert.Equal(7, destinations.Single(d => d.Source == TrafficCounter.OtherSource).Count);
    }

    [Theory]
    [InlineData("WWW.Example.COM", "/Admin/Login", "www.example.com/Admin/Login")]
    [InlineData("www.example.com", "", "www.example.com/")]
    public void A_destination_is_the_host_in_lower_case_and_the_path(string host, string path, string expected)
    {
        var entry = new RequestLogEntry(Start, "203.0.113.7", "GET", host, path, null, RequestAction.NoRoute, null, null, null, null, 404, 1);
        Assert.Equal(expected, TrafficClassifier.Destination(entry));
    }

    [Fact]
    public void A_long_destination_is_cut()
    {
        var entry = new RequestLogEntry(Start, "203.0.113.7", "GET", new string('h', 200), "/" + new string('p', 500), null, RequestAction.NoRoute, null, null, null, null, 404, 1);
        var destination = TrafficClassifier.Destination(entry);
        Assert.Equal(TrafficClassifier.MaxDestinationLength, destination.Length);
        Assert.StartsWith(new string('h', 100) + "/", destination, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_the_top_sources_of_a_minute_are_kept_and_the_rest_is_other()
    {
        var minute = Start.ToUnixTimeSeconds();
        var sources = new List<SourceCount>
        {
            new(minute, "10.0.0.1", TrafficKind.RuleBlocked, 10),
            new(minute, "10.0.0.1", TrafficKind.AttackBlocked, 5),
            new(minute, "10.0.0.2", TrafficKind.RuleBlocked, 12),
            new(minute, "10.0.0.3", TrafficKind.RuleBlocked, 3),
            new(minute, "10.0.0.4", TrafficKind.NoRoute, 1),
            new(minute, TrafficCounter.OtherSource, TrafficKind.NoRoute, 4),
            new(minute + 60, "10.0.0.9", TrafficKind.RateLimited, 7),
        };

        var limited = TrafficCounter.LimitSources(sources, top: 2);

        Assert.Equal(
            [
                new SourceCount(minute, "10.0.0.1", TrafficKind.RuleBlocked, 10),
                new SourceCount(minute, "10.0.0.1", TrafficKind.AttackBlocked, 5),
                new SourceCount(minute, "10.0.0.2", TrafficKind.RuleBlocked, 12),
                new SourceCount(minute, TrafficCounter.OtherSource, TrafficKind.RuleBlocked, 3),
                new SourceCount(minute, TrafficCounter.OtherSource, TrafficKind.NoRoute, 5),
                new SourceCount(minute + 60, "10.0.0.9", TrafficKind.RateLimited, 7),
            ],
            limited);
        Assert.Equal(sources.Sum(s => s.Count), limited.Sum(s => s.Count));
    }

    [Fact]
    public void Too_many_sources_at_once_are_counted_as_other()
    {
        var counter = new TrafficCounter(maxCells: 1000, maxSourceCells: 3);
        for (var i = 0; i < 10; i++)
        {
            Assert.True(counter.Add(Start, TrafficKind.RuleBlocked, "r", "website", $"10.0.0.{i}"));
        }

        var sources = counter.TakeCompleted(Start.AddMinutes(5), TimeSpan.Zero).Sources;
        Assert.Equal(10, sources.Sum(s => s.Count));
        Assert.Equal(7, sources.Single(s => s.Source == TrafficCounter.OtherSource).Count); // three addresses fit
    }

    [Fact]
    public void A_full_counter_refuses_new_counts_but_keeps_counting_existing_ones()
    {
        var counter = new TrafficCounter(maxCells: 2);
        Assert.True(counter.Add(Start, TrafficKind.Forwarded, "", "a", null));
        Assert.True(counter.Add(Start, TrafficKind.Forwarded, "", "b", null));
        Assert.False(counter.Add(Start, TrafficKind.Forwarded, "", "c", null));
        Assert.True(counter.Add(Start, TrafficKind.Forwarded, "", "a", null));
    }

    [Fact]
    public async Task No_request_is_lost_or_counted_twice_while_buckets_are_taken()
    {
        var counter = new TrafficCounter();
        var time = Start;
        const int Threads = 8;
        const int PerThread = 50_000;
        long taken = 0;
        using var done = new CancellationTokenSource();

        var takerTask = Task.Run(() =>
        {
            while (!done.IsCancellationRequested)
            {
                taken += counter.TakeCompleted(time.AddSeconds(100), TimeSpan.Zero, all: true).Counts.Sum(c => c.Count);
            }
        }, Ct);

        await Task.WhenAll(Enumerable.Range(0, Threads).Select(t => Task.Run(() =>
        {
            for (var i = 0; i < PerThread; i++)
            {
                counter.Add(time.AddSeconds(i % 3), TrafficKind.Forwarded, "", "website", null);
            }
        }, Ct)));

        await done.CancelAsync();
        await takerTask;
        taken += counter.TakeCompleted(time.AddSeconds(100), TimeSpan.Zero, all: true).Counts.Sum(c => c.Count);

        Assert.Equal(Threads * PerThread, taken);
    }

    [Fact]
    public async Task The_store_adds_counts_to_buckets_that_are_stored_already()
    {
        var store = new SqliteMetricsStore(Path.Combine(_directory, "metrics.db"));
        await store.InitializeAsync(Ct);
        await store.InitializeAsync(Ct); // idempotent
        var second = Start.ToUnixTimeSeconds();

        await store.WriteAsync(
            [new(second, TrafficKind.Forwarded, "", "website", 3), new(second, TrafficKind.RuleBlocked, "no-admin", "website", 1)],
            [new(second, "10.0.0.1", TrafficKind.RuleBlocked, 1)],
            Ct);
        await store.WriteAsync(
            [new(second, TrafficKind.Forwarded, "", "website", 2)],
            [new(second, "10.0.0.1", TrafficKind.RuleBlocked, 4)],
            Ct);

        var counts = await store.ReadCountsAsync(MetricsTier.Second, Start, Start.AddSeconds(1), Ct);
        Assert.Equal(
            [new TrafficCount(second, TrafficKind.Forwarded, "", "website", 5), new TrafficCount(second, TrafficKind.RuleBlocked, "no-admin", "website", 1)],
            counts);
        Assert.Equal(
            [new SourceCount(second, "10.0.0.1", TrafficKind.RuleBlocked, 5)],
            await store.ReadSourcesAsync(MetricsTier.Minute, Start, Start.AddMinutes(1), Ct));
        Assert.Empty(await store.ReadCountsAsync(MetricsTier.Minute, Start, Start.AddSeconds(1), Ct));
    }

    [Fact]
    public async Task A_database_from_a_newer_version_is_refused()
    {
        var path = Path.Combine(_directory, "metrics.db");
        var store = new SqliteMetricsStore(path);
        await store.InitializeAsync(Ct);
        await using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            await connection.OpenAsync(Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = $"PRAGMA user_version={SqliteMetricsStore.SchemaVersion + 1}";
            await command.ExecuteNonQueryAsync(Ct);
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.InitializeAsync(Ct));
    }

    [Fact]
    public void The_database_path_is_in_the_data_folder_unless_set()
    {
        var paths = new StoragePaths(_directory, _directory);
        Assert.Equal(Path.Combine(_directory, "metrics.db"), SqliteMetricsStore.ResolvePath(paths, null));
        Assert.Equal(Path.Combine(_directory, "stats", "m.db"), SqliteMetricsStore.ResolvePath(paths, Path.Combine("stats", "m.db")));
    }

    /// <summary>A store that remembers what was written, or fails.</summary>
    private sealed class TestStore : IMetricsStore
    {
        public bool FailInitialize { get; set; }

        public int FailuresLeft { get; set; }

        public List<TrafficCount> Counts { get; } = [];

        public List<SourceCount> Sources { get; } = [];

        public List<SourceCount> Destinations { get; } = [];

        public int Writes { get; private set; }

        public Task InitializeAsync(CancellationToken cancellationToken) =>
            FailInitialize ? throw new IOException("read-only file system") : Task.CompletedTask;

        public Task WriteAsync(IReadOnlyList<TrafficCount> counts, IReadOnlyList<SourceCount> sources, IReadOnlyList<SourceCount> destinations, CancellationToken cancellationToken)
        {
            if (FailuresLeft > 0)
            {
                FailuresLeft--;
                throw new IOException("disk full");
            }

            Counts.AddRange(counts);
            Sources.AddRange(sources);
            Destinations.AddRange(destinations);
            Writes++;
            return Task.CompletedTask;
        }
    }

    private static RequestMetricsWriter Writer(IMetricsStore store, ManualTimeProvider time, int maxPending = 100_000) =>
        new(store, new MetricsOptions { MaxPendingCounts = maxPending }, time, NullLogger<RequestMetricsWriter>.Instance);

    [Fact]
    public async Task The_writer_stores_completed_seconds_in_one_write()
    {
        var store = new TestStore();
        var time = new ManualTimeProvider { Now = Start };
        using var writer = Writer(store, time);
        for (var i = 0; i < 100; i++)
        {
            writer.Record(Entry(RequestAction.Forwarded, at: Start.AddMilliseconds(i * 30)), failed: false); // seconds 0 to 2
        }

        writer.Record(Entry(RequestAction.Blocked, WafEventKind.RuleBlocked, "no-admin", status: 403, at: Start.AddSeconds(1)), failed: false);

        time.Now = Start.AddSeconds(2.5);
        await writer.FlushAsync(all: false, Ct);

        Assert.Equal(1, store.Writes);
        Assert.Equal(new long[] { 34, 33 }, store.Counts.Where(c => c.Kind == TrafficKind.Forwarded).OrderBy(c => c.BucketStart).Select(c => c.Count));
        Assert.Equal(new long[] { 0, 1 }, store.Counts.Select(c => c.BucketStart - Start.ToUnixTimeSeconds()).Distinct().Order());
        Assert.Empty(store.Sources); // the minute is not over yet

        time.Now = Start.AddMinutes(2);
        await writer.FlushAsync(all: false, Ct);
        Assert.Equal(101, store.Counts.Sum(c => c.Count));
        Assert.Equal([new SourceCount(Start.ToUnixTimeSeconds(), "203.0.113.7", TrafficKind.RuleBlocked, 1)], store.Sources);
        Assert.Equal([new SourceCount(Start.ToUnixTimeSeconds(), "www.example.com/", TrafficKind.RuleBlocked, 1)], store.Destinations);

        var statistics = writer.Statistics!;
        Assert.Equal(101, statistics.Counted);
        Assert.Equal(0, statistics.Dropped);
        Assert.Equal(time.Now, statistics.LastWrite);
        Assert.Null(statistics.LastError);
    }

    [Fact]
    public async Task Nothing_is_written_when_nothing_happened()
    {
        var store = new TestStore();
        using var writer = Writer(store, new ManualTimeProvider { Now = Start });
        await writer.FlushAsync(all: true, Ct);
        Assert.Equal(0, store.Writes);
    }

    [Fact]
    public async Task Counts_that_cannot_be_stored_are_dropped_and_counted()
    {
        var store = new TestStore { FailuresLeft = 1 };
        var time = new ManualTimeProvider { Now = Start };
        using var writer = Writer(store, time);
        writer.Record(Entry(RequestAction.Forwarded), failed: false);
        writer.Record(Entry(RequestAction.Forwarded), failed: false);

        time.Now = Start.AddSeconds(1);
        await writer.FlushAsync(all: false, Ct);
        Assert.Equal(2, writer.Statistics!.Dropped);
        Assert.Equal("disk full", writer.Statistics!.LastError);

        writer.Record(Entry(RequestAction.Forwarded, at: Start.AddSeconds(1)), failed: false);
        time.Now = Start.AddSeconds(2);
        await writer.FlushAsync(all: false, Ct);
        Assert.Equal(1, store.Counts.Sum(c => c.Count));
        Assert.Null(writer.Statistics!.LastError);
    }

    [Fact]
    public async Task Counts_beyond_the_limit_are_dropped_and_counted()
    {
        var store = new TestStore();
        var time = new ManualTimeProvider { Now = Start };
        using var writer = Writer(store, time, maxPending: 1000);
        for (var i = 0; i < 1005; i++)
        {
            writer.Record(Entry(RequestAction.Forwarded, route: $"route-{i}"), failed: false);
        }

        Assert.Equal(1000, writer.Statistics!.Counted);
        Assert.Equal(5, writer.Statistics!.Dropped);
        await writer.FlushAsync(all: true, Ct);
        Assert.Equal(1000, store.Counts.Sum(c => c.Count));
    }

    [Fact]
    public async Task A_database_that_cannot_be_opened_drops_counts_until_it_can()
    {
        var store = new TestStore { FailInitialize = true };
        var time = new ManualTimeProvider { Now = Start };
        using var writer = Writer(store, time);
        writer.Record(Entry(RequestAction.Forwarded), failed: false);
        time.Now = Start.AddSeconds(1);
        await writer.FlushAsync(all: false, Ct);
        Assert.Equal(1, writer.Statistics!.Dropped);
        Assert.Equal("read-only file system", writer.Statistics!.LastError);

        store.FailInitialize = false;
        writer.Record(Entry(RequestAction.Forwarded, at: Start.AddSeconds(1)), failed: false);
        time.Now = Start.AddSeconds(2);
        await writer.FlushAsync(all: false, Ct);
        Assert.Equal(1, store.Counts.Sum(c => c.Count));
    }

    [Theory]
    [InlineData(0, 100_000)]
    [InlineData(61, 100_000)]
    [InlineData(5, 999)]
    public void Invalid_settings_are_refused(int flush, int maxPending)
    {
        Assert.NotEmpty(new MetricsOptions { FlushIntervalSeconds = flush, MaxPendingCounts = maxPending }.Validate());
        Assert.Empty(new MetricsOptions().Validate());
    }
}
