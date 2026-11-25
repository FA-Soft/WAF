using Microsoft.Data.Sqlite;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class MetricsRollupTests : IDisposable
{
    /// <summary>Wednesday 2026-01-28 23:58:00 UTC: four days before a new month, minutes before a new day.</summary>
    private static readonly DateTimeOffset Start = new(2026, 1, 28, 23, 58, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteMetricsStore _store;

    public MetricsRollupTests()
    {
        _store = new SqliteMetricsStore(Path.Combine(_directory, "metrics.db"));
    }

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

    private static long Unix(DateTimeOffset time) => time.ToUnixTimeSeconds();

    private static TrafficCount Count(DateTimeOffset at, long count, TrafficKind kind = TrafficKind.Forwarded, string route = "website", string name = "") =>
        new(Unix(at), kind, name, route, count);

    private async Task WriteAsync(params TrafficCount[] counts) => await _store.WriteAsync(counts, [], Ct);

    private Task<MetricsMaintenanceResult> MaintainAsync(DateTimeOffset now, MetricsRetention? retention = null) =>
        _store.MaintainAsync(retention ?? new MetricsRetention(), now, Ct);

    private async Task<long> TotalAsync(MetricsTier tier, DateTimeOffset? from = null, DateTimeOffset? to = null) =>
        (await _store.ReadCountsAsync(tier, from ?? DateTimeOffset.UnixEpoch, to ?? DateTimeOffset.UtcNow.AddYears(10), Ct)).Sum(c => c.Count);

    [Theory]
    [InlineData("2026-01-28T23:58:30Z", MetricsTier.Minute, "2026-01-28T23:58:00Z")]
    [InlineData("2026-01-28T23:58:30Z", MetricsTier.Hour, "2026-01-28T23:00:00Z")]
    [InlineData("2026-01-28T23:58:30Z", MetricsTier.Day, "2026-01-28T00:00:00Z")]
    [InlineData("2026-01-28T23:58:30Z", MetricsTier.Week, "2026-01-26T00:00:00Z")] // Monday
    [InlineData("2026-01-26T00:00:00Z", MetricsTier.Week, "2026-01-26T00:00:00Z")]
    [InlineData("2026-01-25T23:59:59Z", MetricsTier.Week, "2026-01-19T00:00:00Z")] // Sunday belongs to the week before
    [InlineData("1970-01-01T00:00:00Z", MetricsTier.Week, "1969-12-29T00:00:00Z")]
    [InlineData("2026-01-28T23:58:30Z", MetricsTier.Month, "2026-01-01T00:00:00Z")]
    [InlineData("2028-02-29T12:00:00Z", MetricsTier.Month, "2028-02-01T00:00:00Z")]
    public void Buckets_start_at_UTC_boundaries(string time, MetricsTier tier, string expected)
    {
        var at = Unix(DateTimeOffset.Parse(time, System.Globalization.CultureInfo.InvariantCulture));
        var start = MetricsBuckets.Start(tier, at);
        Assert.Equal(Unix(DateTimeOffset.Parse(expected, System.Globalization.CultureInfo.InvariantCulture)), start);
        Assert.True(MetricsBuckets.Next(tier, start) > at);
        Assert.Equal(start, MetricsBuckets.Ceiling(tier, start));
    }

    [Fact]
    public void Month_buckets_follow_the_calendar()
    {
        var january = Unix(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(Unix(new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero)), MetricsBuckets.Next(MetricsTier.Month, january));
        Assert.Equal(Unix(new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero)), MetricsBuckets.Ceiling(MetricsTier.Month, january + 31 * 86400 + 1));
    }

    [Fact]
    public async Task The_database_computes_the_same_buckets()
    {
        await _store.InitializeAsync(Ct);
        await using var connection = new SqliteConnection($"Data Source={_store.DatabasePath}");
        await connection.OpenAsync(Ct);
        var random = new Random(46);
        for (var i = 0; i < 500; i++)
        {
            var at = random.NextInt64(0, Unix(new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero)));
            foreach (var tier in MetricsBuckets.Tiers)
            {
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT " + SqliteMetricsStore.BucketSql(tier, "$t");
                command.Parameters.AddWithValue("$t", at);
                Assert.Equal(MetricsBuckets.Start(tier, at), Convert.ToInt64(await command.ExecuteScalarAsync(Ct), System.Globalization.CultureInfo.InvariantCulture));
            }
        }
    }

    [Fact]
    public async Task Every_tier_is_made_from_the_finer_one_and_totals_stay_equal()
    {
        await _store.InitializeAsync(Ct);
        // Seconds around midnight at the end of January: minutes, hours, days, weeks and months all change.
        var times = Enumerable.Range(0, 400).Select(i => Start.AddSeconds(i * 23)).ToList(); // 2h33m
        await WriteAsync([.. times.Select((t, i) => Count(t, i % 5 + 1)), Count(Start.AddDays(4), 7)]); // and 2 February
        var expected = times.Select((_, i) => (long)(i % 5 + 1)).Sum() + 7;

        // Ten days later (7 February): seconds (3 days) and minutes (7 days) are gone; hours, days and the week are complete.
        var result = await MaintainAsync(Start.AddDays(10));
        Assert.Null(result.Error);
        Assert.Equal(0, await TotalAsync(MetricsTier.Second));
        Assert.Equal(7, await TotalAsync(MetricsTier.Minute)); // only 1 February is less than a week ago
        foreach (var tier in new[] { MetricsTier.Hour, MetricsTier.Day, MetricsTier.Week })
        {
            Assert.Equal(expected, await TotalAsync(tier));
        }

        // A day's total in the day tier equals the sum of its hours.
        var day = new DateTimeOffset(2026, 1, 29, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(await TotalAsync(MetricsTier.Hour, day, day.AddDays(1)), await TotalAsync(MetricsTier.Day, day, day.AddDays(1)));
        Assert.Equal(expected - 7, await TotalAsync(MetricsTier.Month)); // February is not over yet

        // In March: February is complete too; hours (4 weeks) are gone.
        await MaintainAsync(Start.AddDays(35));
        Assert.Equal(0, await TotalAsync(MetricsTier.Hour));
        foreach (var tier in new[] { MetricsTier.Day, MetricsTier.Week, MetricsTier.Month })
        {
            Assert.Equal(expected, await TotalAsync(tier));
        }

        var months = await _store.ReadCountsAsync(MetricsTier.Month, DateTimeOffset.UnixEpoch, Start.AddYears(1), Ct);
        Assert.Equal(
            [Unix(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)), Unix(new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero))],
            months.Select(m => m.BucketStart));
        var weeks = await _store.ReadCountsAsync(MetricsTier.Week, DateTimeOffset.UnixEpoch, Start.AddYears(1), Ct);
        Assert.Equal([Unix(new DateTimeOffset(2026, 1, 26, 0, 0, 0, TimeSpan.Zero))], weeks.Select(w => w.BucketStart).Distinct());
    }

    [Fact]
    public async Task Buckets_are_rolled_up_only_when_complete_and_settled()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start.AddSeconds(10), 3), Count(Start.AddSeconds(70), 4));

        // 23:59:30: the 23:58 minute ended 90 seconds ago, less than the settle delay.
        await MaintainAsync(Start.AddSeconds(90));
        Assert.Equal(0, await TotalAsync(MetricsTier.Minute));

        // 00:00:00: 23:58 ended one minute ago, still not settled.
        await MaintainAsync(Start.AddMinutes(2));
        Assert.Equal(0, await TotalAsync(MetricsTier.Minute));

        // 00:01:00: 23:58 ended two minutes ago.
        await MaintainAsync(Start.AddMinutes(3));
        Assert.Equal(3, await TotalAsync(MetricsTier.Minute));
        Assert.Equal(0, await TotalAsync(MetricsTier.Hour)); // the hour 23:00 is not settled yet

        await MaintainAsync(Start.AddMinutes(4));
        Assert.Equal(7, await TotalAsync(MetricsTier.Minute));
        Assert.Equal(7, await TotalAsync(MetricsTier.Hour));
        Assert.Equal(7, await TotalAsync(MetricsTier.Day));
        Assert.Equal(0, await TotalAsync(MetricsTier.Week)); // this week is not over
        Assert.Equal(0, await TotalAsync(MetricsTier.Month));
        Assert.Equal(7, await TotalAsync(MetricsTier.Second)); // still kept for 3 days
    }

    [Fact]
    public async Task Running_again_changes_nothing()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5), Count(Start.AddMinutes(1), 6, TrafficKind.RuleBlocked, name: "no-admin"));
        var now = Start.AddDays(10);
        await MaintainAsync(now);
        var before = await SnapshotAsync();

        var again = await MaintainAsync(now);
        Assert.Equal(0, again.RolledUp);
        Assert.Equal(0, again.Deleted);
        Assert.Equal(before, await SnapshotAsync());
    }

    private async Task<string> SnapshotAsync()
    {
        var parts = new List<string>();
        foreach (var tier in MetricsBuckets.Tiers)
        {
            parts.AddRange((await _store.ReadCountsAsync(tier, DateTimeOffset.UnixEpoch, Start.AddYears(5), Ct)).Select(c => $"{tier} {c}"));
            parts.AddRange((await _store.ReadSourcesAsync(tier, DateTimeOffset.UnixEpoch, Start.AddYears(5), Ct)).Select(c => $"{tier} {c}"));
            parts.AddRange((await _store.ReadPeaksAsync(tier, DateTimeOffset.UnixEpoch, Start.AddYears(5), Ct)).Select(c => $"{tier} {c}"));
        }

        return string.Join('\n', parts);
    }

    [Fact]
    public async Task A_slow_request_stored_after_its_bucket_was_rolled_up_is_added()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5));
        await MaintainAsync(Start.AddHours(2));
        Assert.Equal(5, await TotalAsync(MetricsTier.Hour));

        // A request that started at Start took two hours (a download): it is counted at its start.
        await WriteAsync(Count(Start.AddSeconds(1), 1));
        await MaintainAsync(Start.AddHours(2).AddMinutes(1));

        foreach (var tier in new[] { MetricsTier.Second, MetricsTier.Minute, MetricsTier.Hour, MetricsTier.Day })
        {
            Assert.Equal(6, await TotalAsync(tier));
        }
    }

    [Fact]
    public async Task The_gap_after_the_gateway_was_off_is_caught_up_before_anything_is_removed()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5), Count(Start.AddHours(5), 6));

        // Off for 20 days: seconds and minutes are past their retention, but are rolled up first.
        var result = await MaintainAsync(Start.AddDays(20));

        Assert.True(result.Deleted > 0);
        Assert.Equal(0, await TotalAsync(MetricsTier.Second));
        Assert.Equal(0, await TotalAsync(MetricsTier.Minute));
        Assert.Equal(11, await TotalAsync(MetricsTier.Hour));
        Assert.Equal(11, await TotalAsync(MetricsTier.Day));
        Assert.Equal(11, await TotalAsync(MetricsTier.Week));
        Assert.Equal(11, await TotalAsync(MetricsTier.Month));
    }

    [Fact]
    public async Task Each_tier_is_removed_after_its_retention_and_nothing_is_kept_beyond_three_years()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5));

        await MaintainAsync(Start.AddDays(2));
        Assert.Equal(5, await TotalAsync(MetricsTier.Second));
        await MaintainAsync(Start.AddDays(4));
        Assert.Equal(0, await TotalAsync(MetricsTier.Second));
        Assert.Equal(5, await TotalAsync(MetricsTier.Minute));
        await MaintainAsync(Start.AddDays(9));
        Assert.Equal(0, await TotalAsync(MetricsTier.Minute));
        await MaintainAsync(Start.AddDays(30));
        Assert.Equal(0, await TotalAsync(MetricsTier.Hour));
        await MaintainAsync(Start.AddDays(100));
        Assert.Equal(0, await TotalAsync(MetricsTier.Day));
        Assert.Equal(5, await TotalAsync(MetricsTier.Week));
        await MaintainAsync(Start.AddDays(380));
        Assert.Equal(0, await TotalAsync(MetricsTier.Week));
        Assert.Equal(5, await TotalAsync(MetricsTier.Month));
        await MaintainAsync(Start.AddDays(1000));
        Assert.Equal(5, await TotalAsync(MetricsTier.Month));
        await MaintainAsync(Start.AddDays(1130));
        Assert.Equal(0, await TotalAsync(MetricsTier.Month));
        Assert.Equal(string.Empty, await SnapshotAsync());
    }

    [Fact]
    public async Task Shorter_retention_from_the_host_settings_applies()
    {
        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5));
        var small = new MetricsRetention { Second = TimeSpan.FromHours(6), Minute = TimeSpan.FromDays(1), Hour = TimeSpan.FromDays(2), Day = TimeSpan.FromDays(30), Week = TimeSpan.FromDays(90), Month = TimeSpan.FromDays(365) };

        await MaintainAsync(Start.AddHours(12), small);
        Assert.Equal(0, await TotalAsync(MetricsTier.Second));
        Assert.Equal(5, await TotalAsync(MetricsTier.Minute));
    }

    [Fact]
    public async Task Peaks_keep_a_short_spike_visible_in_every_coarser_tier()
    {
        await _store.InitializeAsync(Ct);
        // A quiet hour with one second of 80 requests (70 of them bad), and another second of 30.
        await WriteAsync(
            Count(Start.AddSeconds(5), 10),
            Count(Start.AddSeconds(5), 70, TrafficKind.AttackBlocked, name: "SqlInjection"),
            Count(Start.AddSeconds(6), 30),
            Count(Start.AddMinutes(1), 2),
            Count(Start.AddMinutes(1).AddSeconds(1), 1, TrafficKind.NoBackend));
        await MaintainAsync(Start.AddDays(10)); // hours, days and the week
        await AssertPeaksAsync(MetricsTier.Hour, MetricsTier.Day, MetricsTier.Week);
        await MaintainAsync(Start.AddDays(35)); // the month
        await AssertPeaksAsync(MetricsTier.Day, MetricsTier.Week, MetricsTier.Month);
    }

    private async Task AssertPeaksAsync(params MetricsTier[] tiers)
    {
        foreach (var tier in tiers)
        {
            var peaks = await _store.ReadPeaksAsync(tier, DateTimeOffset.UnixEpoch, Start.AddYears(1), Ct);
            var peak = Assert.Single(peaks);
            Assert.Equal((80, 30, 70, 1), (peak.Total, peak.Good, peak.Bad, peak.Failed));
        }
    }

    [Fact]
    public async Task Coarser_buckets_keep_the_top_sources_and_add_up_the_rest_as_other()
    {
        await _store.InitializeAsync(Ct);
        // 150 sources over three minutes of one hour: each minute alone has at most 100, the hour has 150.
        var sources = new List<SourceCount>();
        for (var i = 0; i < 150; i++)
        {
            var minute = Unix(Start.AddMinutes(-30)) + (i / 50 * 60); // 23:28 to 23:30: one hour, one day
            sources.Add(new SourceCount(minute, $"10.0.{i / 100}.{i % 100}", TrafficKind.RuleBlocked, i < 10 ? 100 : 1));
        }

        await _store.WriteAsync([Count(Start, 1)], sources, Ct);
        await MaintainAsync(Start.AddDays(1));

        var hour = await _store.ReadSourcesAsync(MetricsTier.Hour, DateTimeOffset.UnixEpoch, Start.AddYears(1), Ct);
        Assert.Equal(TrafficCounter.TopSources + 1, hour.Select(s => s.Source).Distinct().Count());
        Assert.Equal(sources.Sum(s => s.Count), hour.Sum(s => s.Count));
        Assert.Equal(50, hour.Single(s => s.Source == TrafficCounter.OtherSource).Count); // the 50 beyond the top 100, 1 each
        Assert.All(Enumerable.Range(0, 10), i => Assert.Contains(hour, s => s.Source == $"10.0.0.{i}" && s.Count == 100));

        var day = await _store.ReadSourcesAsync(MetricsTier.Day, DateTimeOffset.UnixEpoch, Start.AddYears(1), Ct);
        Assert.Equal(hour.Sum(s => s.Count), day.Sum(s => s.Count));
        Assert.Equal(TrafficCounter.TopSources + 1, day.Count);
    }

    [Fact]
    public async Task The_status_shows_the_size_and_the_range_of_every_tier()
    {
        var empty = await _store.GetStatusAsync(new MetricsRetention(), Ct);
        Assert.Equal(0, empty.FileBytes);

        await _store.InitializeAsync(Ct);
        await WriteAsync(Count(Start, 5), Count(Start.AddHours(1), 1));
        await MaintainAsync(Start.AddHours(2));

        var status = await _store.GetStatusAsync(new MetricsRetention(), Ct);
        Assert.True(status.FileBytes > 0);
        Assert.Equal(MetricsBuckets.Tiers, status.Tiers.Select(t => t.Tier));
        var seconds = status.Tiers[0];
        Assert.Equal((Start, Start.AddHours(1), TimeSpan.FromDays(3)), (seconds.Oldest!.Value, seconds.Newest!.Value, seconds.KeptFor));
        Assert.Equal(Start.AddMinutes(-58), status.Tiers[2].Oldest); // the hour 23:00
        Assert.Null(status.Tiers[5].Oldest);
    }

    [Fact]
    public async Task A_database_of_step_45_is_upgraded()
    {
        Directory.CreateDirectory(_directory);
        await using (var connection = new SqliteConnection($"Data Source={_store.DatabasePath}"))
        {
            await connection.OpenAsync(Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE TrafficCounts (Tier INTEGER NOT NULL, BucketStart INTEGER NOT NULL, Kind INTEGER NOT NULL, Name TEXT NOT NULL,
                    Route TEXT NOT NULL, Outcome INTEGER NOT NULL, Count INTEGER NOT NULL, PRIMARY KEY (Tier, BucketStart, Kind, Name, Route)) WITHOUT ROWID;
                CREATE TABLE SourceCounts (Tier INTEGER NOT NULL, BucketStart INTEGER NOT NULL, Source TEXT NOT NULL, Kind INTEGER NOT NULL,
                    Outcome INTEGER NOT NULL, Count INTEGER NOT NULL, PRIMARY KEY (Tier, BucketStart, Source, Kind)) WITHOUT ROWID;
                INSERT INTO TrafficCounts VALUES (0, 1769644680, 1, '', 'website', 0, 4);
                PRAGMA user_version = 1;
                """;
            await command.ExecuteNonQueryAsync(Ct);
        }

        await _store.InitializeAsync(Ct);
        await MaintainAsync(Start.AddDays(1));
        Assert.Equal(4, await TotalAsync(MetricsTier.Day));
    }

    [Fact]
    public void The_default_retention_is_valid_and_wrong_ones_are_refused()
    {
        Assert.Empty(new MetricsRetention().Validate("R"));
        Assert.Contains(new MetricsRetention { Second = TimeSpan.FromMinutes(5) }.Validate("R"), e => e.StartsWith("R:Second", StringComparison.Ordinal));
        Assert.Contains(new MetricsRetention { Hour = TimeSpan.FromDays(1) }.Validate("R"), e => e.StartsWith("R:Hour", StringComparison.Ordinal));
        Assert.Contains(new MetricsRetention { Month = TimeSpan.FromDays(5000) }.Validate("R"), e => e.StartsWith("R:Month", StringComparison.Ordinal));
    }
}
