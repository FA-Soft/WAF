using System.Diagnostics;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class MetricsQueryTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteMetricsStore _store;

    public MetricsQueryTests()
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

    private static TrafficCount Count(DateTimeOffset at, long count, TrafficKind kind = TrafficKind.Forwarded, string route = "website", string name = "") =>
        new(at.ToUnixTimeSeconds(), kind, name, route, count);

    [Theory]
    [InlineData(1, MetricsTier.Second)]              // an hour: 3,600 seconds
    [InlineData(24, MetricsTier.Minute)]             // a day: 1,440 minutes
    [InlineData(24 * 7, MetricsTier.Hour)]           // a week: 168 hours
    [InlineData(24 * 30, MetricsTier.Day)]           // 30 days: hours are kept 4 weeks only
    [InlineData(24 * 92, MetricsTier.Day)]           // 3 months: hours are kept 4 weeks only
    [InlineData(24 * 365, MetricsTier.Week)]         // a year: days are kept 3 months only
    [InlineData(24 * 1096, MetricsTier.Month)]       // 3 years
    public void The_finest_tier_that_is_kept_and_fits_is_chosen(int hours, MetricsTier expected)
    {
        Assert.Equal(expected, SqliteMetricsStore.ChooseTier(Now.AddHours(-hours), Now, Now, new MetricsRetention()));
    }

    [Fact]
    public void An_old_short_period_uses_the_tier_that_still_has_it()
    {
        // One hour, two weeks ago: seconds (3 days) and minutes (1 week) are gone, hours are kept.
        Assert.Equal(MetricsTier.Hour, SqliteMetricsStore.ChooseTier(Now.AddDays(-14), Now.AddDays(-14).AddHours(1), Now, new MetricsRetention()));
    }

    [Fact]
    public async Task The_series_has_every_bucket_with_its_rate_and_peak()
    {
        await _store.InitializeAsync(Ct);
        var start = Now.AddMinutes(-3);
        await _store.WriteAsync(
            [
                Count(start, 60),
                Count(start.AddSeconds(1), 120, TrafficKind.RuleBlocked, name: "no-admin"),
                Count(start.AddMinutes(2), 6, TrafficKind.NoBackend),
            ],
            [],
            Ct);
        await _store.MaintainAsync(new MetricsRetention(), Now.AddMinutes(3), Ct); // minutes and their peaks

        var series = await _store.ReadSeriesAsync(new TrafficQuery(start, Now, MetricsTier.Minute), Ct);

        Assert.Equal(3, series.Count); // also the empty minute
        Assert.Equal((60L, 120L, 0L, 120L), (series[0].Good, series[0].Bad, series[0].Failed, series[0].Peak!.Value));
        Assert.Equal(3.0, series[0].PerSecond);
        Assert.Equal(0, series[1].Total);
        Assert.Equal(6, series[2].Failed);
        Assert.All(series, b => Assert.Equal(60, b.Seconds));
    }

    [Fact]
    public async Task Filters_narrow_the_series_to_a_route_kinds_or_sources()
    {
        await _store.InitializeAsync(Ct);
        var minute = Now.AddMinutes(-10);
        await _store.WriteAsync(
            [
                Count(minute, 50, route: "website"),
                Count(minute, 20, route: "api"),
                Count(minute, 4, TrafficKind.RuleBlocked, "website", "no-admin"),
                Count(minute, 3, TrafficKind.RuleBlocked, "api", "only-office"),
                Count(minute, 2, TrafficKind.AttackBlocked, "api", "SqlInjection"),
            ],
            [
                new SourceCount(minute.ToUnixTimeSeconds() - (minute.ToUnixTimeSeconds() % 60), "198.51.100.1", TrafficKind.RuleBlocked, 6),
                new SourceCount(minute.ToUnixTimeSeconds() - (minute.ToUnixTimeSeconds() % 60), "198.51.100.2", TrafficKind.AttackBlocked, 2),
                new SourceCount(minute.ToUnixTimeSeconds() - (minute.ToUnixTimeSeconds() % 60), "198.51.100.3", TrafficKind.RuleBlocked, 1),
            ],
            Ct);
        var period = new TrafficQuery(Now.AddMinutes(-20), Now, MetricsTier.Second);
        async Task<(long Good, long Bad)> TotalsAsync(TrafficQuery query)
        {
            var series = await _store.ReadSeriesAsync(query, Ct);
            return (series.Sum(b => b.Good), series.Sum(b => b.Bad));
        }

        Assert.Equal((70L, 9L), await TotalsAsync(period));
        Assert.Equal((20L, 5L), await TotalsAsync(period with { Route = "api" }));
        Assert.Equal((0L, 7L), await TotalsAsync(period with { Types = [new TrafficType(TrafficKind.RuleBlocked)] }));
        Assert.Equal((0L, 3L), await TotalsAsync(period with { Types = [new TrafficType(TrafficKind.RuleBlocked, "only-office")] }));
        Assert.Equal((0L, 6L), await TotalsAsync(period with { Types = [new TrafficType(TrafficKind.RuleBlocked, "no-admin"), new TrafficType(TrafficKind.AttackBlocked)] }));
        Assert.Equal((0L, 8L), await TotalsAsync(period with { Sources = ["198.51.100.1", "198.51.100.2"] }));
        Assert.Equal((0L, 6L), await TotalsAsync(period with { Sources = ["198.51.100.1", "198.51.100.2"], Types = [new TrafficType(TrafficKind.RuleBlocked)] }));

        // With a filter the peaks are unknown (they are kept for all traffic only).
        Assert.All(await _store.ReadSeriesAsync(period with { Route = "api" }, Ct), b => Assert.Null(b.Peak));
        // A source filter reads the minute tier, even when seconds were asked for.
        Assert.All(await _store.ReadSeriesAsync(period with { Sources = ["198.51.100.1"] }, Ct), b => Assert.Equal(60, b.Seconds));
    }

    [Fact]
    public async Task Kinds_and_top_sources_of_a_period()
    {
        await _store.InitializeAsync(Ct);
        var minute = Now.AddMinutes(-5);
        var bucket = minute.ToUnixTimeSeconds() - (minute.ToUnixTimeSeconds() % 60);
        await _store.WriteAsync(
            [
                Count(minute, 50),
                Count(minute, 4, TrafficKind.RuleBlocked, name: "no-admin"),
                Count(minute, 2, TrafficKind.NoRoute, route: ""),
            ],
            [
                new SourceCount(bucket, "198.51.100.1", TrafficKind.RuleBlocked, 4),
                new SourceCount(bucket, "198.51.100.2", TrafficKind.NoRoute, 2),
                new SourceCount(bucket, TrafficCounter.OtherSource, TrafficKind.NoRoute, 9),
            ],
            Ct);
        var period = new TrafficQuery(Now.AddHours(-1), Now, MetricsTier.Second, Types: [new TrafficType(TrafficKind.NoRoute)]);

        var kinds = await _store.ReadKindsAsync(period, Ct); // the type filter is what it chooses from: not applied
        Assert.Equal(
            [new TrafficKindTotal(TrafficKind.Forwarded, "", 50), new TrafficKindTotal(TrafficKind.RuleBlocked, "no-admin", 4), new TrafficKindTotal(TrafficKind.NoRoute, "", 2)],
            kinds);

        Assert.Equal([new LiveSourceCount("198.51.100.2", 2)], await _store.ReadTopSourcesAsync(period, 10, Ct));
        Assert.Equal(
            [new LiveSourceCount("198.51.100.1", 4), new LiveSourceCount("198.51.100.2", 2)],
            await _store.ReadTopSourcesAsync(period with { Types = [] }, 10, Ct)); // "other" is left out
        Assert.Equal(15, await _store.ReadSourceTotalAsync(period with { Types = [] }, Ct)); // the share is of everything, "other" too
        Assert.Equal(11, await _store.ReadSourceTotalAsync(period, Ct));
    }

    [Fact]
    public async Task Destinations_can_be_listed_and_filtered()
    {
        await _store.InitializeAsync(Ct);
        var minute = Now.AddMinutes(-5);
        var bucket = minute.ToUnixTimeSeconds() - (minute.ToUnixTimeSeconds() % 60);
        await _store.WriteAsync(
            [Count(minute, 50), Count(minute, 7, TrafficKind.NoRoute, route: ""), Count(minute, 3, TrafficKind.RuleBlocked, name: "no-wp")],
            [],
            [
                new SourceCount(bucket, "probe.example.net/.env", TrafficKind.NoRoute, 7),
                new SourceCount(bucket, "www.example.com/wp-login.php", TrafficKind.RuleBlocked, 3),
            ],
            Ct);
        var period = new TrafficQuery(Now.AddHours(-1), Now, MetricsTier.Second);

        Assert.Equal(
            [new LiveSourceCount("probe.example.net/.env", 7), new LiveSourceCount("www.example.com/wp-login.php", 3)],
            await _store.ReadTopDestinationsAsync(period, 10, Ct));
        Assert.Equal(
            [new LiveSourceCount("www.example.com/wp-login.php", 3)],
            await _store.ReadTopDestinationsAsync(period with { Types = [new TrafficType(TrafficKind.RuleBlocked)] }, 10, Ct));

        Assert.Equal(10, await _store.ReadDestinationTotalAsync(period, Ct));
        Assert.Equal(3, await _store.ReadDestinationTotalAsync(period with { Types = [new TrafficType(TrafficKind.RuleBlocked)] }, Ct));

        var series = await _store.ReadSeriesAsync(period with { Destinations = ["www.example.com/wp-login.php"] }, Ct);
        Assert.Equal((0L, 3L), (series.Sum(b => b.Good), series.Sum(b => b.Bad)));
        Assert.All(series, b => Assert.Equal(60, b.Seconds)); // kept per minute

        // Sources win over destinations: they are separate tables and cannot be combined.
        Assert.Empty((period with { Sources = ["198.51.100.1"], Destinations = ["www.example.com/wp-login.php"] }).DestinationFilter);
    }

    [Fact]
    public async Task Without_a_database_the_history_is_empty()
    {
        var period = new TrafficQuery(Now.AddHours(-1), Now, MetricsTier.Minute);
        var series = await _store.ReadSeriesAsync(period, Ct);
        Assert.Equal(60, series.Count);
        Assert.All(series, b => Assert.Equal(0, b.Total));
        Assert.Empty(await _store.ReadKindsAsync(period, Ct));
        Assert.Empty(await _store.ReadTopSourcesAsync(period, 10, Ct));
    }

    [Fact]
    public async Task Three_years_of_history_load_quickly()
    {
        await _store.InitializeAsync(Ct);
        // Three years of a busy site as the history job leaves it: 36 months, a year of weeks, 3 months of days.
        var counts = new List<TrafficCount>();
        foreach (var (tier, from, to) in new[]
        {
            (MetricsTier.Month, Now.AddDays(-1096), Now),
            (MetricsTier.Week, Now.AddDays(-366), Now),
            (MetricsTier.Day, Now.AddDays(-92), Now),
        })
        {
            for (var start = MetricsBuckets.Start(tier, from.ToUnixTimeSeconds()); start < to.ToUnixTimeSeconds(); start = MetricsBuckets.Next(tier, start))
            {
                for (var route = 0; route < 5; route++)
                {
                    counts.Add(new TrafficCount(start, TrafficKind.Forwarded, "", $"route-{route}", 1_000_000));
                    counts.Add(new TrafficCount(start, TrafficKind.RuleBlocked, "no-admin", $"route-{route}", 1_000));
                }
            }

            await InsertAsync(tier, counts);
            counts.Clear();
        }

        var stopwatch = Stopwatch.StartNew();
        var tierChosen = SqliteMetricsStore.ChooseTier(Now.AddDays(-1096), Now, Now, new MetricsRetention());
        var query = new TrafficQuery(Now.AddDays(-1096), Now, tierChosen);
        var series = await _store.ReadSeriesAsync(query, Ct);
        await _store.ReadKindsAsync(query, Ct);
        await _store.ReadTopSourcesAsync(query, 20, Ct);
        stopwatch.Stop();

        Assert.Equal(MetricsTier.Month, tierChosen);
        Assert.InRange(series.Count, 36, 37);
        Assert.True(series.Sum(b => b.Total) > 0);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1), $"took {stopwatch.Elapsed}");
    }

    /// <summary>Rows of a coarser tier, as the history job writes them.</summary>
    private async Task InsertAsync(MetricsTier tier, List<TrafficCount> counts)
    {
        await using var connection = new SqliteConnection($"Data Source={_store.DatabasePath}");
        await connection.OpenAsync(Ct);
        await using var transaction = connection.BeginTransaction();
        foreach (var count in counts)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO TrafficCounts VALUES ($tier, $start, $kind, $name, $route, $outcome, $count)";
            command.Parameters.AddWithValue("$tier", (int)tier);
            command.Parameters.AddWithValue("$start", count.BucketStart);
            command.Parameters.AddWithValue("$kind", (int)count.Kind);
            command.Parameters.AddWithValue("$name", count.Name);
            command.Parameters.AddWithValue("$route", count.Route);
            command.Parameters.AddWithValue("$outcome", (int)count.Outcome);
            command.Parameters.AddWithValue("$count", count.Count);
            await command.ExecuteNonQueryAsync(Ct);
        }

        await transaction.CommitAsync(Ct);
    }

    [Theory]
    [InlineData("RuleBlocked", TrafficKind.RuleBlocked, null)]
    [InlineData("RuleBlocked:no-admin", TrafficKind.RuleBlocked, "no-admin")]
    [InlineData("AttackBlocked:SqlInjection", TrafficKind.AttackBlocked, "SqlInjection")]
    [InlineData("WouldBeBlocked:rule:with:colons", TrafficKind.WouldBeBlocked, "rule:with:colons")]
    public void Types_are_read_from_the_address(string text, TrafficKind kind, string? name)
    {
        var type = TrafficType.Parse(text);
        Assert.Equal(new TrafficType(kind, name), type);
        Assert.Equal(text, type!.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("10")]
    [InlineData("Nonsense")]
    [InlineData("ruleblocked")]
    public void Unknown_types_are_ignored(string? text)
    {
        Assert.Null(TrafficType.Parse(text));
    }
}
