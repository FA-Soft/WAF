using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Logging;

/// <summary>Notices of unusual traffic, against four weeks of recorded history: busy days, quiet nights.</summary>
public sealed class TrafficAlertTests : IDisposable
{
    /// <summary>Wednesday 25 November 2026, 00:00 UTC: history runs the four weeks before.</summary>
    private static readonly DateTimeOffset Today = new(2026, 11, 25, 0, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly ManualTimeProvider _time = new() { Now = Today };
    private readonly ServiceProvider _services;
    private readonly SqliteMetricsStore _store;

    public TrafficAlertTests()
    {
        var paths = new StoragePaths(_directory, _directory);
        paths.EnsureDataDirectory();
        _services = new ServiceCollection().AddSingleton<TimeProvider>(_time).AddWafData(paths).BuildServiceProvider();
        _store = new SqliteMetricsStore(Path.Combine(_directory, "metrics.db"));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _services.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>Busy from 08:00 to 18:00 UTC (10 requests a second, 2 % bad), quiet at night (1 a second, 2 % bad).</summary>
    private static (double Good, double Bad) Usual(DateTimeOffset hour) => hour.Hour is >= 8 and < 18 ? (9.8, 0.2) : (0.98, 0.02);

    private async Task RecordHistoryAsync(int days)
    {
        await _services.GetRequiredService<ConfigurationStore>().InitializeAsync(Ct); // no configuration: default notice settings
        await _store.InitializeAsync(Ct);
        await using var connection = new SqliteConnection($"Data Source={_store.DatabasePath}");
        await connection.OpenAsync(Ct);
        await using var transaction = connection.BeginTransaction();
        for (var hour = Today.AddDays(-days); hour < Today; hour = hour.AddHours(1))
        {
            var (good, bad) = Usual(hour);
            foreach (var (kind, perSecond) in new[] { (TrafficKind.Forwarded, good), (TrafficKind.NoRoute, bad) })
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = "INSERT INTO TrafficCounts VALUES (2, $start, $kind, '', 'website', $outcome, $count)";
                command.Parameters.AddWithValue("$start", hour.ToUnixTimeSeconds());
                command.Parameters.AddWithValue("$kind", (int)kind);
                command.Parameters.AddWithValue("$outcome", (int)TrafficClassifier.OutcomeOf(kind));
                command.Parameters.AddWithValue("$count", (long)Math.Round(perSecond * 3600));
                await command.ExecuteNonQueryAsync(Ct);
            }
        }

        await transaction.CommitAsync(Ct);
    }

    /// <summary>A minute of traffic up to <paramref name="end"/>: per second, good and bad requests (bad from one network).</summary>
    private async Task TrafficAsync(DateTimeOffset end, double good, double bad, TrafficKind badKind = TrafficKind.NoRoute)
    {
        var counter = new TrafficCounter();
        var random = new Random(51);
        for (var second = end.AddSeconds(-70); second < end; second = second.AddSeconds(1))
        {
            var jitter = 0.7 + (random.NextDouble() * 0.6); // ±30 %
            for (var i = 0; i < (int)Math.Round(good * jitter); i++)
            {
                counter.Add(second, TrafficKind.Forwarded, "", "website", "192.0.2.1");
            }

            for (var i = 0; i < (int)Math.Round(bad * jitter); i++)
            {
                counter.Add(second, badKind, badKind == TrafficKind.AttackBlocked ? "SqlInjection" : "", "website", $"203.0.113.{i % 200}");
            }
        }

        await _store.WriteAsync(counter.TakeCompleted(end, TimeSpan.Zero, all: true), Ct);
    }

    private TrafficAlertService Service() =>
        new(_store, _services.GetRequiredService<ConfigurationStore>(), _time, NullLogger<TrafficAlertService>.Instance);

    [Fact]
    public async Task The_usual_level_is_learned_per_hour_of_the_week()
    {
        await RecordHistoryAsync(days: 28);
        var profile = await _store.ReadUsualProfileAsync(Today, Ct);

        Assert.True(profile.IsReady);
        Assert.Equal(28 * 24, profile.Hours);
        Assert.Equal(10.0, profile.RateAt(AlertMetric.Total, Today.AddHours(10)), 2);
        Assert.Equal(1.0, profile.RateAt(AlertMetric.Total, Today.AddHours(3)), 2);
        Assert.Equal(0.02, profile.RateAt(AlertMetric.Bad, Today.AddHours(3)), 3);
        Assert.Equal(0, profile.RateAt(AlertMetric.Failed, Today.AddHours(3)));
        Assert.Equal(0, UsualProfile.Slot(new DateTimeOffset(2026, 11, 23, 0, 30, 0, TimeSpan.Zero).ToUnixTimeSeconds())); // Monday 00:30
        Assert.Equal(167, UsualProfile.Slot(new DateTimeOffset(2026, 11, 29, 23, 59, 0, TimeSpan.Zero).ToUnixTimeSeconds())); // Sunday 23:59
    }

    [Theory]
    [InlineData(3)]   // a quiet night
    [InlineData(9)]   // the busy morning
    [InlineData(14)]  // the afternoon
    [InlineData(22)]  // the evening
    public async Task Normal_daily_patterns_raise_no_notice(int hour)
    {
        await RecordHistoryAsync(days: 28);
        var service = Service();
        var now = Today.AddHours(hour).AddMinutes(30);
        var (good, bad) = Usual(now);

        for (var check = 0; check < 4; check++)
        {
            _time.Now = now.AddSeconds(check * 15);
            await TrafficAsync(_time.Now.AddSeconds(-5), good, bad);
            await service.CheckAsync(Ct);
        }

        Assert.Empty(await service.RunningAsync(Ct));
        Assert.Empty(await service.RecentAsync(10, Ct));
    }

    [Fact]
    public async Task An_attack_raises_a_notice_within_a_minute_and_it_ends_after_the_attack()
    {
        await RecordHistoryAsync(days: 28);
        var service = Service();
        var night = Today.AddHours(3);

        // A quiet night, then an attack: 40 bad requests a second (2,000 times the usual 0.02).
        _time.Now = night;
        await TrafficAsync(night.AddSeconds(-5), 0.98, 0.02);
        await service.CheckAsync(Ct);
        Assert.Empty(await service.RunningAsync(Ct));

        _time.Now = night.AddSeconds(60);
        await TrafficAsync(_time.Now.AddSeconds(-5), 0.98, 40, TrafficKind.AttackBlocked);
        await service.CheckAsync(Ct);

        var alert = Assert.Single(await service.RunningAsync(Ct));
        Assert.Equal(AlertMetric.Bad, alert.Metric);
        Assert.Null(alert.End);
        Assert.True(alert.Ratio > 1000, $"ratio {alert.Ratio}");
        Assert.Equal((TrafficKind.AttackBlocked, "SqlInjection"), (alert.Kind, alert.Name));
        Assert.Equal("203.0.113.0/24", alert.Network);
        Assert.Contains("Bad traffic is", TrafficAlertText.Headline(alert), StringComparison.Ordinal);
        Assert.Equal("Mostly Blocked by attack detection: SQL injection, from 203.0.113.0/24.", TrafficAlertText.Mostly(alert));

        // The attack stops: after two calm checks the notice ends, and stays in the list of past notices.
        foreach (var seconds in new[] { 180, 195 })
        {
            _time.Now = night.AddSeconds(seconds);
            await TrafficAsync(_time.Now.AddSeconds(-5), 0.98, 0.02);
            await service.CheckAsync(Ct);
        }

        Assert.Empty(await service.RunningAsync(Ct));
        var past = Assert.Single(await service.RecentAsync(10, Ct));
        Assert.Equal(night.AddSeconds(195), past.End);
        Assert.Contains("was up to", TrafficAlertText.Headline(past), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Failed_requests_that_usually_never_happen_raise_a_notice_above_the_minimum()
    {
        await RecordHistoryAsync(days: 28);
        var service = Service();
        _time.Now = Today.AddHours(10);

        await TrafficAsync(_time.Now.AddSeconds(-5), 9.8, 0.2, TrafficKind.BackendError);
        await service.CheckAsync(Ct);
        Assert.Empty(await service.RunningAsync(Ct)); // 0.2 a second is 12 a minute: below the minimum of 60

        _time.Now = _time.Now.AddSeconds(15);
        await TrafficAsync(_time.Now.AddSeconds(-5), 9.8, 3, TrafficKind.BackendError);
        await service.CheckAsync(Ct);
        var alert = Assert.Single(await service.RunningAsync(Ct));
        Assert.Equal((AlertMetric.Failed, (double?)null, TrafficKind.BackendError), (alert.Metric, alert.Ratio, alert.Kind));
        Assert.Contains("where there usually is almost none", TrafficAlertText.Headline(alert), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_a_day_of_history_nothing_is_judged()
    {
        await RecordHistoryAsync(days: 0);
        var service = Service();
        _time.Now = Today.AddHours(3);
        await TrafficAsync(_time.Now.AddSeconds(-5), 1, 500);
        await service.CheckAsync(Ct);

        Assert.Empty(await service.RunningAsync(Ct));
        Assert.False(service.Profile!.IsReady);
    }

    [Fact]
    public void The_view_and_log_links_follow_the_notice()
    {
        var start = Today.AddHours(3);
        var alert = new TrafficAlert(1, AlertMetric.Bad, start, start.AddMinutes(5), 0.02, 40, TrafficKind.RuleBlocked, "no-wp", "203.0.113.0/24");

        var view = TrafficAlertText.ViewUrl(alert);
        Assert.Contains("period=custom", view, StringComparison.Ordinal);
        Assert.Contains("type=RuleBlocked%3Ano-wp", view, StringComparison.Ordinal);
        Assert.Contains("network=203.0.113.0%2F24", view, StringComparison.Ordinal);
        Assert.Contains("sources=network", view, StringComparison.Ordinal);

        var log = TrafficAlertText.LogUrl(alert);
        Assert.Contains($"from={start.ToUnixTimeSeconds()}", log, StringComparison.Ordinal);
        Assert.Contains("show=Blocked", log, StringComparison.Ordinal);
        Assert.Contains("q=203.0.113.", log, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1.5, 60, "Sensitivity")]
    [InlineData(101, 60, "Sensitivity")]
    [InlineData(5, 0, "MinimumPerMinute")]
    public void Wrong_notice_settings_are_refused(double sensitivity, int minimum, string field)
    {
        var configuration = new GatewayConfiguration();
        configuration.Settings.TrafficAlerts.Sensitivity = sensitivity;
        configuration.Settings.TrafficAlerts.MinimumPerMinute = minimum;

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.Contains($"TrafficAlerts.{field}", StringComparison.Ordinal));
    }
}
