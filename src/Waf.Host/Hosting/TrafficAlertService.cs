using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Notices unusual traffic: every <see cref="Interval"/> it compares the last minute of total, bad and failed requests
/// with the usual level for that hour of the week (<see cref="UsualProfile"/>), and starts a notice when one is
/// <see cref="TrafficAlertSettings.Sensitivity"/> times higher and above <see cref="TrafficAlertSettings.MinimumPerMinute"/>.
/// A notice ends after two calm checks in a row (half the sensitivity, or half the minimum). Starts and ends go to the
/// service log; notices are kept in <c>metrics.db</c>.
/// </summary>
internal sealed partial class TrafficAlertService(
    SqliteMetricsStore store,
    ConfigurationStore configurations,
    TimeProvider time,
    ILogger<TrafficAlertService> logger) : BackgroundService, ITrafficAlerts
{
    /// <summary>Time between checks.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);

    /// <summary>The period compared: the last minute, without the last seconds (counts are written every few seconds).</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private static readonly TimeSpan WriteDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ProfileAge = TimeSpan.FromMinutes(10);
    private const int CalmChecksToEnd = 2;

    private readonly Dictionary<AlertMetric, (long Id, int Calm)> _open = [];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private UsualProfile? _profile;
    private DateTimeOffset _profileAt;
    private bool _resumed;

    public bool Enabled => true;

    public UsualProfile? Profile => Volatile.Read(ref _profile);

    public async Task<IReadOnlyList<TrafficAlert>> RunningAsync(CancellationToken cancellationToken) =>
        await store.ReadAlertsAsync(10, runningOnly: true, cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<TrafficAlert>> RecentAsync(int limit, CancellationToken cancellationToken) =>
        await store.ReadAlertsAsync(limit, runningOnly: false, cancellationToken).ConfigureAwait(false);

    /// <summary>One check, as of now. Used by the loop and by tests.</summary>
    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await CheckCoreAsync(time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task CheckCoreAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!_resumed)
        {
            // Notices that were running when the gateway stopped go on (or end at the next calm checks).
            foreach (var running in await store.ReadAlertsAsync(10, runningOnly: true, cancellationToken).ConfigureAwait(false))
            {
                _open[running.Metric] = (running.Id, 0);
            }

            _resumed = true;
        }

        var settings = (await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false))?.Configuration.Settings.TrafficAlerts
            ?? new TrafficAlertSettings();
        if (!settings.Enabled)
        {
            if (_open.Count > 0)
            {
                await store.CloseAlertsAsync(null, now, cancellationToken).ConfigureAwait(false);
                _open.Clear();
            }

            return;
        }

        if (_profile is null || now - _profileAt >= ProfileAge || now < _profileAt)
        {
            Volatile.Write(ref _profile, await store.ReadUsualProfileAsync(now, cancellationToken).ConfigureAwait(false));
            _profileAt = now;
        }

        var profile = _profile!;
        if (!profile.IsReady)
        {
            return; // still learning what is usual
        }

        var to = now - WriteDelay;
        var window = new TrafficQuery(to - Window, to, MetricsTier.Second);
        var series = await store.ReadSeriesAsync(window, cancellationToken).ConfigureAwait(false);
        // Bad and failed first: a total-traffic notice is only given when neither explains the spike already.
        var counts = new (AlertMetric Metric, long Count)[]
        {
            (AlertMetric.Bad, series.Sum(b => b.Bad)),
            (AlertMetric.Failed, series.Sum(b => b.Failed)),
            (AlertMetric.Total, series.Sum(b => b.Total)),
        };

        foreach (var (metric, count) in counts)
        {
            var rate = count / Window.TotalSeconds;
            var usual = profile.RateAt(metric, now);
            var unusual = count >= settings.MinimumPerMinute && rate >= settings.Sensitivity * usual;
            var calm = count < settings.MinimumPerMinute / 2.0 || rate < settings.Sensitivity / 2 * usual;

            if (_open.TryGetValue(metric, out var open))
            {
                if (calm)
                {
                    if (open.Calm + 1 >= CalmChecksToEnd)
                    {
                        await store.CloseAlertsAsync(open.Id, now, cancellationToken).ConfigureAwait(false);
                        _open.Remove(metric);
                        LogEnded(logger, metric, open.Id);
                    }
                    else
                    {
                        _open[metric] = open with { Calm = open.Calm + 1 };
                    }
                }
                else
                {
                    _open[metric] = open with { Calm = 0 };
                    var (kind, name, network) = await MostlyAsync(metric, window, cancellationToken).ConfigureAwait(false);
                    await store.UpdateAlertAsync(open.Id, rate, kind, name, network, cancellationToken).ConfigureAwait(false);
                }
            }
            else if (unusual && (metric != AlertMetric.Total || (!_open.ContainsKey(AlertMetric.Bad) && !_open.ContainsKey(AlertMetric.Failed))))
            {
                var (kind, name, network) = await MostlyAsync(metric, window, cancellationToken).ConfigureAwait(false);
                var id = await store.OpenAlertAsync(metric, now - Window, usual, rate, kind, name, network, cancellationToken).ConfigureAwait(false);
                _open[metric] = (id, 0);
                LogStarted(logger, metric, Math.Round(rate, 1), Math.Round(usual, 2), kind?.ToString() ?? "-", name ?? "-", network ?? "-", id);
            }
        }
    }

    /// <summary>What most of the unusual traffic is: the largest kind (bad or failed), and for bad traffic its largest network.</summary>
    private async Task<(TrafficKind? Kind, string? Name, string? Network)> MostlyAsync(AlertMetric metric, TrafficQuery window, CancellationToken cancellationToken)
    {
        if (metric == AlertMetric.Total)
        {
            return (null, null, null);
        }

        var outcome = metric == AlertMetric.Bad ? TrafficOutcome.Bad : TrafficOutcome.Failed;
        var top = (await store.ReadKindsAsync(window, cancellationToken).ConfigureAwait(false)).FirstOrDefault(k => k.Outcome == outcome);
        string? network = null;
        if (metric == AlertMetric.Bad)
        {
            // Networks are stored per minute, a little after each minute: look a few minutes back.
            var recent = window with { From = window.To - TimeSpan.FromMinutes(5), Tier = MetricsTier.Minute };
            network = (await store.ReadTopNetworksAsync(recent, 1, cancellationToken).ConfigureAwait(false)).FirstOrDefault()?.Source;
        }

        return (top?.Kind, top is null || top.Name.Length == 0 ? null : top.Name, network);
    }

    public override void Dispose()
    {
        _gate.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await CheckAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or InvalidOperationException)
                {
                    LogCheckFailed(logger, ex);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    [LoggerMessage(EventId = 440, Level = LogLevel.Warning, Message = "Unusual traffic: {Metric} requests at {Rate} per second, usually {Usual}; mostly {Kind} {Name} from {Network} (notice {Id}).")]
    private static partial void LogStarted(ILogger logger, AlertMetric metric, double rate, double usual, string kind, string name, string network, long id);

    [LoggerMessage(EventId = 441, Level = LogLevel.Information, Message = "Unusual traffic is over: {Metric} requests are back to normal (notice {Id}).")]
    private static partial void LogEnded(ILogger logger, AlertMetric metric, long id);

    [LoggerMessage(EventId = 442, Level = LogLevel.Error, Message = "Checking for unusual traffic failed; it is tried again shortly.")]
    private static partial void LogCheckFailed(ILogger logger, Exception exception);
}
