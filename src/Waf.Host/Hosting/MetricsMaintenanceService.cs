using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Background rollup and retention of the traffic counts: every <see cref="Interval"/>, completed buckets are rolled
/// up into the coarser tiers and buckets beyond their tier's retention are removed
/// (<see cref="SqliteMetricsStore.MaintainAsync"/>). The first run catches up on everything since the last one.
/// </summary>
/// <remarks>A failed run is logged and retried at the next interval; it never affects requests.</remarks>
internal sealed partial class MetricsMaintenanceService(
    SqliteMetricsStore store,
    IMetricsStore writerStore,
    MetricsOptions options,
    ConfigurationStore configurations,
    CountryDatabase countries,
    TimeProvider time,
    ILogger<MetricsMaintenanceService> logger) : BackgroundService, IMetricsHistory
{
    /// <summary>Time between runs.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    /// <summary>Delay of the first run after start.</summary>
    public static readonly TimeSpan FirstRunDelay = TimeSpan.FromSeconds(15);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private MetricsMaintenanceResult? _lastRun;
    private bool _initialized;

    public bool Enabled => true;

    public SqliteMetricsStore? Store => store;

    public MetricsRetention Retention => options.Retention;

    public string? CountrySource => countries.Lookup?.Source;

    public MetricsMaintenanceResult? LastRun => Volatile.Read(ref _lastRun);

    public Task<MetricsStorageStatus?> GetStatusAsync(CancellationToken cancellationToken) =>
        GetStatusCoreAsync(cancellationToken);

    /// <summary>Runs the rollup and retention now (one run at a time).</summary>
    public async Task<MetricsMaintenanceResult> RunNowAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            MetricsMaintenanceResult result;
            try
            {
                if (!_initialized)
                {
                    // The writer creates or upgrades metrics.db too; doing it here as well makes the order irrelevant.
                    await writerStore.InitializeAsync(cancellationToken).ConfigureAwait(false);
                    _initialized = true;
                }

                // Client IPs are kept no longer than the request log keeps its entries (its age limit; 0: no limit).
                var maxAgeDays = (await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false))?.Configuration.Settings.LogRetention.MaxAgeDays ?? 0;
                result = await store.MaintainAsync(
                    options.Retention, time.GetUtcNow(), cancellationToken, maxAgeDays > 0 ? TimeSpan.FromDays(maxAgeDays) : null).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                LogRunFailed(logger, ex);
                result = new MetricsMaintenanceResult(time.GetUtcNow(), 0, 0, TimeSpan.Zero, ex.Message);
            }

            if (result.Deleted > 0)
            {
                LogRemoved(logger, result.Deleted);
            }

            Volatile.Write(ref _lastRun, result);
            return result;
        }
        finally
        {
            _gate.Release();
        }
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
            await Task.Delay(FirstRunDelay, time, stoppingToken).ConfigureAwait(false);
            do
            {
                await RunNowAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    private async Task<MetricsStorageStatus?> GetStatusCoreAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await store.GetStatusAsync(options.Retention, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException)
        {
            LogRunFailed(logger, ex);
            return null;
        }
    }

    [LoggerMessage(EventId = 423, Level = LogLevel.Information, Message = "Traffic history: removed {Count} rows older than their tier's retention.")]
    private static partial void LogRemoved(ILogger logger, long count);

    [LoggerMessage(EventId = 424, Level = LogLevel.Error, Message = "Traffic history: rolling up or removing old counts in metrics.db failed; it is retried in a minute.")]
    private static partial void LogRunFailed(ILogger logger, Exception exception);
}
