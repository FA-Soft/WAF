using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Background cleanup of the request log: every <see cref="Interval"/>, entries beyond the active configuration's
/// retention limits (<see cref="LogRetentionSettings"/>) are removed. A changed limit applies from the next run.
/// </summary>
/// <remarks>
/// One run at a time (a "clean up now" from the UI waits for a running one). A failed run is logged and retried at
/// the next interval; it never affects requests.
/// </remarks>
internal sealed partial class LogRetentionService(
    RequestLogMaintenance maintenance,
    ConfigurationStore store,
    TimeProvider time,
    ILogger<LogRetentionService> logger) : BackgroundService, ILogRetention
{
    /// <summary>Time between runs. Short, so the size limit holds even with heavy traffic.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    /// <summary>Delay of the first run after start.</summary>
    public static readonly TimeSpan FirstRunDelay = TimeSpan.FromSeconds(10);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private LogCleanupResult? _lastRun;

    public LogCleanupResult? LastRun => Volatile.Read(ref _lastRun);

    public async Task<LogCleanupResult> CleanUpNowAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = (await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false))?.Configuration.Settings.LogRetention
                ?? new LogRetentionSettings();
            LogCleanupResult result;
            try
            {
                result = await maintenance.CleanUpAsync(settings, time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or InvalidOperationException)
            {
                LogCleanupFailed(logger, ex);
                result = new LogCleanupResult(time.GetUtcNow(), 0, 0, 0, 0, TimeSpan.Zero, ex.Message);
            }

            if (result.Deleted > 0)
            {
                LogCleanedUp(logger, result.DeletedByAge, result.DeletedBySize, result.FileBytesAfter / (1024 * 1024));
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
            // Let the request log writer create or migrate events.db first.
            await Task.Delay(FirstRunDelay, time, stoppingToken).ConfigureAwait(false);
            do
            {
                await CleanUpNowAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    [LoggerMessage(EventId = 410, Level = LogLevel.Information, Message = "Request log cleanup: removed {ByAge} entries older than the age limit and {BySize} to stay within the size limit; events.db is now {SizeMb} MB.")]
    private static partial void LogCleanedUp(ILogger logger, long byAge, long bySize, long sizeMb);

    [LoggerMessage(EventId = 411, Level = LogLevel.Error, Message = "Request log cleanup failed; it is retried in a minute.")]
    private static partial void LogCleanupFailed(ILogger logger, Exception exception);
}
