namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Picks up configuration changes made outside the gateway: the recovery tool <c>wafctl</c> writes to
/// <c>config.db</c> directly (it works even when the service is down), and while the service runs this applies the
/// new active version within <see cref="Interval"/>.
/// </summary>
internal sealed partial class StoreChangeWatcher(
    GatewayConfigurationService configurations,
    TimeProvider time,
    ILogger<StoreChangeWatcher> logger) : BackgroundService
{
    /// <summary>How often <c>config.db</c> is checked: one small query.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await configurations.SyncWithStoreAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
#pragma warning disable CA1031 // Watching config.db must never stop the gateway.
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    LogCheckFailed(logger, ex);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    [LoggerMessage(EventId = 25, Level = LogLevel.Error, Message = "Checking config.db for changes made outside the gateway failed; retrying.")]
    private static partial void LogCheckFailed(ILogger logger, Exception exception);
}
