using System.Threading.Channels;
using Microsoft.Extensions.Primitives;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Watches appsettings (the built-in files and the administrator file in the config folder). The configuration
/// database is the source of truth, so an edited Gateway section is <b>not</b> applied: it is reported as an
/// <see cref="AppSettingsNotice"/>, and an administrator can import it (with all the usual checks) or dismiss it
/// in the admin UI. Other settings (e.g. logging) reload as usual.
/// </summary>
/// <remarks>
/// Saving a file usually raises several change events; they are merged by waiting <see cref="Debounce"/>
/// after the first one.
/// </remarks>
internal sealed partial class AppSettingsWatcher(
    IConfiguration configuration,
    ConfigurationStore store,
    ConfigurationStatus status,
    TimeProvider time,
    ILogger<AppSettingsWatcher> logger) : BackgroundService
{
    /// <summary>Wait after a change event, so the several events of one save are handled once.</summary>
    public static readonly TimeSpan Debounce = TimeSpan.FromMilliseconds(500);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var changes = Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
        using var registration = ChangeToken.OnChange(configuration.GetReloadToken, () => changes.Writer.TryWrite(true));

        try
        {
            await foreach (var change in changes.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                await Task.Delay(Debounce, time, stoppingToken).ConfigureAwait(false);
                while (changes.Reader.TryRead(out var merged))
                {
                    // merge events raised while waiting
                }

                await CheckAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    /// <summary>Updates the notice: set when appsettings differs from its last import/dismissal, else cleared.</summary>
    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        try
        {
            var recorded = await store.GetAppSettingsFingerprintAsync(cancellationToken).ConfigureAwait(false);
            var notice = ConfigurationBootstrap.Check(configuration, recorded, time);
            if (notice is null)
            {
                status.ClearNotice();
                return;
            }

            if (status.AppSettingsNotice?.Fingerprint != notice.Fingerprint)
            {
                LogEdited(logger, notice.CanImport ? "valid" : "not valid");
            }

            status.SetNotice(notice);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // Watching appsettings must never stop the gateway.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogCheckFailed(logger, ex);
        }
    }

    [LoggerMessage(EventId = 30, Level = LogLevel.Warning,
        Message = "The Gateway section in appsettings was edited ({Validity}). It is NOT applied: the configuration database is the source of truth. Import or dismiss the change in the admin UI.")]
    private static partial void LogEdited(ILogger logger, string validity);

    [LoggerMessage(EventId = 32, Level = LogLevel.Error, Message = "Checking appsettings for changes failed.")]
    private static partial void LogCheckFailed(ILogger logger, Exception exception);
}
