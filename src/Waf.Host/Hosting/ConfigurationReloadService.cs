using System.Threading.Channels;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Primitives;
using Waf.Engine;

namespace Waf.Host.Hosting;

/// <summary>Degraded (HTTP 200) while a rejected configuration change is pending: the last-known-good runs.</summary>
internal sealed class ConfigurationHealthCheck(ConfigurationStatus status) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(status.HasRejection
            ? HealthCheckResult.Degraded(
                $"The configuration from {status.RejectedSource} was rejected at {status.RejectedAt:u}; the last-known-good configuration is running. {string.Join(" ", status.RejectedErrors)}")
            : HealthCheckResult.Healthy("The configured settings are active."));
}

/// <summary>
/// Hot reload: when appsettings changes (the built-in files or the administrator file in the config
/// folder), the Gateway section is read again and activated through <see cref="GatewayConfigurationService"/>
/// (validated, built, stored and swapped without a restart). An invalid change is rejected: the running
/// configuration stays (last-known-good) and <see cref="ConfigurationStatus"/> reports why.
/// </summary>
/// <remarks>
/// Saving a file usually raises several change events; they are merged by waiting <see cref="Debounce"/>
/// after the first one. Listener ports and storage locations are only read at startup.
/// </remarks>
internal sealed partial class ConfigurationReloadService(
    IConfiguration configuration,
    GatewayConfigurationService configurations,
    ConfigurationStatus status,
    TimeProvider time,
    ILogger<ConfigurationReloadService> logger) : BackgroundService
{
    /// <summary>Author recorded for versions activated by a reload.</summary>
    public const string ReloadAuthor = "appsettings reload";

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

                await ReloadAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    /// <summary>Reads the Gateway section and activates it if it is valid and different from what runs.</summary>
    public async Task ReloadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var (candidate, errors) = GatewayConfigurationLoader.TryLoad(configuration);
            if (candidate is null)
            {
                Reject(errors);
                return;
            }

            var result = await configurations.ActivateAsync(candidate, ReloadAuthor, "Reloaded from appsettings after a file change.", cancellationToken).ConfigureAwait(false);
            if (result.Succeeded)
            {
                status.Accepted();
                LogReloaded(logger, result.Version!.Version);
            }
            else
            {
                Reject(result.Errors);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A failed reload must never stop the gateway; the running configuration stays.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogReloadFailed(logger, ex);
            Reject([$"The configuration could not be reloaded: {ex.Message}"]);
        }
    }

    private void Reject(IReadOnlyList<string> errors)
    {
        status.Rejected("appsettings", errors, time.GetUtcNow());
        LogRejected(logger, string.Join(" ", errors));
    }

    [LoggerMessage(EventId = 30, Level = LogLevel.Information, Message = "Configuration reloaded from appsettings; version {Version} is active.")]
    private static partial void LogReloaded(ILogger logger, long version);

    [LoggerMessage(EventId = 31, Level = LogLevel.Error, Message = "The changed configuration in appsettings was rejected; the running configuration stays active. Errors: {Errors}")]
    private static partial void LogRejected(ILogger logger, string errors);

    [LoggerMessage(EventId = 32, Level = LogLevel.Error, Message = "Reloading the configuration failed; the running configuration stays active.")]
    private static partial void LogReloadFailed(ILogger logger, Exception exception);
}
