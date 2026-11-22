using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;
using Waf.Proxy;
using Waf.Web;

namespace Waf.Host.Hosting;

/// <summary>
/// Changes the running configuration safely. Every change is stored as a version; a configuration only
/// becomes active after it passed every check, and on any failure the running configuration stays as it was.
/// </summary>
/// <remarks>
/// Activation: validate → build the complete WAF engine → translate and validate the routes with YARP →
/// store the version → swap engine and routes → record it as last-known-good. Activations are serialized.
/// </remarks>
internal sealed partial class GatewayConfigurationService(
    ConfigurationStore store,
    WafEngineHolder engines,
    ProxyRouteUpdater routes,
    ConfigurationStatus status,
    TimeProvider time,
    ILogger<GatewayConfigurationService> logger) : IGatewayConfigurationService, IDisposable
{
    /// <summary>Author recorded for an appsettings import from the admin UI.</summary>
    public const string AppSettingsImportAuthor = "appsettings import (admin UI)";

    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    public Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken) =>
        ActivateLockedAsync(null, candidate, author, comment, cancellationToken);

    public Task<ActivationResult> ActivateIfCurrentAsync(long baseVersion, GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken) =>
        ActivateLockedAsync(baseVersion, candidate, author, comment, cancellationToken);

    /// <summary>
    /// Activates the configuration of an earlier version again. It is stored as a new version (history only
    /// grows) after the same checks as any other change.
    /// </summary>
    public async Task<ActivationResult> RollbackAsync(long version, string author, CancellationToken cancellationToken)
    {
        var previous = await store.GetAsync(version, cancellationToken).ConfigureAwait(false);
        if (previous is null)
        {
            return ActivationResult.Failed([$"Configuration version {version} does not exist."]);
        }

        return await ActivateAsync(previous.Configuration, author, $"Rollback to version {version}.", cancellationToken).ConfigureAwait(false);
    }

    public async Task<ActivationResult> ImportAppSettingsAsync(string author, CancellationToken cancellationToken)
    {
        var notice = status.AppSettingsNotice;
        if (notice is null)
        {
            return ActivationResult.Failed(["There is no changed configuration in appsettings to import."]);
        }

        if (!notice.CanImport)
        {
            return ActivationResult.Failed(notice.Errors);
        }

        var result = await ActivateAsync(notice.Candidate!, author, "Imported from appsettings.", cancellationToken).ConfigureAwait(false);
        if (result.Succeeded)
        {
            await store.SetAppSettingsFingerprintAsync(notice.Fingerprint, cancellationToken).ConfigureAwait(false);
            ClearNoticeIf(notice);
        }

        return result;
    }

    public async Task DismissAppSettingsAsync(CancellationToken cancellationToken)
    {
        if (status.AppSettingsNotice is { } notice)
        {
            await store.SetAppSettingsFingerprintAsync(notice.Fingerprint, cancellationToken).ConfigureAwait(false);
            ClearNoticeIf(notice);
        }
    }

    /// <summary>The running configuration (last-known-good), or null if none was activated yet.</summary>
    public Task<StoredConfiguration?> GetActiveAsync(CancellationToken cancellationToken) =>
        store.GetLastKnownGoodAsync(cancellationToken);

    /// <summary>Stored versions, newest first.</summary>
    public Task<IReadOnlyList<StoredConfiguration>> GetHistoryAsync(int take, CancellationToken cancellationToken) =>
        store.GetHistoryAsync(take, cancellationToken);

    private void ClearNoticeIf(AppSettingsNotice handled)
    {
        // Only clear the notice that was handled; a newer edit in the meantime stays visible.
        if (status.AppSettingsNotice?.Fingerprint == handled.Fingerprint)
        {
            status.ClearNotice();
        }
    }

    private async Task<ActivationResult> ActivateLockedAsync(
        long? baseVersion, GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentException.ThrowIfNullOrWhiteSpace(author);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var running = await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            if (baseVersion is not null && running is not null && running.Version != baseVersion)
            {
                return ActivationResult.Failed([
                    $"The configuration was changed in the meantime (now version {running.Version}, you started from version {baseVersion}). Reload the page and make your change again.",
                ]);
            }

            return await ActivateCoreAsync(candidate, author, comment, running, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ActivationResult> ActivateCoreAsync(
        GatewayConfiguration candidate, string author, string? comment, StoredConfiguration? running, CancellationToken cancellationToken)
    {
        // 1. Validate.
        var errors = GatewayConfigurationValidator.Validate(candidate);
        if (errors.Count > 0)
        {
            LogRejected(logger, author, errors.Count);
            return ActivationResult.Failed(errors);
        }

        // Identical to what is running: nothing to do (and rate-limit counters are kept).
        var tag = ConfigurationStore.ConfigTag(ConfigurationStore.ComputeHash(candidate));
        if (engines.Current?.ConfigTag == tag && running is not null)
        {
            return new ActivationResult(true, [], running);
        }

        // 2. Build everything before changing anything. Engine and routes carry the same tag.
        WafEngine engine;
        try
        {
            engine = WafEngine.Build(candidate, time, tag);
        }
        catch (ArgumentException ex)
        {
            return ActivationResult.Failed([$"The WAF engine could not be built: {ex.Message}"]);
        }

        var (prepared, routeErrors) = await routes.PrepareAsync(candidate.Routes, tag).ConfigureAwait(false);
        if (prepared is null)
        {
            return ActivationResult.Failed(routeErrors);
        }

        // 3. Store, then 4. swap. Nothing is swapped if storing fails. The engine goes first: requests routed
        // by the new routes then always find their engine, and requests still routed by the old routes are
        // judged by the previous engine (WafEngineHolder.Resolve), so every request sees one configuration.
        var (stored, _) = await store.SaveIfChangedAsync(candidate, author, comment, cancellationToken).ConfigureAwait(false);
        engines.Activate(engine);
        routes.Apply(prepared);
        await store.SetLastKnownGoodAsync(stored.Version, cancellationToken).ConfigureAwait(false);

        LogActivated(logger, stored.Version, author);
        return new ActivationResult(true, [], stored);
    }

    [LoggerMessage(EventId = 20, Level = LogLevel.Information, Message = "Configuration version {Version} activated by {Author}.")]
    private static partial void LogActivated(ILogger logger, long version, string author);

    [LoggerMessage(EventId = 21, Level = LogLevel.Warning, Message = "Configuration change by {Author} rejected with {ErrorCount} error(s); the running configuration is unchanged.")]
    private static partial void LogRejected(ILogger logger, string author, int errorCount);
}
