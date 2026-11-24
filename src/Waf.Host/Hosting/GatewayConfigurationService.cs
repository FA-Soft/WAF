using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

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
    AuditLogStore audit,
    CertificateService certificates,
    CertificateStore certificateStore,
    WafEngineHolder engines,
    ProxyRouteUpdater routes,
    ITargetAddressSource addresses,
    ConfigurationStatus status,
    StoragePaths paths,
    TimeProvider time,
    ILogger<GatewayConfigurationService> logger) : IGatewayConfigurationService, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Tag of a version activated elsewhere that could not be applied; not retried until it changes.</summary>
    private string? _failedExternalTag;

    public void Dispose() => _gate.Dispose();

    public Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken) =>
        ActivateLockedAsync(null, candidate, actor, comment, cancellationToken);

    public Task<ActivationResult> ActivateIfCurrentAsync(long baseVersion, GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken) =>
        ActivateLockedAsync(baseVersion, candidate, actor, comment, cancellationToken);

    /// <summary>
    /// Activates the configuration of an earlier version again. It is stored as a new version (history only
    /// grows) after the same checks as any other change.
    /// </summary>
    public async Task<ActivationResult> RollbackAsync(long version, AuditActor actor, CancellationToken cancellationToken)
    {
        var previous = await store.GetAsync(version, cancellationToken).ConfigureAwait(false);
        if (previous is null)
        {
            return ActivationResult.Failed([$"Configuration version {version} does not exist."]);
        }

        return await ActivateAsync(previous.Configuration, actor, $"Rollback to version {version}.", cancellationToken).ConfigureAwait(false);
    }

    public async Task<ActivationResult> RollbackAsync(long version, long baseVersion, AuditActor actor, CancellationToken cancellationToken)
    {
        var previous = await store.GetAsync(version, cancellationToken).ConfigureAwait(false);
        if (previous is null)
        {
            return ActivationResult.Failed([$"Configuration version {version} does not exist."]);
        }

        return await ActivateIfCurrentAsync(baseVersion, previous.Configuration, actor, $"Restored version {version}.", cancellationToken).ConfigureAwait(false);
    }

    public async Task<RestoreResult> RestoreBackupAsync(GatewayBackup backup, AuditActor actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentNullException.ThrowIfNull(actor);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 1. Check every version: fill left-out secrets from the running configuration, then validate.
            var running = await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            var errors = new List<string>();
            var versions = new List<BackupVersion>();
            foreach (var version in backup.Versions)
            {
                var configuration = Copy(version.Configuration);
                var problems = ConfigurationSecrets.FillFrom(configuration, running?.Configuration);
                errors.AddRange(problems.Select(p => $"Version {version.Version}: {p}"));
                if (problems.Count == 0)
                {
                    errors.AddRange(GatewayConfigurationValidator.Validate(configuration).Select(e => $"Version {version.Version}: {e}"));
                }

                versions.Add(version with { Configuration = configuration });
            }

            if (errors.Count > 0)
            {
                const int Shown = 10;
                return RestoreResult.Failed(errors.Count <= Shown ? errors : [.. errors.Take(Shown), $"... and {errors.Count - Shown} more."]);
            }

            // 2. Build the engine and routes of the active version before changing anything.
            var active = versions.First(v => v.Version == backup.ActiveVersion).Configuration;
            var tag = ConfigurationStore.ConfigTag(ConfigurationStore.ComputeHash(active));
            WafEngine engine;
            try
            {
                engine = WafEngine.Build(active, time, tag);
            }
            catch (ArgumentException ex)
            {
                return RestoreResult.Failed([$"The WAF engine could not be built: {ex.Message}"]);
            }

            var (prepared, routeErrors) = await routes.PrepareAsync(TargetResolver.Resolve(active, addresses), tag).ConfigureAwait(false);
            if (prepared is null)
            {
                return RestoreResult.Failed(routeErrors);
            }

            // 3. Keep a copy of the current database, 4. replace the history, 5. swap.
            var safetyCopy = SafetyCopyPath();
            await store.CopyDatabaseToAsync(safetyCopy, cancellationToken).ConfigureAwait(false);
            await store.ReplaceAllAsync(versions, backup.ActiveVersion, actor, cancellationToken).ConfigureAwait(false);
            var certificateCount = await ImportCertificatesAsync(backup, actor, cancellationToken).ConfigureAwait(false);
            if (engines.Current?.ConfigTag != tag)
            {
                engines.Activate(engine);
                routes.Apply(prepared);
            }

            await audit.RecordAsync(
                AuditCategory.Maintenance,
                AuditActions.BackupRestored,
                actor,
                $"Backup restored: {versions.Count} version(s), version {backup.ActiveVersion} active.",
                $"Backup created at {backup.CreatedAtUtc:u} by WAF Gateway {backup.ProductVersion}; {certificateCount} certificate(s) added to the certificate store. The previous database was copied to {Path.GetFileName(safetyCopy)}.",
                cancellationToken).ConfigureAwait(false);
            await certificates.ReloadAsync(cancellationToken).ConfigureAwait(false);
            LogRestored(logger, actor.UserName, versions.Count, backup.ActiveVersion, safetyCopy);
            return new RestoreResult(true, [], backup.ActiveVersion, safetyCopy);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Stores the certificates of a backup that includes secrets (already stored ones are kept); returns how many were new.</summary>
    private async Task<int> ImportCertificatesAsync(GatewayBackup backup, AuditActor actor, CancellationToken cancellationToken)
    {
        var added = 0;
        foreach (var certificate in backup.Certificates)
        {
            using var loaded = CertificateFiles.LoadPfx(certificate.Pfx);
            if ((await certificateStore.AddAsync(loaded, actor.UserName, cancellationToken).ConfigureAwait(false)).Added)
            {
                added++;
            }
        }

        return added;
    }

    private string SafetyCopyPath()
    {
        var stamp = time.GetUtcNow().ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        var path = Path.Combine(paths.DataDirectory, $"config.before-restore-{stamp}.db");
        for (var i = 2; File.Exists(path); i++)
        {
            path = Path.Combine(paths.DataDirectory, $"config.before-restore-{stamp}-{i}.db");
        }

        return path;
    }

    private static GatewayConfiguration Copy(GatewayConfiguration configuration) =>
        GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration)).Configuration
            ?? throw new InvalidOperationException("The configuration could not be copied.");

    public async Task<ActivationResult> ImportAppSettingsAsync(AuditActor actor, CancellationToken cancellationToken)
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

        var result = await ActivateAsync(notice.Candidate!, actor, "Imported from appsettings.", cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// Applies the last-known-good version when another process changed it (the recovery tool <c>wafctl</c> stores a
    /// version and marks it active while the gateway runs). The version was checked when it was stored; it is built
    /// and swapped in like any other change. Returns true when something was applied.
    /// </summary>
    public async Task<bool> SyncWithStoreAsync(CancellationToken cancellationToken)
    {
        // Cheap check first: only the number and hash, no lock.
        var head = await store.GetLastKnownGoodHeadAsync(cancellationToken).ConfigureAwait(false);
        if (head is null || !NeedsSync(ConfigurationStore.ConfigTag(head.Value.Sha256)))
        {
            return false;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Again under the lock: an activation from the admin UI stores its version before marking it active.
            var stored = await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            if (stored is null)
            {
                return false;
            }

            var tag = ConfigurationStore.ConfigTag(stored.Sha256);
            if (!NeedsSync(tag))
            {
                return false;
            }

            WafEngine engine;
            try
            {
                engine = WafEngine.Build(stored.Configuration, time, tag);
            }
            catch (ArgumentException ex)
            {
                _failedExternalTag = tag;
                LogExternalFailed(logger, stored.Version, ex.Message);
                return false;
            }

            var (prepared, routeErrors) = await routes.PrepareAsync(TargetResolver.Resolve(stored.Configuration, addresses), tag).ConfigureAwait(false);
            if (prepared is null)
            {
                _failedExternalTag = tag;
                LogExternalFailed(logger, stored.Version, string.Join(" ", routeErrors));
                return false;
            }

            engines.Activate(engine);
            routes.Apply(prepared);
            _failedExternalTag = null;
            await certificates.ReloadAsync(cancellationToken).ConfigureAwait(false);
            LogExternalApplied(logger, stored.Version, stored.Author);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool NeedsSync(string tag) => engines.Current?.ConfigTag != tag && tag != _failedExternalTag;

    /// <summary>
    /// Builds the routes of the running configuration again with the current target addresses (a device found at
    /// another address by its MAC address) and swaps them in. No new version: the configuration did not change, and the
    /// WAF engine keeps running (same tag). Skipped while the running engine is not the one of the active version.
    /// </summary>
    public async Task ReapplyTargetAddressesAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var stored = await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            if (stored is null)
            {
                return;
            }

            var tag = ConfigurationStore.ConfigTag(stored.Sha256);
            if (engines.Current?.ConfigTag != tag)
            {
                return; // the next activation uses the current addresses anyway
            }

            var (prepared, routeErrors) = await routes.PrepareAsync(TargetResolver.Resolve(stored.Configuration, addresses), tag).ConfigureAwait(false);
            if (prepared is null)
            {
                LogTargetRoutesFailed(logger, string.Join(" ", routeErrors));
                return;
            }

            routes.Apply(prepared);
        }
        finally
        {
            _gate.Release();
        }
    }

    [LoggerMessage(EventId = 105, Level = LogLevel.Error, Message = "The routes could not be updated with the new target addresses; they keep the previous ones. {Errors}")]
    private static partial void LogTargetRoutesFailed(ILogger logger, string errors);

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
        long? baseVersion, GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(actor);

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

            return await ActivateCoreAsync(candidate, actor, comment, running, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ActivationResult> ActivateCoreAsync(
        GatewayConfiguration candidate, AuditActor actor, string? comment, StoredConfiguration? running, CancellationToken cancellationToken)
    {
        // 1. Validate.
        var errors = GatewayConfigurationValidator.Validate(candidate);
        if (errors.Count > 0)
        {
            LogRejected(logger, actor.UserName, errors.Count);
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

        var (prepared, routeErrors) = await routes.PrepareAsync(TargetResolver.Resolve(candidate, addresses), tag).ConfigureAwait(false);
        if (prepared is null)
        {
            return ActivationResult.Failed(routeErrors);
        }

        // 3. Store, then 4. swap. Nothing is swapped if storing fails. The engine goes first: requests routed
        // by the new routes then always find their engine, and requests still routed by the old routes are
        // judged by the previous engine (WafEngineHolder.Resolve), so every request sees one configuration.
        var (stored, _) = await store.SaveIfChangedAsync(candidate, actor, comment, cancellationToken).ConfigureAwait(false);
        engines.Activate(engine);
        routes.Apply(prepared);
        await store.SetLastKnownGoodAsync(stored.Version, cancellationToken).ConfigureAwait(false);
        await certificates.ReloadAsync(cancellationToken).ConfigureAwait(false);

        LogActivated(logger, stored.Version, actor.UserName);
        return new ActivationResult(true, [], stored);
    }

    [LoggerMessage(EventId = 20, Level = LogLevel.Information, Message = "Configuration version {Version} activated by {Author}.")]
    private static partial void LogActivated(ILogger logger, long version, string author);

    [LoggerMessage(EventId = 22, Level = LogLevel.Warning, Message = "Backup restored by {Author}: {VersionCount} version(s), version {ActiveVersion} active. The previous database was copied to {SafetyCopy}.")]
    private static partial void LogRestored(ILogger logger, string author, int versionCount, long activeVersion, string safetyCopy);

    [LoggerMessage(EventId = 23, Level = LogLevel.Warning, Message = "Configuration version {Version}, activated by {Author} outside the gateway (wafctl), is now running.")]
    private static partial void LogExternalApplied(ILogger logger, long version, string author);

    [LoggerMessage(EventId = 24, Level = LogLevel.Error, Message = "Configuration version {Version}, activated outside the gateway (wafctl), could not be applied; the running configuration is unchanged. {Reason}")]
    private static partial void LogExternalFailed(ILogger logger, long version, string reason);

    [LoggerMessage(EventId = 21, Level = LogLevel.Warning, Message = "Configuration change by {Author} rejected with {ErrorCount} error(s); the running configuration is unchanged.")]
    private static partial void LogRejected(ILogger logger, string author, int errorCount);
}
