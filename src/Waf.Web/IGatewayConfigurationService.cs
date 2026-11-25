using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Outcome of an activation (save, rollback or import).</summary>
/// <param name="Succeeded">True when the configuration is now active.</param>
/// <param name="Errors">Why it was rejected, in plain language; empty on success.</param>
/// <param name="Version">The stored version that is now active; null on failure.</param>
public sealed record ActivationResult(bool Succeeded, IReadOnlyList<string> Errors, StoredConfiguration? Version)
{
    public static ActivationResult Failed(IEnumerable<string> errors) => new(false, [.. errors], null);
}

/// <summary>Outcome of restoring a full backup.</summary>
/// <param name="Succeeded">True when the backup's history is stored and its active version is running.</param>
/// <param name="Errors">Why it was refused, in plain language; empty on success.</param>
/// <param name="ActiveVersion">The version that is now active; null on failure.</param>
/// <param name="SafetyCopyPath">Where the database was copied before it was replaced; null on failure.</param>
public sealed record RestoreResult(bool Succeeded, IReadOnlyList<string> Errors, long? ActiveVersion, string? SafetyCopyPath)
{
    public static RestoreResult Failed(IEnumerable<string> errors) => new(false, [.. errors], null, null);
}

/// <summary>
/// Changes the running configuration. Implemented by the host: every change is validated, stored as a new
/// version and swapped in without a restart; on any failure the running configuration stays as it was.
/// </summary>
public interface IGatewayConfigurationService
{
    /// <summary>The running configuration (last-known-good), or null if none was activated yet.</summary>
    Task<StoredConfiguration?> GetActiveAsync(CancellationToken cancellationToken);

    /// <summary>Validates <paramref name="candidate"/> and, if everything checks out, makes it the running configuration.</summary>
    Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="ActivateAsync"/>, but only when <paramref name="baseVersion"/> is still the running
    /// version; otherwise the change is refused, so a concurrent change is never overwritten unseen.
    /// </summary>
    Task<ActivationResult> ActivateIfCurrentAsync(long baseVersion, GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken);

    /// <summary>
    /// Activates the configuration of an earlier version again, stored as a new version, but only when
    /// <paramref name="baseVersion"/> is still the running version.
    /// </summary>
    Task<ActivationResult> RollbackAsync(long version, long baseVersion, AuditActor actor, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the whole configuration history with <paramref name="backup"/> and activates its active version.
    /// Secret values left out of the backup are taken from the running configuration. Everything is checked
    /// first; the current database is copied next to it before it is replaced.
    /// </summary>
    Task<RestoreResult> RestoreBackupAsync(GatewayBackup backup, AuditActor actor, CancellationToken cancellationToken);

    /// <summary>Activates the edited appsettings configuration (see the appsettings notice).</summary>
    Task<ActivationResult> ImportAppSettingsAsync(AuditActor actor, CancellationToken cancellationToken);

    /// <summary>Ignores the edited appsettings configuration; the notice disappears until it is edited again.</summary>
    Task DismissAppSettingsAsync(CancellationToken cancellationToken);
}

/// <summary>The request log's retention job, for the log settings page.</summary>
public interface ILogRetention
{
    /// <summary>The last cleanup run; null until the first run.</summary>
    LogCleanupResult? LastRun { get; }

    /// <summary>Runs a cleanup now with the active configuration's limits.</summary>
    Task<LogCleanupResult> CleanUpNowAsync(CancellationToken cancellationToken);
}

/// <summary>The traffic history (metrics.db): its rollup and retention job and what it holds, for the log settings page.</summary>
public interface IMetricsHistory
{
    /// <summary>False when the traffic counts are switched off in the host settings.</summary>
    bool Enabled { get; }

    /// <summary>The last rollup and retention run; null until the first run.</summary>
    MetricsMaintenanceResult? LastRun { get; }

    /// <summary>Size of metrics.db and the stored range of each tier; null when switched off.</summary>
    Task<MetricsStorageStatus?> GetStatusAsync(CancellationToken cancellationToken);
}

/// <summary>Traffic history that is switched off.</summary>
public sealed class DisabledMetricsHistory : IMetricsHistory
{
    public bool Enabled => false;

    public MetricsMaintenanceResult? LastRun => null;

    public Task<MetricsStorageStatus?> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult<MetricsStorageStatus?>(null);
}
