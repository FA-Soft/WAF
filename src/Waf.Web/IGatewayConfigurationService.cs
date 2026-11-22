using Waf.Core.Configuration;
using Waf.Data;

namespace Waf.Web;

/// <summary>Outcome of an activation (save, rollback or import).</summary>
/// <param name="Succeeded">True when the configuration is now active.</param>
/// <param name="Errors">Why it was rejected, in plain language; empty on success.</param>
/// <param name="Version">The stored version that is now active; null on failure.</param>
public sealed record ActivationResult(bool Succeeded, IReadOnlyList<string> Errors, StoredConfiguration? Version)
{
    public static ActivationResult Failed(IEnumerable<string> errors) => new(false, [.. errors], null);
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
    Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="ActivateAsync"/>, but only when <paramref name="baseVersion"/> is still the running
    /// version; otherwise the change is refused, so a concurrent change is never overwritten unseen.
    /// </summary>
    Task<ActivationResult> ActivateIfCurrentAsync(long baseVersion, GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken);

    /// <summary>Activates the edited appsettings configuration (see the appsettings notice).</summary>
    Task<ActivationResult> ImportAppSettingsAsync(string author, CancellationToken cancellationToken);

    /// <summary>Ignores the edited appsettings configuration; the notice disappears until it is edited again.</summary>
    Task DismissAppSettingsAsync(CancellationToken cancellationToken);
}
