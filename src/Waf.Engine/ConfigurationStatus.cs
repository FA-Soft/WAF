using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Engine;

/// <summary>
/// The configuration in appsettings was edited since it was last imported or dismissed. The configuration
/// database is the source of truth, so the edit is not applied; an administrator can import it (it then goes
/// through the usual checks) or dismiss it.
/// </summary>
/// <param name="Fingerprint">Fingerprint of the edited appsettings Gateway section.</param>
/// <param name="Candidate">The edited configuration, or null when it is not valid.</param>
/// <param name="Errors">Why it is not valid; empty when it is.</param>
/// <param name="DetectedAt">When the edit was noticed.</param>
public sealed record AppSettingsNotice(string Fingerprint, GatewayConfiguration? Candidate, IReadOnlyList<string> Errors, DateTimeOffset DetectedAt)
{
    public bool CanImport => Candidate is not null && Errors.Count == 0;
}

/// <summary>Holds the current <see cref="AppSettingsNotice"/>, if any. Thread-safe.</summary>
public sealed class ConfigurationStatus
{
    private AppSettingsNotice? _notice;

    /// <summary>The pending notice, or null when appsettings has not been edited since the last import/dismissal.</summary>
    public AppSettingsNotice? AppSettingsNotice => Volatile.Read(ref _notice);

    public void SetNotice(AppSettingsNotice notice)
    {
        ArgumentNullException.ThrowIfNull(notice);
        Volatile.Write(ref _notice, notice);
    }

    public void ClearNotice() => Volatile.Write(ref _notice, null);
}
