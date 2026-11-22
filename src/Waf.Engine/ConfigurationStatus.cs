namespace Waf.Engine;

/// <summary>
/// Whether the configuration in appsettings is the one running. When a change was rejected (at startup or
/// on reload), the last-known-good keeps running and this records why. Thread-safe.
/// </summary>
public sealed class ConfigurationStatus
{
    private Snapshot _snapshot = new(null, [], null);

    /// <summary>Where the rejected configuration came from; null when nothing is rejected.</summary>
    public string? RejectedSource => Volatile.Read(ref _snapshot).Source;

    /// <summary>Why it was rejected; empty when nothing is rejected.</summary>
    public IReadOnlyList<string> RejectedErrors => Volatile.Read(ref _snapshot).Errors;

    /// <summary>When it was rejected.</summary>
    public DateTimeOffset? RejectedAt => Volatile.Read(ref _snapshot).At;

    public bool HasRejection => RejectedSource is not null;

    public void Rejected(string source, IReadOnlyList<string> errors, DateTimeOffset at) =>
        Volatile.Write(ref _snapshot, new Snapshot(source, [.. errors], at));

    public void Accepted() => Volatile.Write(ref _snapshot, new Snapshot(null, [], null));

    private sealed record Snapshot(string? Source, IReadOnlyList<string> Errors, DateTimeOffset? At);
}
