using System.Net;

namespace Waf.Engine;

/// <summary>Kind of security event.</summary>
public enum WafEventKind
{
    /// <summary>A request exceeded a rate limit and was rejected (HTTP 429).</summary>
    RateLimited,

    /// <summary>A request exceeded a rate limit in detection-only mode and was let through.</summary>
    RateLimitDetected,
}

/// <summary>A security event, e.g. a request rejected by a rate limit.</summary>
public sealed record WafEvent(
    DateTimeOffset Timestamp,
    WafEventKind Kind,
    IPAddress ClientIp,
    string Method,
    string Host,
    string Path,
    string? RouteName,
    string RuleName,
    int StatusCode);

/// <summary>
/// Receives security events. Implementations must be fast and must not throw; slow work (e.g. writing to a
/// database) belongs on a background queue.
/// </summary>
public interface IWafEventSink
{
    void Publish(WafEvent wafEvent);
}
