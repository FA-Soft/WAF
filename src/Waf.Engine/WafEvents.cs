using System.Net;

namespace FASoft.Waf.Engine;

/// <summary>Kind of security event.</summary>
public enum WafEventKind
{
    /// <summary>A Block rule rejected the request (HTTP 403).</summary>
    RuleBlocked,

    /// <summary>A Block rule matched in detection-only mode; the request was let through.</summary>
    RuleDetected,

    /// <summary>A LogOnly rule matched.</summary>
    RuleLogged,

    /// <summary>An attack was detected and the request rejected (HTTP 403).</summary>
    AttackBlocked,

    /// <summary>An attack was detected in detection-only mode; the request was let through.</summary>
    AttackDetected,

    /// <summary>A request exceeded a rate limit and was rejected (HTTP 429).</summary>
    RateLimited,

    /// <summary>A request exceeded a rate limit in detection-only mode and was let through.</summary>
    RateLimitDetected,

    /// <summary>The WAF could not judge the request (unavailable or failed); it was rejected (HTTP 503).</summary>
    FailClosed,
}

/// <summary>A security event, e.g. a request rejected by a rule.</summary>
/// <param name="Timestamp">When it happened.</param>
/// <param name="Kind">What happened.</param>
/// <param name="ClientIp">Resolved client IP.</param>
/// <param name="Method">HTTP method.</param>
/// <param name="Host">Host name.</param>
/// <param name="Path">URL path.</param>
/// <param name="RouteName">Matched route, if any.</param>
/// <param name="RuleName">Rule, rate limit or signature responsible; empty for fail-closed events.</param>
/// <param name="StatusCode">Status code sent (200 when the request was let through).</param>
/// <param name="Detail">Extra information, e.g. attack category, location and matching snippet.</param>
public sealed record WafEvent(
    DateTimeOffset Timestamp,
    WafEventKind Kind,
    IPAddress ClientIp,
    string Method,
    string Host,
    string Path,
    string? RouteName,
    string RuleName,
    int StatusCode,
    string? Detail = null);

/// <summary>
/// Receives security events. Implementations must be fast and must not throw; slow work (e.g. writing to a
/// database) belongs on a background queue.
/// </summary>
public interface IWafEventSink
{
    void Publish(WafEvent wafEvent);
}
