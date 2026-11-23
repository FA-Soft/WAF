namespace FASoft.Waf.Engine;

/// <summary>What the gateway did with a request.</summary>
public enum RequestAction
{
    /// <summary>Forwarded to a backend.</summary>
    Forwarded,

    /// <summary>Rejected by a rule or by attack detection (403).</summary>
    Blocked,

    /// <summary>Rejected by a rate limit (429).</summary>
    RateLimited,

    /// <summary>Rejected because the WAF was unavailable or failed (503, fail-closed).</summary>
    FailClosed,

    /// <summary>No route matched (404).</summary>
    NoRoute,

    /// <summary>A route matched, but no backend was available.</summary>
    BackendUnavailable,

    /// <summary>Answered by the gateway itself, e.g. a Let's Encrypt challenge.</summary>
    Answered,

    /// <summary>Redirected from HTTP to HTTPS (308).</summary>
    Redirected,
}

/// <summary>
/// One request in the request log. Holds no query string, headers, cookies or bodies: only the fields below,
/// so secrets in URLs, authorization headers or form posts are never stored.
/// </summary>
/// <param name="Timestamp">When the request arrived (UTC).</param>
/// <param name="ClientIp">Resolved client IP.</param>
/// <param name="Method">HTTP method.</param>
/// <param name="Host">Host name, without port.</param>
/// <param name="Path">URL path, without the query string.</param>
/// <param name="RouteName">Matched route, if any.</param>
/// <param name="Action">What happened.</param>
/// <param name="Event">The most important WAF event of the request (e.g. a detection-only match), if any.</param>
/// <param name="RuleName">Rule, rate limit or attack signature of <paramref name="Event"/>.</param>
/// <param name="Detail">Extra information, e.g. the attack category and where it was found.</param>
/// <param name="Destination">Backend the request was forwarded to, e.g. <c>http://10.0.0.5:8080/</c>.</param>
/// <param name="StatusCode">Status code sent to the client.</param>
/// <param name="LatencyMs">Time from arrival until the response was complete, in milliseconds.</param>
public sealed record RequestLogEntry(
    DateTimeOffset Timestamp,
    string ClientIp,
    string Method,
    string Host,
    string Path,
    string? RouteName,
    RequestAction Action,
    WafEventKind? Event,
    string? RuleName,
    string? Detail,
    string? Destination,
    int StatusCode,
    double LatencyMs);

/// <summary>
/// Receives request log entries. <see cref="Write"/> must never block or throw: it is called on the request path.
/// Implementations queue entries and write them in the background.
/// </summary>
public interface IRequestLog
{
    void Write(RequestLogEntry entry);
}

/// <summary>Current state of the request log.</summary>
public interface IRequestLogMonitor
{
    /// <summary>The counters; null when request logging is switched off.</summary>
    RequestLogStatistics? Statistics { get; }
}

/// <summary>Request log that discards everything (logging switched off).</summary>
public sealed class NullRequestLog : IRequestLog, IRequestLogMonitor
{
    public RequestLogStatistics? Statistics => null;

    public void Write(RequestLogEntry entry)
    {
    }
}

/// <summary>Counters of the request log, for the dashboard and health information.</summary>
/// <param name="Written">Entries stored since start.</param>
/// <param name="Dropped">Entries discarded because the queue was full or storing failed.</param>
/// <param name="Queued">Entries waiting to be stored.</param>
/// <param name="QueueCapacity">Maximum number of waiting entries.</param>
/// <param name="LastError">The last storage error, if storing currently fails.</param>
public sealed record RequestLogStatistics(long Written, long Dropped, int Queued, int QueueCapacity, string? LastError);
