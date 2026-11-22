namespace Waf.Core.Configuration;

/// <summary>
/// A rate limit: at most <see cref="PermitLimit"/> requests per <see cref="WindowSeconds"/> for each
/// <see cref="Key"/> (e.g. per client IP). Requests over the limit get HTTP 429.
/// </summary>
/// <remarks>
/// Uses a sliding window. Rejected requests count too, so a client that keeps sending stays limited until
/// it slows down. IPv6 clients are counted per /64 network, because a single host can easily rotate
/// addresses within its /64.
/// </remarks>
public sealed class RateLimitRule
{
    /// <summary>Unique name (letters, digits, '-', '_' and '.').</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional explanation shown in the UI and logs.</summary>
    public string? Description { get; set; }

    /// <summary>Disabled limits are kept but not applied.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Maximum number of requests per window.</summary>
    public int PermitLimit { get; set; } = 100;

    /// <summary>Window length in seconds.</summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>What is counted separately.</summary>
    public RateLimitKey Key { get; set; } = RateLimitKey.ClientIp;

    /// <summary>Log requests over the limit instead of rejecting them.</summary>
    public bool DetectionOnly { get; set; }

    /// <summary>Names of the routes this limit applies to. Empty means all requests, including unrouted ones.</summary>
    public IList<string> Routes { get; } = [];

    /// <summary>Optional conditions (all must match) to limit only some requests, e.g. POST to /login.</summary>
    public IList<RuleCondition> Conditions { get; } = [];
}

/// <summary>How requests are grouped for counting.</summary>
public enum RateLimitKey
{
    /// <summary>One counter per client IP (IPv6: per /64), across all routes the limit applies to.</summary>
    ClientIp,

    /// <summary>One counter per client IP and route.</summary>
    ClientIpAndRoute,

    /// <summary>One counter per route for all clients together, to protect a backend.</summary>
    Route,
}
