using System.Text.Json.Serialization;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Core.Configuration;

/// <summary>
/// The complete gateway configuration: settings, routes, WAF rules and certificates.
/// This is the unit that is validated, versioned, exported/imported and proposed by the AI assistant.
/// </summary>
/// <remarks>Listener ports are host settings (<c>Gateway:Endpoints</c>) and not part of this model.</remarks>
public sealed class GatewayConfiguration
{
    /// <summary>The schema version this code reads and writes.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Optional reference to the JSON schema, for editor validation and completion.</summary>
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    /// <summary>Version of the configuration format.</summary>
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    /// <summary>Global settings.</summary>
    public GatewaySettings Settings { get; set; } = new();

    /// <summary>
    /// Named backend machines with labelled ports, which route destinations can use instead of an address. Left out
    /// of the JSON while empty, so configurations without targets keep their exact JSON (and hash).
    /// </summary>
    public IList<BackendTarget> Targets { get; } = [];

    /// <summary>Routes: which requests go to which backends.</summary>
    public IList<ProxyRouteOptions> Routes { get; } = [];

    /// <summary>WAF rules, evaluated by priority (lowest number first).</summary>
    public IList<WafRule> Rules { get; } = [];

    /// <summary>Rate limits; every limit that applies to a request is checked.</summary>
    public IList<RateLimitRule> RateLimits { get; } = [];

    /// <summary>TLS certificates per host name.</summary>
    public IList<CertificateBinding> Certificates { get; } = [];
}

/// <summary>Global gateway settings.</summary>
public sealed class GatewaySettings
{
    /// <summary>
    /// Global detection-only mode: Block decisions are logged but not enforced, for every rule.
    /// Use it to try out new rules without risk.
    /// </summary>
    public bool DetectionOnly { get; set; }

    /// <summary>
    /// Proxies or load balancers in front of the gateway (IP addresses or CIDR ranges). Only these may
    /// supply the client IP via X-Forwarded-For; everyone else's header is ignored.
    /// </summary>
    public IList<string> TrustedProxies { get; } = [];

    /// <summary>Let's Encrypt account settings.</summary>
    public AcmeSettings Acme { get; set; } = new();

    /// <summary>The Strict-Transport-Security header sent by routes that enable HSTS.</summary>
    public HstsSettings Hsts { get; set; } = new();

    /// <summary>Built-in attack detection.</summary>
    public AttackDetectionSettings AttackDetection { get; set; } = new();

    /// <summary>How long request log entries are kept, and how large the log may grow.</summary>
    public LogRetentionSettings LogRetention { get; set; } = new();

    /// <summary>
    /// Upper bound on rate-limit counters kept in memory (all limits together). When full, idle counters
    /// and those with the fewest requests are dropped first.
    /// </summary>
    public int RateLimitMaxTrackedClients { get; set; } = DefaultRateLimitMaxTrackedClients;

    /// <summary>Default for <see cref="RateLimitMaxTrackedClients"/>.</summary>
    public const int DefaultRateLimitMaxTrackedClients = 100_000;
}

/// <summary>
/// Limits of the request log (<c>events.db</c>). A background job removes the oldest entries when either is exceeded.
/// </summary>
public sealed class LogRetentionSettings
{
    /// <summary>Remove entries older than this many days. 0: no age limit (the size limit still applies).</summary>
    public int MaxAgeDays { get; set; } = DefaultMaxAgeDays;

    /// <summary>Largest size of the request log on disk, in megabytes (MB).</summary>
    public int MaxDatabaseSizeMb { get; set; } = DefaultMaxDatabaseSizeMb;

    public const int DefaultMaxAgeDays = 30;
    public const int DefaultMaxDatabaseSizeMb = 1024;

    /// <summary>Longest age limit: ten years.</summary>
    public const int MaxMaxAgeDays = 3650;

    /// <summary>Smallest size limit, in MB.</summary>
    public const int MinDatabaseSizeMb = 10;

    /// <summary>Largest size limit, in MB (1 TB).</summary>
    public const int MaxDatabaseSizeLimitMb = 1_048_576;
}

/// <summary>
/// The HTTP Strict Transport Security header (RFC 6797) for routes with <c>Https.Hsts</c>. It is only sent over HTTPS.
/// </summary>
public sealed class HstsSettings
{
    /// <summary>One year: what browsers and the HSTS preload list expect.</summary>
    public const int DefaultMaxAgeSeconds = 31_536_000;

    /// <summary>Two years: the longest value accepted here.</summary>
    public const int MaxMaxAgeSeconds = 63_072_000;

    /// <summary>How long browsers use HTTPS only, in seconds. 0 tells browsers to forget the host's HSTS.</summary>
    public int MaxAgeSeconds { get; set; } = DefaultMaxAgeSeconds;

    /// <summary>Also for every subdomain of the host name. Only when all of them support HTTPS.</summary>
    public bool IncludeSubDomains { get; set; }

    /// <summary>
    /// Ask to be included in browsers' built-in HSTS list (hstspreload.org). Needs IncludeSubDomains and a max-age
    /// of at least one year; very hard to undo.
    /// </summary>
    public bool Preload { get; set; }

    /// <summary>The header value, e.g. <c>max-age=31536000; includeSubDomains</c>.</summary>
    public string HeaderValue() =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"max-age={MaxAgeSeconds}")
        + (IncludeSubDomains ? "; includeSubDomains" : string.Empty)
        + (Preload ? "; preload" : string.Empty);
}

/// <summary>Let's Encrypt (ACME) account settings.</summary>
public sealed class AcmeSettings
{
    /// <summary>Contact e-mail for the Let's Encrypt account (expiry notices).</summary>
    public string? Email { get; set; }

    /// <summary>Must be true to use Let's Encrypt: you accept the Let's Encrypt subscriber agreement.</summary>
    public bool AcceptTermsOfService { get; set; }

    /// <summary>Use the Let's Encrypt staging environment (untrusted test certificates, high rate limits).</summary>
    public bool UseStaging { get; set; }
}
