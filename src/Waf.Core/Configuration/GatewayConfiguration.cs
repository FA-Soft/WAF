using System.Text.Json.Serialization;
using Waf.Core.Routing;

namespace Waf.Core.Configuration;

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

    /// <summary>
    /// Upper bound on rate-limit counters kept in memory (all limits together). When full, idle counters
    /// and those with the fewest requests are dropped first.
    /// </summary>
    public int RateLimitMaxTrackedClients { get; set; } = DefaultRateLimitMaxTrackedClients;

    /// <summary>Default for <see cref="RateLimitMaxTrackedClients"/>.</summary>
    public const int DefaultRateLimitMaxTrackedClients = 100_000;
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
