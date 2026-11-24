namespace FASoft.Waf.Core.Routing;

/// <summary>
/// A route: which requests it matches and which backend(s) they are forwarded to.
/// Bound from the <c>Gateway:Routes</c> configuration section (a list).
/// </summary>
public sealed class ProxyRouteOptions
{
    /// <summary>The configuration section holding the list of routes.</summary>
    public const string SectionName = "Gateway:Routes";

    /// <summary>Unique route name (letters, digits, '-', '_' and '.').</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Disabled routes are kept in the configuration but not used: their requests get 404.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Which requests this route handles.</summary>
    public RouteMatchOptions Match { get; set; } = new();

    /// <summary>
    /// Backends to forward to. More than one primary spreads the load across them; failover destinations
    /// (<see cref="ProxyDestinationOptions.Failover"/>) only get traffic while no primary is healthy.
    /// </summary>
    public IList<ProxyDestinationOptions> Destinations { get; } = [];

    /// <summary>
    /// Forward the client's original Host header (default). Needed by backends that select a site by
    /// host name, such as IIS. When false, the backend receives its own address as Host.
    /// </summary>
    public bool PreserveHost { get; set; } = true;

    /// <summary>
    /// Accept any TLS certificate from HTTPS backends, e.g. a self-signed certificate on a local IIS.
    /// Off by default; only enable for backends you control on a trusted network.
    /// </summary>
    public bool AllowInvalidBackendCertificate { get; set; }

    /// <summary>Active health check settings. Passive health checks are always on.</summary>
    public RouteHealthCheckOptions HealthCheck { get; set; } = new();

    /// <summary>HTTPS enforcement: redirect plain HTTP and send HSTS. Both off by default (plain HTTP routes work).</summary>
    public RouteHttpsOptions Https { get; set; } = new();

    /// <summary>
    /// Optional short text for visitors when no backend answers, e.g. "Planned maintenance until 14:00". Shown in the
    /// error response, in every format.
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>How a route enforces HTTPS.</summary>
public sealed class RouteHttpsOptions
{
    /// <summary>
    /// Answer plain HTTP requests (port 80) with a permanent redirect (308) to the same URL over HTTPS. Needs a
    /// certificate for every host name of the route. Let's Encrypt challenges on port 80 still work.
    /// </summary>
    public bool RedirectHttp { get; set; }

    /// <summary>
    /// Send the Strict-Transport-Security header on HTTPS responses, so browsers use HTTPS only for the host name
    /// (see <c>Settings.Hsts</c> for how long). Browsers remember it: only enable it when HTTPS works for good.
    /// </summary>
    public bool Hsts { get; set; }
}

/// <summary>Request matching. All given conditions must match; omitted conditions match anything.</summary>
public sealed class RouteMatchOptions
{
    /// <summary>Host names, e.g. <c>api.example.com</c> or <c>*.example.com</c>. Empty matches any host.</summary>
    public IList<string> Hosts { get; } = [];

    /// <summary>
    /// Path prefix, matched on whole segments: <c>/api</c> matches <c>/api</c> and <c>/api/users</c>,
    /// not <c>/apix</c>. Default <c>/</c> matches every path. The path is forwarded unchanged.
    /// </summary>
    public string PathPrefix { get; set; } = "/";

    /// <summary>HTTP methods, e.g. <c>GET</c>, <c>POST</c>. Empty matches any method.</summary>
    public IList<string> Methods { get; } = [];
}

/// <summary>
/// A backend: either an address (<see cref="Scheme"/>, <see cref="Address"/>, <see cref="Port"/>), or a labelled port
/// of a named target (<see cref="Target"/> and <see cref="TargetPort"/>; then address and port stay empty).
/// </summary>
public sealed class ProxyDestinationOptions
{
    /// <summary><c>http</c> (default) or <c>https</c>. With a target, the target port's scheme is used.</summary>
    public string Scheme { get; set; } = "http";

    /// <summary>IP address (e.g. <c>10.0.0.5</c>, <c>fd00::10</c>) or host name. Empty with a target.</summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>Backend port. 0 with a target.</summary>
    public int Port { get; set; }

    /// <summary>Name of a target in <c>Targets</c>, e.g. <c>nas</c>; together with <see cref="TargetPort"/>.</summary>
    public string? Target { get; set; }

    /// <summary>Label of one of the target's ports, e.g. <c>web</c>.</summary>
    public string? TargetPort { get; set; }

    /// <summary>
    /// Empty (the default): a primary destination. 1, 2, …: a failover destination, used in this order only while no
    /// primary is healthy (failovers with the same number share the load).
    /// </summary>
    public int? Failover { get; set; }

    /// <summary>True for a failover destination. Not part of the configuration JSON.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsFailover => Failover is not null;

    /// <summary>True when this destination names a target instead of an address. Not part of the configuration JSON.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool UsesTarget => !string.IsNullOrEmpty(Target) || !string.IsNullOrEmpty(TargetPort);
}

/// <summary>Active health checks: the gateway probes each backend periodically.</summary>
public sealed class RouteHealthCheckOptions
{
    /// <summary>Path to probe, e.g. <c>/health</c>. Active checks are off when empty.</summary>
    public string? Path { get; set; }

    /// <summary>Seconds between probes.</summary>
    public int IntervalSeconds { get; set; } = 10;

    /// <summary>Probe timeout in seconds.</summary>
    public int TimeoutSeconds { get; set; } = 5;
}
