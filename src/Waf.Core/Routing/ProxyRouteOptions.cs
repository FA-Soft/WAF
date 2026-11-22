namespace Waf.Core.Routing;

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

    /// <summary>Backends to forward to. More than one spreads the load across them.</summary>
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

/// <summary>A backend address.</summary>
public sealed class ProxyDestinationOptions
{
    /// <summary><c>http</c> (default) or <c>https</c>.</summary>
    public string Scheme { get; set; } = "http";

    /// <summary>IP address (e.g. <c>10.0.0.5</c>, <c>fd00::10</c>) or host name.</summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>Backend port.</summary>
    public int Port { get; set; }
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
