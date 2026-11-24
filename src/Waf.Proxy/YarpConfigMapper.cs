using System.Globalization;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Routing;
using Yarp.ReverseProxy.Configuration;

namespace FASoft.Waf.Proxy;

/// <summary>
/// Translates the gateway's route configuration into YARP routes and clusters (one cluster per route).
/// </summary>
public static class YarpConfigMapper
{
    /// <summary>Catch-all segment appended to a path prefix.</summary>
    internal const string CatchAll = "{**rest}";

    /// <summary>Route metadata key holding the configuration tag (see <c>WafEngine.ConfigTag</c>).</summary>
    public const string ConfigTagMetadataKey = "WafConfigTag";

    /// <summary>Route metadata key: "true" when plain HTTP is redirected to HTTPS.</summary>
    public const string RedirectHttpMetadataKey = "WafRedirectHttp";

    /// <summary>Route metadata key: "true" when HTTPS responses carry the HSTS header.</summary>
    public const string HstsMetadataKey = "WafHsts";

    /// <summary>Destination metadata key: the target label ("nas · web") of a destination that uses a target.</summary>
    public const string TargetMetadataKey = "WafTarget";

    /// <summary>Destination metadata key: the failover number of a failover destination ("1", "2", …).</summary>
    public const string FailoverMetadataKey = "WafFailover";

    /// <summary>Cluster metadata key: "true" when the route has failover destinations.</summary>
    public const string HasFailoverMetadataKey = "WafHasFailover";

    /// <summary>
    /// How a destination appears in the request log: its address, preceded by the target label when it has one
    /// (<c>nas · web (http://192.168.1.20:5000/)</c>), followed by its failover number when it is one
    /// (<c>http://10.0.0.6:8080/ · failover 1</c>).
    /// </summary>
    /// <param name="destination">The destination.</param>
    /// <param name="withFailover">False: leave out the failover number.</param>
    public static string DescribeDestination(DestinationConfig destination, bool withFailover = true)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var text = destination.Metadata?.TryGetValue(TargetMetadataKey, out var label) == true
            ? $"{label} ({destination.Address})"
            : destination.Address;
        return withFailover && FailoverOf(destination) is { } failover
            ? string.Create(CultureInfo.InvariantCulture, $"{text} · failover {failover}")
            : text;
    }

    /// <summary>The failover number of a destination; null for a primary.</summary>
    public static int? FailoverOf(DestinationConfig destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return destination.Metadata?.TryGetValue(FailoverMetadataKey, out var value) == true
            && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var failover)
            ? failover
            : null;
    }

    /// <summary>True for a cluster (route) with failover destinations.</summary>
    public static bool HasFailover(ClusterConfig cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);
        return cluster.Metadata?.ContainsKey(HasFailoverMetadataKey) == true;
    }

    /// <param name="routes">The routes to translate; disabled routes are left out.</param>
    /// <param name="configTag">Tag of the configuration the routes belong to; stored in each route's metadata.</param>
    public static (IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters) Map(
        IEnumerable<ProxyRouteOptions> routes, string configTag = "")
    {
        ArgumentNullException.ThrowIfNull(routes);

        var yarpRoutes = new List<RouteConfig>();
        var clusters = new List<ClusterConfig>();

        foreach (var route in routes.Where(r => r.Enabled))
        {
            var metadata = new Dictionary<string, string> { [ConfigTagMetadataKey] = configTag };
            if (route.Https?.RedirectHttp == true)
            {
                metadata[RedirectHttpMetadataKey] = "true";
            }

            if (route.Https?.Hsts == true)
            {
                metadata[HstsMetadataKey] = "true";
            }

            yarpRoutes.Add(MapRoute(route) with { Metadata = metadata });
            clusters.Add(MapCluster(route));
        }

        return (yarpRoutes, clusters);
    }

    /// <summary>Turns a path prefix into a YARP path template: <c>/api</c> becomes <c>/api/{**rest}</c>.</summary>
    public static string ToPathTemplate(string? prefix)
    {
        var trimmed = (prefix ?? "/").TrimEnd('/');
        return $"{trimmed}/{CatchAll}";
    }

    /// <summary>Builds a destination URL, bracketing IPv6 addresses and escaping zone indexes.</summary>
    public static string ToDestinationUrl(ProxyDestinationOptions destination)
    {
        ArgumentNullException.ThrowIfNull(destination);

        var host = destination.Address;
        if (StrictIpAddress.TryParse(host, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            host = $"[{host.Replace("%", "%25", StringComparison.Ordinal)}]";
        }

        var scheme = destination.Scheme.ToLowerInvariant();
        return string.Create(CultureInfo.InvariantCulture, $"{scheme}://{host}:{destination.Port}/");
    }

    private static RouteConfig MapRoute(ProxyRouteOptions route) => new()
    {
        RouteId = route.Name,
        ClusterId = route.Name,
        Match = new RouteMatch
        {
            Hosts = route.Match.Hosts.Count > 0 ? [.. route.Match.Hosts] : null,
            Path = ToPathTemplate(route.Match.PathPrefix),
            Methods = route.Match.Methods.Count > 0 ? [.. route.Match.Methods.Select(m => m.ToUpperInvariant())] : null,
        },
        Transforms =
        [
            new Dictionary<string, string>
            {
                ["RequestHeaderOriginalHost"] = route.PreserveHost ? "true" : "false",
            },
            // Always overwrite X-Forwarded-For/Proto/Host/Prefix with what the gateway saw, so clients
            // cannot spoof them. Trusted upstream proxies are handled separately (issue #44).
            new Dictionary<string, string>
            {
                ["X-Forwarded"] = "Set",
            },
            // Clients must not be able to inject the standard Forwarded header either.
            new Dictionary<string, string>
            {
                ["RequestHeaderRemove"] = "Forwarded",
            },
        ],
    };

    private static ClusterConfig MapCluster(ProxyRouteOptions route)
    {
        var destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < route.Destinations.Count; i++)
        {
            var destination = route.Destinations[i];
            if (TargetResolver.IsUnresolved(destination))
            {
                continue; // a target without an address right now: no traffic for it (no destinations at all: 503)
            }

            var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
            if (destination.UsesTarget)
            {
                // "nas · web" for a target destination, shown in the request log next to the address.
                metadata[TargetMetadataKey] = TargetResolver.Label(destination.Target, destination.TargetPort);
            }

            if (destination.Failover is { } failover)
            {
                metadata[FailoverMetadataKey] = failover.ToString(CultureInfo.InvariantCulture);
            }

            destinations[string.Create(CultureInfo.InvariantCulture, $"{route.Name}-{i + 1}")] = new DestinationConfig
            {
                Address = ToDestinationUrl(destination),
                Metadata = metadata.Count > 0 ? metadata : null,
            };
        }

        var health = route.HealthCheck;
        var active = string.IsNullOrEmpty(health?.Path)
            ? null
            : new ActiveHealthCheckConfig
            {
                Enabled = true,
                Interval = TimeSpan.FromSeconds(health.IntervalSeconds),
                Timeout = TimeSpan.FromSeconds(health.TimeoutSeconds),
                Policy = "ConsecutiveFailures",
                Path = health.Path,
            };

        return new ClusterConfig
        {
            ClusterId = route.Name,
            Destinations = destinations,
            // Routes with failover destinations get the "primary, then failover" choice and a short connect time-out.
            Metadata = route.Destinations.Any(d => d.IsFailover)
                ? new Dictionary<string, string> { [HasFailoverMetadataKey] = "true" }
                : null,
            HttpClient = new HttpClientConfig
            {
                DangerousAcceptAnyServerCertificate = route.AllowInvalidBackendCertificate,
            },
            HealthCheck = new HealthCheckConfig
            {
                Active = active,
                Passive = new PassiveHealthCheckConfig
                {
                    Enabled = true,
                    Policy = "TransportFailureRate",
                    ReactivationPeriod = TimeSpan.FromSeconds(30),
                },
            },
        };
    }
}
