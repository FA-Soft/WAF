using System.Globalization;
using Waf.Core.Net;
using Waf.Core.Routing;
using Yarp.ReverseProxy.Configuration;

namespace Waf.Proxy;

/// <summary>
/// Translates the gateway's route configuration into YARP routes and clusters (one cluster per route).
/// </summary>
public static class YarpConfigMapper
{
    /// <summary>Catch-all segment appended to a path prefix.</summary>
    internal const string CatchAll = "{**rest}";

    public static (IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters) Map(
        IEnumerable<ProxyRouteOptions> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        var yarpRoutes = new List<RouteConfig>();
        var clusters = new List<ClusterConfig>();

        foreach (var route in routes)
        {
            yarpRoutes.Add(MapRoute(route));
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
            destinations[string.Create(CultureInfo.InvariantCulture, $"{route.Name}-{i + 1}")] =
                new DestinationConfig { Address = ToDestinationUrl(route.Destinations[i]) };
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
