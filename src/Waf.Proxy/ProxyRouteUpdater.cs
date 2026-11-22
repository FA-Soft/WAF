using Waf.Core.Routing;
using Yarp.ReverseProxy.Configuration;

namespace Waf.Proxy;

/// <summary>Routes translated for YARP and checked by YARP's own validator, ready to apply.</summary>
public sealed record PreparedRoutes(IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters);

/// <summary>
/// Replaces the proxy routes at runtime. Two steps, so a configuration can be checked completely before
/// anything changes: <see cref="PrepareAsync"/> validates, <see cref="Apply"/> swaps (atomically for YARP).
/// </summary>
public sealed class ProxyRouteUpdater(InMemoryConfigProvider provider, IConfigValidator validator)
{
    /// <summary>Validates and translates <paramref name="routes"/>; returns errors instead of throwing.</summary>
    public async Task<(PreparedRoutes? Prepared, IReadOnlyList<string> Errors)> PrepareAsync(IEnumerable<ProxyRouteOptions> routes, string configTag = "")
    {
        ArgumentNullException.ThrowIfNull(routes);

        var list = routes.ToList();
        var errors = ProxyRouteValidator.Validate(list).ToList();
        if (errors.Count > 0)
        {
            return (null, errors);
        }

        var (yarpRoutes, clusters) = YarpConfigMapper.Map(list, configTag);
        foreach (var route in yarpRoutes)
        {
            errors.AddRange((await validator.ValidateRouteAsync(route).ConfigureAwait(false)).Select(e => $"Route '{route.RouteId}': {e.Message}"));
        }

        foreach (var cluster in clusters)
        {
            errors.AddRange((await validator.ValidateClusterAsync(cluster).ConfigureAwait(false)).Select(e => $"Route '{cluster.ClusterId}': {e.Message}"));
        }

        return errors.Count > 0 ? (null, errors) : (new PreparedRoutes(yarpRoutes, clusters), errors);
    }

    /// <summary>Activates prepared routes. In-flight requests finish on the routes they started with.</summary>
    public void Apply(PreparedRoutes prepared)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        provider.Update(prepared.Routes, prepared.Clusters);
    }
}
