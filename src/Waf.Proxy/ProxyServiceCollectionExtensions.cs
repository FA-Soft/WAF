using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Waf.Core.Routing;

namespace Waf.Proxy;

/// <summary>
/// Registers and maps the reverse proxy.
/// </summary>
public static class ProxyServiceCollectionExtensions
{
    /// <summary>
    /// Validates <paramref name="routes"/> and registers YARP with an in-memory configuration
    /// (the hook for hot reload later).
    /// </summary>
    /// <exception cref="OptionsValidationException">The route configuration is invalid.</exception>
    public static IServiceCollection AddWafProxy(this IServiceCollection services, IEnumerable<ProxyRouteOptions> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        var list = routes.ToList();
        var errors = ProxyRouteValidator.Validate(list);
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(ProxyRouteOptions.SectionName, typeof(ProxyRouteOptions), errors);
        }

        var (yarpRoutes, clusters) = YarpConfigMapper.Map(list);
        services.AddReverseProxy().LoadFromMemory(yarpRoutes, clusters);
        services.AddSingleton<ProxyRouteUpdater>();
        return services;
    }

    /// <summary>Maps the proxy endpoints (load balancing and passive health checks included).</summary>
    public static ReverseProxyConventionBuilder MapWafProxy(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapReverseProxy();
}
