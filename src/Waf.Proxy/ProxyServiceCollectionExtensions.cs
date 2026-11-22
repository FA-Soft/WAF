using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
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
    /// Loads routes from <c>Gateway:Routes</c>, validates them and registers YARP with an in-memory
    /// configuration (the hook for hot reload later).
    /// </summary>
    /// <exception cref="OptionsValidationException">The route configuration is invalid.</exception>
    public static IServiceCollection AddWafProxy(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var routes = LoadRoutes(configuration);

        var errors = ProxyRouteValidator.Validate(routes);
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(ProxyRouteOptions.SectionName, typeof(ProxyRouteOptions), errors);
        }

        var (yarpRoutes, clusters) = YarpConfigMapper.Map(routes);
        services.AddReverseProxy().LoadFromMemory(yarpRoutes, clusters);
        return services;
    }

    /// <summary>Maps the proxy endpoints (load balancing and passive health checks included).</summary>
    public static ReverseProxyConventionBuilder MapWafProxy(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapReverseProxy();

    internal static List<ProxyRouteOptions> LoadRoutes(IConfiguration configuration) =>
        configuration.GetSection(ProxyRouteOptions.SectionName).Get<List<ProxyRouteOptions>>() ?? [];
}
