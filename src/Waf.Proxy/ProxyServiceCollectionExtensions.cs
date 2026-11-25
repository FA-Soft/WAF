using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using FASoft.Waf.Core.Routing;
using Yarp.ReverseProxy.Forwarder;

namespace FASoft.Waf.Proxy;

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
    public static IServiceCollection AddWafProxy(this IServiceCollection services, IEnumerable<ProxyRouteOptions> routes, string configTag = "")
    {
        ArgumentNullException.ThrowIfNull(routes);

        var list = routes.ToList();
        var errors = ProxyRouteValidator.Validate(list);
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(ProxyRouteOptions.SectionName, typeof(ProxyRouteOptions), errors);
        }

        var (yarpRoutes, clusters) = YarpConfigMapper.Map(list, configTag);
        services.AddReverseProxy().LoadFromMemory(yarpRoutes, clusters);
        services.AddSingleton<ProxyRouteUpdater>();

        // Failover: the host may register its own FailoverOptions (Gateway:Failover) first.
        services.TryAddSingleton(new FailoverOptions());
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<FailoverMonitor>();
        services.AddSingleton<IRouteFailoverMonitor>(sp => sp.GetRequiredService<FailoverMonitor>());
        services.Replace(ServiceDescriptor.Singleton<IForwarderHttpClientFactory, FailoverHttpClientFactory>());
        services.AddSingleton<BackendErrorCounter>();
        services.AddSingleton<IBackendErrorStatistics>(sp => sp.GetRequiredService<BackendErrorCounter>());
        return services;
    }

    /// <summary>
    /// Maps the proxy endpoints: clear error responses when no backend answers, the failover choice and connect retry,
    /// then YARP's load balancing and passive health checks (YARP's default pipeline).
    /// </summary>
    public static ReverseProxyConventionBuilder MapWafProxy(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapReverseProxy(proxy =>
        {
            proxy.UseMiddleware<BackendErrorMiddleware>();
            proxy.UseMiddleware<FailoverMiddleware>();
            proxy.UseSessionAffinity();
            proxy.UseLoadBalancing();
            proxy.UsePassiveHealthChecks();
            proxy.UseMiddleware<BackendTimingMiddleware>(); // last: the time of the forwarding itself
        });
}
