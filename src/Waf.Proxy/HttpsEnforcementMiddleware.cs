using FASoft.Waf.Core.Hosting;
using FASoft.Waf.Engine;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;

namespace FASoft.Waf.Proxy;

/// <summary>
/// Pipeline step 5: HTTPS enforcement per route. A plain HTTP request to a route with <c>Https.RedirectHttp</c> gets a
/// permanent redirect (308, keeps the method and body) to the same URL over HTTPS; an HTTPS response of a route with
/// <c>Https.Hsts</c> carries the Strict-Transport-Security header. Routes without these options work over plain HTTP.
/// </summary>
/// <remarks>
/// Runs after the WAF, so an attack over HTTP is blocked rather than redirected. Let's Encrypt challenges are answered
/// earlier (step 1) and are never redirected. A request that a trusted proxy received over HTTPS
/// (<c>X-Forwarded-Proto: https</c>) counts as HTTPS, so a TLS-terminating proxy in front causes no redirect loop.
/// The settings come from the selected route's metadata and the WAF engine of the same configuration, so they change
/// together with the routes.
/// </remarks>
public sealed class HttpsEnforcementMiddleware(RequestDelegate next, WafEngineHolder engines, IOptions<GatewayEndpointOptions> endpoints)
{
    /// <summary><see cref="HttpContext.Items"/> key set on a redirected request (for the request log).</summary>
    public const string RedirectedItemKey = "WafRedirectedToHttps";

    private const int DefaultHttpsPort = 443;

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.Metadata;
        if (metadata is null)
        {
            return next(context);
        }

        // The connection comes from a trusted proxy (whatever it says in X-Forwarded-For): it may report the scheme.
        var engine = engines.Resolve(HttpContextWafRequest.GetConfigTag(context));
        var viaTrustedProxy = context.Features.Get<IClientIpFeature>() is { } client
            && engine?.TrustedProxies.Contains(client.ConnectionIp) == true;
        var https = context.Request.IsHttps
            || (viaTrustedProxy && string.Equals(context.Request.Headers["X-Forwarded-Proto"], "https", StringComparison.OrdinalIgnoreCase));

        if (!https && metadata.ContainsKey(YarpConfigMapper.RedirectHttpMetadataKey))
        {
            // Behind a proxy the public HTTPS port is the standard one; otherwise the gateway's own HTTPS port.
            var port = endpoints.Value.HttpsPort;
            var host = viaTrustedProxy || port == DefaultHttpsPort
                ? new HostString(context.Request.Host.Host)
                : new HostString(context.Request.Host.Host, port);
            context.Items[RedirectedItemKey] = true;
            context.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
            context.Response.Headers.Location = UriHelper.BuildAbsolute("https", host, context.Request.PathBase, context.Request.Path, context.Request.QueryString);
            return Task.CompletedTask;
        }

        if (https && metadata.ContainsKey(YarpConfigMapper.HstsMetadataKey) && engine is not null)
        {
            // Set when the response starts: replaces an HSTS header the backend may send, never duplicates it.
            var value = engine.HstsHeader;
            context.Response.OnStarting(() =>
            {
                context.Response.Headers.StrictTransportSecurity = value;
                return Task.CompletedTask;
            });
        }

        return next(context);
    }
}

/// <summary>Pipeline registration for <see cref="HttpsEnforcementMiddleware"/>.</summary>
public static class HttpsEnforcementApplicationBuilderExtensions
{
    public static IApplicationBuilder UseHttpsEnforcement(this IApplicationBuilder app) =>
        app.UseMiddleware<HttpsEnforcementMiddleware>();
}
