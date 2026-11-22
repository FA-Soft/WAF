using System.Net;
using Microsoft.AspNetCore.Http;
using Waf.Engine;
using Yarp.ReverseProxy.Model;

namespace Waf.Proxy;

/// <summary>
/// <see cref="IWafRequest"/> over an <see cref="HttpContext"/>, without copying. Use after client-IP
/// resolution (for the real client IP) and after routing (for the route name).
/// </summary>
public sealed class HttpContextWafRequest(HttpContext context) : IWafRequest
{
    private readonly HttpContext _context = context ?? throw new ArgumentNullException(nameof(context));

    /// <summary>The underlying request context.</summary>
    public HttpContext Context => _context;

    public IPAddress ClientIp => _context.Connection.RemoteIpAddress ?? IPAddress.None;

    public string Host => _context.Request.Host.Host;

    public string Path => _context.Request.Path.HasValue ? _context.Request.Path.Value! : "/";

    public string QueryString => _context.Request.QueryString.HasValue ? _context.Request.QueryString.Value![1..] : string.Empty;

    public string Method => _context.Request.Method;

    public string? RouteName => GetRouteName(_context);

    public string? GetHeader(string name)
    {
        var values = _context.Request.Headers[name];
        return values.Count == 0 ? null : values.ToString();
    }

    /// <summary>The name of the proxy route selected by routing, or null.</summary>
    public static string? GetRouteName(HttpContext context) =>
        context?.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.RouteId;

    /// <summary>Tag of the configuration whose routes routed this request, or null when no route matched.</summary>
    public static string? GetConfigTag(HttpContext context) =>
        context?.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.Metadata is { } metadata
        && metadata.TryGetValue(YarpConfigMapper.ConfigTagMetadataKey, out var tag)
            ? tag
            : null;
}
