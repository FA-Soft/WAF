using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Waf.Core.Net;

namespace Waf.Proxy;

/// <summary>Client IP of the current request, as resolved by <see cref="ClientIpMiddleware"/>.</summary>
public interface IClientIpFeature
{
    /// <summary>The resolved client IP (also set as <see cref="ConnectionInfo.RemoteIpAddress"/>).</summary>
    IPAddress ClientIp { get; }

    /// <summary>The IP of the TCP connection before resolution.</summary>
    IPAddress ConnectionIp { get; }

    /// <summary>True when the client IP came from X-Forwarded-For sent by a trusted proxy.</summary>
    bool ViaTrustedProxy { get; }
}

/// <summary>
/// Resolves the real client IP (see <see cref="ClientIpResolver"/>) and makes it the request's
/// <see cref="ConnectionInfo.RemoteIpAddress"/>, so everything downstream (rules, rate limiting,
/// logging and the X-Forwarded-For sent to backends) uses the same, trustworthy value.
/// </summary>
public sealed partial class ClientIpMiddleware(RequestDelegate next, TrustedProxies trustedProxies, ILogger<ClientIpMiddleware> logger)
{
    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var connectionIp = context.Connection.RemoteIpAddress;
        if (connectionIp is not null)
        {
            var resolution = ClientIpResolver.Resolve(
                connectionIp,
                context.Request.Headers[ClientIpResolver.ForwardedForHeader],
                trustedProxies);

            if (resolution.IgnoredInvalidEntry)
            {
                LogInvalidEntry(logger, resolution.ConnectionIp);
            }

            context.Features.Set<IClientIpFeature>(new ClientIpFeature(resolution.ClientIp, resolution.ConnectionIp, resolution.ViaTrustedProxy));
            context.Connection.RemoteIpAddress = resolution.ClientIp;
        }

        return next(context);
    }

    [LoggerMessage(EventId = 100, Level = LogLevel.Debug, Message = "Trusted proxy {ProxyIp} sent an invalid X-Forwarded-For entry; using the last valid address.")]
    private static partial void LogInvalidEntry(ILogger logger, IPAddress proxyIp);

    private sealed record ClientIpFeature(IPAddress ClientIp, IPAddress ConnectionIp, bool ViaTrustedProxy) : IClientIpFeature;
}

/// <summary>Pipeline registration for <see cref="ClientIpMiddleware"/>.</summary>
public static class ClientIpApplicationBuilderExtensions
{
    /// <summary>Resolves the client IP. Requires a <see cref="TrustedProxies"/> service.</summary>
    public static IApplicationBuilder UseClientIpResolution(this IApplicationBuilder app) =>
        app.UseMiddleware<ClientIpMiddleware>();
}
