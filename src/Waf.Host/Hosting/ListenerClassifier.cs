using System.Net;
using Microsoft.Extensions.Options;
using Waf.Core.Hosting;

namespace Waf.Host.Hosting;

/// <summary>
/// Decides whether a request arrived on the loopback admin listener or on a public listener.
/// </summary>
/// <remarks>
/// Uses the connection's local endpoint, never the Host header, so it cannot be spoofed by clients.
/// </remarks>
internal sealed class ListenerClassifier(IOptions<GatewayEndpointOptions> options)
{
    private readonly int _adminPort = options.Value.AdminPort;

    public bool IsAdminListener(HttpContext context)
    {
        var connection = context.Connection;
        return connection.LocalPort == _adminPort
            && connection.LocalIpAddress is { } local
            && IPAddress.IsLoopback(local);
    }
}
