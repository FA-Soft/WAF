using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using FASoft.Waf.Core.Hosting;
using FASoft.Waf.Core.Tls;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Configures the Kestrel listeners: public HTTP/HTTPS and the loopback-only admin listener.
/// </summary>
internal static class KestrelListeners
{
    public static void Configure(KestrelServerOptions kestrel, GatewayEndpointOptions endpoints)
    {
        // The real server header gives attackers free fingerprinting.
        kestrel.AddServerHeader = false;

        ListenPublic(kestrel, endpoints.PublicBindAddress, endpoints.HttpPort, _ => { });

        ListenPublic(kestrel, endpoints.PublicBindAddress, endpoints.HttpsPort, listen =>
            listen.UseHttps(new HttpsConnectionAdapterOptions
            {
                // Certificates are resolved per SNI host name at handshake time. Without a matching
                // certificate the handshake is rejected instead of serving a wrong or default certificate.
                ServerCertificateSelector = (_, hostName) =>
                    listen.ApplicationServices.GetRequiredService<IServerCertificateSelector>().SelectCertificate(hostName),
            }));

        // Admin UI: loopback only, never all interfaces. Not configurable on purpose.
        kestrel.Listen(IPAddress.Loopback, endpoints.AdminPort);
        if (System.Net.Sockets.Socket.OSSupportsIPv6)
        {
            kestrel.Listen(IPAddress.IPv6Loopback, endpoints.AdminPort);
        }
    }

    private static void ListenPublic(
        KestrelServerOptions kestrel, string bindAddress, int port, Action<ListenOptions> configure)
    {
        if (bindAddress == "*")
        {
            // Binds IPv6Any (dual-mode) and falls back to IPv4 Any when IPv6 is unavailable.
            kestrel.ListenAnyIP(port, configure);
        }
        else
        {
            kestrel.Listen(IPAddress.Parse(bindAddress), port, configure);
        }
    }
}
