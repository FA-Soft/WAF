using System.Globalization;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Connections;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Turns listener bind failures into actionable messages (port in use, permission denied).
/// </summary>
internal static partial class StartupErrorReporter
{
    public static bool TryDescribe(Exception exception, bool isWindows, out string message)
    {
        var port = FindPort(exception);

        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is AddressInUseException
                || current is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse })
            {
                message = $"Port {port} is already in use. " + (isWindows
                    ? "On Windows this is often IIS or another HTTP.sys user, which can reserve the port on all addresses. "
                      + $"Find the owner with 'netsh http show servicestate' or 'Get-NetTCPConnection -LocalPort {port} -State Listen', "
                      + "then move that site to another port and add it as a route (see README, Ports)."
                    : $"Find the owner with 'sudo ss -ltnp \"sport = :{port}\"' and stop it or move it to another port.");
                return true;
            }

            if (current is SocketException { SocketErrorCode: SocketError.AccessDenied })
            {
                message = $"Permission denied when binding port {port}. " + (isWindows
                    ? $"The port may be in an excluded range; check 'netsh int ipv4 show excludedportrange protocol=tcp'."
                    : "Ports below 1024 need root or CAP_NET_BIND_SERVICE; the systemd unit grants this capability.");
                return true;
            }
        }

        message = string.Empty;
        return false;
    }

    private static string FindPort(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var match = PortPattern().Match(current.Message);
            if (match.Success)
            {
                return int.Parse(match.Groups["port"].Value, CultureInfo.InvariantCulture)
                    .ToString(CultureInfo.InvariantCulture);
            }
        }

        return "(unknown)";
    }

    // Kestrel reports e.g. "Failed to bind to address http://[::]:80: address already in use."
    [GeneratedRegex(@"://[^\s/]*:(?<port>\d{1,5})")]
    private static partial Regex PortPattern();
}
