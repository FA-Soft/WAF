using System.Globalization;
using System.Net;

namespace Waf.Core.Net;

/// <summary>Result of resolving the client IP of a request.</summary>
/// <param name="ClientIp">The client IP to use for rules, rate limiting and logging.</param>
/// <param name="ConnectionIp">The IP of the TCP connection (the peer the gateway talks to).</param>
/// <param name="ViaTrustedProxy">True when the client IP was taken from X-Forwarded-For.</param>
/// <param name="IgnoredInvalidEntry">True when an unparseable X-Forwarded-For entry stopped resolution.</param>
public sealed record ClientIpResolution(IPAddress ClientIp, IPAddress ConnectionIp, bool ViaTrustedProxy, bool IgnoredInvalidEntry);

/// <summary>
/// Determines the real client IP from the connection IP and X-Forwarded-For, trusting the header only
/// as far as it was written by trusted proxies.
/// </summary>
/// <remarks>
/// <para>
/// Each proxy appends the address it received the request from, so the header reads
/// <c>client, proxy1, proxy2</c> and the connection comes from the last proxy. Resolution starts at the
/// connection IP and walks the header from right to left while the current hop is a trusted proxy.
/// The first address that is not a trusted proxy is the client. Entries further left were written by that
/// client (or by untrusted parties) and are ignored, so they cannot be spoofed.
/// </para>
/// <para>
/// If the connection does not come from a trusted proxy, the header is ignored entirely. An entry that
/// is not a valid IP address (e.g. <c>unknown</c>) stops the walk at the last trustworthy address.
/// </para>
/// </remarks>
public static class ClientIpResolver
{
    /// <summary>The standard header name.</summary>
    public const string ForwardedForHeader = "X-Forwarded-For";

    /// <summary>Upper bound on the number of header entries examined.</summary>
    public const int MaxEntries = 32;

    public static ClientIpResolution Resolve(IPAddress connectionIp, IEnumerable<string?> forwardedForValues, TrustedProxies trustedProxies)
    {
        ArgumentNullException.ThrowIfNull(connectionIp);
        ArgumentNullException.ThrowIfNull(forwardedForValues);
        ArgumentNullException.ThrowIfNull(trustedProxies);

        var connection = Normalize(connectionIp);
        if (trustedProxies.Count == 0 || !trustedProxies.Contains(connection))
        {
            return new ClientIpResolution(connection, connection, ViaTrustedProxy: false, IgnoredInvalidEntry: false);
        }

        var entries = SplitEntries(forwardedForValues);
        var current = connection;
        var viaProxy = false;

        for (var i = entries.Count - 1; i >= 0 && i >= entries.Count - MaxEntries; i--)
        {
            if (!TryParseEntry(entries[i], out var hop))
            {
                return new ClientIpResolution(current, connection, viaProxy, IgnoredInvalidEntry: true);
            }

            current = hop;
            viaProxy = true;

            if (!trustedProxies.Contains(current))
            {
                break;
            }
        }

        return new ClientIpResolution(current, connection, viaProxy, IgnoredInvalidEntry: false);
    }

    /// <summary>Maps IPv4-mapped IPv6 addresses (<c>::ffff:10.0.0.1</c>) to IPv4 and drops IPv6 scope ids.</summary>
    public static IPAddress Normalize(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
        {
            return new IPAddress(address.GetAddressBytes());
        }

        return address;
    }

    /// <summary>
    /// Parses one header entry: an IP address, optionally with a port (<c>203.0.113.7:4711</c>,
    /// <c>[2001:db8::1]:443</c>) or in brackets (<c>[2001:db8::1]</c>).
    /// </summary>
    public static bool TryParseEntry(string? entry, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrEmpty(entry))
        {
            return false;
        }

        var text = entry;
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 0 || !IsOptionalPort(text[(close + 1)..]))
            {
                return false;
            }

            text = text[1..close];
        }
        else if (text.Count(c => c == ':') == 1)
        {
            var colon = text.IndexOf(':', StringComparison.Ordinal);
            if (!IsOptionalPort(text[colon..]))
            {
                return false;
            }

            text = text[..colon];
        }

        if (!StrictIpAddress.TryParse(text, out var parsed))
        {
            return false;
        }

        address = Normalize(parsed);
        return true;
    }

    private static bool IsOptionalPort(string text) =>
        text.Length == 0
        || (text[0] == ':' && text.Length is > 1 and <= 6
            && text[1..].All(char.IsAsciiDigit)
            && int.Parse(text[1..], CultureInfo.InvariantCulture) <= 65535);

    private static List<string> SplitEntries(IEnumerable<string?> values)
    {
        var entries = new List<string>();
        foreach (var value in values)
        {
            if (value is null)
            {
                continue;
            }

            foreach (var part in value.Split(','))
            {
                entries.Add(part.Trim());
            }
        }

        return entries;
    }
}
