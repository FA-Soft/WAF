using System.Net;

namespace FASoft.Waf.Core.Net;

/// <summary>
/// The set of proxies (IP addresses or CIDR ranges) allowed to report the client IP via X-Forwarded-For.
/// </summary>
public sealed class TrustedProxies
{
    private readonly IPNetwork[] _networks;

    private TrustedProxies(IPNetwork[] networks) => _networks = networks;

    /// <summary>No trusted proxies: the connection IP is always the client IP.</summary>
    public static TrustedProxies None { get; } = new([]);

    public int Count => _networks.Length;

    /// <summary>Builds the set from configuration values, which must be valid (see <see cref="StrictCidr"/>).</summary>
    /// <exception cref="ArgumentException">An entry is not a valid IP address or CIDR range.</exception>
    public static TrustedProxies Parse(IEnumerable<string> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var networks = new List<IPNetwork>();
        foreach (var entry in entries)
        {
            if (!StrictCidr.TryParse(entry, out var network, out var error))
            {
                throw new ArgumentException($"Trusted proxy '{entry}': {error}.", nameof(entries));
            }

            networks.Add(network);
        }

        return networks.Count == 0 ? None : new TrustedProxies([.. networks]);
    }

    /// <summary>True when <paramref name="address"/> is a trusted proxy. IPv4-mapped IPv6 addresses are matched as IPv4.</summary>
    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var normalized = ClientIpResolver.Normalize(address);
        foreach (var network in _networks)
        {
            if (network.Contains(normalized))
            {
                return true;
            }
        }

        return false;
    }
}
