using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace FASoft.Waf.Core.Net;

/// <summary>
/// Strict parsing of an IP address range in CIDR notation (<c>10.0.0.0/8</c>, <c>fd00::/8</c>) or a
/// single address (<c>10.0.0.5</c>, treated as /32 or /128).
/// </summary>
/// <remarks>
/// The address part uses <see cref="StrictIpAddress"/>. Host bits must be zero:
/// <c>10.0.0.5/8</c> is rejected because it most likely means <c>10.0.0.0/8</c> or <c>10.0.0.5/32</c>.
/// </remarks>
public static class StrictCidr
{
    public static bool TryParse(string? text, out IPNetwork network) => TryParse(text, out network, out _);

    /// <summary>Parses <paramref name="text"/>; on failure <paramref name="error"/> explains why.</summary>
    public static bool TryParse(string? text, out IPNetwork network, out string error)
    {
        network = default;

        if (string.IsNullOrEmpty(text))
        {
            error = "an address or range is required";
            return false;
        }

        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? text : text[..slash];

        if (!StrictIpAddress.TryParse(addressText, out var address))
        {
            error = $"'{addressText}' is not a valid IP address";
            return false;
        }

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefixLength = maxPrefix;

        if (slash >= 0)
        {
            var prefixText = text[(slash + 1)..];
            if (prefixText.Length is 0 or > 3
                || !prefixText.All(char.IsAsciiDigit)
                || (prefixText.Length > 1 && prefixText[0] == '0')
                || (prefixLength = int.Parse(prefixText, CultureInfo.InvariantCulture)) > maxPrefix)
            {
                error = $"the prefix length must be a number from 0 to {maxPrefix}";
                return false;
            }
        }

        var candidate = new IPNetwork(Mask(address, prefixLength), prefixLength);
        if (!candidate.BaseAddress.Equals(address))
        {
            error = $"host bits are set (did you mean {candidate} or {address}/{maxPrefix}?)";
            return false;
        }

        network = candidate;
        error = string.Empty;
        return true;
    }

    private static IPAddress Mask(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitsInByte = Math.Clamp(prefixLength - (i * 8), 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - bitsInByte));
        }

        return new IPAddress(bytes);
    }
}
