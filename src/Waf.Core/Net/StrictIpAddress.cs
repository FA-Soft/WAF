using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Waf.Core.Net;

/// <summary>
/// Strict IP address parsing for configuration input.
/// </summary>
/// <remarks>
/// <see cref="IPAddress.TryParse(string?, out IPAddress?)"/> accepts legacy IPv4 shorthand such as
/// <c>10</c> (0.0.0.10), <c>1.2</c> (1.0.0.2) or <c>0x0A000001</c>, which hides typos. This parser accepts:
/// <list type="bullet">
/// <item>IPv4 only in dotted-decimal form: four parts of 0–255, no leading zeros, no signs or spaces.</item>
/// <item>IPv6 in standard notation (including embedded IPv4 and a zone index), without brackets.</item>
/// </list>
/// </remarks>
public static class StrictIpAddress
{
    public static bool TryParse(string? text, [NotNullWhen(true)] out IPAddress? address)
    {
        address = null;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (text.Contains(':', StringComparison.Ordinal))
        {
            return !text.Contains('[', StringComparison.Ordinal)
                && IPAddress.TryParse(text, out address)
                && address.AddressFamily == AddressFamily.InterNetworkV6;
        }

        return IsDottedDecimal(text) && IPAddress.TryParse(text, out address);
    }

    private static bool IsDottedDecimal(string text)
    {
        var parts = text.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3
                || !part.All(char.IsAsciiDigit)
                || (part.Length > 1 && part[0] == '0')
                || int.Parse(part, System.Globalization.CultureInfo.InvariantCulture) > 255)
            {
                return false;
            }
        }

        return true;
    }
}
