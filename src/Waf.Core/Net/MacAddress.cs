namespace FASoft.Waf.Core.Net;

/// <summary>MAC addresses (48-bit), written as <c>aa:bb:cc:dd:ee:ff</c>.</summary>
public static class MacAddress
{
    /// <summary>
    /// Reads a MAC address in the usual notations: <c>AA:BB:CC:DD:EE:FF</c>, <c>aa-bb-cc-dd-ee-ff</c> (Windows),
    /// <c>aabb.ccdd.eeff</c> (Cisco) or <c>aabbccddeeff</c>, and returns it as <c>aa:bb:cc:dd:ee:ff</c>. All zeros and
    /// broadcast (all ff) are refused: they never name a device.
    /// </summary>
    public static bool TryNormalize(string? text, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        string hex;
        if (value.Length == 17 && (value.Count(c => c == ':') == 5 || value.Count(c => c == '-') == 5))
        {
            var separator = value[2];
            if (separator is not (':' or '-') || Enumerable.Range(1, 5).Any(i => value[(i * 3) - 1] != separator))
            {
                return false;
            }

            hex = value.Replace(separator.ToString(), string.Empty, StringComparison.Ordinal);
        }
        else if (value.Length == 14 && value[4] == '.' && value[9] == '.')
        {
            hex = value.Replace(".", string.Empty, StringComparison.Ordinal);
        }
        else
        {
            hex = value;
        }

        if (hex.Length != 12 || !hex.All(char.IsAsciiHexDigit))
        {
            return false;
        }

        hex = hex.ToLowerInvariant();
        if (hex == "000000000000" || hex == "ffffffffffff")
        {
            return false;
        }

        normalized = string.Join(':', Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
        return true;
    }

    /// <summary><c>aa:bb:cc:dd:ee:ff</c> from raw bytes (6 bytes); null for anything else, all zeros or broadcast.</summary>
    public static string? FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 6)
        {
            return null;
        }

        // Through TryNormalize, so all-zero and broadcast are refused here too.
        return TryNormalize(Convert.ToHexString(bytes), out var mac) ? mac : null;
    }
}
