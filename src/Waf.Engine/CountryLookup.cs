using System.Globalization;
using System.Net;
using System.Numerics;

namespace FASoft.Waf.Engine;

/// <summary>
/// The country of a client IP, from an offline IP range file that the admin supplies; no address ever leaves the
/// gateway. Reads CSV files with one range per line: start, end and a two-letter country code, as for example DB-IP
/// "IP to Country Lite" (<c>1.0.0.0,1.0.0.255,AU</c>) and IP2Location LITE DB1 (<c>"16777216","16777471","AU","Australia"</c>,
/// addresses as numbers) publish them. Both IPv4 and IPv6 ranges are read.
/// </summary>
/// <remarks>
/// The ranges are kept in sorted arrays (IPv4 as IPv4-mapped IPv6 numbers) and looked up by binary search: a few
/// hundred nanoseconds per address. A file of the size DB-IP publishes (about 600,000 ranges) takes about 20 MB.
/// </remarks>
public sealed class CountryLookup
{
    private readonly UInt128[] _starts;
    private readonly UInt128[] _ends;
    private readonly string[] _countries;

    private CountryLookup(UInt128[] starts, UInt128[] ends, string[] countries, string source)
    {
        _starts = starts;
        _ends = ends;
        _countries = countries;
        Source = source;
    }

    /// <summary>The file the ranges were read from (its name), for the attribution on the page.</summary>
    public string Source { get; }

    /// <summary>Number of ranges.</summary>
    public int Count => _starts.Length;

    /// <summary>The two-letter country code (upper case) of <paramref name="clientIp"/>; null when it is in no range.</summary>
    public string? Find(string? clientIp) =>
        IPAddress.TryParse(clientIp, out var address) ? Find(address) : null;

    public string? Find(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var value = ToNumber(address);
        var index = Array.BinarySearch(_starts, value);
        if (index < 0)
        {
            index = ~index - 1; // the last range that starts before it
        }

        return index >= 0 && value <= _ends[index] ? _countries[index] : null;
    }

    /// <summary>Reads a range file; lines that cannot be read (a header, comments) are skipped.</summary>
    public static CountryLookup Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var ranges = new List<(UInt128 Start, UInt128 End, string Country)>();
        var codes = new Dictionary<string, string>(StringComparer.Ordinal); // one string per country
        foreach (var line in File.ReadLines(path))
        {
            if (TryParseLine(line, out var start, out var end, out var country))
            {
                if (!codes.TryGetValue(country, out var code))
                {
                    codes[country] = code = country;
                }

                ranges.Add((start, end, code));
            }
        }

        ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        return new CountryLookup(
            [.. ranges.Select(r => r.Start)],
            [.. ranges.Select(r => r.End)],
            [.. ranges.Select(r => r.Country)],
            Path.GetFileName(path));
    }

    /// <summary>One CSV line: start, end, country code (further columns ignored).</summary>
    internal static bool TryParseLine(string line, out UInt128 start, out UInt128 end, out string country)
    {
        start = end = UInt128.Zero;
        country = string.Empty;
        if (string.IsNullOrWhiteSpace(line) || line[0] == '#')
        {
            return false;
        }

        var parts = line.Split(',');
        if (parts.Length < 3)
        {
            return false;
        }

        var code = Unquote(parts[2]).ToUpperInvariant();
        if (code.Length != 2 || !char.IsAsciiLetterUpper(code[0]) || !char.IsAsciiLetterUpper(code[1]) || code == "ZZ")
        {
            return false; // "-" or "ZZ": no country
        }

        if (!TryParseAddress(Unquote(parts[0]), out start) || !TryParseAddress(Unquote(parts[1]), out end) || end < start)
        {
            return false;
        }

        country = code;
        return true;
    }

    private static string Unquote(string text) => text.Trim().Trim('"');

    /// <summary>An address as text, or as a number (IPv4 below 2^32, as IP2Location writes them; larger numbers are IPv6).</summary>
    private static bool TryParseAddress(string text, out UInt128 value)
    {
        if (IPAddress.TryParse(text, out var address))
        {
            value = ToNumber(address);
            return true;
        }

        if (BigInteger.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number >= 0 && number <= (BigInteger)UInt128.MaxValue)
        {
            value = number <= uint.MaxValue ? MappedPrefix | (UInt128)(uint)number : (UInt128)number;
            return true;
        }

        value = UInt128.Zero;
        return false;
    }

    /// <summary>::ffff:0:0, the prefix of IPv4-mapped IPv6 addresses.</summary>
    private static readonly UInt128 MappedPrefix = (UInt128)0xFFFF << 32;

    private static UInt128 ToNumber(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            address = address.MapToIPv6();
        }

        var bytes = address.GetAddressBytes();
        UInt128 value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return value;
    }
}
