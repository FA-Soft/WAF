using System.Globalization;
using System.Net;
using System.Text;

namespace Waf.Engine.Detection;

/// <summary>
/// Turns a raw request value into a canonical form for attack matching, undoing the encodings attackers
/// use to slip payloads past filters.
/// </summary>
/// <remarks>
/// Steps, in order:
/// <list type="number">
/// <item>Percent-decoding, repeated up to <see cref="MaxDecodePasses"/> times (catches double encoding
/// such as <c>%253C</c>), including IIS-style <c>%uXXXX</c>; optionally <c>+</c> as space (query strings).</item>
/// <item>HTML entity decoding (<c>&amp;lt;</c>, <c>&amp;#x3c;</c>, <c>&amp;#60;</c>), also repeated.</item>
/// <item>Unicode compatibility folding (NFKC): full-width <c>＜</c> becomes <c>&lt;</c>.</item>
/// <item>Control characters become spaces (null bytes are kept, as an attack signal); <c>\</c> becomes <c>/</c>.</item>
/// <item>SQL block comments (<c>/**/</c>) become a space, so <c>UNION/**/SELECT</c> reads as <c>union select</c>.</item>
/// <item>Whitespace runs collapse to one space; everything is lower-cased (invariant).</item>
/// </list>
/// The result is only used for matching; the request itself is never changed.
/// </remarks>
public static class InputNormalizer
{
    /// <summary>How many times percent/HTML decoding is repeated at most.</summary>
    public const int MaxDecodePasses = 3;

    public static string Normalize(string? value, bool plusIsSpace = false)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (IsAlreadyCanonical(value, plusIsSpace))
        {
            return value; // common case: nothing to decode or fold, no allocation
        }

        var text = value;

        if (plusIsSpace && text.Contains('+', StringComparison.Ordinal))
        {
            text = text.Replace('+', ' ');
        }

        for (var pass = 0; pass < MaxDecodePasses; pass++)
        {
            var decoded = text;
            if (decoded.Contains('%', StringComparison.Ordinal))
            {
                decoded = PercentDecode(decoded);
            }

            if (decoded.Contains('&', StringComparison.Ordinal))
            {
                decoded = WebUtility.HtmlDecode(decoded);
            }

            if (decoded == text)
            {
                break;
            }

            text = decoded;
        }

        if (!Ascii.IsValid(text))
        {
            text = text.Normalize(NormalizationForm.FormKC);
        }

        return Canonicalize(text);
    }

    /// <summary>
    /// Lenient percent-decoding: valid <c>%XX</c> sequences are decoded as UTF-8 bytes, <c>%uXXXX</c> as a
    /// UTF-16 unit, and anything malformed is kept as is.
    /// </summary>
    internal static string PercentDecode(string text)
    {
        var builder = new StringBuilder(text.Length);
        var bytes = new List<byte>();

        void FlushBytes()
        {
            if (bytes.Count > 0)
            {
                builder.Append(Encoding.UTF8.GetString([.. bytes]));
                bytes.Clear();
            }
        }

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '%')
            {
                if (i + 2 < text.Length
                    && byte.TryParse(text.AsSpan(i + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var b))
                {
                    bytes.Add(b);
                    i += 2;
                    continue;
                }

                if (i + 5 < text.Length && (text[i + 1] == 'u' || text[i + 1] == 'U')
                    && ushort.TryParse(text.AsSpan(i + 2, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var unit))
                {
                    FlushBytes();
                    builder.Append((char)unit);
                    i += 5;
                    continue;
                }
            }

            FlushBytes();
            builder.Append(c);
        }

        FlushBytes();
        return builder.ToString();
    }

    /// <summary>
    /// True when normalization would return the value unchanged: printable ASCII without upper case,
    /// encoding characters (%, &amp;, \, + for query values), comment openers or whitespace runs.
    /// </summary>
    private static bool IsAlreadyCanonical(string value, bool plusIsSpace)
    {
        var previous = '\0';
        foreach (var c in value)
        {
            if (c is < ' ' or > '~' or (>= 'A' and <= 'Z') or '%' or '&' or '\\'
                || (c == '+' && plusIsSpace)
                || (c == '*' && previous == '/')
                || (c == ' ' && previous == ' '))
            {
                return false;
            }

            previous = c;
        }

        return true;
    }

    private static string Canonicalize(string text)
    {
        var builder = new StringBuilder(text.Length);
        var lastWasSpace = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];

            // SQL block comment: /* ... */ (unterminated: to the end).
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? text.Length : end + 1;
                c = ' ';
            }

            // Null bytes are kept: they are an attack signal themselves (file.php%00.jpg).
            if (c == '\0')
            {
                builder.Append(c);
                lastWasSpace = false;
                continue;
            }

            if (char.IsWhiteSpace(c) || char.IsControl(c))
            {
                if (!lastWasSpace)
                {
                    builder.Append(' ');
                    lastWasSpace = true;
                }

                continue;
            }

            lastWasSpace = false;
            builder.Append(c == '\\' ? '/' : char.ToLowerInvariant(c));
        }

        return builder.ToString();
    }
}
