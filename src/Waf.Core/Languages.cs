using System.Globalization;

namespace FASoft.Waf.Core;

/// <summary>
/// The languages of the gateway's texts (the admin UI, and the answers visitors get from the gateway itself): English,
/// Dutch, French and German. English is the default and the fallback.
/// </summary>
public static class Languages
{
    public const string English = "en";

    /// <summary>The supported languages (two-letter codes), English first.</summary>
    public static IReadOnlyList<string> Supported { get; } = [English, "nl", "fr", "de"];

    /// <summary>The languages other than English, which have translations.</summary>
    public static IReadOnlyList<string> Translated { get; } = ["nl", "fr", "de"];

    public static bool IsSupported(string? code) => code is not null && Supported.Contains(code, StringComparer.Ordinal);

    /// <summary>
    /// The first supported language of an <c>Accept-Language</c> header, in order of preference (quality, then
    /// position): <c>nl-BE</c> gives <c>nl</c>. Null when none is supported (or the header is missing or invalid).
    /// </summary>
    public static string? Match(string? acceptLanguage)
    {
        if (string.IsNullOrWhiteSpace(acceptLanguage))
        {
            return null;
        }

        var choices = new List<(string Language, double Quality, int Position)>();
        var position = 0;
        foreach (var part in acceptLanguage.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var pieces = part.Split(';', StringSplitOptions.TrimEntries);
            var tag = pieces[0];
            if (tag.Length == 0 || tag == "*" || !tag.All(c => char.IsAsciiLetter(c) || c == '-'))
            {
                position++;
                continue;
            }

            var quality = 1.0;
            foreach (var parameter in pieces.Skip(1))
            {
                if (parameter.StartsWith("q=", StringComparison.OrdinalIgnoreCase)
                    && !double.TryParse(parameter[2..], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out quality))
                {
                    quality = 0; // an invalid quality: ignore the language
                }
            }

            choices.Add((tag.Split('-', 2)[0].ToLowerInvariant(), quality, position++));
        }

        return choices
            .Where(c => c.Quality > 0)
            .OrderByDescending(c => c.Quality)
            .ThenBy(c => c.Position)
            .Select(c => c.Language)
            .FirstOrDefault(IsSupported);
    }

    /// <summary>The language for an <c>Accept-Language</c> header: the first supported one, else English.</summary>
    public static string For(string? acceptLanguage) => Match(acceptLanguage) ?? English;
}
