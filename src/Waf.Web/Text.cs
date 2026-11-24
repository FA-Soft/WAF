using System.Globalization;
using System.Net;
using System.Resources;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;

namespace FASoft.Waf.Web;

/// <summary>
/// The admin UI's texts in the language of the request (<see cref="CultureInfo.CurrentUICulture"/>, set by
/// <see cref="AdminLanguage"/>). The key is the English text, which is also the fallback; the translations are in
/// <c>Resources/SharedResource.{nl,fr,de}.resx</c>. Values go in placeholders (<c>{0}</c>), never in concatenated
/// pieces, so each language can order its words.
/// </summary>
/// <remarks>
/// Razor files use these through <c>@using static FASoft.Waf.Web.Text</c>: <c>@T("Routes")</c>. A test finds every
/// literal key in the source (<c>T</c>, <c>TM</c>, <c>N</c>, <c>Plural</c>) and checks it is translated.
/// </remarks>
public static partial class Text
{
    private static readonly ResourceManager Resources = new("FASoft.Waf.Web.Resources.SharedResource", typeof(Text).Assembly);

    /// <summary>The text in the current language.</summary>
    public static string T(string english)
    {
        ArgumentNullException.ThrowIfNull(english);
        return Lookup(english) ?? english;
    }

    /// <summary>The text in the current language, with <paramref name="args"/> in its placeholders.</summary>
    public static string T(string english, params object?[] args) =>
        string.Format(CultureInfo.CurrentCulture, T(english), args);

    /// <summary>
    /// A text with markup (<c>&lt;strong&gt;</c>, <c>&lt;em&gt;</c>, <c>&lt;code&gt;</c>, links) in the current
    /// language. The translations are trusted; the values are HTML-encoded.
    /// </summary>
    public static MarkupString TM(string english, params object?[] args) =>
        new(string.Format(CultureInfo.CurrentCulture, T(english), [.. args.Select(a => WebUtility.HtmlEncode(Convert.ToString(a, CultureInfo.CurrentCulture)))]));

    /// <summary>Marks a text that is translated later, where it is shown (with <see cref="T(string)"/>), e.g. in a list of templates.</summary>
    public static string N(string english) => english;

    /// <summary>
    /// A message in English with <paramref name="args"/> in its placeholders, translated later where it is shown (with
    /// <see cref="Message"/>, which finds this template again), e.g. an error passed on to a page.
    /// </summary>
    public static string F(string english, params object?[] args) => string.Format(CultureInfo.InvariantCulture, english, args);

    /// <summary>
    /// "1 rule" or "3 rules": <paramref name="one"/> or <paramref name="other"/>, each with <c>{0}</c> for the count.
    /// French uses the singular for 0 too.
    /// </summary>
    public static string Plural(long count, string one, string other) => Plural(count, one, other, []);

    /// <summary>As <see cref="Plural(long, string, string)"/>, with more values in <c>{1}</c>, <c>{2}</c>, …</summary>
    public static string Plural(long count, string one, string other, params object?[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var singular = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "fr" ? count is 0 or 1 : count == 1;
        return T(singular ? one : other, [count.ToString("N0", CultureInfo.CurrentCulture), .. args]);
    }

    /// <summary>
    /// A message made elsewhere in English (e.g. a validation error of the configuration), in the current language: the
    /// whole message when it is a key; else the first resource template that matches it, with the values it holds
    /// translated too; else "prefix: rest" translated part by part. Unknown messages stay English.
    /// </summary>
    public static string Message(string? message)
    {
        if (string.IsNullOrEmpty(message) || CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "en")
        {
            return message ?? string.Empty;
        }

        if (Lookup(message) is { } exact)
        {
            return exact;
        }

        foreach (var (template, pattern) in Templates.Value)
        {
            var match = pattern.Match(message);
            if (match.Success)
            {
                var values = match.Groups.Cast<Group>().Skip(1).OrderBy(g => g.Name, StringComparer.Ordinal).Select(g => (object?)Message(g.Value)).ToArray();
                return string.Format(CultureInfo.CurrentCulture, T(template), values);
            }
        }

        var colon = message.IndexOf(": ", StringComparison.Ordinal);
        return colon > 0 ? $"{Message(message[..colon])}: {Message(message[(colon + 2)..])}" : message;
    }

    private static string? Lookup(string english)
    {
        var culture = CultureInfo.CurrentUICulture;
        return culture.TwoLetterISOLanguageName == "en" ? null : Resources.GetString(english, culture);
    }

    /// <summary>The keys with placeholders as patterns, longest literal text first (the most specific wins).</summary>
    private static readonly Lazy<IReadOnlyList<(string Template, Regex Pattern)>> Templates = new(() =>
    {
        var set = Resources.GetResourceSet(CultureInfo.InvariantCulture, createIfNotExists: true, tryParents: false);
        var keys = set is null ? [] : set.Cast<System.Collections.DictionaryEntry>().Select(e => (string)e.Key).ToList();
        return [.. keys
            .Where(k => PlaceholderPattern().IsMatch(k))
            .Select(k => (Key: k, Literal: PlaceholderPattern().Replace(k, string.Empty)))
            .Where(k => k.Literal.Trim().Length >= 4) // "{0}: {1}" alone would match anything
            .OrderByDescending(k => k.Literal.Length)
            .Select(k => (k.Key, new Regex(
                "^" + PlaceholderPattern().Replace(Regex.Escape(k.Key).Replace(@"\{", "{", StringComparison.Ordinal), m => $"(?<a{m.Groups[1].Value.PadLeft(2, '0')}>.+?)") + "$",
                RegexOptions.CultureInvariant | RegexOptions.Singleline, TimeSpan.FromMilliseconds(50))))];
    });

    [GeneratedRegex(@"\{(\d+)\}")]
    private static partial Regex PlaceholderPattern();
}
