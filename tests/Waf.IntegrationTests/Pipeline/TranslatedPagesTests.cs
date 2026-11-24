using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// The whole admin UI in German: every page (and the sign-in page) is rendered for a German browser and must not
/// contain English text. Names (HTTPS, Let's Encrypt, product names) and data the user entered are not English text.
/// </summary>
public sealed partial class TranslatedPagesTests(AdminUiFixture gateway) : IClassFixture<AdminUiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>English words that German, Dutch or French UI text never uses on its own.</summary>
    private static readonly string[] EnglishWords =
    [
        "the", "and", "with", "your", "this", "that", "from", "which", "when", "should", "would", "there", "their",
        "been", "have", "has", "into", "only", "than", "then", "these", "those", "what", "where", "while", "you", "are",
        "not", "for", "our", "can", "cannot", "does", "must", "each", "every", "after", "before", "here", "yet", "any",
        "add", "save", "delete", "edit", "remove", "enabled", "disabled", "request", "requests", "rule", "rules", "page",
    ];

    /// <summary>Names and fixed technical phrases that stay as they are in every language.</summary>
    private static readonly string[] Names =
    [
        "Let's Encrypt", "Too Many Requests", "Microsoft Authenticator", "Google Authenticator", "Anthropic Console",
        "No admin account exists yet", "HTTP Strict Transport Security", "Cross-Site-Scripting", "WAF Gateway",
    ];

    /// <summary>Every routable page of the admin UI, with its route parameters filled in.</summary>
    private static List<string> Pages() =>
        [.. typeof(AdminIdentity).Assembly.GetTypes()
            .Where(type => type.GetCustomAttribute<Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute>() is null)
            .SelectMany(type => type.GetCustomAttributes<RouteAttribute>().Select(route => RouteParameterPattern().Replace(route.Template, "1")))
            .Order(StringComparer.Ordinal)];

    /// <summary>The text a person reads: element text and the titles, labels and placeholders of elements.</summary>
    private static string VisibleText(string html)
    {
        html = DropPattern().Replace(html, " ");
        var attributes = string.Join(' ', AttributePattern().Matches(html).Select(m => m.Groups["text"].Value));
        return WebUtility.HtmlDecode(TagPattern().Replace(html, " ") + " " + attributes);
    }

    private static IEnumerable<string> EnglishIn(string text)
    {
        foreach (var name in Names)
        {
            text = text.Replace(name, " ", StringComparison.Ordinal);
        }

        // Each English word with the text around it, so the message shows where it is.
        return WordPattern().Matches(text)
            .Where(m => EnglishWords.Contains(m.Value, StringComparer.Ordinal))
            .Select(m =>
            {
                var start = Math.Max(0, m.Index - 50);
                return WhitespacePattern().Replace(text.Substring(start, Math.Min(110, text.Length - start)), " ").Trim();
            })
            .Distinct();
    }

    [Fact]
    public async Task No_page_of_the_admin_ui_has_english_text_for_a_german_browser()
    {
        using var browser = new HttpClient(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(15) };
        browser.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "de-DE,de;q=0.9");

        // The sign-in page first, before signing in.
        var problems = new List<string>();
        var login = await browser.GetStringAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}{AdminIdentity.LoginPath}"), Ct);
        problems.AddRange(EnglishIn(VisibleText(login)).Select(e => $"{AdminIdentity.LoginPath}: {e}"));

        await gateway.SignInAsync(browser);
        var pages = Pages();
        Assert.True(pages.Count > 30, $"Only {pages.Count} pages found.");
        foreach (var path in pages)
        {
            using var response = await browser.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}{path}"), Ct);
            var html = await response.Content.ReadAsStringAsync(Ct);
            if (html.Length == 0)
            {
                continue; // a page that only sends you elsewhere (e.g. the preset "1" does not exist): nothing to read
            }

            Assert.True(html.Contains("<html lang=\"de\"", StringComparison.Ordinal), $"{path} is not in German.");
            problems.AddRange(EnglishIn(VisibleText(html)).Select(e => $"{path}: {e}"));
        }

        Assert.True(problems.Count == 0, $"English text on {problems.Count} places:\n" + string.Join("\n", problems));
    }

    // Scripts, styles, code samples, and data the user typed or the configuration holds (pre, code, textarea, the JSON of a change).
    [GeneratedRegex("""<(script|style|code|pre|textarea|kbd)\b.*?</\1>|<input[^>]*>""", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex DropPattern();

    [GeneratedRegex("""\s(?:title|aria-label|placeholder|alt)="(?<text>[^"]*)""")]
    private static partial Regex AttributePattern();

    [GeneratedRegex("""<[^>]*>""")]
    private static partial Regex TagPattern();

    // A word on its own: not part of an example such as office-only, q=shoes&page=2 or a host name.
    [GeneratedRegex("""(?<![\w\-=&./])[a-z]+(?![\w\-=./])""")]
    private static partial Regex WordPattern();

    [GeneratedRegex("""\s+""")]
    private static partial Regex WhitespacePattern();

    [GeneratedRegex("""\{[^}]+\}""")]
    private static partial Regex RouteParameterPattern();
}
