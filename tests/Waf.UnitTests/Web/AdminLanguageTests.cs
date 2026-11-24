using System.Xml.Linq;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

/// <summary>Choosing the admin UI's language, and the completeness of its translations.</summary>
public class AdminLanguageTests
{
    [Theory]
    [InlineData("nl-BE", "nl")]
    [InlineData("de-AT,de;q=0.9,en;q=0.8", "de")]
    [InlineData("fr-CA", "fr")]
    [InlineData("EN-gb", "en")]
    [InlineData("ja-JP, nl;q=0.4", "nl")] // the first supported one
    [InlineData("en;q=0.5, de;q=0.8", "de")] // by quality, not by position
    [InlineData("fr;q=0, de;q=0.1", "de")] // q=0 means "not this one"
    [InlineData("*", null)]
    [InlineData("es-ES,ja", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    [InlineData("not a ; valid ;; header", null)]
    public void The_first_supported_browser_language_wins(string? header, string? expected)
    {
        Assert.Equal(expected, AdminLanguage.FromAcceptLanguage(header));
    }

    [Theory]
    [InlineData("browser", true)]
    [InlineData("en", true)]
    [InlineData("nl", true)]
    [InlineData("fr", true)]
    [InlineData("de", true)]
    [InlineData("es", false)]
    [InlineData("NL", false)]
    [InlineData("nl-BE", false)]
    [InlineData(null, false)]
    public void Only_supported_languages_and_browser_are_valid_choices(string? choice, bool valid)
    {
        Assert.Equal(valid, AdminLanguage.IsValid(choice));
    }

    [Fact]
    public void A_stored_language_wins_and_an_unknown_one_is_ignored()
    {
        static System.Security.Claims.ClaimsPrincipal User(string? language) => new(new System.Security.Claims.ClaimsIdentity(
            language is null ? [] : [new System.Security.Claims.Claim(AdminLanguage.ClaimType, language)], "test"));

        Assert.Equal("fr", AdminLanguage.Stored(User("fr")));
        Assert.Null(AdminLanguage.Stored(User("xx")));
        Assert.Null(AdminLanguage.Stored(User(null)));
    }

    private static Dictionary<string, string> Texts(string file) =>
        XDocument.Load(Path.Combine(RepoRoot(), "src", "Waf.Web", "Resources", file)).Root!.Elements("data")
            .ToDictionary(d => d.Attribute("name")!.Value, d => d.Element("value")!.Value, StringComparer.Ordinal);

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    [Theory]
    [InlineData("nl")]
    [InlineData("fr")]
    [InlineData("de")]
    public void Every_text_is_translated_into_every_language(string language)
    {
        var english = Texts("SharedResource.resx");
        var translated = Texts($"SharedResource.{language}.resx");

        Assert.Equal(english.Keys.Order(StringComparer.Ordinal), translated.Keys.Order(StringComparer.Ordinal));
        Assert.All(translated, pair => Assert.False(string.IsNullOrWhiteSpace(pair.Value), $"'{pair.Key}' has no {language} text."));
        Assert.All(english, pair => Assert.Equal(pair.Key, pair.Value)); // the key is the English text
    }
}
