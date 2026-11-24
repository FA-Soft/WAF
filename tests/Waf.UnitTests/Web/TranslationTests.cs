using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

/// <summary>
/// The admin UI's translations: every text the source uses (<c>T</c>, <c>TM</c>, <c>N</c>, <c>Plural</c>) exists in
/// English, Dutch, French and German, none is empty, and the placeholders match.
/// </summary>
public sealed partial class TranslationTests
{
    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static Dictionary<string, string> Texts(string language) =>
        XDocument.Load(Path.Combine(RepoRoot(), "src", "Waf.Web", "Resources", language == "en" ? "SharedResource.resx" : $"SharedResource.{language}.resx"))
            .Root!.Elements("data")
            .ToDictionary(d => d.Attribute("name")!.Value, d => d.Element("value")!.Value, StringComparer.Ordinal);

    private static IEnumerable<string> SourceFiles() =>
        Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src", "Waf.Web"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    /// <summary>Every literal key in the source, with the file it is in.</summary>
    internal static IReadOnlyList<(string Key, string File)> UsedKeys() =>
        [.. SourceFiles().SelectMany(file =>
        {
            var source = File.ReadAllText(file);
            var single = KeyPattern().Matches(source).Select(m => m.Groups["key"].Value);
            var plural = PluralPattern().Matches(source).SelectMany(m => new[] { m.Groups["one"].Value, m.Groups["other"].Value });
            return single.Concat(plural).Select(k => (Unescape(k), Path.GetFileName(file)));
        })];

    private static string Unescape(string literal) =>
        literal.Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\n", "\n", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal);

    [Fact]
    public void Every_text_in_the_source_is_in_the_english_resources()
    {
        var english = Texts("en");
        var missing = UsedKeys().Where(k => !english.ContainsKey(k.Key)).Select(k => $"{k.File}: {k.Key}").Distinct().ToList();

        Assert.True(missing.Count == 0, $"{missing.Count} texts are not in SharedResource.resx:\n" + string.Join("\n", missing.Take(200)));
    }

    [Theory]
    [InlineData("nl")]
    [InlineData("fr")]
    [InlineData("de")]
    public void Every_text_is_translated_with_the_same_placeholders(string language)
    {
        var english = Texts("en");
        var translated = Texts(language);

        Assert.Equal(english.Keys.Order(StringComparer.Ordinal), translated.Keys.Order(StringComparer.Ordinal));
        var problems = translated
            .Where(pair => string.IsNullOrWhiteSpace(pair.Value) || !Placeholders(pair.Value).SequenceEqual(Placeholders(pair.Key)))
            .Select(pair => $"{pair.Key} -> {pair.Value}")
            .ToList();
        Assert.True(problems.Count == 0, $"{language}: empty or with other placeholders:\n" + string.Join("\n", problems));
        Assert.All(english, pair => Assert.Equal(pair.Key, pair.Value)); // the key is the English text
    }

    private static IEnumerable<string> Placeholders(string text) => PlaceholderPattern().Matches(text).Select(m => m.Value).Order(StringComparer.Ordinal);

    [Fact]
    public void Every_validation_message_of_the_forms_is_translated()
    {
        // Attribute texts are constants, so they are not T("…") calls; they are translated where they are shown.
        var messages = typeof(AdminLanguage).Assembly.GetTypes()
            .SelectMany(type => type.GetProperties())
            .SelectMany(property => property.GetCustomAttributes(typeof(System.ComponentModel.DataAnnotations.ValidationAttribute), inherit: true)
                .Cast<System.ComponentModel.DataAnnotations.ValidationAttribute>())
            .Select(attribute => attribute.ErrorMessage)
            .OfType<string>()
            .Distinct()
            .ToList();
        var english = Texts("en");

        Assert.True(messages.Count > 20, $"Only {messages.Count} validation messages found.");
        var missing = messages.Where(m => !english.ContainsKey(m)).ToList();
        Assert.True(missing.Count == 0, "Not translated:\n" + string.Join("\n", missing));
    }

    [Fact]
    public void Texts_are_keys_not_interpolated_strings()
    {
        var interpolated = SourceFiles()
            .SelectMany(file => InterpolatedPattern().Matches(File.ReadAllText(file)).Select(m => $"{Path.GetFileName(file)}: {m.Value}"))
            .ToList();
        Assert.True(interpolated.Count == 0, "Use placeholders instead:\n" + string.Join("\n", interpolated));
    }

    [Fact]
    public void Plurals_follow_the_language()
    {
        var (ui, format) = (CultureInfo.CurrentUICulture, CultureInfo.CurrentCulture);
        try
        {
            static string Codes(long n) => Text.Plural(n, "{0} recovery code left", "{0} recovery codes left");

            CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en");
            Assert.Equal(("0 recovery codes left", "1 recovery code left", "2 recovery codes left"), (Codes(0), Codes(1), Codes(2)));

            // French uses the singular for 0 as well.
            CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr");
            Assert.Equal(("0 code de récupération restant", "1 code de récupération restant", "2 codes de récupération restants"), (Codes(0), Codes(1), Codes(2)));

            // Numbers in the language's format.
            CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("de");
            Assert.Equal("1.234 Wiederherstellungscodes übrig", Codes(1234));
        }
        finally
        {
            (CultureInfo.CurrentUICulture, CultureInfo.CurrentCulture) = (ui, format);
        }
    }

    [Fact]
    public void Messages_made_elsewhere_are_translated_by_their_template()
    {
        var ui = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("de");
            // A configuration error: the label and the message are translated separately.
            var message = Text.Message("Route 'api': the name is used by more than one route.");
            Assert.Equal($"{Text.T("Route '{0}'", "api")}: {Text.T("the name is used by more than one route.")}", message);
            Assert.NotEqual("Route 'api': the name is used by more than one route.", message);
            Assert.Equal("Something nobody translated.", Text.Message("Something nobody translated."));

            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en");
            Assert.Equal("Route 'api': the name is used by more than one route.", Text.Message("Route 'api': the name is used by more than one route."));
        }
        finally
        {
            CultureInfo.CurrentUICulture = ui;
        }
    }

    // T("…"), TM("…"), N("…"), Text.T("…"): the first argument, a plain string literal.
    [GeneratedRegex("""\b(?:T|TM|N|F)\(\s*"(?<key>(?:[^"\\]|\\.)*)"(?=\s*[,)])""")]
    private static partial Regex KeyPattern();

    [GeneratedRegex("""\bPlural\([^,]+,\s*"(?<one>(?:[^"\\]|\\.)*)",\s*"(?<other>(?:[^"\\]|\\.)*)"\s*[,)]""")]
    private static partial Regex PluralPattern();

    [GeneratedRegex("""\b(?:T|TM|N)\(\s*\$""")]
    private static partial Regex InterpolatedPattern();

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex PlaceholderPattern();
}
