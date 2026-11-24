using System.Net;
using System.Text.RegularExpressions;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// The language of the admin UI: the browser's language by default (English when it is none of English, Dutch, French
/// and German); a choice in the switch is stored with the account, so it applies on every device.
/// </summary>
public sealed partial class LanguageTests(AdminUiFixture gateway) : IClassFixture<AdminUiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private Uri Admin(string path) => new($"http://127.0.0.1:{gateway.AdminPort}{path}");

    /// <summary>A browser on its own device, with its own cookies and language setting.</summary>
    private static HttpClient Browser(string? acceptLanguage = null)
    {
        var client = new HttpClient(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(15) };
        if (acceptLanguage is not null)
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", acceptLanguage);
        }

        return client;
    }

    private async Task<string> PageAsync(HttpClient browser, string path = "/routes")
    {
        using var response = await browser.GetAsync(Admin(path), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync(Ct)); // é is sent as &#xE9;
    }

    private static string Lang(string html) => LangPattern().Match(html).Groups["lang"].Value;

    private static string? Pressed(string html) => PressedPattern().Match(html) is { Success: true } m ? m.Groups["language"].Value : null;

    /// <summary>Clicks a language in the switch on <paramref name="path"/>.</summary>
    private async Task<HttpResponseMessage> ChooseAsync(HttpClient browser, string language, string path = "/routes?q=1")
    {
        var page = await PageAsync(browser, path);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = TokenPattern().Match(page).Groups["token"].Value,
            ["returnUrl"] = ReturnUrlPattern().Match(page).Groups["url"].Value,
            ["language"] = language,
        });
        return await browser.PostAsync(Admin(AdminLanguage.Path), form, Ct);
    }

    [Theory]
    [InlineData("nl-BE,nl;q=0.9,en;q=0.8", "nl", "Afmelden")]
    [InlineData("fr-CA", "fr", "Se déconnecter")]
    [InlineData("de-AT,de;q=0.9", "de", "Abmelden")]
    [InlineData("ja-JP,ja;q=0.9", "en", "Sign out")]
    [InlineData("es, fr;q=0.5", "fr", "Se déconnecter")]
    [InlineData(null, "en", "Sign out")]
    public async Task Without_a_choice_the_browser_language_is_used_and_english_otherwise(string? acceptLanguage, string lang, string signOut)
    {
        // The sign-in page: nobody is signed in yet, so the browser decides.
        using var browser = Browser(acceptLanguage);
        Assert.Equal(lang, Lang(await PageAsync(browser, AdminIdentity.LoginPath)));

        await gateway.SignInAsync(browser);
        using (var reset = await ChooseAsync(browser, AdminLanguage.Browser))
        {
            Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        }

        var page = await PageAsync(browser);
        Assert.Equal(lang, Lang(page));
        Assert.Contains($">{signOut}</button>", page, StringComparison.Ordinal);
        Assert.Equal(AdminLanguage.Browser, Pressed(page));
    }

    [Fact]
    public async Task The_choice_is_kept_with_the_account_on_every_device_and_browser_goes_back_to_the_browser_language()
    {
        using var laptop = Browser("de-DE");
        await gateway.SignInAsync(laptop);

        // French on a German browser: back on the same page, in French, with French number formatting.
        using (var french = await ChooseAsync(laptop, "fr"))
        {
            Assert.Equal(HttpStatusCode.OK, french.StatusCode);
            Assert.Equal("/routes?q=1", french.RequestMessage!.RequestUri!.PathAndQuery);
            var html = WebUtility.HtmlDecode(await french.Content.ReadAsStringAsync(Ct));
            Assert.Equal(("fr", "fr"), (Lang(html), Pressed(html)));
            Assert.Contains(">Tableau de bord</a>", html, StringComparison.Ordinal);
        }

        // Another device with an English browser, signing in: the stored choice applies.
        using var phone = Browser("en-US");
        await gateway.SignInAsync(phone);
        Assert.Equal("fr", Lang(await PageAsync(phone, "/")));

        // "Browser": each device follows its own browser again.
        using (var browser = await ChooseAsync(phone, AdminLanguage.Browser))
        {
            Assert.Equal("en", Lang(await browser.Content.ReadAsStringAsync(Ct)));
        }

        var german = await PageAsync(laptop);
        Assert.Equal("de", Lang(german));
        Assert.Contains(">Übersicht</a>", german, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_languages_and_forged_requests_are_refused()
    {
        using var browser = Browser();
        await gateway.SignInAsync(browser);

        using (var unknown = await ChooseAsync(browser, "es"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        }

        using (var forged = await browser.PostAsync(Admin(AdminLanguage.Path), new FormUrlEncodedContent(new Dictionary<string, string> { ["language"] = "nl" }), Ct))
        {
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        }

        Assert.Equal("en", Lang(await PageAsync(browser)));
    }

    [GeneratedRegex("""<html lang="(?<lang>[a-z]+)""")]
    private static partial Regex LangPattern();

    [GeneratedRegex("""name="language" value="(?<language>[a-z]+)"(?: lang="[a-z]+")? aria-pressed="true""")]
    private static partial Regex PressedPattern();

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex TokenPattern();

    [GeneratedRegex("""name="returnUrl" value="(?<url>[^"]*)""")]
    private static partial Regex ReturnUrlPattern();
}
