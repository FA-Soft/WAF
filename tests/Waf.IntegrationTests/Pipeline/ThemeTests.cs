using System.Net;
using System.Text.RegularExpressions;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// The light/dark switch of the admin UI: the system setting by default; a choice is stored with the account, so it
/// applies on every device and at the next sign-in.
/// </summary>
public sealed partial class ThemeTests(AdminUiFixture gateway) : IClassFixture<AdminUiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private Uri Admin(string path) => new($"http://127.0.0.1:{gateway.AdminPort}{path}");

    /// <summary>A browser on its own device: its own cookies.</summary>
    private static HttpClient Browser() =>
        new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(15) };

    private async Task<string> PageAsync(HttpClient browser, string path = "/routes")
    {
        using var response = await browser.GetAsync(Admin(path), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    private static string? DataTheme(string html) =>
        HtmlTagPattern().Match(html) is { Success: true } tag && DataThemePattern().Match(tag.Value) is { Success: true } attribute
            ? attribute.Groups["theme"].Value
            : null;

    private static string? Pressed(string html) => PressedPattern().Match(html) is { Success: true } m ? m.Groups["theme"].Value : null;

    /// <summary>Clicks a theme button on <paramref name="path"/>, as the switch in the top bar does.</summary>
    private async Task<HttpResponseMessage> ChooseAsync(HttpClient browser, string theme, string path = "/routes?q=1", string? returnUrl = null)
    {
        var page = await PageAsync(browser, path);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = TokenPattern().Match(page).Groups["token"].Value,
            ["returnUrl"] = returnUrl ?? ReturnUrlPattern().Match(page).Groups["url"].Value,
            ["theme"] = theme,
        });
        return await browser.PostAsync(Admin(AdminTheme.Path), form, Ct);
    }

    [Fact]
    public async Task The_choice_is_kept_with_the_account_on_every_device_and_system_is_the_default()
    {
        using var laptop = Browser();
        await gateway.SignInAsync(laptop);
        using (var reset = await ChooseAsync(laptop, AdminTheme.System))
        {
            Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        }

        // Default: no data-theme, so the stylesheet follows the system setting.
        var page = await PageAsync(laptop);
        Assert.Null(DataTheme(page));
        Assert.Equal(AdminTheme.System, Pressed(page));

        // Dark: back on the same page (with its query), now dark.
        using (var dark = await ChooseAsync(laptop, AdminTheme.Dark))
        {
            Assert.Equal(HttpStatusCode.OK, dark.StatusCode);
            Assert.Equal("/routes?q=1", dark.RequestMessage!.RequestUri!.PathAndQuery);
            var html = await dark.Content.ReadAsStringAsync(Ct);
            Assert.Equal(AdminTheme.Dark, DataTheme(html));
            Assert.Equal(AdminTheme.Dark, Pressed(html));
        }

        // Another device, signing in: the stored choice applies.
        using var phone = Browser();
        await gateway.SignInAsync(phone);
        Assert.Equal(AdminTheme.Dark, DataTheme(await PageAsync(phone, "/")));

        // A change on one device reaches the session on the other at its next page.
        using (var light = await ChooseAsync(phone, AdminTheme.Light))
        {
            Assert.Equal(AdminTheme.Light, DataTheme(await light.Content.ReadAsStringAsync(Ct)));
        }

        Assert.Equal(AdminTheme.Light, DataTheme(await PageAsync(laptop)));

        // Back to the system setting.
        using (var system = await ChooseAsync(laptop, AdminTheme.System))
        {
            Assert.Null(DataTheme(await system.Content.ReadAsStringAsync(Ct)));
        }

        Assert.Null(DataTheme(await PageAsync(phone)));
    }

    [Fact]
    public async Task Unknown_themes_forged_requests_and_other_sites_as_return_address_are_refused()
    {
        using var browser = Browser();
        await gateway.SignInAsync(browser);

        using (var unknown = await ChooseAsync(browser, "purple"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        }

        // Without the antiforgery token (a form on another site).
        using (var forged = await browser.PostAsync(Admin(AdminTheme.Path), new FormUrlEncodedContent(new Dictionary<string, string> { ["theme"] = "dark" }), Ct))
        {
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        }

        // Never redirects to another site (open redirect): the dashboard instead.
        using (var external = await ChooseAsync(browser, AdminTheme.System, returnUrl: "https://attacker.example/"))
        {
            Assert.Equal(HttpStatusCode.OK, external.StatusCode);
            Assert.Equal(Admin("/").AbsoluteUri, external.RequestMessage!.RequestUri!.AbsoluteUri);
        }

        // Not signed in: nothing to store it with.
        using var anonymous = Browser();
        using var response = await anonymous.PostAsync(Admin(AdminTheme.Path), new FormUrlEncodedContent(new Dictionary<string, string> { ["theme"] = "dark" }), Ct);
        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest
            || response.RequestMessage!.RequestUri!.AbsolutePath == AdminIdentity.LoginPath,
            $"{(int)response.StatusCode} {response.RequestMessage?.RequestUri}");
    }

    [GeneratedRegex("""<html[^>]*>""")]
    private static partial Regex HtmlTagPattern();

    [GeneratedRegex("""data-theme="(?<theme>[a-z]+)""")]
    private static partial Regex DataThemePattern();

    [GeneratedRegex("""name="theme" value="(?<theme>[a-z]+)" aria-pressed="true""")]
    private static partial Regex PressedPattern();

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex TokenPattern();

    [GeneratedRegex("""name="returnUrl" value="(?<url>[^"]*)""")]
    private static partial Regex ReturnUrlPattern();
}
