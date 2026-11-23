using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>Signing in to the admin UI, and creating the first admin account, against a running gateway.</summary>
public sealed partial class AdminLoginTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A fresh gateway without an admin account.</summary>
    private static async Task<GatewayFixture> StartAsync()
    {
        var gateway = new GatewayFixture();
        await gateway.InitializeAsync();
        return gateway;
    }

    private static HttpClient NewClient(bool followRedirects = true) =>
        new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer(), AllowAutoRedirect = followRedirects })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };

    private static Uri Admin(GatewayFixture gateway, string path) => new($"http://127.0.0.1:{gateway.AdminPort}{path}");

    /// <summary>A GET as a browser sends it when opening a page.</summary>
    private static async Task<HttpResponseMessage> OpenAsync(HttpClient client, GatewayFixture gateway, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Admin(gateway, path));
        request.Headers.Accept.ParseAdd("text/html");
        return await client.SendAsync(request, Ct);
    }

    /// <summary>Opens <paramref name="path"/> and posts its form <paramref name="handler"/>; returns where the browser ends up.</summary>
    private static async Task<(Uri Url, string Html)> PostFormAsync(
        HttpClient client, GatewayFixture gateway, string path, string handler, Dictionary<string, string> fields)
    {
        var page = await client.GetStringAsync(Admin(gateway, path), Ct);
        fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
        fields["_handler"] = handler;
        using var content = new FormUrlEncodedContent(fields);
        using var response = await client.PostAsync(Admin(gateway, path), content, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (response.RequestMessage!.RequestUri!, await response.Content.ReadAsStringAsync(Ct));
    }

    private static Task<(Uri Url, string Html)> LoginAsync(HttpClient client, GatewayFixture gateway, string password, string? returnUrl = null)
    {
        var fields = new Dictionary<string, string> { ["Model.UserName"] = GatewayFixture.AdminUserName, ["Model.Password"] = password };
        if (returnUrl is not null)
        {
            fields["Model.ReturnUrl"] = returnUrl;
        }

        return PostFormAsync(client, gateway, "/account/login", "login", fields);
    }

    private static async Task<int> AccountCountAsync(GatewayFixture gateway)
    {
        await using var scope = gateway.App.Services.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>().Users.Count();
    }

    /// <summary>Every routable page of the admin UI, with its route parameters filled in.</summary>
    private static List<(string Path, bool Anonymous)> Pages() =>
        [.. typeof(AdminIdentity).Assembly.GetTypes()
            .SelectMany(type => type.GetCustomAttributes<RouteAttribute>().Select(route => (
                Path: RouteParameterPattern().Replace(route.Template, "1"),
                Anonymous: type.GetCustomAttribute<AllowAnonymousAttribute>() is not null)))
            .OrderBy(page => page.Path, StringComparer.Ordinal)];

    [Fact]
    public async Task Every_page_and_endpoint_of_the_admin_ui_requires_sign_in()
    {
        await using var gateway = await StartAsync();
        using var signedIn = NewClient();
        await gateway.SignInAsync(signedIn); // so the sign-in page no longer sends to first-run setup
        using var anonymous = NewClient(followRedirects: false);

        var pages = Pages();
        Assert.True(pages.Count > 20, $"Only {pages.Count} pages found.");
        Assert.Equal(["/account/login", "/account/login/recovery", "/account/login/two-factor", "/account/setup"], pages.Where(p => p.Anonymous).Select(p => p.Path));

        foreach (var (path, _) in pages.Where(p => !p.Anonymous))
        {
            using var response = await OpenAsync(anonymous, gateway, path);
            Assert.True(response.StatusCode == HttpStatusCode.Found, $"{path}: {(int)response.StatusCode}");
            Assert.Equal("/account/login", response.Headers.Location!.AbsolutePath);
            Assert.Equal($"?ReturnUrl={Uri.EscapeDataString(path)}", response.Headers.Location.Query);
        }

        // Data endpoints answer 401 instead of redirecting to a page.
        using (var live = await anonymous.GetAsync(Admin(gateway, "/logs/live?after=0"), Ct))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, live.StatusCode);
        }

        foreach (var download in new[] { AdminDownloads.ConfigurationPath, AdminDownloads.BackupPath })
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["includeSecrets"] = "true" });
            using var response = await anonymous.PostAsync(Admin(gateway, download), form, Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // Open without signing in: the sign-in page with its stylesheet, and the health endpoint.
        using var login = await OpenAsync(anonymous, gateway, "/account/login");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var stylesheet = StylesheetPattern().Match(await login.Content.ReadAsStringAsync(Ct)).Groups["href"].Value;
        using (var css = await anonymous.GetAsync(Admin(gateway, "/" + stylesheet), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, css.StatusCode);
        }

        using (var health = await anonymous.GetAsync(Admin(gateway, "/healthz"), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        }

        // Signed in, the pages open.
        foreach (var path in new[] { "/", "/routes", "/rules", "/logs", "/account" })
        {
            using var response = await OpenAsync(signedIn, gateway, path);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{path}: {(int)response.StatusCode}");
        }
    }

    [Fact]
    public async Task First_run_on_this_machine_creates_the_account_and_closes_setup()
    {
        await using var gateway = await StartAsync();
        var setup = gateway.App.Services.GetRequiredService<FirstRunSetup>();
        Assert.NotNull(setup.Token);

        // Opening the admin UI leads to the first-run page; on this machine no token is asked.
        using var browser = NewClient();
        using (var first = await OpenAsync(browser, gateway, "/"))
        {
            Assert.Equal("/account/setup", first.RequestMessage!.RequestUri!.AbsolutePath);
            var html = await first.Content.ReadAsStringAsync(Ct);
            Assert.Contains("Create the admin account", html, StringComparison.Ordinal);
            Assert.DoesNotContain("Setup token", html, StringComparison.Ordinal);
        }

        var (url, created) = await PostFormAsync(browser, gateway, "/account/setup", "setup", new()
        {
            ["Model.UserName"] = "frank",
            ["Model.Password"] = GatewayFixture.AdminPassword,
            ["Model.ConfirmPassword"] = GatewayFixture.AdminPassword,
        });
        Assert.Equal("/", url.AbsolutePath);
        Assert.Contains("<h1>Dashboard</h1>", created, StringComparison.Ordinal);
        Assert.Contains("frank", created, StringComparison.Ordinal); // signed in
        Assert.Null(setup.Token);

        // Setup is closed: the page sends to the sign-in page, and a post creates nothing.
        using var other = NewClient();
        using (var closed = await OpenAsync(other, gateway, "/account/setup"))
        {
            Assert.Equal("/account/login", closed.RequestMessage!.RequestUri!.AbsolutePath);
        }

        var loginPage = await other.GetStringAsync(Admin(gateway, "/account/login"), Ct);
        using var post = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryPattern().Match(loginPage).Groups["token"].Value,
            ["_handler"] = "setup",
            ["Model.UserName"] = "intruder",
            ["Model.Password"] = "another long password",
            ["Model.ConfirmPassword"] = "another long password",
        });
        using var refused = await other.PostAsync(Admin(gateway, "/account/setup"), post, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode); // the page has no setup form any more
        Assert.Equal(1, await AccountCountAsync(gateway));
    }

    [Fact]
    public async Task Remote_first_run_is_impossible_without_the_setup_token()
    {
        await using var gateway = await StartAsync();
        var token = gateway.App.Services.GetRequiredService<FirstRunSetup>().Token!;

        // As passed on by a proxy: the connection comes from this machine, the client does not.
        using var remote = NewClient();
        remote.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.9");
        static Dictionary<string, string> Fields(string? setupToken) => new()
        {
            ["Model.UserName"] = "admin",
            ["Model.Password"] = GatewayFixture.AdminPassword,
            ["Model.ConfirmPassword"] = GatewayFixture.AdminPassword,
            ["Model.SetupToken"] = setupToken ?? string.Empty,
        };

        var page = await remote.GetStringAsync(Admin(gateway, "/account/setup"), Ct);
        Assert.Contains("Setup token", page, StringComparison.Ordinal);

        foreach (var attempt in new[] { null, "wrong", token[..^1] })
        {
            var (url, html) = await PostFormAsync(remote, gateway, "/account/setup", "setup", Fields(attempt));
            Assert.Equal("/account/setup", url.AbsolutePath);
            Assert.Contains("The setup token is not correct.", html, StringComparison.Ordinal);
            Assert.DoesNotContain(GatewayFixture.AdminPassword, html, StringComparison.Ordinal);
            Assert.Equal(0, await AccountCountAsync(gateway));
        }

        var (done, dashboard) = await PostFormAsync(remote, gateway, "/account/setup", "setup", Fields(token));
        Assert.Equal("/", done.AbsolutePath);
        Assert.Contains("Sign out", dashboard, StringComparison.Ordinal);
        Assert.Equal(1, await AccountCountAsync(gateway));
        Assert.Null(gateway.App.Services.GetRequiredService<FirstRunSetup>().Token);
    }

    [Fact]
    public async Task Sign_in_and_sign_out()
    {
        await using var gateway = await StartAsync();
        using (var creator = NewClient())
        {
            await gateway.SignInAsync(creator);
        }

        using var browser = NewClient();

        // Wrong password: an error, the password is not sent back, and still signed out.
        var (failedUrl, failed) = await LoginAsync(browser, gateway, "not the password");
        Assert.Equal("/account/login", failedUrl.AbsolutePath);
        Assert.Contains("The user name or password is not correct.", failed, StringComparison.Ordinal);
        Assert.DoesNotContain("not the password", failed, StringComparison.Ordinal);
        using (var stillOut = await OpenAsync(browser, gateway, "/routes"))
        {
            Assert.Equal("/account/login", stillOut.RequestMessage!.RequestUri!.AbsolutePath);
        }

        // Right password: back to the page that asked for it.
        var (url, routes) = await LoginAsync(browser, gateway, GatewayFixture.AdminPassword, "/routes");
        Assert.Equal("/routes", url.AbsolutePath);
        Assert.Contains("Sign out", routes, StringComparison.Ordinal);

        // Signing out needs the page's antiforgery token, so another site cannot sign you out.
        using (var forged = await browser.PostAsync(Admin(gateway, AdminIdentity.LogoutPath), new FormUrlEncodedContent([]), Ct))
        {
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        }

        using var signOut = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryPattern().Match(routes).Groups["token"].Value,
        });
        using var signedOut = await browser.PostAsync(Admin(gateway, AdminIdentity.LogoutPath), signOut, Ct);
        Assert.Equal("/account/login", signedOut.RequestMessage!.RequestUri!.AbsolutePath);
        Assert.Contains("You are signed out.", await signedOut.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        using (var afterwards = await OpenAsync(browser, gateway, "/routes"))
        {
            Assert.Equal("/account/login", afterwards.RequestMessage!.RequestUri!.AbsolutePath);
        }

        // A return URL to another site is ignored.
        var (dashboard, _) = await LoginAsync(browser, gateway, GatewayFixture.AdminPassword, "//evil.example/");
        Assert.Equal(Admin(gateway, "/"), dashboard);
    }

    [Fact]
    public async Task Changing_the_password()
    {
        await using var gateway = await StartAsync();
        using var browser = NewClient();
        await gateway.SignInAsync(browser);
        const string NewPassword = "a different long password";

        var (_, wrong) = await PostFormAsync(browser, gateway, "/account", "change-password", new()
        {
            ["Model.CurrentPassword"] = "not the password",
            ["Model.NewPassword"] = NewPassword,
            ["Model.ConfirmPassword"] = NewPassword,
        });
        Assert.Contains("The current password is not correct.", wrong, StringComparison.Ordinal);

        var (_, changed) = await PostFormAsync(browser, gateway, "/account", "change-password", new()
        {
            ["Model.CurrentPassword"] = GatewayFixture.AdminPassword,
            ["Model.NewPassword"] = NewPassword,
            ["Model.ConfirmPassword"] = NewPassword,
        });
        Assert.Contains("Your password was changed.", changed, StringComparison.Ordinal);
        Assert.DoesNotContain(NewPassword, changed, StringComparison.Ordinal);

        using var other = NewClient();
        Assert.Contains("not correct", (await LoginAsync(other, gateway, GatewayFixture.AdminPassword)).Html, StringComparison.Ordinal);
        Assert.Equal("/", (await LoginAsync(other, gateway, NewPassword)).Url.AbsolutePath);
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();

    [GeneratedRegex("""<link rel="stylesheet" href="(?<href>[^"]+)""")]
    private static partial Regex StylesheetPattern();

    [GeneratedRegex("""\{[^}]+\}""")]
    private static partial Regex RouteParameterPattern();
}
