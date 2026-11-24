using System.Net;
using System.Text.RegularExpressions;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>Gateway with one route and one rule, for admin UI tests.</summary>
public sealed class AdminUiFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs =>
    [
        .. new RouteArgs().Add("website", [("http", _backend!.Port)], hosts: ["www.example.com"]).ToArray(),
        "--Gateway:Rules:0:Name=no-admin",
        "--Gateway:Rules:0:Action=Block",
        "--Gateway:Rules:0:Conditions:0:Field=Path",
        "--Gateway:Rules:0:Conditions:0:Operator=StartsWith",
        "--Gateway:Rules:0:Conditions:0:Values:0=/admin",
    ];

    protected override async ValueTask AfterStopAsync()
    {
        if (_backend is not null)
        {
            await _backend.DisposeAsync();
        }
    }
}

public sealed partial class AdminUiTests(AdminUiFixture gateway) : IClassFixture<AdminUiFixture>, IAsyncLifetime
{
    private readonly HttpClient _http = new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync() => await gateway.SignInAsync(_http);

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }

    private Uri Admin(string path) => new($"http://127.0.0.1:{gateway.AdminPort}{path}");

    private async Task<string> GetPageAsync(string path)
    {
        using var response = await _http.GetAsync(Admin(path), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    [Fact]
    public async Task Dashboard_shows_state_configuration_routes_and_rules()
    {
        var html = await GetPageAsync("/");

        Assert.Contains("<h1>Dashboard</h1>", html, StringComparison.Ordinal);
        Assert.Contains("Protecting", html, StringComparison.Ordinal);
        Assert.Contains("Version 1", html, StringComparison.Ordinal);
        Assert.Contains("Requests for www.example.com", html, StringComparison.Ordinal);
        Assert.Contains("no-admin", html, StringComparison.Ordinal);
        Assert.Contains("The path starts with /admin", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task History_lists_the_active_version()
    {
        var html = await GetPageAsync("/history");

        Assert.Contains("Imported from appsettings at startup.", html, StringComparison.Ordinal);
        Assert.Contains("Active", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_page_gives_404()
    {
        using var response = await _http.GetAsync(Admin("/does-not-exist"), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Pages_are_sent_with_strict_security_headers()
    {
        using var response = await _http.GetAsync(Admin("/"), Ct);

        Assert.Equal(FASoft.Waf.Host.Hosting.AdminPipeline.ContentSecurityPolicy, response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal(FASoft.Waf.Host.Hosting.AdminPipeline.PermissionsPolicy, response.Headers.GetValues("Permissions-Policy").Single());
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Opener-Policy").Single());
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Resource-Policy").Single());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.False(response.Headers.Contains("Strict-Transport-Security"), "HSTS over plain HTTP (loopback) means nothing");
    }

    [Fact]
    public async Task Stylesheet_and_blazor_script_referenced_by_the_page_are_served()
    {
        var html = await GetPageAsync("/");
        var stylesheet = StylesheetPattern().Match(html).Groups["href"].Value;
        var script = ScriptPattern().Match(html).Groups["src"].Value;

        foreach (var asset in new[] { stylesheet, script })
        {
            Assert.False(string.IsNullOrEmpty(asset));
            using var response = await _http.GetAsync(Admin("/" + asset), Ct);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{asset}: {(int)response.StatusCode}");
        }
    }

    [Fact]
    public async Task Favicon_and_logo_marks_referenced_by_the_page_are_served()
    {
        var html = await GetPageAsync("/");
        var assets = SvgPattern().Matches(html).Select(m => m.Groups["url"].Value).Distinct().ToList();

        Assert.Contains(assets, a => a.Contains("favicon", StringComparison.Ordinal));
        Assert.Contains(assets, a => a.Contains("waf-mark.", StringComparison.Ordinal));
        Assert.Contains(assets, a => a.Contains("waf-mark-dark", StringComparison.Ordinal));
        // Status only, as for the stylesheet: the test host has no wwwroot, so it answers with empty files (a published
        // gateway serves them in full).
        foreach (var asset in assets)
        {
            using var response = await _http.GetAsync(Admin("/" + asset), Ct);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{asset}: {(int)response.StatusCode}");
        }
    }

    [Fact]
    public async Task Admin_ui_is_not_served_on_the_public_listener()
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.HttpPort}/test-request"), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); // no route for 127.0.0.1
    }

    [Fact]
    public async Task Test_a_request_form_shows_the_firewall_decision()
    {
        var html = await PostTestRequestAsync(new Dictionary<string, string>
        {
            ["Model.Method"] = "GET",
            ["Model.Host"] = "www.example.com",
            ["Model.Path"] = "/admin/users",
            ["Model.ClientIp"] = "203.0.113.10",
            ["Model.Route"] = "website",
        });

        Assert.Contains("result-blocked", html, StringComparison.Ordinal);
        Assert.Contains("Blocked (403) by rule &#x27;no-admin&#x27;.", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Test_a_request_form_shows_validation_errors_in_plain_language()
    {
        var html = await PostTestRequestAsync(new Dictionary<string, string>
        {
            ["Model.Method"] = "GET",
            ["Model.Host"] = "www.example.com",
            ["Model.Path"] = "admin",
            ["Model.ClientIp"] = "not-an-ip",
        });

        Assert.Contains("The path must start with /, e.g. /admin.", html, StringComparison.Ordinal);
        Assert.Contains("This is not a valid IP address.", html, StringComparison.Ordinal);
        Assert.DoesNotContain("result-blocked", html, StringComparison.Ordinal);
        Assert.DoesNotContain("result-allowed", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Form_post_without_antiforgery_token_is_rejected()
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["_handler"] = "test-request", ["Model.Path"] = "/" });

        using var response = await _http.PostAsync(Admin("/test-request"), content, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<string> PostTestRequestAsync(Dictionary<string, string> fields)
    {
        var form = await GetPageAsync("/test-request");
        fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(form).Groups["token"].Value;
        fields["_handler"] = "test-request";
        Assert.False(string.IsNullOrEmpty(fields["__RequestVerificationToken"]), "The form has no antiforgery token.");

        using var content = new FormUrlEncodedContent(fields);
        using var response = await _http.PostAsync(Admin("/test-request"), content, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    [GeneratedRegex("""<link rel="stylesheet" href="(?<href>[^"]+)""")]
    private static partial Regex StylesheetPattern();

    [GeneratedRegex("""<script src="(?<src>[^"]+)""")]
    private static partial Regex ScriptPattern();

    [GeneratedRegex("""(?:href|src|srcset)="(?<url>[^"]+\.svg)""")]
    private static partial Regex SvgPattern();

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();
}
