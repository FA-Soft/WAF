using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Data;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// The routes pages of the admin UI, driven through real form posts (with antiforgery tokens) against a
/// running gateway. Every test has its own gateway, because every test changes the configuration.
/// </summary>
public sealed partial class RoutesUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Route "website" (www.example.com → A) and a rule scoped to it; backend B is unused at start.</summary>
    private sealed class Gateway : GatewayFixture
    {
        public BackendServer A { get; private set; } = null!;

        public BackendServer B { get; private set; } = null!;

        public HttpClient Admin { get; } = new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };

        public HttpClient Public { get; } = new() { Timeout = TimeSpan.FromSeconds(15) };

        public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

        protected override async ValueTask BeforeStartAsync()
        {
            A = await BackendServer.StartAsync("A");
            B = await BackendServer.StartAsync("B");
        }

        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("website", [("http", A.Port)], hosts: ["www.example.com"]).ToArray(),
            "--Gateway:Rules:0:Name=no-admin",
            "--Gateway:Rules:0:Action=Block",
            "--Gateway:Rules:0:Routes:0=website",
            "--Gateway:Rules:0:Conditions:0:Field=Path",
            "--Gateway:Rules:0:Conditions:0:Operator=StartsWith",
            "--Gateway:Rules:0:Conditions:0:Values:0=/admin",
        ];

        protected override async ValueTask AfterStartAsync() => await SignInAsync(Admin);

        public async Task<string> GetPageAsync(string path)
        {
            using var response = await Admin.GetAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await response.Content.ReadAsStringAsync(Ct);
        }

        /// <summary>Opens <paramref name="path"/>, then posts a form of it with the page's antiforgery token.</summary>
        public async Task<string> PostAsync(string path, string handler, Dictionary<string, string> fields)
        {
            var page = await GetPageAsync(path);
            fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
            fields["_handler"] = handler;

            using var content = new FormUrlEncodedContent(fields);
            using var response = await Admin.PostAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), content, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode); // after the redirect, if any
            return await response.Content.ReadAsStringAsync(Ct);
        }

        public async Task<(HttpStatusCode Status, string? Backend)> ProxyAsync(string host, string path = "/")
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}{path}"));
            request.Headers.Host = host;
            using var response = await Public.SendAsync(request, Ct);
            var backend = response.StatusCode == HttpStatusCode.OK ? (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend : null;
            return (response.StatusCode, backend);
        }

        protected override async ValueTask AfterStopAsync()
        {
            Admin.Dispose();
            Public.Dispose();
            await A.DisposeAsync();
            await B.DisposeAsync();
        }
    }

    private static Dictionary<string, string> RouteFields(string name, string hosts, string destinations, bool enabled = true, string pathPrefix = "/") => new()
    {
        ["Model.BaseVersion"] = "1",
        ["Model.IsNew"] = "true",
        ["Model.Name"] = name,
        ["Model.Hosts"] = hosts,
        ["Model.PathPrefix"] = pathPrefix,
        ["Model.Destinations"] = destinations,
        ["Model.HealthCheckIntervalSeconds"] = "10",
        ["Model.HealthCheckTimeoutSeconds"] = "5",
        ["Model.PreserveHost"] = "True",
        ["Model.Enabled"] = enabled ? "True" : string.Empty,
    };

    [Fact]
    public async Task Routes_page_lists_the_routes()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.GetPageAsync("/routes");

        Assert.Contains("<td>website</td>", html, StringComparison.Ordinal);
        Assert.Contains("Requests for www.example.com", html, StringComparison.Ordinal);
        Assert.Contains("Add a route", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Adding_a_route_creates_a_version_and_proxies_immediately()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await gateway.ProxyAsync("shop.example.com")).Status);

        var html = await gateway.PostAsync("/routes/new", "route-edit", RouteFields("shop", "shop.example.com", $"http://127.0.0.1:{gateway.B.Port}"));

        Assert.Contains("Route &#x27;shop&#x27; added (version 2).", html, StringComparison.Ordinal);
        Assert.Equal((HttpStatusCode.OK, "B"), await gateway.ProxyAsync("shop.example.com"));
        var latest = await gateway.Store.GetLatestAsync(Ct);
        Assert.Equal((2L, GatewayFixture.AdminUserName, "Route 'shop' added."), (latest!.Version, latest.Author, latest.Comment));
    }

    [Fact]
    public async Task Editing_a_route_changes_where_traffic_goes()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var form = await gateway.GetPageAsync("/routes/website/edit");
        Assert.Contains($"http://127.0.0.1:{gateway.A.Port}", form, StringComparison.Ordinal);

        var fields = RouteFields("website", "www.example.com", $"http://127.0.0.1:{gateway.B.Port}");
        fields["Model.IsNew"] = "false";
        await gateway.PostAsync("/routes/website/edit", "route-edit", fields);

        Assert.Equal((HttpStatusCode.OK, "B"), await gateway.ProxyAsync("www.example.com"));
    }

    [Fact]
    public async Task Unticking_enabled_disables_the_route()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var fields = RouteFields("website", "www.example.com", $"http://127.0.0.1:{gateway.A.Port}", enabled: false);
        fields["Model.IsNew"] = "false";
        fields.Remove("Model.Enabled"); // an unticked checkbox is not posted
        await gateway.PostAsync("/routes/website/edit", "route-edit", fields);

        Assert.Equal(HttpStatusCode.NotFound, (await gateway.ProxyAsync("www.example.com")).Status);
        Assert.False(Assert.Single((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Routes).Enabled);
    }

    [Fact]
    public async Task Invalid_input_is_explained_and_nothing_is_stored()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/routes/new", "route-edit", RouteFields("my shop", "shop.example.com", "ftp://10.0.0.5"));

        Assert.Contains("Use only letters, digits, &#x27;-&#x27;, &#x27;_&#x27; and &#x27;.&#x27; (no spaces).", html, StringComparison.Ordinal);
        Assert.Contains("only http:// and https:// backends are supported.", html, StringComparison.Ordinal);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Duplicate_name_is_refused()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/routes/new", "route-edit", RouteFields("WEBSITE", "x.example.com", "10.0.0.5:80"));

        Assert.Contains("A route named &#x27;WEBSITE&#x27; already exists.", html, StringComparison.Ordinal);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Change_based_on_an_outdated_version_is_refused()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/routes/new", "route-edit", RouteFields("first", "first.example.com", "10.0.0.5:80")); // now version 2

        var html = await gateway.PostAsync("/routes/new", "route-edit", RouteFields("second", "second.example.com", "10.0.0.6:80")); // still says version 1

        Assert.Contains("The configuration was changed in the meantime (now version 2, you started from version 1).", html, StringComparison.Ordinal);
        Assert.DoesNotContain((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Routes, r => r.Name == "second");
    }

    [Fact]
    public async Task Disable_and_enable_buttons_switch_the_route()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/routes", "toggle-website", []);
        Assert.Contains("Route &#x27;website&#x27; disabled (version 2).", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await gateway.ProxyAsync("www.example.com")).Status);

        await gateway.PostAsync("/routes", "toggle-website", []);
        Assert.Equal((HttpStatusCode.OK, "A"), await gateway.ProxyAsync("www.example.com"));
    }

    [Fact]
    public async Task Route_used_by_a_rule_cannot_be_deleted()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.GetPageAsync("/routes/website/delete");

        Assert.Contains("This route cannot be deleted yet", html, StringComparison.Ordinal);
        Assert.Contains("rule &#x27;no-admin&#x27;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("route-delete", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unused_route_can_be_deleted()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/routes/new", "route-edit", RouteFields("temp", "temp.example.com", $"http://127.0.0.1:{gateway.B.Port}"));
        Assert.Equal(HttpStatusCode.OK, (await gateway.ProxyAsync("temp.example.com")).Status);

        var html = await gateway.PostAsync("/routes/temp/delete", "route-delete", new() { ["BaseVersion"] = "2" });

        Assert.Contains("Route &#x27;temp&#x27; deleted (version 3).", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await gateway.ProxyAsync("temp.example.com")).Status);
    }

    [Fact]
    public async Task Edited_appsettings_can_be_imported_from_the_dashboard()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.DoesNotContain("not used", await gateway.GetPageAsync("/"), StringComparison.Ordinal);

        // Simulate an edited appsettings: the watcher reads the configuration, which now has an extra route.
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        var status = gateway.App.Services.GetRequiredService<FASoft.Waf.Engine.ConfigurationStatus>();
        var extra = new FASoft.Waf.Core.Routing.ProxyRouteOptions { Name = "imported" };
        extra.Match.Hosts.Add("imported.example.com");
        extra.Destinations.Add(new FASoft.Waf.Core.Routing.ProxyDestinationOptions { Address = "127.0.0.1", Port = gateway.B.Port });
        configuration.Routes.Add(extra);
        status.SetNotice(new FASoft.Waf.Engine.AppSettingsNotice("edited-fingerprint", configuration, [], DateTimeOffset.UtcNow));

        var dashboard = await gateway.GetPageAsync("/");
        Assert.Contains("The configuration in appsettings was changed, but it is not used.", dashboard, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await gateway.ProxyAsync("imported.example.com")).Status);

        var after = await gateway.PostAsync("/", "appsettings-import", []);

        Assert.DoesNotContain("but it is not used", after, StringComparison.Ordinal);
        Assert.Equal((HttpStatusCode.OK, "B"), await gateway.ProxyAsync("imported.example.com"));
        Assert.Equal("edited-fingerprint", await gateway.Store.GetAppSettingsFingerprintAsync(Ct));
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();
}
