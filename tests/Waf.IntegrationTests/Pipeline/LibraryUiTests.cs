using System.Net;
using System.Text.RegularExpressions;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// Template library and one-click presets, driven through real form posts against a running gateway.
/// Every test has its own gateway (one catch-all route to backend A, no rules).
/// </summary>
public sealed partial class LibraryUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)]).ToArray();
    }

    private static string PreviewTag(string html) => PreviewTagPattern().Match(html).Groups["tag"].Value;

    private static async Task<long> ActiveVersionAsync(Gateway gateway) =>
        (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version;

    [Fact]
    public async Task Library_lists_presets_and_templates()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.GetPageAsync("/library");

        Assert.Contains("href=\"presets/block-common-attacks\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"presets/lock-path\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"routes/new?template=website\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"rules/new?template=block-wordpress-probes\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"rate-limits/new?template=login\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"library\"", await gateway.GetPageAsync("/"), StringComparison.Ordinal); // navigation
    }

    [Fact]
    public async Task Templates_prefill_the_editors()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var route = await gateway.GetPageAsync("/routes/new?template=api");
        var rule = await gateway.GetPageAsync("/rules/new?template=block-wordpress-probes");
        var limit = await gateway.GetPageAsync("/rate-limits/new?template=login");

        Assert.Contains("Started from the template &quot;API under a path&quot;", route, StringComparison.Ordinal);
        Assert.Contains("value=\"/api\"", route, StringComparison.Ordinal);
        Assert.Contains("value=\"block-wordpress-probes\"", rule, StringComparison.Ordinal);
        Assert.Contains("/wp-login.php", rule, StringComparison.Ordinal);
        Assert.Contains("value=\"login-attempts\"", limit, StringComparison.Ordinal);
        Assert.DoesNotContain("Started from the template", await gateway.GetPageAsync("/rules/new"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Preset_shows_a_preview_and_changes_nothing_until_applied()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.GetPageAsync("/presets/block-common-attacks");

        Assert.Contains("Preview: what will change", html, StringComparison.Ordinal);
        Assert.Contains("Add rule &#x27;block-sensitive-files&#x27;", html, StringComparison.Ordinal);
        Assert.Contains("Add rule &#x27;block-unusual-methods&#x27;", html, StringComparison.Ordinal);
        Assert.Contains("value=\"apply\"", html, StringComparison.Ordinal);
        Assert.Equal(1, await ActiveVersionAsync(gateway));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/backup.zip")); // attack detection alone lets it through
    }

    [Fact]
    public async Task Applying_a_preset_activates_exactly_the_previewed_changes()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var tag = PreviewTag(await gateway.GetPageAsync("/presets/block-common-attacks"));

        var html = await gateway.PostAsync("/presets/block-common-attacks", "preset-apply", new()
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = tag,
        });

        Assert.Contains("Preset &#x27;Block common attacks&#x27; applied (version 2).", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/backup.zip"));
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/index.php.bak"));
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/", new HttpMethod("TRACE")));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/"));

        // Applying it again has nothing left to change.
        Assert.Contains("Nothing to change: this preset is already in place.", await gateway.GetPageAsync("/presets/block-common-attacks"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Apply_is_refused_when_the_preview_is_out_of_date()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/presets/block-common-attacks", "preset-apply", new()
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = "0123456789abcdef",
        });

        Assert.Contains("changed since the preview", html, StringComparison.Ordinal);
        Assert.Equal(1, await ActiveVersionAsync(gateway));
        Assert.NotEqual("0123456789abcdef", PreviewTag(html)); // the page now shows the current preview
    }

    [Fact]
    public async Task Lock_path_preset_needs_inputs_then_locks_the_path()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var empty = await gateway.GetPageAsync("/presets/lock-path");
        Assert.Contains("Enter at least one IP address", empty, StringComparison.Ordinal);
        Assert.DoesNotContain("value=\"apply\"", empty, StringComparison.Ordinal);

        var fields = new Dictionary<string, string>
        {
            ["Model.Command"] = "preview",
            ["Model.PathPrefix"] = "/admin",
            ["Model.AllowedIps"] = "198.51.100.7", // the test client is 127.0.0.1, so it is locked out
        };
        var preview = await gateway.PostAsync("/presets/lock-path", "preset-apply", new(fields));
        Assert.Contains("Add rule &#x27;lock-admin&#x27;", preview, StringComparison.Ordinal);
        Assert.Contains("The path starts with /admin and the client IP is not in 198.51.100.7", preview, StringComparison.Ordinal);
        Assert.Equal(1, await ActiveVersionAsync(gateway));

        // Changing an input after the preview must not apply unseen changes.
        var edited = await gateway.PostAsync("/presets/lock-path", "preset-apply", new(fields)
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = PreviewTag(preview),
            ["Model.PathPrefix"] = "/manage",
        });
        Assert.Contains("changed since the preview", edited, StringComparison.Ordinal);
        Assert.Equal(1, await ActiveVersionAsync(gateway));

        var applied = await gateway.PostAsync("/presets/lock-path", "preset-apply", new(fields)
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = PreviewTag(preview),
        });
        Assert.Contains("applied (version 2)", applied, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/admin/users"));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/manage"));
    }

    [Fact]
    public async Task Unknown_preset_says_so()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        Assert.Contains("There is no preset", await gateway.GetPageAsync("/presets/nope"), StringComparison.Ordinal);
    }

    [GeneratedRegex("""name="Model.PreviewTag" value="(?<tag>[0-9a-f]*)""")]
    private static partial Regex PreviewTagPattern();
}
