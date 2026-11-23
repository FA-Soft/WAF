using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;
using Waf.IntegrationTests.Proxy;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>The log viewer pages and the live view endpoint, against a running gateway.</summary>
public sealed class LogViewerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway(params string[] extra) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            [.. new RouteArgs().Add("website", [("http", A.Port)]).ToArray(), .. extra];
    }

    private static async Task<Gateway> StartWithTrafficAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "no-admin",
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/admin" } } },
        });
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/products/42"));
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/admin/users"));
        await WaitForAsync(gateway, 2);
        return gateway;
    }

    private static async Task WaitForAsync(Gateway gateway, long written)
    {
        var monitor = gateway.App.Services.GetRequiredService<IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (monitor.Statistics!.Written < written)
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }
    }

    private static async Task<JsonElement> LiveAsync(Gateway gateway, string query)
    {
        using var response = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/logs/live?{query}"), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonElement.Parse(await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Log_page_lists_and_filters_requests()
    {
        await using var gateway = await StartWithTrafficAsync();

        var all = await gateway.GetPageAsync("/logs");
        Assert.Contains("/products/42", all, StringComparison.Ordinal);
        Assert.Contains("/admin/users", all, StringComparison.Ordinal);
        Assert.Contains("<span class=\"badge badge-danger\">Blocked</span>", all, StringComparison.Ordinal);
        Assert.Contains("data-live-log", all, StringComparison.Ordinal);
        Assert.Contains("_content/Waf.Web/logs", all, StringComparison.Ordinal); // the live view script

        var blocked = await gateway.GetPageAsync("/logs?show=Blocked");
        Assert.Contains("/admin/users", blocked, StringComparison.Ordinal);
        Assert.DoesNotContain("/products/42", blocked, StringComparison.Ordinal);
        Assert.Contains("<option value=\"Blocked\" selected", blocked, StringComparison.Ordinal);

        var search = await gateway.GetPageAsync("/logs?q=PRODUCTS");
        Assert.Contains("/products/42", search, StringComparison.Ordinal);
        Assert.DoesNotContain("/admin/users", search, StringComparison.Ordinal);

        Assert.Contains("No requests match these filters.", await gateway.GetPageAsync("/logs?ip=192.0.2.1"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Pages_link_to_older_entries_and_back()
    {
        await using var gateway = await StartWithTrafficAsync();

        var first = await gateway.GetPageAsync("/logs?size=25");
        Assert.DoesNotContain("Older →", first, StringComparison.Ordinal);

        for (var i = 0; i < 30; i++)
        {
            await gateway.SendAsync($"/bulk/{i}");
        }

        await WaitForAsync(gateway, 32);
        var newest = await gateway.GetPageAsync("/logs?size=25");
        Assert.Contains("/bulk/29", newest, StringComparison.Ordinal);
        var older = System.Text.RegularExpressions.Regex.Match(newest, "href=\"(logs\\?size=25&amp;before=\\d+)\"").Groups[1].Value;
        Assert.NotEmpty(older);

        var page2 = await gateway.GetPageAsync("/" + WebUtility.HtmlDecode(older));
        Assert.Contains("/products/42", page2, StringComparison.Ordinal);
        Assert.DoesNotContain("/bulk/29", page2, StringComparison.Ordinal);
        Assert.Contains("← Newer", page2, StringComparison.Ordinal);
        Assert.Contains("Back to the newest", page2, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Live_view_returns_new_entries_after_the_last_one_shown()
    {
        await using var gateway = await StartWithTrafficAsync();
        var page = await gateway.GetPageAsync("/logs");
        var after = System.Text.RegularExpressions.Regex.Match(page, "data-live-after=\"(\\d+)\"").Groups[1].Value;

        var nothing = await LiveAsync(gateway, $"after={after}");
        Assert.Equal(0, nothing.GetProperty("items").GetArrayLength());

        await gateway.SendAsync("/new-page");
        await gateway.SendAsync("/admin/again");
        await WaitForAsync(gateway, 4);

        var blockedOnly = await LiveAsync(gateway, $"after={after}&show=Blocked");
        var item = Assert.Single(blockedOnly.GetProperty("items").EnumerateArray());
        Assert.Equal("/admin/again", item.GetProperty("path").GetString());
        Assert.Equal("Blocked", item.GetProperty("outcome").GetString());
        Assert.Equal("no-admin", item.GetProperty("rule").GetString());
        Assert.StartsWith("logs/", item.GetProperty("url").GetString(), StringComparison.Ordinal);

        // The cursor moves past entries that did not match, so the next poll does not read them again.
        var latest = blockedOnly.GetProperty("latest").GetInt64();
        Assert.Equal(await gateway.App.Services.GetRequiredService<RequestLogReader>().GetLatestIdAsync(Ct), latest);
        Assert.Equal(0, (await LiveAsync(gateway, $"after={latest}")).GetProperty("items").GetArrayLength());

        using var bad = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/logs/live"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }

    [Fact]
    public async Task Entry_page_shows_every_field()
    {
        await using var gateway = await StartWithTrafficAsync();
        var reader = gateway.App.Services.GetRequiredService<RequestLogReader>();
        var blocked = (await reader.ReadPageAsync(new RequestLogFilter { Show = LogView.Blocked }, null, null, 1, Ct)).Items.Single();

        var html = await gateway.GetPageAsync($"/logs/{blocked.Id}");

        Assert.Contains("/admin/users", html, StringComparison.Ordinal);
        Assert.Contains("no-admin", html, StringComparison.Ordinal);
        Assert.Contains("RuleBlocked", html, StringComparison.Ordinal);
        Assert.Contains("logs?range=all&amp;ip=127.0.0.1", html, StringComparison.Ordinal);
        Assert.Contains("does not exist", await gateway.GetPageAsync("/logs/999999"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Viewer_explains_when_logging_is_off()
    {
        await using var gateway = new Gateway("--Gateway:EventLog:Enabled=false");
        await gateway.InitializeAsync();

        var html = await gateway.GetPageAsync("/logs");

        Assert.Contains("Request logging is switched off", html, StringComparison.Ordinal);
        Assert.Contains("No requests have been logged yet.", html, StringComparison.Ordinal);
    }
}
