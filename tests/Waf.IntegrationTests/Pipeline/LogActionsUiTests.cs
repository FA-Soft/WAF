using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;
using Waf.IntegrationTests.Proxy;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// From a request log entry to configuration: every action opens a pre-filled form, which is saved unchanged (as a
/// user who reviewed it would) and must then change how the same request is handled.
/// </summary>
public sealed partial class LogActionsUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Route "website" for www.example.com to backend A, and a rule blocking /admin.</summary>
    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)], hosts: ["www.example.com"]).ToArray();
    }

    private static async Task<Gateway> StartAsync(Action<GatewayConfiguration>? configure = null)
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "no-admin",
            Priority = 30,
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/admin" } } },
        });
        configure?.Invoke(configuration);
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, "test", null, Ct)).Succeeded);
        return gateway;
    }

    private static async Task<HttpStatusCode> SendAsync(Gateway gateway, string pathAndQuery, string host = "www.example.com")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{pathAndQuery}"));
        request.Headers.Host = host;
        using var response = await gateway.Public.SendAsync(request, Ct);
        return response.StatusCode;
    }

    /// <summary>The log entry of the last request, once it is written.</summary>
    private static async Task<RequestEvent> LastEntryAsync(Gateway gateway)
    {
        var monitor = gateway.App.Services.GetRequiredService<IRequestLogMonitor>();
        var reader = gateway.App.Services.GetRequiredService<RequestLogReader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (monitor.Statistics!.Queued > 0 || await reader.GetLatestIdAsync(Ct) == 0)
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }

        await Task.Delay(200, Ct); // the writer commits in batches
        return (await reader.GetAsync(await reader.GetLatestIdAsync(Ct), Ct))!;
    }

    /// <summary>Opens the entry page, follows the action link with <paramref name="label"/>, returns the editor's address and HTML.</summary>
    private static async Task<(string Path, string Html)> OpenActionAsync(Gateway gateway, RequestEvent entry, string label)
    {
        var page = await gateway.GetPageAsync($"/logs/{entry.Id}");
        var link = Regex.Match(page, $"<a class=\"button[^\"]*\" href=\"(?<href>[^\"]+)\">{Regex.Escape(WebUtility.HtmlEncode(label))}</a>");
        Assert.True(link.Success, $"Action '{label}' not on the entry page.");
        var path = "/" + WebUtility.HtmlDecode(link.Groups["href"].Value);
        var html = await gateway.GetPageAsync(path);
        Assert.Contains($"Pre-filled from <a href=\"logs/{entry.Id}\">request {entry.Id}</a>", html, StringComparison.Ordinal);
        return (path, html);
    }

    [Fact]
    public async Task Blocking_a_source_starts_an_ip_block_list()
    {
        await using var gateway = await StartAsync();
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/products"));
        var entry = await LastEntryAsync(gateway);

        var (path, html) = await OpenActionAsync(gateway, entry, "Block 127.0.0.1");
        Assert.StartsWith("/rules/new?fromLog=", path, StringComparison.Ordinal);

        var saved = await gateway.PostAsync(path, "rule-edit", AdminGateway.ScrapeForm(html, "rule-edit"));

        Assert.Contains("Rule &#x27;blocked-ips&#x27; added", saved, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/products"));
    }

    [Fact]
    public async Task Blocking_a_source_adds_it_to_the_existing_ip_block_list()
    {
        await using var gateway = await StartAsync(c => c.Rules.Add(new WafRule
        {
            Name = "bad-networks",
            Priority = 10,
            Conditions = { new RuleCondition { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = { "198.51.100.0/24" } } },
        }));
        await SendAsync(gateway, "/products");
        var entry = await LastEntryAsync(gateway);

        var (path, html) = await OpenActionAsync(gateway, entry, "Block 127.0.0.1");
        Assert.StartsWith("/rules/bad-networks/edit?", path, StringComparison.Ordinal);
        Assert.Contains("127.0.0.1 was added to this IP block list.", html, StringComparison.Ordinal);

        await gateway.PostAsync(path, "rule-edit", AdminGateway.ScrapeForm(html, "rule-edit"));

        var rule = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Rules.Single(r => r.Name == "bad-networks");
        Assert.Equal(["198.51.100.0/24", "127.0.0.1"], rule.Conditions[0].Values);
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/products"));
    }

    [Fact]
    public async Task Allowing_a_false_positive_of_a_rule_adds_an_exception_before_it()
    {
        await using var gateway = await StartAsync();
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/admin/users"));
        var entry = await LastEntryAsync(gateway);
        Assert.Equal("no-admin", entry.RuleName);

        var (path, html) = await OpenActionAsync(gateway, entry, "Allow this (false positive)");
        await gateway.PostAsync(path, "rule-edit", AdminGateway.ScrapeForm(html, "rule-edit"));

        var allow = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Rules.Single(r => r.Action == RuleAction.Allow);
        Assert.Equal(("allow-no-admin-exception", 29), (allow.Name, allow.Priority));
        Assert.Equal(["website"], allow.Routes);
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/admin/users"));
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/admin/settings")); // only the path that was allowed
    }

    [Fact]
    public async Task Allowing_a_false_positive_of_attack_detection_adds_an_exclusion()
    {
        await using var gateway = await StartAsync();
        const string Request = "/cms/editor/save?body=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, Request));
        var entry = await LastEntryAsync(gateway);

        var (path, html) = await OpenActionAsync(gateway, entry, "Allow this (false positive)");
        Assert.StartsWith("/detection/exclusions/new?", path, StringComparison.Ordinal);

        var saved = await gateway.PostAsync(path, "exclusion-edit", AdminGateway.ScrapeForm(html, "exclusion-edit"));

        Assert.Contains("Detection exclusion for /cms/editor/save added", saved, StringComparison.Ordinal);
        var exclusion = Assert.Single((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.AttackDetection.Exclusions);
        Assert.Equal([AttackCategory.CrossSiteScripting], exclusion.Categories);
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, Request));
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/other?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")); // elsewhere still checked

        // The Rules page lists the exclusion and can remove it again.
        var rules = await gateway.GetPageAsync("/rules");
        Assert.Contains("<code>/cms/editor/save</code>", rules, StringComparison.Ordinal);
        var removed = await gateway.PostAsync("/rules", "remove-exclusion-0", []);
        Assert.Contains("Detection exclusion for /cms/editor/save removed", removed, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, Request));
    }

    [Fact]
    public async Task A_request_without_a_route_becomes_a_route()
    {
        await using var gateway = await StartAsync();
        Assert.Equal(HttpStatusCode.NotFound, await SendAsync(gateway, "/", host: "shop.example.org"));
        var entry = await LastEntryAsync(gateway);

        var (path, html) = await OpenActionAsync(gateway, entry, "Create a route for shop.example.org");
        Assert.Contains("Enter the backend that should receive these requests.", html, StringComparison.Ordinal);

        // The user reviews the form and enters the backend.
        var fields = AdminGateway.ScrapeForm(html, "route-edit");
        Assert.Equal(("shop-example-org", "shop.example.org"), (fields["Model.Name"], fields["Model.Hosts"]));
        fields["Model.Destinations"] = $"http://127.0.0.1:{gateway.B.Port}";
        await gateway.PostAsync(path, "route-edit", fields);

        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/", host: "shop.example.org"));
    }

    [Fact]
    public async Task A_rule_for_a_path_is_pre_filled_with_the_path_and_route()
    {
        await using var gateway = await StartAsync();
        await SendAsync(gateway, "/reports/2026");
        var entry = await LastEntryAsync(gateway);

        var (path, html) = await OpenActionAsync(gateway, entry, "Create a rule for this path");
        await gateway.PostAsync(path, "rule-edit", AdminGateway.ScrapeForm(html, "rule-edit"));

        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync(gateway, "/reports/2026/q1"));
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "/reports"));
    }
}
