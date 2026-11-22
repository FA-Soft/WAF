using System.Net;
using Waf.Core.Configuration;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// Rules and rate-limit pages of the admin UI, driven through real form posts against a running gateway.
/// Every test has its own gateway (one catch-all route to backend A, no rules).
/// </summary>
public sealed class RulesUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)]).ToArray();
    }

    /// <summary>Form fields of a new rule with one condition, as a browser posts them (unticked checkboxes are left out).</summary>
    private static Dictionary<string, string> RuleFields(
        string name, string field, string op, string values, string action = "Block", bool enabled = true, bool negate = false, int priority = 100)
    {
        var fields = new Dictionary<string, string>
        {
        ["Model.BaseVersion"] = "1",
        ["Model.IsNew"] = "true",
        ["Model.Name"] = name,
        ["Model.Action"] = action,
        ["Model.Priority"] = priority.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["Model.Conditions[0].Field"] = field,
        ["Model.Conditions[0].Operator"] = op,
        ["Model.Conditions[0].Values"] = values,
        };

        if (enabled)
        {
            fields["Model.Enabled"] = "True";
        }

        if (negate)
        {
            fields["Model.Conditions[0].Negate"] = "true";
        }

        return fields;
    }

    private static async Task<WafRule?> StoredRuleAsync(Gateway gateway, string name) =>
        (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Rules.FirstOrDefault(r => r.Name == name);

    [Fact]
    public async Task Adding_a_rule_blocks_matching_requests_immediately()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/secret/x"));

        var html = await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("no-secret", "Path", "StartsWith", "/secret"));

        Assert.Contains("Rule &#x27;no-secret&#x27; added (version 2).", html, StringComparison.Ordinal);
        Assert.Contains("The path starts with /secret", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/secret/x"));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/public"));
    }

    [Fact]
    public async Task Ip_block_list_blocks_the_listed_clients()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var form = await gateway.GetPageAsync("/rules/new?template=block-ips");
        Assert.Contains("value=\"blocked-ips\"", form, StringComparison.Ordinal);

        // The test client connects from 127.0.0.1.
        await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("blocked-ips", "ClientIp", "InCidr", "198.51.100.0/24\n127.0.0.1", priority: 10));

        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/"));
        Assert.Equal(["198.51.100.0/24", "127.0.0.1"], (await StoredRuleAsync(gateway, "blocked-ips"))!.Conditions[0].Values);
    }

    [Fact]
    public async Task Invalid_ip_entries_are_explained_and_nothing_is_stored()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("bad-ips", "ClientIp", "InCidr", "10.0.0.1/8\n10"));

        Assert.Contains("Condition 1: &#x27;10.0.0.1/8&#x27;: host bits are set (did you mean 10.0.0.0/8 or 10.0.0.1/32?).", html, StringComparison.Ordinal);
        Assert.Contains("Condition 1: &#x27;10&#x27;: &#x27;10&#x27; is not a valid IP address.", html, StringComparison.Ordinal);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Operator_that_does_not_fit_the_field_is_explained()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("odd", "Method", "Contains", "POST"));

        Assert.Contains("operator Contains cannot be used with Method (use Equals)", html, StringComparison.Ordinal);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Add_condition_button_adds_a_row_without_saving()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var fields = RuleFields("two", "Path", "StartsWith", "/admin");
        fields["Model.Command"] = "add-condition";

        var html = await gateway.PostAsync("/rules/new", "rule-edit", fields);

        Assert.Contains("Condition 2", html, StringComparison.Ordinal);
        Assert.Contains("/admin", html, StringComparison.Ordinal); // what was typed is kept
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Rule_with_two_conditions_requires_both()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var fields = RuleFields("admin-post", "Path", "StartsWith", "/admin");
        fields["Model.Conditions[1].Field"] = "Method";
        fields["Model.Conditions[1].Operator"] = "Equals";
        fields["Model.Conditions[1].Values"] = "POST";

        await gateway.PostAsync("/rules/new", "rule-edit", fields);

        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/admin", HttpMethod.Post));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/admin"));
    }

    [Fact]
    public async Task Editing_and_unticking_enabled_disables_the_rule()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("no-secret", "Path", "StartsWith", "/secret"));

        var fields = RuleFields("no-secret", "Path", "StartsWith", "/secret", enabled: false);
        fields["Model.IsNew"] = "false";
        fields["Model.BaseVersion"] = "2";
        fields.Remove("Model.Enabled"); // an unticked checkbox is not posted
        await gateway.PostAsync("/rules/no-secret/edit", "rule-edit", fields);

        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/secret"));
        Assert.False((await StoredRuleAsync(gateway, "no-secret"))!.Enabled);
    }

    [Fact]
    public async Task Global_detection_only_lets_blocked_requests_through_and_can_be_switched_back()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("no-secret", "Path", "StartsWith", "/secret"));

        var html = await gateway.PostAsync("/rules", "detection-only-toggle", []);

        Assert.Contains("Detection-only mode switched on (version 3).", html, StringComparison.Ordinal);
        Assert.Contains("Detection only", html, StringComparison.Ordinal); // badge in the top bar
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/secret"));

        await gateway.PostAsync("/rules", "detection-only-toggle", []);
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/secret"));
    }

    [Fact]
    public async Task Rule_can_be_disabled_from_the_list_and_deleted()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/rules/new", "rule-edit", RuleFields("no-secret", "Path", "StartsWith", "/secret"));

        await gateway.PostAsync("/rules", "toggle-rule-no-secret", []);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/secret"));

        var html = await gateway.PostAsync("/rules/no-secret/delete", "rule-delete", new() { ["BaseVersion"] = "3" });
        Assert.Contains("Rule &#x27;no-secret&#x27; deleted (version 4).", html, StringComparison.Ordinal);
        Assert.Null(await StoredRuleAsync(gateway, "no-secret"));
    }

    [Fact]
    public async Task Rate_limit_added_in_the_ui_limits_requests()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var html = await gateway.PostAsync("/rate-limits/new", "rate-limit-edit", new()
        {
            ["Model.BaseVersion"] = "1",
            ["Model.IsNew"] = "true",
            ["Model.Name"] = "login-attempts",
            ["Model.PermitLimit"] = "2",
            ["Model.WindowAmount"] = "1",
            ["Model.WindowUnitSeconds"] = "60",
            ["Model.Key"] = "ClientIp",
            ["Model.Enabled"] = "True",
            ["Model.Conditions[0].Field"] = "Path",
            ["Model.Conditions[0].Operator"] = "Equals",
            ["Model.Conditions[0].Values"] = "/login",
        });

        Assert.Contains("Rate limit &#x27;login-attempts&#x27; added (version 2).", html, StringComparison.Ordinal);
        Assert.Contains("2 requests per minute per client IP", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/login"));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/login"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await gateway.SendAsync("/login"));
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/products")); // other paths are not counted
    }

    [Fact]
    public async Task Rate_limit_can_be_disabled_and_deleted()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.PostAsync("/rate-limits/new", "rate-limit-edit", new()
        {
            ["Model.BaseVersion"] = "1",
            ["Model.IsNew"] = "true",
            ["Model.Name"] = "tight",
            ["Model.PermitLimit"] = "1",
            ["Model.WindowAmount"] = "1",
            ["Model.WindowUnitSeconds"] = "3600",
            ["Model.Key"] = "ClientIp",
            ["Model.Enabled"] = "True",
        });
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await gateway.SendAsync("/"));

        await gateway.PostAsync("/rate-limits", "toggle-limit-tight", []);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/"));

        var html = await gateway.PostAsync("/rate-limits/tight/delete", "rate-limit-delete", new() { ["BaseVersion"] = "3" });
        Assert.Contains("Rate limit &#x27;tight&#x27; deleted (version 4).", html, StringComparison.Ordinal);
    }
}
