using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

public class LogActionsTests
{
    private static GatewayConfiguration Configuration()
    {
        var configuration = new GatewayConfiguration();
        configuration.Routes.Add(new ProxyRouteOptions { Name = "website", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } });
        configuration.Routes.Add(new ProxyRouteOptions { Name = "api", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.6", Port = 80 } } });
        configuration.Rules.Add(new WafRule
        {
            Name = "no-admin",
            Priority = 30,
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/admin" } } },
        });
        return configuration;
    }

    private static RequestEvent Entry(string action = "Blocked", string? wafEvent = "RuleBlocked", string? rule = "no-admin", string? route = "website",
        string path = "/admin/users", string host = "www.example.com", string? detail = null) => new()
        {
            Id = 42,
            ClientIp = "203.0.113.7",
            Method = "GET",
            Host = host,
            Path = path,
            RouteName = route,
            Action = action,
            Event = wafEvent,
            RuleName = rule,
            Detail = detail,
            StatusCode = 403,
        };

    private static List<string> Errors(IValidatableObject model) =>
        [.. model.Validate(new ValidationContext(model)).Select(r => r.ErrorMessage!)];

    [Fact]
    public void Actions_depend_on_what_happened()
    {
        var configuration = Configuration();

        Assert.Equal(
            [LogAction.Allow, LogAction.Block, LogAction.Rule],
            LogActions.Available(Entry(), configuration).Select(a => a.Action));
        Assert.Equal(
            [LogAction.Route, LogAction.Block, LogAction.Rule],
            LogActions.Available(Entry(action: "NoRoute", wafEvent: null, rule: null, route: null), configuration).Select(a => a.Action));
        Assert.Equal(
            [LogAction.Block, LogAction.Rule],
            LogActions.Available(Entry(action: "Forwarded", wafEvent: null, rule: null), configuration).Select(a => a.Action));
        Assert.Contains("before 'no-admin'", LogActions.Available(Entry(), configuration)[0].Help, StringComparison.Ordinal);
    }

    [Fact]
    public void Urls_open_the_right_editor()
    {
        var configuration = Configuration();

        Assert.Equal("routes/new?fromLog=42", LogActions.Url(Entry(), LogAction.Route, configuration));
        Assert.Equal("rules/new?fromLog=42&action=Allow", LogActions.Url(Entry(), LogAction.Allow, configuration));
        Assert.Equal("detection/exclusions/new?fromLog=42", LogActions.Url(Entry(wafEvent: "AttackBlocked", rule: "sqli-1", detail: "SqlInjection in QueryString 'q': union select"), LogAction.Allow, configuration));
        Assert.Equal("rules/new?fromLog=42&action=Block", LogActions.Url(Entry(), LogAction.Block, configuration));

        configuration.Rules.Add(new WafRule { Name = "blocked-ips", Priority = 10, Conditions = { new RuleCondition { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = { "198.51.100.0/24" } } } });
        Assert.Equal("rules/blocked-ips/edit?fromLog=42&action=Block", LogActions.Url(Entry(), LogAction.Block, configuration));
    }

    [Fact]
    public void New_route_takes_the_host_and_needs_a_backend()
    {
        var configuration = Configuration();
        configuration.Routes.Add(new ProxyRouteOptions { Name = "shop-example-org", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.7", Port = 80 } } });

        var form = LogActions.NewRoute(Entry(action: "NoRoute", route: null, host: "Shop.Example.org"), configuration, 3);

        Assert.Equal(("shop-example-org-2", "Shop.Example.org", "/", 3L, true), (form.Name, form.Hosts, form.PathPrefix, form.BaseVersion, form.Enabled));
        // The backend is left for the user: saving without one is refused by the form.
        var results = new List<ValidationResult>();
        Assert.False(Validator.TryValidateObject(form, new ValidationContext(form), results, validateAllProperties: true));
        Assert.Contains(results, r => r.ErrorMessage!.StartsWith("Enter at least one backend address", StringComparison.Ordinal));
    }

    [Fact]
    public void New_rule_matches_the_path_on_the_same_route()
    {
        var form = LogActions.NewRule(Entry(path: "/Reports/2026"), LogAction.Rule, Configuration(), 3);

        Assert.Equal(("rule-reports-2026", RuleAction.Block), (form.Name, form.Action));
        Assert.Equal("/Reports/2026", Assert.Single(form.Conditions).Values);
        Assert.Equal(["website"], form.RouteChoices.Where(r => r.Selected).Select(r => r.Name));
        Assert.Empty(Errors(form));
    }

    [Fact]
    public void Block_starts_an_ip_block_list_with_the_client()
    {
        var form = LogActions.NewRule(Entry(), LogAction.Block, Configuration(), 3);

        Assert.Equal(("blocked-ips", RuleAction.Block, 10), (form.Name, form.Action, form.Priority));
        Assert.Equal(["203.0.113.7"], form.ToRule().Conditions.Single().Values);
        Assert.DoesNotContain(form.RouteChoices, r => r.Selected); // a source is blocked everywhere
        Assert.Empty(Errors(form));
    }

    [Fact]
    public void Block_adds_the_client_to_an_existing_list_once()
    {
        var rule = new WafRule { Name = "blocked-ips", Conditions = { new RuleCondition { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = { "198.51.100.0/24" } } } };
        var form = RuleFormModel.FromRule(rule, 3, ["website"]);

        Assert.True(LogActions.AddToBlockList(form, Entry()));
        Assert.Equal(["198.51.100.0/24", "203.0.113.7"], form.ToRule().Conditions.Single().Values);
        Assert.False(LogActions.AddToBlockList(form, Entry()));

        var covered = RuleFormModel.FromRule(rule, 3, []);
        var inRange = Entry();
        inRange.ClientIp = "198.51.100.9";
        Assert.False(LogActions.AddToBlockList(covered, inRange));
    }

    [Fact]
    public void Allow_runs_before_the_rule_that_blocked()
    {
        var form = LogActions.NewRule(Entry(), LogAction.Allow, Configuration(), 3);

        Assert.Equal(("allow-no-admin-exception", RuleAction.Allow, 29), (form.Name, form.Action, form.Priority));
        Assert.Equal("The path starts with /admin/users and the client IP is in 203.0.113.7", Describe.Conditions(form.ToRule().Conditions));
        Assert.Empty(Errors(form));

        var limited = LogActions.NewRule(Entry(action: "RateLimited", wafEvent: "RateLimited", rule: "per-client"), LogAction.Allow, Configuration(), 3);
        Assert.Equal("The client IP is in 203.0.113.7", Describe.Conditions(limited.ToRule().Conditions));
    }

    [Fact]
    public void False_positive_of_attack_detection_becomes_an_exclusion()
    {
        var entry = Entry(wafEvent: "AttackBlocked", rule: "xss-script-tag", path: "/cms/editor/save", detail: "CrossSiteScripting in QueryString 'body': <script>");

        var form = LogActions.NewExclusion(entry, Configuration(), 3);
        var exclusion = form.ToExclusion();

        Assert.Equal(AttackCategory.CrossSiteScripting, LogActions.AttackCategoryOf(entry));
        Assert.Equal("/cms/editor/save", exclusion.PathPrefix);
        Assert.Equal([AttackCategory.CrossSiteScripting], exclusion.Categories);
        Assert.Equal(["website"], exclusion.Routes);
        Assert.StartsWith("False positive: CrossSiteScripting", exclusion.Reason, StringComparison.Ordinal);
        Assert.Empty(Errors(form));

        var configuration = Configuration();
        configuration.Settings.AttackDetection.Exclusions.Add(exclusion);
        Assert.Empty(GatewayConfigurationValidator.Validate(configuration));
    }

    [Theory]
    [InlineData("www.example.com", "site", "www-example-com")]
    [InlineData("/", "root", "root")]
    [InlineData("/a b/ÄÖ/c", "x", "a-b-c")]
    public void Slugs(string text, string fallback, string expected)
    {
        Assert.Equal(expected, LogActions.Slug(text, fallback));
    }
}
