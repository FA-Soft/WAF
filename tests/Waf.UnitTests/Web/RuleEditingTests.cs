using System.ComponentModel.DataAnnotations;
using Waf.Core.Configuration;
using Waf.Web;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Web;

public class RuleEditingTests
{
    private static List<string> Errors(IValidatableObject model) =>
        [.. model.Validate(new ValidationContext(model)).Select(r => r.ErrorMessage!)];

    [Fact]
    public void Rule_round_trips_through_the_form()
    {
        var rule = Rule("office-only", RuleAction.Block, 10,
            When(ConditionField.Path, ConditionOperator.StartsWith, "/admin", "/manage"),
            WhenNot(ConditionField.ClientIp, ConditionOperator.InCidr, "203.0.113.0/24", "2001:db8::/32"),
            When(ConditionField.Header, ConditionOperator.Regex, negate: true, caseSensitive: true, headerName: "X-Api-Key", "^[a-z]{8}$"));
        rule.Description = "Office only";
        rule.DetectionOnly = true;
        rule.Routes.Add("website");

        var form = RuleFormModel.FromRule(rule, baseVersion: 4, routeNames: ["website", "api"]);
        var back = form.ToRule();

        Assert.Equal(4, form.BaseVersion);
        Assert.Equal([true, false], form.RouteChoices.Select(c => c.Selected));
        Assert.Equal(Serialize(rule), Serialize(back));
    }

    [Fact]
    public void Ip_list_accepts_lines_commas_and_spaces()
    {
        var condition = new ConditionFormModel { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = "10.0.0.1\n10.0.0.2, 10.0.1.0/24  fd00::/8;192.0.2.7" };

        Assert.Equal(["10.0.0.1", "10.0.0.2", "10.0.1.0/24", "fd00::/8", "192.0.2.7"], condition.ToCondition().Values);
        Assert.Empty(condition.Problems(1));
    }

    [Fact]
    public void Other_fields_keep_spaces_and_commas_inside_values()
    {
        var condition = new ConditionFormModel { Field = ConditionField.UserAgent, Operator = ConditionOperator.Contains, Values = "MSIE 6.0, beta\r\nMSIE 7.0\n\n" };

        Assert.Equal(["MSIE 6.0, beta", "MSIE 7.0"], condition.ToCondition().Values);
    }

    [Fact]
    public void Ip_list_problems_name_the_entry_and_condition()
    {
        var condition = new ConditionFormModel { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = "10.0.0.1/8\n10" };

        Assert.Equal(
            ["Condition 2: '10.0.0.1/8': host bits are set (did you mean 10.0.0.0/8 or 10.0.0.1/32?).", "Condition 2: '10': '10' is not a valid IP address."],
            condition.Problems(2));
    }

    [Fact]
    public void Header_condition_needs_a_header_name()
    {
        Assert.Contains("enter the name of the header", new ConditionFormModel { Field = ConditionField.Header, Values = "x" }.Problems(1).Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_condition_rows_are_ignored_but_a_rule_needs_one_condition()
    {
        var form = RuleFormModel.ForNewRule(1, []);
        form.Name = "r";
        form.Conditions.Add(new ConditionFormModel());

        Assert.Contains(Errors(form), e => e.StartsWith("Add at least one condition.", StringComparison.Ordinal));

        form.Conditions[0].Values = "/admin";
        Assert.Empty(Errors(form));
        Assert.Single(form.ToRule().Conditions);
    }

    [Fact]
    public void A_condition_row_with_changed_choices_but_no_values_is_not_silently_dropped()
    {
        var form = RuleFormModel.ForNewRule(1, []);
        form.Name = "lock";
        form.Conditions = [new() { Values = "/admin" }, new() { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Negate = true }];

        // Dropping the IP row would turn "only these IPs may open /admin" into "nobody may open /admin".
        Assert.Contains("Condition 2: enter at least one value.", Errors(form));
    }

    [Theory]
    [InlineData("block-ips", "blocked-ips", RuleAction.Block, 10)]
    [InlineData("allow-ips", "trusted-ips", RuleAction.Allow, 5)]
    public void Ip_list_templates_prefill_a_client_ip_condition(string template, string name, RuleAction action, int priority)
    {
        var form = RuleFormModel.ForNewRule(1, ["website"], template);

        Assert.Equal((name, action, priority, true), (form.Name, form.Action, form.Priority, form.Enabled));
        var condition = Assert.Single(form.Conditions);
        Assert.Equal((ConditionField.ClientIp, ConditionOperator.InCidr), (condition.Field, condition.Operator));
    }

    [Fact]
    public void Condition_commands_add_and_remove_rows()
    {
        List<ConditionFormModel> rows = [new() { Values = "/a" }, new() { Values = "/b" }];

        Assert.True(ConditionCommands.TryApply(ConditionCommands.Add, rows));
        Assert.Equal(3, rows.Count);
        Assert.True(ConditionCommands.TryApply("remove-condition-0", rows));
        Assert.Equal("/b", rows[0].Values);
        Assert.True(ConditionCommands.TryApply("remove-condition-9", rows)); // out of range: ignored
        Assert.False(ConditionCommands.TryApply(null, rows));               // Save

        List<ConditionFormModel> single = [new() { Values = "/a" }];
        ConditionCommands.TryApply("remove-condition-0", single);
        Assert.Single(single); // an empty row stays, so the editor is never empty
        Assert.True(single[0].IsEmpty);
    }

    [Theory]
    [InlineData(60, 1, 60)]
    [InlineData(120, 2, 60)]
    [InlineData(90, 90, 1)]
    [InlineData(7200, 2, 3600)]
    [InlineData(86_400, 1, 86_400)]
    public void Rate_limit_window_is_shown_in_the_largest_whole_unit(int seconds, int amount, int unit)
    {
        var form = RateLimitFormModel.FromLimit(new RateLimitRule { Name = "x", WindowSeconds = seconds }, 1, []);

        Assert.Equal((amount, unit), (form.WindowAmount, form.WindowUnitSeconds));
        Assert.Equal(seconds, form.ToLimit().WindowSeconds);
    }

    [Fact]
    public void Rate_limit_round_trips_through_the_form()
    {
        var limit = new RateLimitRule { Name = "login", Description = "Login", PermitLimit = 5, WindowSeconds = 60, Key = RateLimitKey.ClientIpAndRoute, DetectionOnly = true };
        limit.Routes.Add("website");
        limit.Conditions.Add(When(ConditionField.Path, ConditionOperator.Equals, "/login"));

        var back = RateLimitFormModel.FromLimit(limit, 1, ["website"]).ToLimit();

        var a = new GatewayConfiguration();
        a.RateLimits.Add(limit);
        var b = new GatewayConfiguration();
        b.RateLimits.Add(back);
        Assert.Equal(GatewayConfigurationJson.Serialize(a), GatewayConfigurationJson.Serialize(b));
    }

    [Fact]
    public void Rate_limit_without_conditions_counts_all_requests()
    {
        var form = RateLimitFormModel.ForNewLimit(1, []);
        form.Name = "per-client";

        Assert.Empty(Errors(form));
        Assert.Empty(form.ToLimit().Conditions);
    }

    [Fact]
    public void Rate_limit_window_longer_than_a_day_is_rejected()
    {
        var form = RateLimitFormModel.ForNewLimit(1, []);
        form.Name = "x";
        form.WindowAmount = 2;
        form.WindowUnitSeconds = 86_400;

        Assert.Contains("The window can be at most one day.", Errors(form));
    }

    private static string Serialize(WafRule rule)
    {
        var configuration = new GatewayConfiguration();
        configuration.Rules.Add(rule);
        return GatewayConfigurationJson.Serialize(configuration);
    }
}
