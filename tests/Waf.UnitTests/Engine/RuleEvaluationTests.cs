using Waf.Core.Configuration;
using Waf.Engine;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Engine;

public class RuleEvaluationTests
{
    private static readonly FakeRequest Request = new();

    [Fact]
    public void Empty_rule_set_allows_without_allocating_a_decision()
    {
        var decision = CompiledRuleSet.Empty.Evaluate(Request);

        Assert.Same(WafDecision.AllowedByDefault, decision);
        Assert.Equal(WafVerdict.Allow, decision.Verdict);
        Assert.Null(decision.DecidingRule);
    }

    [Fact]
    public void Lower_priority_number_runs_first()
    {
        var allowFirst = Compile(Rule("block", RuleAction.Block, 20), Rule("allow", RuleAction.Allow, 10));
        var blockFirst = Compile(Rule("block", RuleAction.Block, 10), Rule("allow", RuleAction.Allow, 20));

        Assert.Equal(("allow", WafVerdict.Allow), (allowFirst.Evaluate(Request).DecidingRule!.RuleName, allowFirst.Evaluate(Request).Verdict));
        Assert.Equal(("block", WafVerdict.Block), (blockFirst.Evaluate(Request).DecidingRule!.RuleName, blockFirst.Evaluate(Request).Verdict));
    }

    [Fact]
    public void Equal_priorities_are_ordered_by_name()
    {
        var rules = Compile(Rule("b-block", RuleAction.Block, 10), Rule("a-allow", RuleAction.Allow, 10));

        Assert.Equal(["a-allow", "b-block"], rules.RuleNames);
        Assert.Equal(WafVerdict.Allow, rules.Evaluate(Request).Verdict);
    }

    [Fact]
    public void First_deciding_rule_stops_evaluation()
    {
        var decision = Compile(Rule("block", RuleAction.Block, 10), Rule("log", RuleAction.LogOnly, 20)).Evaluate(Request);

        Assert.Equal(["block"], decision.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void LogOnly_records_and_continues()
    {
        var decision = Compile(Rule("log", RuleAction.LogOnly, 10), Rule("block", RuleAction.Block, 20)).Evaluate(Request);

        Assert.Equal(WafVerdict.Block, decision.Verdict);
        Assert.Equal("block", decision.DecidingRule!.RuleName);
        Assert.Equal(["log", "block"], decision.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void LogOnly_alone_allows_but_reports_the_match()
    {
        var decision = Compile(Rule("log", RuleAction.LogOnly, 10)).Evaluate(Request);

        Assert.Equal(WafVerdict.Allow, decision.Verdict);
        Assert.Null(decision.DecidingRule);
        Assert.Equal(RuleAction.LogOnly, Assert.Single(decision.Matches).Action);
    }

    [Fact]
    public void Rule_in_detection_only_mode_does_not_block_and_evaluation_continues()
    {
        var tryOut = Rule("try-out", RuleAction.Block, 10);
        tryOut.DetectionOnly = true;
        var decision = Compile(tryOut, Rule("allow", RuleAction.Allow, 20)).Evaluate(Request);

        Assert.Equal(WafVerdict.Allow, decision.Verdict);
        Assert.Equal("allow", decision.DecidingRule!.RuleName);
        Assert.True(decision.WouldHaveBlocked);
        Assert.Equal(new RuleMatch("try-out", RuleAction.Block, DetectionOnly: true), decision.Matches[0]);
    }

    [Fact]
    public void Detection_only_rule_does_not_hide_a_later_enforced_block()
    {
        var tryOut = Rule("try-out", RuleAction.Block, 10);
        tryOut.DetectionOnly = true;
        var decision = Compile(tryOut, Rule("block", RuleAction.Block, 20)).Evaluate(Request);

        Assert.Equal(WafVerdict.Block, decision.Verdict);
        Assert.Equal("block", decision.DecidingRule!.RuleName);
    }

    [Fact]
    public void Global_detection_only_suppresses_every_block_but_not_allow()
    {
        var configuration = Config(Rule("block-1", RuleAction.Block, 10), Rule("block-2", RuleAction.Block, 20));
        configuration.Settings.DetectionOnly = true;
        var rules = CompiledRuleSet.Compile(configuration);

        var decision = rules.Evaluate(Request);

        Assert.True(rules.DetectionOnly);
        Assert.Equal(WafVerdict.Allow, decision.Verdict);
        Assert.All(decision.Matches, m => Assert.True(m.DetectionOnly));
        Assert.Equal(2, decision.Matches.Count);
    }

    [Fact]
    public void Disabled_rules_are_ignored()
    {
        var disabled = Rule("block", RuleAction.Block, 10);
        disabled.Enabled = false;
        var rules = Compile(disabled);

        Assert.Empty(rules.RuleNames);
        Assert.Equal(WafVerdict.Allow, rules.Evaluate(Request).Verdict);
    }

    [Fact]
    public void All_conditions_must_match()
    {
        var rules = Compile(Rule("admin-post", RuleAction.Block, 10,
            When(ConditionField.Path, ConditionOperator.StartsWith, "/admin"),
            When(ConditionField.Method, ConditionOperator.Equals, "POST")));

        Assert.True(rules.Evaluate(Request with { Path = "/admin/x", Method = "POST" }).IsBlocked);
        Assert.False(rules.Evaluate(Request with { Path = "/admin/x", Method = "GET" }).IsBlocked);
        Assert.False(rules.Evaluate(Request with { Path = "/shop", Method = "POST" }).IsBlocked);
    }

    [Theory]
    [InlineData("website", true)]
    [InlineData("WEBSITE", true)]
    [InlineData("api", false)]
    [InlineData(null, false)]
    public void Route_scoped_rules_only_apply_to_their_routes(string? routeName, bool blocked)
    {
        var rule = Rule("website-only", RuleAction.Block, 10);
        rule.Routes.Add("website");

        Assert.Equal(blocked, Compile(rule).Evaluate(Request with { RouteName = routeName }).IsBlocked);
    }

    [Fact]
    public void Rules_without_route_scope_apply_to_unrouted_requests_too()
    {
        Assert.True(Compile(Rule("all", RuleAction.Block, 10)).Evaluate(Request with { RouteName = null }).IsBlocked);
    }

    [Fact]
    public void Compile_rejects_an_invalid_configuration()
    {
        var invalid = Rule("bad", RuleAction.Block, 10, When(ConditionField.ClientIp, ConditionOperator.InCidr, "10.0.0.1/8"));

        var ex = Assert.Throws<ArgumentException>(() => Compile(invalid));

        Assert.Contains("host bits are set", ex.Message, StringComparison.Ordinal);
    }
}
