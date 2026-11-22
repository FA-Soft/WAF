using Waf.Core.Configuration;
using Waf.Core.Routing;
using Waf.Engine;

namespace Waf.UnitTests.Engine;

/// <summary>Builds configurations for engine tests with little ceremony.</summary>
internal static class RuleBuilder
{
    public static RuleCondition When(ConditionField field, ConditionOperator op, params string[] values) =>
        When(field, op, negate: false, caseSensitive: false, headerName: null, values);

    public static RuleCondition WhenNot(ConditionField field, ConditionOperator op, params string[] values) =>
        When(field, op, negate: true, caseSensitive: false, headerName: null, values);

    public static RuleCondition When(ConditionField field, ConditionOperator op, bool negate, bool caseSensitive, string? headerName, params string[] values)
    {
        var condition = new RuleCondition { Field = field, Operator = op, Negate = negate, CaseSensitive = caseSensitive, HeaderName = headerName };
        foreach (var value in values)
        {
            condition.Values.Add(value);
        }

        return condition;
    }

    public static RuleCondition AnyPath() => When(ConditionField.Path, ConditionOperator.StartsWith, "/");

    public static WafRule Rule(string name, RuleAction action, int priority, params RuleCondition[] conditions)
    {
        var rule = new WafRule { Name = name, Action = action, Priority = priority };
        foreach (var condition in conditions.Length == 0 ? [AnyPath()] : conditions)
        {
            rule.Conditions.Add(condition);
        }

        return rule;
    }

    public static GatewayConfiguration Config(params WafRule[] rules)
    {
        var configuration = new GatewayConfiguration();
        foreach (var name in new[] { "website", "api" })
        {
            var route = new ProxyRouteOptions { Name = name };
            route.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = 8080 });
            configuration.Routes.Add(route);
        }

        foreach (var rule in rules)
        {
            configuration.Rules.Add(rule);
        }

        return configuration;
    }

    public static CompiledRuleSet Compile(params WafRule[] rules) => CompiledRuleSet.Compile(Config(rules));
}
