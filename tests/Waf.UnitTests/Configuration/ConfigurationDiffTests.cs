using Waf.Core.Configuration;
using Waf.Core.Routing;

namespace Waf.UnitTests.Configuration;

public class ConfigurationDiffTests
{
    private static GatewayConfiguration Sample()
    {
        var configuration = new GatewayConfiguration();
        configuration.Routes.Add(new ProxyRouteOptions { Name = "website", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } });
        configuration.Rules.Add(new WafRule { Name = "a", Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/a" } } } });
        configuration.Rules.Add(new WafRule { Name = "b", Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/b" } } } });
        configuration.RateLimits.Add(new RateLimitRule { Name = "per-client" });
        return configuration;
    }

    private static GatewayConfiguration Copy(GatewayConfiguration configuration) =>
        GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration)).Configuration!;

    [Fact]
    public void Equal_configurations_have_no_changes()
    {
        Assert.Empty(ConfigurationDiff.Compare(Sample(), Sample()));
    }

    [Fact]
    public void Items_are_matched_by_name_regardless_of_order()
    {
        var before = Sample();
        var after = Copy(before);
        (after.Rules[0], after.Rules[1]) = (after.Rules[1], after.Rules[0]);

        Assert.Empty(ConfigurationDiff.Compare(before, after));
    }

    [Fact]
    public void Added_changed_and_removed_items_are_reported()
    {
        var before = Sample();
        var after = Copy(before);
        after.Rules.RemoveAt(0);
        after.Rules[0].Priority = 5;
        after.RateLimits.Add(new RateLimitRule { Name = "login", PermitLimit = 10 });

        var changes = ConfigurationDiff.Compare(before, after);

        Assert.Equal(
            [(ChangeKind.Changed, ConfigurationSection.Rule, "b"), (ChangeKind.Removed, ConfigurationSection.Rule, "a"), (ChangeKind.Added, ConfigurationSection.RateLimit, "login")],
            changes.Select(c => (c.Kind, c.Section, c.Name)));
        Assert.Contains("\"Priority\": 100", changes[0].Before, StringComparison.Ordinal);
        Assert.Contains("\"Priority\": 5", changes[0].After, StringComparison.Ordinal);
        Assert.Null(changes[1].After);
        Assert.Null(changes[2].Before);
    }

    [Fact]
    public void Settings_are_compared_per_value()
    {
        var before = Sample();
        before.Settings.AttackDetection.SqlInjection = false;
        var after = Copy(before);
        after.Settings.AttackDetection.SqlInjection = true;
        after.Settings.TrustedProxies.Add("10.0.0.1");

        var changes = ConfigurationDiff.Compare(before, after);

        Assert.Equal(["TrustedProxies", "AttackDetection.SqlInjection"], changes.Select(c => c.Name));
        Assert.All(changes, c => Assert.Equal((ChangeKind.Changed, ConfigurationSection.Settings), (c.Kind, c.Section)));
        Assert.Equal(("false", "true"), (changes[1].Before, changes[1].After));
    }
}
