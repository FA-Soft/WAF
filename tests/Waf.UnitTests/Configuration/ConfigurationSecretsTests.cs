using Waf.Core.Configuration;
using Waf.Core.Routing;

namespace Waf.UnitTests.Configuration;

public class ConfigurationSecretsTests
{
    /// <summary>A route, an API-key rule (header condition plus a path condition) and a rate limit on a header.</summary>
    public static GatewayConfiguration WithSecrets()
    {
        var configuration = new GatewayConfiguration();
        configuration.Routes.Add(new ProxyRouteOptions { Name = "api", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } });
        configuration.Rules.Add(new WafRule
        {
            Name = "require-api-key",
            Conditions =
            {
                new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/api" } },
                new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Negate = true, Values = { "key-one", "key-two" } },
            },
        });
        configuration.RateLimits.Add(new RateLimitRule
        {
            Name = "partner",
            Conditions = { new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Partner", Operator = ConditionOperator.Equals, Values = { "acme" } } },
        });
        return configuration;
    }

    private static GatewayConfiguration Copy(GatewayConfiguration configuration) =>
        GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration)).Configuration!;

    [Fact]
    public void Header_condition_values_are_the_secrets()
    {
        var configuration = WithSecrets();

        Assert.Equal(3, ConfigurationSecrets.Count(configuration));
        Assert.Equal(3, ConfigurationSecrets.Redact(configuration));
        Assert.True(ConfigurationSecrets.HasPlaceholders(configuration));
        Assert.Equal(["/api"], configuration.Rules[0].Conditions[0].Values); // not a secret
        Assert.Equal([ConfigurationSecrets.Placeholder, ConfigurationSecrets.Placeholder], configuration.Rules[0].Conditions[1].Values);
    }

    [Fact]
    public void A_placeholder_can_never_become_active()
    {
        var configuration = WithSecrets();
        ConfigurationSecrets.Redact(configuration);

        var errors = GatewayConfigurationValidator.Validate(configuration);

        Assert.Equal(3, errors.Count(e => e.Contains("secret value was left out", StringComparison.Ordinal)));
    }

    [Fact]
    public void Placeholders_are_filled_from_the_running_configuration()
    {
        var running = WithSecrets();
        var exported = Copy(running);
        ConfigurationSecrets.Redact(exported);

        Assert.Empty(ConfigurationSecrets.FillFrom(exported, running));
        Assert.Equal(GatewayConfigurationJson.Serialize(running), GatewayConfigurationJson.Serialize(exported));
    }

    [Fact]
    public void Placeholders_without_a_matching_condition_are_reported()
    {
        var exported = WithSecrets();
        ConfigurationSecrets.Redact(exported);
        var running = WithSecrets();
        running.Rules[0].Conditions[1].HeaderName = "X-Other-Key"; // another header: its value must not be used
        running.RateLimits.Clear();

        var problems = ConfigurationSecrets.FillFrom(exported, running);

        Assert.Equal(2, problems.Count);
        Assert.StartsWith("Rule 'require-api-key', condition 2 (header X-Api-Key)", problems[0], StringComparison.Ordinal);
        Assert.StartsWith("Rate limit 'partner', condition 1 (header X-Partner)", problems[1], StringComparison.Ordinal);
        Assert.Equal(2, ConfigurationSecrets.FillFrom(exported, null).Count);
    }

    [Fact]
    public void Names_match_case_insensitively_and_real_values_are_left_alone()
    {
        var running = WithSecrets();
        var exported = Copy(running);
        ConfigurationSecrets.Redact(exported);
        exported.Rules[0].Name = "REQUIRE-API-KEY";
        exported.RateLimits[0].Conditions[0].Values[0] = "new-partner"; // typed in by hand

        Assert.Empty(ConfigurationSecrets.FillFrom(exported, running));
        Assert.Equal(["key-one", "key-two"], exported.Rules[0].Conditions[1].Values);
        Assert.Equal(["new-partner"], exported.RateLimits[0].Conditions[0].Values);
    }
}
