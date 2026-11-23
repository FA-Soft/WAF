using FASoft.Waf.Core.Configuration;
using static FASoft.Waf.UnitTests.Engine.RuleBuilder;

namespace FASoft.Waf.UnitTests.Configuration;

public class RateLimitValidationTests
{
    private static IReadOnlyList<string> Validate(RateLimitRule limit)
    {
        var configuration = Config();
        configuration.RateLimits.Add(limit);
        return GatewayConfigurationValidator.Validate(configuration);
    }

    [Fact]
    public void Valid_limit_is_accepted()
    {
        var limit = new RateLimitRule { Name = "login", PermitLimit = 5, WindowSeconds = 60 };
        limit.Routes.Add("website");
        limit.Conditions.Add(When(ConditionField.Path, ConditionOperator.Equals, "/login"));

        Assert.Empty(Validate(limit));
    }

    [Theory]
    [InlineData("", 10, 60, "a name is required")]
    [InlineData("a b", 10, 60, "the name may only contain")]
    [InlineData("x", 0, 60, "PermitLimit must be between 1 and 1000000")]
    [InlineData("x", 1_000_001, 60, "PermitLimit must be between 1 and 1000000")]
    [InlineData("x", 10, 0, "WindowSeconds must be between 1 and 86400")]
    [InlineData("x", 10, 86_401, "WindowSeconds must be between 1 and 86400")]
    public void Invalid_values_are_explained(string name, int permits, int window, string expected)
    {
        var errors = Validate(new RateLimitRule { Name = name, PermitLimit = permits, WindowSeconds = window });

        Assert.Contains(errors, e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void Unknown_route_is_rejected()
    {
        var limit = new RateLimitRule { Name = "x" };
        limit.Routes.Add("shop");

        Assert.Equal(["Rate limit 'x': route 'shop' does not exist."], Validate(limit));
    }

    [Fact]
    public void Conditions_are_validated_like_rule_conditions()
    {
        var limit = new RateLimitRule { Name = "x" };
        limit.Conditions.Add(When(ConditionField.Method, ConditionOperator.Contains, "POST"));

        Assert.Contains(Validate(limit), e => e.StartsWith("Rate limit 'x': operator Contains cannot be used with Method", StringComparison.Ordinal));
    }

    [Fact]
    public void Duplicate_names_are_rejected()
    {
        var configuration = Config();
        configuration.RateLimits.Add(new RateLimitRule { Name = "x" });
        configuration.RateLimits.Add(new RateLimitRule { Name = "X" });

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.Contains("used by more than one rate limit", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(999, false)]
    [InlineData(1_000, true)]
    [InlineData(10_000_000, true)]
    [InlineData(10_000_001, false)]
    public void Max_tracked_clients_is_bounded(int value, bool valid)
    {
        var configuration = Config();
        configuration.Settings.RateLimitMaxTrackedClients = value;

        Assert.Equal(valid, GatewayConfigurationValidator.Validate(configuration).Count == 0);
    }
}
