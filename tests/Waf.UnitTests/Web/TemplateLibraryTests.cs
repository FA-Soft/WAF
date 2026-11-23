using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

public class TemplateLibraryTests
{
    private static List<string> Errors(IValidatableObject model) =>
        [.. model.Validate(new ValidationContext(model)).Select(r => r.ErrorMessage!)];

    private static GatewayConfiguration WithWebsiteRoute()
    {
        var configuration = new GatewayConfiguration();
        configuration.Routes.Add(new ProxyRouteOptions { Name = "website", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } });
        return configuration;
    }

    /// <summary>Fills the values a template deliberately leaves empty (IP lists, API keys), as a user would.</summary>
    private static void FillEmptyValues(IEnumerable<ConditionFormModel> conditions)
    {
        foreach (var condition in conditions.Where(c => string.IsNullOrWhiteSpace(c.Values)))
        {
            condition.Values = condition.Field == ConditionField.ClientIp ? "203.0.113.0/24" : "secret-key";
        }
    }

    [Fact]
    public void Template_ids_are_unique_and_found_case_insensitively()
    {
        Assert.Equal(TemplateLibrary.Routes.Count, TemplateLibrary.Routes.Select(t => t.Id).Distinct().Count());
        Assert.Equal(TemplateLibrary.Rules.Count, TemplateLibrary.Rules.Select(t => t.Id).Distinct().Count());
        Assert.Equal(TemplateLibrary.RateLimits.Count, TemplateLibrary.RateLimits.Select(t => t.Id).Distinct().Count());
        Assert.Equal("block-ips", TemplateLibrary.FindRule("BLOCK-IPS")!.Id);
        Assert.Null(TemplateLibrary.FindRoute("nope"));
        Assert.Null(TemplateLibrary.FindRateLimit(null));
    }

    [Fact]
    public void Every_route_template_is_a_valid_route()
    {
        foreach (var template in TemplateLibrary.Routes)
        {
            var form = RouteFormModel.ForNewRoute(1, template.Id);
            Assert.True(Errors(form).Count == 0, $"{template.Id}: {string.Join(" ", Errors(form))}");

            var configuration = new GatewayConfiguration();
            configuration.Routes.Add(form.ToRoute());
            var errors = GatewayConfigurationValidator.Validate(configuration);
            Assert.True(errors.Count == 0, $"{template.Id}: {string.Join(" ", errors)}");
            Assert.True(form.Enabled);
        }
    }

    [Fact]
    public void Every_rule_template_is_a_valid_rule_once_its_empty_values_are_filled()
    {
        foreach (var template in TemplateLibrary.Rules)
        {
            var form = RuleFormModel.ForNewRule(1, ["website"], template.Id);
            FillEmptyValues(form.Conditions);
            Assert.True(Errors(form).Count == 0, $"{template.Id}: {string.Join(" ", Errors(form))}");

            var configuration = WithWebsiteRoute();
            configuration.Rules.Add(form.ToRule());
            var errors = GatewayConfigurationValidator.Validate(configuration);
            Assert.True(errors.Count == 0, $"{template.Id}: {string.Join(" ", errors)}");
        }
    }

    [Fact]
    public void Every_rate_limit_template_is_a_valid_limit()
    {
        foreach (var template in TemplateLibrary.RateLimits)
        {
            var form = RateLimitFormModel.ForNewLimit(1, ["website"], template.Id);
            Assert.True(Errors(form).Count == 0, $"{template.Id}: {string.Join(" ", Errors(form))}");

            var configuration = WithWebsiteRoute();
            configuration.RateLimits.Add(form.ToLimit());
            var errors = GatewayConfigurationValidator.Validate(configuration);
            Assert.True(errors.Count == 0, $"{template.Id}: {string.Join(" ", errors)}");
        }
    }

    [Fact]
    public void Lock_path_template_blocks_the_path_for_everyone_outside_the_list()
    {
        var form = RuleFormModel.ForNewRule(1, [], "lock-path");

        Assert.Contains(Errors(form), e => e.Contains("enter at least one value", StringComparison.Ordinal));
        form.Conditions[1].Values = "203.0.113.7";

        Assert.Equal("The path starts with /admin and the client IP is not in 203.0.113.7", Describe.Conditions(form.ToRule().Conditions));
    }

    [Fact]
    public void Unknown_template_gives_an_empty_form()
    {
        Assert.Equal(string.Empty, RuleFormModel.ForNewRule(1, [], "nope").Name);
        Assert.Equal(string.Empty, RouteFormModel.ForNewRoute(1, "nope").Name);
        Assert.Equal(string.Empty, RateLimitFormModel.ForNewLimit(1, [], "nope").Name);
    }
}
