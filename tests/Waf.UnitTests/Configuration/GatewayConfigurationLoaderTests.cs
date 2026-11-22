using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Waf.Core.Configuration;
using Waf.Host.Hosting;

namespace Waf.UnitTests.Configuration;

public class GatewayConfigurationLoaderTests
{
    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void Empty_section_gives_an_empty_valid_configuration()
    {
        var configuration = GatewayConfigurationLoader.Load(Config([]));

        Assert.Empty(configuration.Routes);
        Assert.Empty(configuration.Rules);
        Assert.False(configuration.Settings.DetectionOnly);
    }

    [Fact]
    public void Rules_settings_and_certificates_bind_from_configuration()
    {
        var configuration = GatewayConfigurationLoader.Load(Config(new()
        {
            ["Gateway:Endpoints:HttpPort"] = "80", // host settings in the same section are ignored here
            ["Gateway:Settings:DetectionOnly"] = "true",
            ["Gateway:Settings:TrustedProxies:0"] = "10.0.0.1",
            ["Gateway:Rules:0:Name"] = "block-admin",
            ["Gateway:Rules:0:Priority"] = "5",
            ["Gateway:Rules:0:Action"] = "LogOnly",
            ["Gateway:Rules:0:Conditions:0:Field"] = "ClientIp",
            ["Gateway:Rules:0:Conditions:0:Operator"] = "InCidr",
            ["Gateway:Rules:0:Conditions:0:Values:0"] = "10.0.0.0/8",
            ["Gateway:Rules:0:Conditions:0:Negate"] = "true",
            ["Gateway:Certificates:0:HostName"] = "www.example.com",
            ["Gateway:Certificates:0:Source"] = "File",
            ["Gateway:Certificates:0:CertificatePath"] = "certs/www.pfx",
        }));

        Assert.True(configuration.Settings.DetectionOnly);
        Assert.Equal(["10.0.0.1"], configuration.Settings.TrustedProxies);

        var rule = Assert.Single(configuration.Rules);
        Assert.Equal(("block-admin", 5, RuleAction.LogOnly), (rule.Name, rule.Priority, rule.Action));
        var condition = Assert.Single(rule.Conditions);
        Assert.Equal((ConditionField.ClientIp, ConditionOperator.InCidr, true), (condition.Field, condition.Operator, condition.Negate));
        Assert.Equal(["10.0.0.0/8"], condition.Values);

        var certificate = Assert.Single(configuration.Certificates);
        Assert.Equal(CertificateSource.File, certificate.Source);
    }

    [Fact]
    public void Invalid_enum_value_is_reported_with_its_key()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => GatewayConfigurationLoader.Load(Config(new()
        {
            ["Gateway:Rules:0:Name"] = "r",
            ["Gateway:Rules:0:Action"] = "Deny",
        })));

        Assert.Contains("Gateway:Rules:0:Action", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Allowed values: Allow, Block, LogOnly.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invalid_enum_value_in_a_nested_list_is_reported()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => GatewayConfigurationLoader.Load(Config(new()
        {
            ["Gateway:Rules:0:Name"] = "r",
            ["Gateway:Rules:0:Conditions:0:Field"] = "Url",
            ["Gateway:Rules:0:Conditions:0:Operator"] = "Equals",
            ["Gateway:Rules:0:Conditions:0:Values:0"] = "/x",
        })));

        Assert.Contains("Gateway:Rules:0:Conditions:0:Field", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Gateway:Rulez:0:Name", "Unknown setting 'Gateway:Rulez'")]
    [InlineData("Gateway:Rules:0:Nmae", "Nmae")]
    [InlineData("Gateway:Settings:DetectOnly", "DetectOnly")]
    public void Misspelled_setting_names_are_reported(string key, string expected)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => GatewayConfigurationLoader.Load(Config(new() { [key] = "x" })));

        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invalid_rule_fails_with_validation_messages()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => GatewayConfigurationLoader.Load(Config(new()
        {
            ["Gateway:Rules:0:Name"] = "r",
        })));

        Assert.Contains(ex.Failures, f => f.Contains("Rule 'r': at least one condition is required", StringComparison.Ordinal));
    }
}
