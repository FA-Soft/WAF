using System.Text.Json.Nodes;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.UnitTests.Configuration;

public class GatewayConfigurationJsonTests
{
    private static string RepoFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(directory.FullName, relativePath);
    }

    [Fact]
    public void Example_configuration_is_valid()
    {
        var result = GatewayConfigurationJson.Parse(File.ReadAllText(RepoFile("schemas/gateway-config.example.json")));

        Assert.Empty(result.Errors);
        Assert.True(result.IsValid);
        var configuration = result.Configuration!;
        Assert.Equal(2, configuration.Routes.Count);
        Assert.Equal(3, configuration.Rules.Count);
        Assert.Equal(3, configuration.Certificates.Count);
        Assert.Equal(["10.0.0.1", "192.168.10.0/24"], configuration.Settings.TrustedProxies);

        var adminRule = configuration.Rules[0];
        Assert.Equal(RuleAction.Block, adminRule.Action);
        Assert.Equal(["website"], adminRule.Routes);
        Assert.True(adminRule.Conditions[1].Negate);
        Assert.True(configuration.Rules[2].DetectionOnly);
    }

    [Fact]
    public void Serialize_then_parse_round_trips()
    {
        var original = GatewayConfigurationJson.Parse(File.ReadAllText(RepoFile("schemas/gateway-config.example.json"))).Configuration!;

        var json = GatewayConfigurationJson.Serialize(original);
        var again = GatewayConfigurationJson.Parse(json);

        Assert.True(again.IsValid, string.Join(Environment.NewLine, again.Errors));
        Assert.Equal(json, GatewayConfigurationJson.Serialize(again.Configuration!));
        Assert.Contains("\"Action\": \"Block\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Defaults_apply_for_omitted_settings()
    {
        var result = GatewayConfigurationJson.Parse("""{ "Rules": [ { "Name": "r", "Conditions": [ { "Field": "Path", "Operator": "StartsWith", "Values": ["/"] } ] } ] }""");

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
        var rule = Assert.Single(result.Configuration!.Rules);
        Assert.True(rule.Enabled);
        Assert.Equal(100, rule.Priority);
        Assert.Equal(RuleAction.Block, rule.Action);
        Assert.False(rule.DetectionOnly);
        Assert.Equal(GatewayConfiguration.CurrentSchemaVersion, result.Configuration.SchemaVersion);
    }

    [Fact]
    public void Comments_trailing_commas_and_any_property_case_are_accepted()
    {
        var result = GatewayConfigurationJson.Parse("""
            {
              // global switch
              "settings": { "detectionOnly": true, },
            }
            """);

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
        Assert.True(result.Configuration!.Settings.DetectionOnly);
    }

    [Theory]
    [InlineData("""{ "Routes": [ { "Name": "a", "Desinations": [] } ] }""", "Unknown setting 'Desinations' in $.Routes[0]")]
    [InlineData("""{ "Rules": [ { "Name": "r", "Action": "Deny" } ] }""", "Invalid value at $.Rules[0].Action: expected one of: Allow, Block, LogOnly.")]
    [InlineData("""{ "Rules": [ { "Name": "r", "Action": 1 } ] }""", "Invalid value at $.Rules[0].Action: expected one of: Allow, Block, LogOnly.")]
    [InlineData("""{ "Rules": [ { "Name": "r", "Priority": "high" } ] }""", "Invalid value at $.Rules[0].Priority: expected a whole number.")]
    [InlineData("""{ "Settings": { "DetectionOnly": "yes" } }""", "Invalid value at $.Settings.DetectionOnly: expected true or false.")]
    public void Json_errors_are_explained_with_their_location(string json, string expected)
    {
        var result = GatewayConfigurationJson.Parse(json);

        Assert.False(result.IsValid);
        Assert.Null(result.Configuration);
        Assert.StartsWith(expected, Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Null_for_a_required_value_is_rejected()
    {
        var result = GatewayConfigurationJson.Parse("""{ "Rules": [ { "Name": null } ] }""");

        Assert.False(result.IsValid);
        Assert.Equal("Invalid value at $.Rules[0].Name: a value is required (null is not allowed).", Assert.Single(result.Errors));
    }

    [Theory]
    [InlineData("""{ "Routes": null }""")]
    [InlineData("""{ "Settings": null }""")]
    [InlineData("""{ "Settings": { "TrustedProxies": null } }""")]
    [InlineData("""{ "Settings": { "TrustedProxies": [ null ] } }""")]
    [InlineData("""{ "Rules": [ null ] }""")]
    [InlineData("""{ "Rules": [ { "Name": "r", "Conditions": [ { "Field": "Path", "Operator": "Equals", "Values": [ null ] } ] } ] }""")]
    public void Null_for_a_list_section_or_list_entry_is_rejected(string json)
    {
        var result = GatewayConfigurationJson.Parse(json);

        Assert.False(result.IsValid);
        Assert.Contains("a value is required (null is not allowed)", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Null_is_accepted_where_the_model_allows_it()
    {
        var result = GatewayConfigurationJson.Parse("""{ "$schema": null, "Settings": { "Acme": { "Email": null } } }""");

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
    }

    [Fact]
    public void Null_error_reports_the_exact_location()
    {
        var result = GatewayConfigurationJson.Parse("""{ "Rules": [ { "Name": "r", "Routes": null } ] }""");

        Assert.Equal("Invalid value at $.Rules[0].Routes: a value is required (null is not allowed).", Assert.Single(result.Errors));
    }

    [Fact]
    public void Schema_does_not_allow_null_for_lists()
    {
        var properties = GatewayConfigurationJson.GetSchema()["properties"]!;

        Assert.Equal("array", (string?)properties["Routes"]!["type"]);
        Assert.Equal("array", (string?)properties["Rules"]!["type"]);
    }

    [Fact]
    public void Syntax_errors_report_line_and_position()
    {
        var result = GatewayConfigurationJson.Parse("{\n  \"Rules\": [ { \"Name\": \"r\" ]\n}");

        Assert.StartsWith("Invalid JSON at line 2", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Semantic_errors_are_returned_with_the_parsed_configuration()
    {
        var result = GatewayConfigurationJson.Parse("""{ "Rules": [ { "Name": "r" } ] }""");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Configuration);
        Assert.Contains(result.Errors, e => e.Contains("at least one condition", StringComparison.Ordinal));
    }

    [Fact]
    public void Schema_describes_the_model()
    {
        var schema = GatewayConfigurationJson.GetSchema();

        Assert.Equal(GatewayConfigurationJson.SchemaDialect, (string?)schema["$schema"]);
        var properties = schema["properties"]!.AsObject();
        Assert.True(properties.ContainsKey("Routes"));
        Assert.True(properties.ContainsKey("Rules"));
        Assert.True(properties.ContainsKey("Settings"));
        Assert.True(properties.ContainsKey("Certificates"));
        Assert.Contains("\"Allow\"", schema.ToJsonString(), StringComparison.Ordinal);
        Assert.Contains("\"LogOnly\"", schema.ToJsonString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The checked-in schema must match the model. To update it after changing the model, run the tests
    /// with WAF_UPDATE_SCHEMA=1.
    /// </summary>
    [Fact]
    public void Checked_in_schema_is_up_to_date()
    {
        var path = RepoFile("schemas/gateway-config.schema.json");
        var generated = GatewayConfigurationJson.GetSchema().ToJsonString(new() { WriteIndented = true }) + "\n";

        if (Environment.GetEnvironmentVariable("WAF_UPDATE_SCHEMA") == "1")
        {
            File.WriteAllText(path, generated);
        }

        Assert.True(File.Exists(path), $"Missing {path}. Run the tests with WAF_UPDATE_SCHEMA=1 to create it.");
        var current = File.ReadAllText(path).ReplaceLineEndings("\n");
        Assert.True(
            JsonNode.DeepEquals(JsonNode.Parse(current), JsonNode.Parse(generated)),
            "schemas/gateway-config.schema.json is out of date. Run the tests with WAF_UPDATE_SCHEMA=1 to regenerate it.");
    }
}
