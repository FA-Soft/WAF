using Waf.Core.Configuration;
using Waf.Data;
using Waf.UnitTests.Configuration;
using Waf.Web;

namespace Waf.UnitTests.Web;

public class ConfigurationImportTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Export_then_import_gives_the_identical_configuration(bool includeSecrets)
    {
        var running = ConfigurationSecretsTests.WithSecrets();

        var json = ConfigurationExport.ToJson(running, includeSecrets);
        var preview = ConfigurationImport.Preview(json, running);

        Assert.Empty(preview.Errors);
        Assert.Empty(preview.Changes);
        Assert.Equal(ConfigurationStore.ComputeHash(running), ConfigurationStore.ComputeHash(preview.Candidate!));
        Assert.Equal(includeSecrets ? 0 : 3, preview.KeptSecrets);
        Assert.Equal(!includeSecrets, json.Contains(ConfigurationSecrets.Placeholder, StringComparison.Ordinal));
        Assert.Equal(includeSecrets, json.Contains("key-one", StringComparison.Ordinal));
    }

    [Fact]
    public void Export_with_secrets_imports_identically_on_another_gateway()
    {
        var source = ConfigurationSecretsTests.WithSecrets();
        var otherGateway = new GatewayConfiguration();

        var preview = ConfigurationImport.Preview(ConfigurationExport.ToJson(source, includeSecrets: true), otherGateway);

        Assert.True(preview.CanApply);
        Assert.Equal(ConfigurationStore.ComputeHash(source), ConfigurationStore.ComputeHash(preview.Candidate!));
    }

    [Fact]
    public void Export_without_secrets_cannot_be_imported_where_the_secrets_are_unknown()
    {
        var preview = ConfigurationImport.Preview(ConfigurationExport.ToJson(ConfigurationSecretsTests.WithSecrets(), includeSecrets: false), new GatewayConfiguration());

        Assert.False(preview.CanApply);
        Assert.Null(preview.Candidate);
        Assert.Equal(2, preview.Errors.Count);
    }

    [Fact]
    public void Changes_are_previewed_and_tagged()
    {
        var running = ConfigurationSecretsTests.WithSecrets();
        var edited = ConfigurationSecretsTests.WithSecrets();
        edited.Settings.DetectionOnly = true;

        var preview = ConfigurationImport.Preview(ConfigurationExport.ToJson(edited, includeSecrets: false), running);

        Assert.True(preview.CanApply);
        var change = Assert.Single(preview.Changes);
        Assert.Equal((ConfigurationSection.Settings, "DetectionOnly"), (change.Section, change.Name));
        Assert.Matches("^[0-9a-f]{16}$", preview.Tag);
    }

    [Theory]
    [InlineData("", "Choose a configuration file")]
    [InlineData("{ not json", "")]
    [InlineData("{\"Routs\": []}", "Routs")]
    public void Unusable_files_are_explained(string json, string expected)
    {
        var preview = ConfigurationImport.Preview(json, new GatewayConfiguration());

        Assert.False(preview.CanApply);
        Assert.Contains(preview.Errors, e => e.Contains(expected, StringComparison.Ordinal));
    }
}
