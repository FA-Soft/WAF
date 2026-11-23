using FASoft.Waf.Cli;

namespace FASoft.Waf.UnitTests.Cli;

/// <summary>wafctl finds the data folder the same way the service does.</summary>
public sealed class DataFolderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));

    public DataFolderTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static Func<string, string?> Environment(params (string Name, string Value)[] variables) =>
        name => variables.FirstOrDefault(v => v.Name == name).Value;

    private string Install(string json)
    {
        var install = Path.Combine(_root, "install");
        Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "appsettings.json"), json);
        return install;
    }

    [Fact]
    public void Data_dir_option_wins()
    {
        var install = Install("""{ "Gateway": { "Storage": { "DataDirectory": "from-appsettings" } } }""");
        var explicitDir = Path.Combine(_root, "explicit");

        var paths = DataFolder.Resolve(explicitDir, install, Environment(("Gateway__Storage__DataDirectory", "from-env")));

        Assert.Equal(explicitDir, paths.DataDirectory);
    }

    [Fact]
    public void Appsettings_next_to_the_program_is_used_relative_to_it()
    {
        var install = Install("""
            {
              // comments are allowed, as in the service's files
              "gateway": { "storage": { "dataDirectory": "data" } },
            }
            """);

        var paths = DataFolder.Resolve(null, install, Environment());

        Assert.Equal(Path.Combine(install, "data"), paths.DataDirectory);
    }

    [Fact]
    public void Environment_variables_override_appsettings()
    {
        var install = Install("""{ "Gateway": { "Storage": { "DataDirectory": "data" } } }""");
        var fromEnv = Path.Combine(_root, "env-data");

        var paths = DataFolder.Resolve(null, install, Environment(("Gateway__Storage__DataDirectory", fromEnv)));

        Assert.Equal(fromEnv, paths.DataDirectory);
    }

    [Fact]
    public void The_administrators_appsettings_in_the_config_folder_can_move_the_data_folder()
    {
        var config = Path.Combine(_root, "etc");
        Directory.CreateDirectory(config);
        var moved = Path.Combine(_root, "moved");
        File.WriteAllText(Path.Combine(config, "appsettings.json"), $$"""{ "Gateway": { "Storage": { "DataDirectory": {{System.Text.Json.JsonSerializer.Serialize(moved)}} } } }""");
        var install = Install($$"""{ "Gateway": { "Storage": { "ConfigDirectory": {{System.Text.Json.JsonSerializer.Serialize(config)}} } } }""");

        var paths = DataFolder.Resolve(null, install, Environment());

        Assert.Equal(moved, paths.DataDirectory);
    }

    [Fact]
    public void Without_settings_the_platform_default_is_used()
    {
        var install = Path.Combine(_root, "empty");
        Directory.CreateDirectory(install);

        var paths = DataFolder.Resolve(null, install, Environment());

        Assert.Equal(
            OperatingSystem.IsWindows()
                ? Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData), "WafGateway")
                : "/var/lib/wafgateway",
            paths.DataDirectory);
    }

    [Fact]
    public void An_unreadable_settings_file_falls_back_to_the_defaults()
    {
        var install = Install("{ not json");

        var paths = DataFolder.Resolve(Path.Combine(_root, "x"), install, Environment());

        Assert.Equal(Path.Combine(_root, "x"), paths.DataDirectory);
        Assert.NotNull(DataFolder.Resolve(null, install, Environment()).DataDirectory);
    }
}
