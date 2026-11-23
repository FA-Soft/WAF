using FASoft.Waf.Data;

namespace FASoft.Waf.UnitTests.Data;

public class StoragePathsTests
{
    private static readonly string ContentRoot = Path.Combine(Path.GetTempPath(), "app");

    [Fact]
    public void Windows_defaults_to_program_data_for_data_and_config()
    {
        var paths = StoragePaths.Resolve(null, ContentRoot, isWindows: true);

        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WafGateway");
        Assert.Equal(expected, paths.DataDirectory);
        Assert.Equal(expected, paths.ConfigDirectory);
        Assert.Equal(Path.Combine(expected, "config.db"), paths.ConfigDatabasePath);
    }

    [Fact]
    public void Linux_defaults_to_var_lib_and_etc()
    {
        var paths = StoragePaths.Resolve(new StorageOptions(), ContentRoot, isWindows: false);

        Assert.Equal("/var/lib/wafgateway", paths.DataDirectory);
        Assert.Equal("/etc/wafgateway", paths.ConfigDirectory);
    }

    [Fact]
    public void Relative_paths_are_relative_to_the_content_root()
    {
        var paths = StoragePaths.Resolve(new StorageOptions { DataDirectory = ".data" }, ContentRoot, isWindows: false);

        Assert.Equal(Path.Combine(ContentRoot, ".data"), paths.DataDirectory);
        Assert.Equal(paths.DataDirectory, paths.ConfigDirectory); // a custom data folder also holds the settings file
    }

    [Fact]
    public void Config_folder_can_be_set_separately()
    {
        var data = Path.Combine(ContentRoot, "data");
        var config = Path.Combine(ContentRoot, "config");

        var paths = StoragePaths.Resolve(new StorageOptions { DataDirectory = data, ConfigDirectory = config }, ContentRoot);

        Assert.Equal((data, config), (paths.DataDirectory, paths.ConfigDirectory));
        Assert.Equal(Path.Combine(config, "appsettings.json"), paths.SettingsFilePath);
    }

    [Fact]
    public void Data_folder_is_created_when_missing()
    {
        var directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"), "nested");
        try
        {
            new StoragePaths(directory, directory).EnsureDataDirectory();

            Assert.True(Directory.Exists(directory));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute,
                    File.GetUnixFileMode(directory));
            }
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(directory)!, recursive: true);
        }
    }
}
