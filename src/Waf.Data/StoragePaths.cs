namespace Waf.Data;

/// <summary>
/// Storage locations, bound from <c>Gateway:Storage</c>. Empty values use the platform defaults.
/// </summary>
public sealed class StorageOptions
{
    /// <summary>The configuration section these options are bound from.</summary>
    public const string SectionName = "Gateway:Storage";

    /// <summary>Folder for databases (config.db, later events.db). Relative paths are relative to the content root.</summary>
    public string? DataDirectory { get; set; }

    /// <summary>Folder for an optional <c>appsettings.json</c> that overrides the built-in one.</summary>
    public string? ConfigDirectory { get; set; }
}

/// <summary>Resolved storage locations.</summary>
/// <param name="DataDirectory">Folder for databases.</param>
/// <param name="ConfigDirectory">Folder for the optional administrator <c>appsettings.json</c>.</param>
public sealed record StoragePaths(string DataDirectory, string ConfigDirectory)
{
    /// <summary>File name of the configuration database.</summary>
    public const string ConfigDatabaseFileName = "config.db";

    /// <summary>File name of the administrator settings file in <see cref="ConfigDirectory"/>.</summary>
    public const string SettingsFileName = "appsettings.json";

    /// <summary>Full path of the configuration database.</summary>
    public string ConfigDatabasePath => Path.Combine(DataDirectory, ConfigDatabaseFileName);

    /// <summary>Full path of the administrator settings file.</summary>
    public string SettingsFilePath => Path.Combine(ConfigDirectory, SettingsFileName);

    /// <summary>
    /// Resolves the locations. Defaults: Windows <c>%ProgramData%\WafGateway</c> for both; Linux
    /// <c>/var/lib/wafgateway</c> for data and <c>/etc/wafgateway</c> for configuration.
    /// </summary>
    public static StoragePaths Resolve(StorageOptions? options, string contentRoot, bool? isWindows = null)
    {
        ArgumentNullException.ThrowIfNull(contentRoot);

        var windows = isWindows ?? OperatingSystem.IsWindows();
        var defaultData = windows
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WafGateway")
            : "/var/lib/wafgateway";
        var defaultConfig = windows ? defaultData : "/etc/wafgateway";

        var data = Absolute(options?.DataDirectory, contentRoot) ?? defaultData;
        var config = Absolute(options?.ConfigDirectory, contentRoot)
            ?? (string.IsNullOrWhiteSpace(options?.DataDirectory) ? defaultConfig : data);

        return new StoragePaths(data, config);
    }

    /// <summary>
    /// Creates the data folder if needed. On Linux and macOS a new folder gets mode 0750 (owner and group only).
    /// </summary>
    public void EnsureDataDirectory()
    {
        if (Directory.Exists(DataDirectory))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(DataDirectory);
        }
        else
        {
            Directory.CreateDirectory(
                DataDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        }
    }

    private static string? Absolute(string? path, string contentRoot) =>
        string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path, contentRoot);
}
