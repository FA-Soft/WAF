using System.Text.Json;
using FASoft.Waf.Data;

namespace FASoft.Waf.Cli;

/// <summary>
/// Finds the gateway's data folder the same way the service does, without starting it: <c>--data-dir</c> if given,
/// otherwise <c>Gateway:Storage</c> from the environment and the appsettings files next to the program (then the
/// administrator's appsettings in the config folder), otherwise the platform default
/// (<c>%ProgramData%\WafGateway</c> or <c>/var/lib/wafgateway</c>).
/// </summary>
internal static class DataFolder
{
    private const string EnvironmentPrefix = "Gateway__Storage__";

    public static StoragePaths Resolve(string? dataDirectory, string? baseDirectory = null, Func<string, string?>? environment = null)
    {
        var contentRoot = baseDirectory ?? AppContext.BaseDirectory;
        environment ??= Environment.GetEnvironmentVariable;

        if (!string.IsNullOrWhiteSpace(dataDirectory))
        {
            return StoragePaths.Resolve(new StorageOptions { DataDirectory = dataDirectory }, Directory.GetCurrentDirectory());
        }

        // Same order as the service: appsettings.json, appsettings.{environment}.json, then environment variables.
        var hostEnvironment = environment("DOTNET_ENVIRONMENT") ?? environment("ASPNETCORE_ENVIRONMENT") ?? "Production";
        var options = new StorageOptions();
        Read(Path.Combine(contentRoot, StoragePaths.SettingsFileName), options);
        Read(Path.Combine(contentRoot, $"appsettings.{hostEnvironment}.json"), options);
        ReadEnvironment(environment, options);
        var paths = StoragePaths.Resolve(options, contentRoot);

        // The administrator's appsettings in the config folder may move the data folder; environment variables win.
        Read(paths.SettingsFilePath, options);
        ReadEnvironment(environment, options);
        return StoragePaths.Resolve(options, contentRoot);
    }

    private static void ReadEnvironment(Func<string, string?> environment, StorageOptions options)
    {
        if (environment(EnvironmentPrefix + nameof(StorageOptions.DataDirectory)) is { Length: > 0 } data)
        {
            options.DataDirectory = data;
        }

        if (environment(EnvironmentPrefix + nameof(StorageOptions.ConfigDirectory)) is { Length: > 0 } config)
        {
            options.ConfigDirectory = config;
        }
    }

    private static void Read(string path, StorageOptions options)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
            if (Find(document.RootElement, "Gateway") is { } gateway && Find(gateway, "Storage") is { } storage)
            {
                options.DataDirectory = Text(storage, nameof(StorageOptions.DataDirectory)) ?? options.DataDirectory;
                options.ConfigDirectory = Text(storage, nameof(StorageOptions.ConfigDirectory)) ?? options.ConfigDirectory;
            }
        }
        catch (JsonException)
        {
            // An unreadable settings file does not stop recovery: the defaults (or --data-dir) still work.
        }
    }

    /// <summary>A property by name, ignoring case like .NET configuration does.</summary>
    private static JsonElement? Find(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return property.Value;
            }
        }

        return null;
    }

    private static string? Text(JsonElement element, string name) =>
        Find(element, name) is { ValueKind: JsonValueKind.String } value && value.GetString() is { Length: > 0 } text ? text : null;
}
