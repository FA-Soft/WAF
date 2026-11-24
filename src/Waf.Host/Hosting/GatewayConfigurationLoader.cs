using System.Collections;
using Microsoft.Extensions.Options;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Loads the <see cref="GatewayConfiguration"/> from the <c>Gateway</c> configuration section
/// (appsettings, environment variables, command line) and validates it.
/// </summary>
/// <remarks>
/// Loading is strict, like the JSON parser: unknown setting names fail, and an entry that cannot be read
/// (e.g. an invalid enum value) fails instead of being dropped. The default configuration binder silently
/// skips list entries it cannot convert, which would make a rule with a typo disappear.
/// </remarks>
internal static class GatewayConfigurationLoader
{
    public const string SectionName = "Gateway";

    /// <summary>Keys of the Gateway section that are not part of <see cref="GatewayConfiguration"/>.</summary>
    private static readonly string[] HostKeys = ["Endpoints", "Storage", "EventLog", "Acme", "Ai", "TargetResolver", "Failover"];

    /// <summary>
    /// Fingerprint (SHA-256, hex) of the configuration part of the Gateway section, i.e. without the host-only
    /// keys (Endpoints, Storage, EventLog, Acme). Computed from the raw settings, so it also works for invalid configurations.
    /// </summary>
    public static string Fingerprint(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var lines = configuration.GetSection(SectionName).AsEnumerable(makePathsRelative: true)
            .Where(pair => pair.Value is not null)
            .Where(pair => !HostKeys.Any(key => pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase)
                || pair.Key.StartsWith(key + ":", StringComparison.OrdinalIgnoreCase)))
            .Select(pair => $"{pair.Key.ToUpperInvariant()}={pair.Value}")
            .Order(StringComparer.Ordinal);

        var bytes = System.Text.Encoding.UTF8.GetBytes(string.Join('\n', lines));
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
    }

    /// <exception cref="OptionsValidationException">The configuration cannot be read or is invalid.</exception>
    public static GatewayConfiguration Load(IConfiguration configuration)
    {
        var (result, errors) = TryLoad(configuration);
        return result ?? throw new OptionsValidationException(SectionName, typeof(GatewayConfiguration), errors);
    }

    /// <summary>Like <see cref="Load"/>, but returns the errors instead of throwing (configuration is null then).</summary>
    public static (GatewayConfiguration? Configuration, IReadOnlyList<string> Errors) TryLoad(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(SectionName);
        var result = new GatewayConfiguration();
        var errors = new List<string>();

        foreach (var child in section.GetChildren())
        {
            if (!IsKnownKey(child.Key))
            {
                errors.Add($"Unknown setting '{child.Path}'. Check the spelling.");
            }
        }

        Bind(section, nameof(GatewayConfiguration.Settings), result.Settings, errors);

        // Every list in the model (Routes, Rules, RateLimits, Certificates, ...), so new ones cannot be forgotten.
        foreach (var property in typeof(GatewayConfiguration).GetProperties())
        {
            if (property.GetValue(result) is ICollection list)
            {
                Bind(section, property.Name, list, errors);
            }
        }

        var schemaVersion = section[nameof(GatewayConfiguration.SchemaVersion)];
        if (schemaVersion is not null)
        {
            if (int.TryParse(schemaVersion, System.Globalization.CultureInfo.InvariantCulture, out var version))
            {
                result.SchemaVersion = version;
            }
            else
            {
                errors.Add($"'{SectionName}:SchemaVersion' must be a whole number (was '{schemaVersion}').");
            }
        }

        if (errors.Count == 0)
        {
            errors.AddRange(GatewayConfigurationValidator.Validate(result));
        }

        return errors.Count > 0 ? (null, errors) : (result, errors);
    }

    private static bool IsKnownKey(string key) =>
        HostKeys.Contains(key, StringComparer.OrdinalIgnoreCase)
        || typeof(GatewayConfiguration).GetProperties().Any(p => string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The binder wraps the useful message ("Failed to convert configuration value at
    /// 'Gateway:Rules:0:Action' to type ...", "... unknown key 'Nmae' ...") in generic outer exceptions;
    /// report the most specific messages of the chain.
    /// </summary>
    private static string Describe(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            messages.Add(current.Message);
        }

        var specific = messages.Where(m => m.Contains('\'', StringComparison.Ordinal) && !m.StartsWith("'ErrorOnUnknownConfiguration' was set", StringComparison.Ordinal)).ToList();
        var text = string.Join(" ", specific.Count > 0 ? specific : messages);

        // For enum values, list what is allowed.
        var enumType = typeof(GatewayConfiguration).Assembly.GetTypes()
            .FirstOrDefault(t => t.IsEnum && text.Contains($"to type '{t.FullName}'", StringComparison.Ordinal));
        return enumType is null ? text : $"{text} Allowed values: {string.Join(", ", Enum.GetNames(enumType))}.";
    }

    private static void Bind(IConfigurationSection parent, string key, object target, List<string> errors)
    {
        var section = parent.GetSection(key);
        try
        {
            section.Bind(target, options => options.ErrorOnUnknownConfiguration = true);
        }
        catch (InvalidOperationException ex)
        {
            errors.Add(Describe(ex));
            return;
        }

        // Safety net: never silently lose list entries.
        if (target is ICollection list && section.GetChildren().Count() is var expected && list.Count != expected)
        {
            errors.Add($"'{section.Path}' has {expected} entries but only {list.Count} could be read. Check the values of each entry.");
        }
    }
}
