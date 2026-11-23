using System.Text.Json;
using System.Text.Json.Nodes;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Ai;

/// <summary>
/// The only view of the configuration an AI provider ever gets: built from an allowlist, so a setting added later is
/// left out until it is added here on purpose.
/// </summary>
/// <remarks>
/// Included: routes (host names, paths, methods, backend addresses, HTTPS options), rules and rate limits (with the
/// values of secret conditions such as API keys replaced), detection-only mode, attack detection, trusted proxies, log
/// retention and HSTS settings, and which host names have a certificate from which source. Left out: secret condition
/// values, the Let's Encrypt contact e-mail, certificate files, paths and thumbprints, and anything outside the
/// configuration (request log, events, admin accounts, remote access, API keys).
/// </remarks>
public static class ConfigurationSummary
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Settings sent as they are (and the only settings a proposal may change).</summary>
    internal static readonly string[] AllowedSettings =
        [nameof(GatewaySettings.DetectionOnly), nameof(GatewaySettings.TrustedProxies), nameof(GatewaySettings.AttackDetection),
         nameof(GatewaySettings.LogRetention), nameof(GatewaySettings.Hsts)];

    /// <summary>The sanitized summary of <paramref name="configuration"/> as indented JSON.</summary>
    public static string Create(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // A copy with every secret value replaced by the placeholder; the caller's object is left as it is.
        var copy = GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration)).Configuration
            ?? throw new InvalidOperationException("The configuration could not be copied.");
        ConfigurationSecrets.Redact(copy);
        var full = JsonNode.Parse(GatewayConfigurationJson.Serialize(copy))!.AsObject();

        var settings = new JsonObject();
        if (full["Settings"] is JsonObject allSettings)
        {
            foreach (var name in AllowedSettings)
            {
                if (allSettings[name] is { } value)
                {
                    settings[name] = value.DeepClone();
                }
            }
        }

        var certificates = new JsonArray();
        foreach (var certificate in configuration.Certificates)
        {
            certificates.Add(new JsonObject { ["HostName"] = certificate.HostName, ["Source"] = certificate.Source.ToString() });
        }

        var summary = new JsonObject
        {
            ["SchemaVersion"] = configuration.SchemaVersion,
            ["Settings"] = settings,
            ["Routes"] = full["Routes"]?.DeepClone() ?? new JsonArray(),
            ["Rules"] = full["Rules"]?.DeepClone() ?? new JsonArray(),
            ["RateLimits"] = full["RateLimits"]?.DeepClone() ?? new JsonArray(),
            ["Certificates"] = certificates,
        };
        return summary.ToJsonString(Indented);
    }
}
