using Waf.Core.Configuration;
using Waf.Data;

namespace Waf.Web;

/// <summary>What importing a configuration file would do to the running configuration.</summary>
/// <param name="Candidate">The configuration that would become active; null when the file cannot be used.</param>
/// <param name="Errors">Why the file cannot be imported (JSON errors, missing secrets, validation errors).</param>
/// <param name="Changes">Differences with the running configuration.</param>
/// <param name="KeptSecrets">Number of secret values that were left out of the file and are kept from the running configuration.</param>
/// <param name="Tag">Identifies exactly this candidate, so Apply activates what the user saw.</param>
internal sealed record ImportPreview(
    GatewayConfiguration? Candidate, IReadOnlyList<string> Errors, IReadOnlyList<ConfigurationChange> Changes, int KeptSecrets, string? Tag)
{
    public bool CanApply => Candidate is not null && Errors.Count == 0 && Changes.Count > 0;
}

/// <summary>Checks a configuration file before it is imported.</summary>
internal static class ConfigurationImport
{
    /// <summary>Largest file accepted, in bytes.</summary>
    public const int MaxBytes = 5 * 1024 * 1024;

    public static ImportPreview Preview(string? json, GatewayConfiguration? running)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new ImportPreview(null, ["Choose a configuration file or paste its contents."], [], 0, null);
        }

        // Parse reports validation errors too, but a file without secrets only becomes valid after they are filled in.
        var parsed = GatewayConfigurationJson.Parse(json);
        if (parsed.Configuration is null)
        {
            return new ImportPreview(null, parsed.Errors, [], 0, null);
        }

        var candidate = parsed.Configuration;
        candidate.Schema = null;
        var placeholders = CountPlaceholders(candidate);
        var problems = ConfigurationSecrets.FillFrom(candidate, running);
        if (problems.Count > 0)
        {
            return new ImportPreview(null, problems, [], 0, null);
        }

        var errors = GatewayConfigurationValidator.Validate(candidate);
        if (errors.Count > 0)
        {
            return new ImportPreview(null, errors, [], 0, null);
        }

        var changes = running is null ? [] : ConfigurationDiff.Compare(running, candidate);
        return new ImportPreview(candidate, [], changes, placeholders, ConfigurationStore.ConfigTag(ConfigurationStore.ComputeHash(candidate)));
    }

    private static int CountPlaceholders(GatewayConfiguration configuration) =>
        configuration.Rules.SelectMany(r => r.Conditions)
            .Concat(configuration.RateLimits.SelectMany(l => l.Conditions))
            .Where(c => c.Field == ConditionField.Header)
            .Sum(c => c.Values.Count(v => v == ConfigurationSecrets.Placeholder));
}
