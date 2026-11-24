using System.Text.Json;
using System.Text.Json.Nodes;

namespace FASoft.Waf.Core.Configuration;

/// <summary>What happened to a configuration item.</summary>
public enum ChangeKind
{
    Added,
    Changed,
    Removed,
}

/// <summary>The part of the configuration a change is in.</summary>
public enum ConfigurationSection
{
    Settings,
    Route,
    Rule,
    RateLimit,
    Certificate,
    Target,
}

/// <summary>One difference between two configurations.</summary>
/// <param name="Kind">Added, changed or removed.</param>
/// <param name="Section">Where the item lives.</param>
/// <param name="Name">
/// The item's name (target, route, rule, rate limit) or host name (certificate); for <see cref="ConfigurationSection.Settings"/>
/// the path of the setting, e.g. <c>AttackDetection.SqlInjection</c>.
/// </param>
/// <param name="Before">The old value as JSON; null when added.</param>
/// <param name="After">The new value as JSON; null when removed.</param>
public sealed record ConfigurationChange(ChangeKind Kind, ConfigurationSection Section, string Name, string? Before, string? After);

/// <summary>
/// Compares two configurations item by item: targets, routes, rules, rate limits and certificates by name, settings per
/// value. Used to show what a preset, an import or the AI assistant would change before it is applied.
/// </summary>
public static class ConfigurationDiff
{
    /// <summary>Differences from <paramref name="before"/> to <paramref name="after"/>; empty when they are equivalent.</summary>
    public static IReadOnlyList<ConfigurationChange> Compare(GatewayConfiguration before, GatewayConfiguration after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var changes = new List<ConfigurationChange>();
        CompareSettings(Node(before.Settings), Node(after.Settings), string.Empty, changes);
        CompareItems(ConfigurationSection.Target, before.Targets, after.Targets, t => t.Name, changes);
        CompareItems(ConfigurationSection.Route, before.Routes, after.Routes, r => r.Name, changes);
        CompareItems(ConfigurationSection.Rule, before.Rules, after.Rules, r => r.Name, changes);
        CompareItems(ConfigurationSection.RateLimit, before.RateLimits, after.RateLimits, l => l.Name, changes);
        CompareItems(ConfigurationSection.Certificate, before.Certificates, after.Certificates, c => c.HostName, changes);
        return changes;
    }

    private static void CompareItems<T>(
        ConfigurationSection section, IEnumerable<T> before, IEnumerable<T> after, Func<T, string> name, List<ConfigurationChange> changes)
    {
        var old = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in before)
        {
            old.TryAdd(name(item), item);
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in after)
        {
            var key = name(item);
            if (!seen.Add(key))
            {
                continue;
            }

            var json = Json(item);
            if (!old.TryGetValue(key, out var previous))
            {
                changes.Add(new ConfigurationChange(ChangeKind.Added, section, key, null, json));
            }
            else if (Json(previous) is var previousJson && previousJson != json)
            {
                changes.Add(new ConfigurationChange(ChangeKind.Changed, section, key, previousJson, json));
            }
        }

        foreach (var (key, item) in old)
        {
            if (!seen.Contains(key))
            {
                changes.Add(new ConfigurationChange(ChangeKind.Removed, section, key, Json(item), null));
            }
        }
    }

    /// <summary>Settings are compared per value, so a change reads "AttackDetection.SqlInjection: false → true".</summary>
    private static void CompareSettings(JsonNode? before, JsonNode? after, string path, List<ConfigurationChange> changes)
    {
        if (before is JsonObject oldObject && after is JsonObject newObject)
        {
            foreach (var (key, value) in newObject)
            {
                CompareSettings(oldObject[key], value, path.Length == 0 ? key : $"{path}.{key}", changes);
            }

            foreach (var (key, value) in oldObject)
            {
                if (!newObject.ContainsKey(key))
                {
                    CompareSettings(value, null, path.Length == 0 ? key : $"{path}.{key}", changes);
                }
            }

            return;
        }

        var oldJson = before?.ToJsonString(GatewayConfigurationJson.Options);
        var newJson = after?.ToJsonString(GatewayConfigurationJson.Options);
        if (oldJson == newJson)
        {
            return;
        }

        var kind = oldJson is null ? ChangeKind.Added : newJson is null ? ChangeKind.Removed : ChangeKind.Changed;
        changes.Add(new ConfigurationChange(kind, ConfigurationSection.Settings, path, oldJson, newJson));
    }

    private static JsonNode? Node(GatewaySettings settings) =>
        JsonSerializer.SerializeToNode(settings, GatewayConfigurationJson.Options);

    private static string Json<T>(T item) => JsonSerializer.Serialize(item, GatewayConfigurationJson.Options);
}
