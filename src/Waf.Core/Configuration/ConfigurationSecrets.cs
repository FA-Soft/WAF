namespace Waf.Core.Configuration;

/// <summary>
/// Secret values in a configuration and their removal from exports and backups.
/// </summary>
/// <remarks>
/// Secrets are the values of header conditions in rules and rate limits (for example the API keys of a
/// "require X-Api-Key" rule). An export without secrets replaces each such value with <see cref="Placeholder"/>.
/// When that file is imported, every placeholder gets the value the running configuration has for the same
/// condition (same rule or rate limit, same position, same header), so an export without secrets can be imported
/// back without losing them. A placeholder can never become active: the validator rejects it.
/// </remarks>
public static class ConfigurationSecrets
{
    /// <summary>Stands in for a secret value that was left out of an export or backup.</summary>
    public const string Placeholder = "[secret not exported]";

    /// <summary>Number of secret values in <paramref name="configuration"/> (placeholders included).</summary>
    public static int Count(GatewayConfiguration configuration) =>
        SecretConditions(configuration).Sum(c => c.Condition.Values.Count);

    /// <summary>Replaces every secret value with <see cref="Placeholder"/>; returns how many were replaced.</summary>
    /// <remarks>Changes <paramref name="configuration"/> itself: pass a copy.</remarks>
    public static int Redact(GatewayConfiguration configuration)
    {
        var count = 0;
        foreach (var (_, _, condition) in SecretConditions(configuration))
        {
            for (var i = 0; i < condition.Values.Count; i++)
            {
                condition.Values[i] = Placeholder;
                count++;
            }
        }

        return count;
    }

    /// <summary>True when <paramref name="configuration"/> still contains placeholders.</summary>
    public static bool HasPlaceholders(GatewayConfiguration configuration) =>
        SecretConditions(configuration).Any(c => c.Condition.Values.Contains(Placeholder));

    /// <summary>
    /// Fills placeholders in <paramref name="candidate"/> with the values of the same conditions in
    /// <paramref name="running"/>. Returns a message for every condition that could not be filled; empty when
    /// <paramref name="candidate"/> has no placeholders left.
    /// </summary>
    /// <remarks>Changes <paramref name="candidate"/> itself.</remarks>
    public static IReadOnlyList<string> FillFrom(GatewayConfiguration candidate, GatewayConfiguration? running)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var current = new Dictionary<(string, int), RuleCondition>();
        if (running is not null)
        {
            foreach (var (item, index, condition) in SecretConditions(running))
            {
                current.TryAdd((item.ToUpperInvariant(), index), condition);
            }
        }

        var problems = new List<string>();
        foreach (var (item, index, condition) in SecretConditions(candidate))
        {
            if (!condition.Values.Contains(Placeholder))
            {
                continue;
            }

            if (current.TryGetValue((item.ToUpperInvariant(), index), out var source)
                && string.Equals(source.HeaderName, condition.HeaderName, StringComparison.OrdinalIgnoreCase)
                && !source.Values.Contains(Placeholder))
            {
                condition.Values.Clear();
                foreach (var value in source.Values)
                {
                    condition.Values.Add(value);
                }
            }
            else
            {
                problems.Add($"{item}, condition {index + 1} (header {condition.HeaderName}): the secret value was left out of the file "
                    + "and this gateway has no value to keep for it. Use a file exported with secrets, or enter the value in the file.");
            }
        }

        return problems;
    }

    /// <summary>Header conditions of all rules and rate limits, named "Rule 'x'" or "Rate limit 'y'", with their position.</summary>
    private static IEnumerable<(string Item, int Index, RuleCondition Condition)> SecretConditions(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        foreach (var rule in configuration.Rules)
        {
            for (var i = 0; i < rule.Conditions.Count; i++)
            {
                if (rule.Conditions[i].Field == ConditionField.Header)
                {
                    yield return ($"Rule '{rule.Name}'", i, rule.Conditions[i]);
                }
            }
        }

        foreach (var limit in configuration.RateLimits)
        {
            for (var i = 0; i < limit.Conditions.Count; i++)
            {
                if (limit.Conditions[i].Field == ConditionField.Header)
                {
                    yield return ($"Rate limit '{limit.Name}'", i, limit.Conditions[i]);
                }
            }
        }
    }
}
