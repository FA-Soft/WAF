using System.Globalization;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Web;

/// <summary>Plain-language descriptions of configuration items for the admin UI.</summary>
internal static class Describe
{
    /// <summary>e.g. "Requests for api.example.com under /api (GET, POST)" or "Every request".</summary>
    public static string Match(RouteMatchOptions match)
    {
        ArgumentNullException.ThrowIfNull(match);

        var parts = new List<string>();
        if (match.Hosts.Count > 0)
        {
            parts.Add("for " + Join(match.Hosts, "or"));
        }

        if (!string.IsNullOrEmpty(match.PathPrefix) && match.PathPrefix != "/")
        {
            parts.Add($"under {match.PathPrefix}");
        }

        var text = parts.Count == 0 ? "Every request" : "Requests " + string.Join(' ', parts);
        return match.Methods.Count > 0 ? $"{text} ({string.Join(", ", match.Methods.Select(m => m.ToUpperInvariant()))})" : text;
    }

    /// <summary>
    /// e.g. "http://10.0.0.5:8080", or "nas · web (http://192.168.1.20:5000)" for a target destination (just the label
    /// when <paramref name="targets"/> is not given or does not know it); a list for several destinations.
    /// </summary>
    /// <param name="destinations">The destinations.</param>
    /// <param name="targets">The configuration's targets, to show the address a label stands for.</param>
    /// <param name="addresses">Where targets are right now (MAC addresses found); null: their configured addresses.</param>
    public static string Destinations(
        IEnumerable<ProxyDestinationOptions> destinations, IEnumerable<BackendTarget>? targets = null, ITargetAddressSource? addresses = null)
    {
        ArgumentNullException.ThrowIfNull(destinations);

        var known = targets?.ToList() ?? [];
        addresses ??= ConfiguredTargetAddresses.Instance;
        return string.Join(", ", destinations.Select(d =>
        {
            if (!d.UsesTarget)
            {
                return Address(d.Scheme, d.Address, d.Port);
            }

            var label = TargetResolver.Label(d.Target, d.TargetPort);
            if (TargetResolver.Find(known, d.Target) is not { } target || TargetResolver.FindPort(target, d.TargetPort) is not { } port)
            {
                return label;
            }

            return addresses.CurrentAddress(target) is { Length: > 0 } address
                ? $"{label} ({Address(port.Scheme, address, port.Port)})"
                : $"{label} (not found: no traffic)";
        }));
    }

    /// <summary>e.g. "http://10.0.0.5:8080" or "http://[fd00::5]:8080".</summary>
    public static string Address(string scheme, string address, int port)
    {
        ArgumentNullException.ThrowIfNull(scheme);
        ArgumentNullException.ThrowIfNull(address);
        return string.Create(CultureInfo.InvariantCulture, $"{scheme.ToLowerInvariant()}://{(address.Contains(':', StringComparison.Ordinal) ? $"[{address}]" : address)}:{port}");
    }

    /// <summary>e.g. "the path starts with /admin" or "the client IP is not in 203.0.113.0/24".</summary>
    public static string Condition(RuleCondition condition)
    {
        ArgumentNullException.ThrowIfNull(condition);

        var field = condition.Field switch
        {
            ConditionField.ClientIp => "the client IP",
            ConditionField.Host => "the host",
            ConditionField.Path => "the path",
            ConditionField.QueryString => "the query string",
            ConditionField.Method => "the method",
            ConditionField.Header => $"the {condition.HeaderName} header",
            ConditionField.UserAgent => "the user agent",
            _ => condition.Field.ToString(),
        };

        var not = condition.Negate;
        var verb = condition.Operator switch
        {
            ConditionOperator.Equals => not ? "is not" : "is",
            ConditionOperator.StartsWith => not ? "does not start with" : "starts with",
            ConditionOperator.EndsWith => not ? "does not end with" : "ends with",
            ConditionOperator.Contains => not ? "does not contain" : "contains",
            ConditionOperator.Regex => not ? "does not match the pattern" : "matches the pattern",
            ConditionOperator.InCidr => not ? "is not in" : "is in",
            _ => condition.Operator.ToString(),
        };

        return $"{field} {verb} {Join(condition.Values.Select(Shorten), "or")}";
    }

    /// <summary>All conditions of a rule, e.g. "the path starts with /admin and the client IP is not in …".</summary>
    public static string Conditions(IEnumerable<RuleCondition> conditions)
    {
        ArgumentNullException.ThrowIfNull(conditions);

        var text = string.Join(" and ", conditions.Select(Condition));
        return text.Length == 0 ? "always" : char.ToUpperInvariant(text[0]) + text[1..];
    }

    /// <summary>e.g. "Block", "Block (detection only: logged, not enforced)".</summary>
    public static string Action(WafRule rule, bool globalDetectionOnly)
    {
        ArgumentNullException.ThrowIfNull(rule);

        return rule.Action switch
        {
            RuleAction.Allow => "Allow (skip further checks)",
            RuleAction.LogOnly => "Log only",
            _ when rule.DetectionOnly || globalDetectionOnly => "Block (detection only: logged, not enforced)",
            _ => "Block",
        };
    }

    /// <summary>e.g. "100 requests per minute per client IP".</summary>
    public static string RateLimit(RateLimitRule limit)
    {
        ArgumentNullException.ThrowIfNull(limit);

        var window = limit.WindowSeconds switch
        {
            1 => "second",
            60 => "minute",
            3600 => "hour",
            86_400 => "day",
            _ => string.Create(CultureInfo.InvariantCulture, $"{limit.WindowSeconds} seconds"),
        };

        var per = limit.Key switch
        {
            RateLimitKey.ClientIp => "per client IP",
            RateLimitKey.ClientIpAndRoute => "per client IP and route",
            _ => "per route for all clients together",
        };

        return string.Create(CultureInfo.InvariantCulture, $"{limit.PermitLimit} requests per {window} {per}");
    }

    /// <summary>The attack categories that are switched on, in plain language.</summary>
    public static IReadOnlyList<string> EnabledDetections(AttackDetectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!settings.Enabled)
        {
            return [];
        }

        var enabled = new List<string>();
        if (settings.SqlInjection) { enabled.Add("SQL injection"); }
        if (settings.CrossSiteScripting) { enabled.Add("Cross-site scripting"); }
        if (settings.PathTraversal) { enabled.Add("Path traversal"); }
        if (settings.CommandInjection) { enabled.Add("Command injection"); }
        if (settings.BadUserAgents) { enabled.Add("Attack tools"); }
        return enabled;
    }

    /// <summary>e.g. "Add rule 'lock-admin'" or "Change setting: SQL injection detection".</summary>
    public static string ChangeTitle(ConfigurationChange change)
    {
        ArgumentNullException.ThrowIfNull(change);

        var verb = change.Kind switch
        {
            ChangeKind.Added => "Add",
            ChangeKind.Removed => "Remove",
            _ => "Change",
        };

        return change.Section switch
        {
            ConfigurationSection.Settings => $"{(change.Kind == ChangeKind.Changed ? "Change" : verb)} setting: {SettingLabel(change.Name)}",
            ConfigurationSection.Route => $"{verb} route '{change.Name}'",
            ConfigurationSection.Rule => $"{verb} rule '{change.Name}'",
            ConfigurationSection.RateLimit => $"{verb} rate limit '{change.Name}'",
            ConfigurationSection.Target => $"{verb} target '{change.Name}'",
            _ => $"{verb} certificate for {change.Name}",
        };
    }

    /// <summary>What the item does after the change (or did, when removed), in plain language.</summary>
    public static string ChangeDetail(ConfigurationChange change, GatewayConfiguration before, GatewayConfiguration after)
    {
        ArgumentNullException.ThrowIfNull(change);
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var source = change.Kind == ChangeKind.Removed ? before : after;
        bool Named(string name) => string.Equals(name, change.Name, StringComparison.OrdinalIgnoreCase);

        switch (change.Section)
        {
            case ConfigurationSection.Settings:
                return $"{SettingValue(change.Before)} → {SettingValue(change.After)}";

            case ConfigurationSection.Route when source.Routes.FirstOrDefault(r => Named(r.Name)) is { } route:
                return $"{Match(route.Match)} → {Destinations(route.Destinations, source.Targets)}";

            case ConfigurationSection.Target when source.Targets.FirstOrDefault(t => Named(t.Name)) is { } target:
                return $"{target.Address}: " + string.Join(", ", target.Ports.Select(p => $"{p.Name} {Address(p.Scheme, target.Address, p.Port)}"));

            case ConfigurationSection.Rule when source.Rules.FirstOrDefault(r => Named(r.Name)) is { } rule:
                return string.Create(CultureInfo.InvariantCulture, $"{Conditions(rule.Conditions)} → {Action(rule, after.Settings.DetectionOnly)} (priority {rule.Priority})")
                    + Scope(rule.Routes);

            case ConfigurationSection.RateLimit when source.RateLimits.FirstOrDefault(l => Named(l.Name)) is { } limit:
                var text = RateLimit(limit);
                if (limit.Conditions.Count > 0)
                {
                    text += ", when " + char.ToLowerInvariant(Conditions(limit.Conditions)[0]) + Conditions(limit.Conditions)[1..];
                }

                return text + (limit.DetectionOnly ? " (detection only: logged, not enforced)" : string.Empty) + Scope(limit.Routes);

            default:
                return string.Empty;
        }
    }

    /// <summary>The item's own description (rules and rate limits), or null.</summary>
    public static string? ChangeNote(ConfigurationChange change, GatewayConfiguration before, GatewayConfiguration after)
    {
        ArgumentNullException.ThrowIfNull(change);
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var source = change.Kind == ChangeKind.Removed ? before : after;
        bool Named(string name) => string.Equals(name, change.Name, StringComparison.OrdinalIgnoreCase);
        return change.Section switch
        {
            ConfigurationSection.Rule => source.Rules.FirstOrDefault(r => Named(r.Name))?.Description,
            ConfigurationSection.RateLimit => source.RateLimits.FirstOrDefault(l => Named(l.Name))?.Description,
            _ => null,
        };
    }

    /// <summary>Long values (mostly regular expressions) are cut off; the editor shows them in full.</summary>
    private const int MaxValueLength = 60;

    private static string Shorten(string value) =>
        value.Length <= MaxValueLength ? value : value[..(MaxValueLength - 1)] + "…";

    private static string Scope(IList<string> routes) =>
        routes.Count == 0 ? string.Empty : $"; only on route {string.Join(", ", routes)}";

    private static readonly Dictionary<string, string> SettingLabels = new(StringComparer.Ordinal)
    {
        ["DetectionOnly"] = "Detection-only mode",
        ["TrustedProxies"] = "Trusted proxies",
        ["RateLimitMaxTrackedClients"] = "Rate-limit counters kept in memory",
        ["AttackDetection.Enabled"] = "Attack detection",
        ["AttackDetection.SqlInjection"] = "SQL injection detection",
        ["AttackDetection.CrossSiteScripting"] = "Cross-site scripting detection",
        ["AttackDetection.PathTraversal"] = "Path traversal detection",
        ["AttackDetection.CommandInjection"] = "Command injection detection",
        ["AttackDetection.BadUserAgents"] = "Attack tool detection",
        ["AttackDetection.InspectBody"] = "Inspect request bodies",
        ["AttackDetection.MaxBodyBytes"] = "Largest body inspected (bytes)",
        ["AttackDetection.Exclusions"] = "Detection exclusions",
    };

    private static string SettingLabel(string path) =>
        SettingLabels.TryGetValue(path, out var label) ? label : path.Replace(".", " › ", StringComparison.Ordinal);

    private static string SettingValue(string? json) => json switch
    {
        null => "(not set)",
        "true" => "on",
        "false" => "off",
        _ => json,
    };

    private static string Join(IEnumerable<string> values, string conjunction)
    {
        var list = values.ToList();
        return list.Count switch
        {
            0 => string.Empty,
            1 => list[0],
            _ => $"{string.Join(", ", list.Take(list.Count - 1))} {conjunction} {list[^1]}",
        };
    }
}
