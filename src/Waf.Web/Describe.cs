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

        var hosts = match.Hosts.Count > 0 ? Join(match.Hosts, Text.T("or")) : null;
        var path = !string.IsNullOrEmpty(match.PathPrefix) && match.PathPrefix != "/" ? match.PathPrefix : null;
        var text = (hosts, path) switch
        {
            (null, null) => Text.T("Every request"),
            (_, null) => Text.T("Requests for {0}", hosts),
            (null, _) => Text.T("Requests under {0}", path),
            _ => Text.T("Requests for {0} under {1}", hosts, path),
        };
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
        // Primaries first, then the failovers in the order they take over.
        return string.Join(", ", destinations.OrderBy(d => d.Failover ?? 0).Select(d =>
        {
            var text = Destination(d, known, addresses);
            return d.Failover is { } failover ? Text.T("{0} · failover {1}", text, failover) : text;
        }));
    }

    private static string Destination(ProxyDestinationOptions d, List<BackendTarget> known, ITargetAddressSource addresses)
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
            : Text.T("{0} (not found: no traffic)", label);
    }

    /// <summary>A moment as the admin UI shows it: "2026-11-24 10:42 UTC".</summary>
    public static string Time(DateTimeOffset moment) =>
        moment.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";

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
            ConditionField.ClientIp => Text.T("the client IP"),
            ConditionField.Host => Text.T("the host"),
            ConditionField.Path => Text.T("the path"),
            ConditionField.QueryString => Text.T("the query string"),
            ConditionField.Method => Text.T("the method"),
            ConditionField.Header => Text.T("the {0} header", condition.HeaderName),
            ConditionField.UserAgent => Text.T("the user agent"),
            _ => condition.Field.ToString(),
        };

        var not = condition.Negate;
        var verb = condition.Operator switch
        {
            ConditionOperator.Equals => not ? Text.T("is not") : Text.T("is"),
            ConditionOperator.StartsWith => not ? Text.T("does not start with") : Text.T("starts with"),
            ConditionOperator.EndsWith => not ? Text.T("does not end with") : Text.T("ends with"),
            ConditionOperator.Contains => not ? Text.T("does not contain") : Text.T("contains"),
            ConditionOperator.Regex => not ? Text.T("does not match the pattern") : Text.T("matches the pattern"),
            ConditionOperator.InCidr => not ? Text.T("is not in") : Text.T("is in"),
            _ => condition.Operator.ToString(),
        };

        return Text.T("{0} {1} {2}", field, verb, Join(condition.Values.Select(Shorten), Text.T("or")));
    }

    /// <summary>All conditions of a rule, e.g. "the path starts with /admin and the client IP is not in …".</summary>
    public static string Conditions(IEnumerable<RuleCondition> conditions)
    {
        ArgumentNullException.ThrowIfNull(conditions);

        var text = string.Join($" {Text.T("and")} ", conditions.Select(Condition));
        return text.Length == 0 ? Text.T("always") : char.ToUpper(text[0], CultureInfo.CurrentCulture) + text[1..];
    }

    /// <summary>e.g. "Block", "Block (detection only: logged, not enforced)".</summary>
    public static string Action(WafRule rule, bool globalDetectionOnly)
    {
        ArgumentNullException.ThrowIfNull(rule);

        return rule.Action switch
        {
            RuleAction.Allow => Text.T("Allow (skip further checks)"),
            RuleAction.LogOnly => Text.T("Log only"),
            _ when rule.DetectionOnly || globalDetectionOnly => Text.T("Block (detection only: logged, not enforced)"),
            _ => Text.T("Block"),
        };
    }

    /// <summary>e.g. "100 requests per minute per client IP".</summary>
    public static string RateLimit(RateLimitRule limit)
    {
        ArgumentNullException.ThrowIfNull(limit);

        var window = limit.WindowSeconds switch
        {
            1 => Text.T("second"),
            60 => Text.T("minute"),
            3600 => Text.T("hour"),
            86_400 => Text.T("day"),
            _ => Text.T("{0} seconds", limit.WindowSeconds),
        };

        var per = limit.Key switch
        {
            RateLimitKey.ClientIp => Text.T("per client IP"),
            RateLimitKey.ClientIpAndRoute => Text.T("per client IP and route"),
            _ => Text.T("per route for all clients together"),
        };

        return Text.Plural(limit.PermitLimit, "{0} request per {1} {2}", "{0} requests per {1} {2}", window, per);
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
        if (settings.SqlInjection) { enabled.Add(Text.T("SQL injection")); }
        if (settings.CrossSiteScripting) { enabled.Add(Text.T("Cross-site scripting")); }
        if (settings.PathTraversal) { enabled.Add(Text.T("Path traversal")); }
        if (settings.CommandInjection) { enabled.Add(Text.T("Command injection")); }
        if (settings.BadUserAgents) { enabled.Add(Text.T("Attack tools")); }
        return enabled;
    }

    /// <summary>e.g. "Add rule 'lock-admin'" or "Change setting: SQL injection detection".</summary>
    public static string ChangeTitle(ConfigurationChange change)
    {
        ArgumentNullException.ThrowIfNull(change);

        // Whole phrases per kind and section, so each language can order the words.
        var name = change.Name;
        return (change.Section, change.Kind) switch
        {
            (ConfigurationSection.Settings, ChangeKind.Added) => Text.T("Add setting: {0}", SettingLabel(name)),
            (ConfigurationSection.Settings, ChangeKind.Removed) => Text.T("Remove setting: {0}", SettingLabel(name)),
            (ConfigurationSection.Settings, _) => Text.T("Change setting: {0}", SettingLabel(name)),
            (ConfigurationSection.Route, ChangeKind.Added) => Text.T("Add route '{0}'", name),
            (ConfigurationSection.Route, ChangeKind.Removed) => Text.T("Remove route '{0}'", name),
            (ConfigurationSection.Route, _) => Text.T("Change route '{0}'", name),
            (ConfigurationSection.Rule, ChangeKind.Added) => Text.T("Add rule '{0}'", name),
            (ConfigurationSection.Rule, ChangeKind.Removed) => Text.T("Remove rule '{0}'", name),
            (ConfigurationSection.Rule, _) => Text.T("Change rule '{0}'", name),
            (ConfigurationSection.RateLimit, ChangeKind.Added) => Text.T("Add rate limit '{0}'", name),
            (ConfigurationSection.RateLimit, ChangeKind.Removed) => Text.T("Remove rate limit '{0}'", name),
            (ConfigurationSection.RateLimit, _) => Text.T("Change rate limit '{0}'", name),
            (ConfigurationSection.Target, ChangeKind.Added) => Text.T("Add target '{0}'", name),
            (ConfigurationSection.Target, ChangeKind.Removed) => Text.T("Remove target '{0}'", name),
            (ConfigurationSection.Target, _) => Text.T("Change target '{0}'", name),
            (_, ChangeKind.Added) => Text.T("Add certificate for {0}", name),
            (_, ChangeKind.Removed) => Text.T("Remove certificate for {0}", name),
            _ => Text.T("Change certificate for {0}", name),
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
                return Text.T("{0} → {1} (priority {2})", Conditions(rule.Conditions), Action(rule, after.Settings.DetectionOnly), rule.Priority)
                    + Scope(rule.Routes);

            case ConfigurationSection.RateLimit when source.RateLimits.FirstOrDefault(l => Named(l.Name)) is { } limit:
                var text = RateLimit(limit);
                if (limit.Conditions.Count > 0)
                {
                    var conditions = Conditions(limit.Conditions);
                    text = Text.T("{0}, when {1}", text, char.ToLower(conditions[0], CultureInfo.CurrentCulture) + conditions[1..]);
                }

                return (limit.DetectionOnly ? Text.T("{0} (detection only: logged, not enforced)", text) : text) + Scope(limit.Routes);

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
        routes.Count == 0 ? string.Empty : Text.Plural(routes.Count, "; only on route {1}", "; only on routes {1}", string.Join(", ", routes));

    private static readonly Dictionary<string, string> SettingLabels = new(StringComparer.Ordinal)
    {
        ["DetectionOnly"] = Text.N("Detection-only mode"),
        ["TrustedProxies"] = Text.N("Trusted proxies"),
        ["RateLimitMaxTrackedClients"] = Text.N("Rate-limit counters kept in memory"),
        ["AttackDetection.Enabled"] = Text.N("Attack detection"),
        ["AttackDetection.SqlInjection"] = Text.N("SQL injection detection"),
        ["AttackDetection.CrossSiteScripting"] = Text.N("Cross-site scripting detection"),
        ["AttackDetection.PathTraversal"] = Text.N("Path traversal detection"),
        ["AttackDetection.CommandInjection"] = Text.N("Command injection detection"),
        ["AttackDetection.BadUserAgents"] = Text.N("Attack tool detection"),
        ["AttackDetection.InspectBody"] = Text.N("Inspect request bodies"),
        ["AttackDetection.MaxBodyBytes"] = Text.N("Largest body inspected (bytes)"),
        ["AttackDetection.Exclusions"] = Text.N("Detection exclusions"),
    };

    private static string SettingLabel(string path) =>
        SettingLabels.TryGetValue(path, out var label) ? Text.T(label) : path.Replace(".", " › ", StringComparison.Ordinal);

    private static string SettingValue(string? json) => json switch
    {
        null => Text.T("(not set)"),
        "true" => Text.T("on"),
        "false" => Text.T("off"),
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
