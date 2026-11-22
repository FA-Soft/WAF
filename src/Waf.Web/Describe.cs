using System.Globalization;
using Waf.Core.Configuration;
using Waf.Core.Routing;

namespace Waf.Web;

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

    /// <summary>e.g. "http://10.0.0.5:8080" or a list for several destinations.</summary>
    public static string Destinations(IEnumerable<ProxyDestinationOptions> destinations)
    {
        ArgumentNullException.ThrowIfNull(destinations);

        return string.Join(", ", destinations.Select(d =>
            string.Create(CultureInfo.InvariantCulture, $"{d.Scheme.ToLowerInvariant()}://{(d.Address.Contains(':', StringComparison.Ordinal) ? $"[{d.Address}]" : d.Address)}:{d.Port}")));
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

        return $"{field} {verb} {Join(condition.Values, "or")}";
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
