using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text;
using Waf.Core.Configuration;
using Waf.Core.Net;
using Waf.Data;

namespace Waf.Web;

/// <summary>What to do with a log entry; each opens a pre-filled editor (nothing is saved until the user saves).</summary>
internal enum LogAction
{
    /// <summary>A new route for the entry's host (for requests that matched no route).</summary>
    Route,

    /// <summary>A new rule matching the entry's path (and route).</summary>
    Rule,

    /// <summary>Block the entry's client IP: added to an existing IP block list, or a new one.</summary>
    Block,

    /// <summary>Allow a false positive: an Allow rule that runs before the rule that blocked the request.</summary>
    Allow,
}

/// <summary>
/// Turns a log entry into configuration: pre-filled form models for the route, rule and exclusion editors, and the
/// actions that make sense for an entry.
/// </summary>
internal static class LogActions
{
    /// <summary>Query parameters the editors read: <c>?fromLog=42&amp;action=Block</c>.</summary>
    public const string FromLogParameter = "fromLog";

    public const string ActionParameter = "action";

    /// <summary>A link to the editor for <paramref name="action"/> on <paramref name="entry"/>.</summary>
    public static string Url(RequestEvent entry, LogAction action, GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(configuration);

        var id = entry.Id.ToString(CultureInfo.InvariantCulture);
        return action switch
        {
            LogAction.Route => $"routes/new?{FromLogParameter}={id}",
            LogAction.Block when FindBlockList(configuration) is { } list => $"rules/{Uri.EscapeDataString(list.Name)}/edit?{FromLogParameter}={id}&{ActionParameter}=Block",
            LogAction.Allow when AttackCategoryOf(entry) is not null => $"detection/exclusions/new?{FromLogParameter}={id}",
            _ => $"rules/new?{FromLogParameter}={id}&{ActionParameter}={action}",
        };
    }

    /// <summary>The actions offered for <paramref name="entry"/>, with button labels.</summary>
    public static IReadOnlyList<(LogAction Action, string Label, string Help)> Available(RequestEvent entry, GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(configuration);

        var actions = new List<(LogAction, string, string)>();
        if (entry.Event is "RuleBlocked" or "RuleDetected" or "AttackBlocked" or "AttackDetected" or "RateLimited" or "RateLimitDetected")
        {
            actions.Add((LogAction.Allow, "Allow this (false positive)",
                AttackCategoryOf(entry) is { } category
                    ? $"Switch off {Label(category)} detection for {entry.Path} and below."
                    : $"Add an Allow rule for this client and path that runs before '{entry.RuleName}'."));
        }

        if (entry.RouteName is null && entry.Action == "NoRoute")
        {
            actions.Add((LogAction.Route, $"Create a route for {entry.Host}", "Send requests for this host to a backend."));
        }

        actions.Add((LogAction.Block, $"Block {entry.ClientIp}",
            FindBlockList(configuration) is { } list ? $"Add the address to the IP block list '{list.Name}'." : "Start an IP block list with this address."));
        actions.Add((LogAction.Rule, "Create a rule for this path", $"A rule for requests to {entry.Path}; choose what it does."));
        return actions;
    }

    /// <summary>A new route for the entry's host. The backend must still be entered.</summary>
    public static RouteFormModel NewRoute(RequestEvent entry, GatewayConfiguration configuration, long baseVersion)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(configuration);

        var model = RouteFormModel.ForNewRoute(baseVersion);
        model.Name = UniqueName(Slug(entry.Host, "site"), configuration.Routes.Select(r => r.Name));
        model.Hosts = entry.Host;
        model.PathPrefix = "/";
        return model;
    }

    /// <summary>A new rule for <paramref name="action"/> (Rule, Block or Allow) from the entry.</summary>
    public static RuleFormModel NewRule(RequestEvent entry, LogAction action, GatewayConfiguration configuration, long baseVersion)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(configuration);

        var routes = configuration.Routes.Select(r => r.Name).ToList();
        var names = configuration.Rules.Select(r => r.Name);
        var model = RuleFormModel.ForNewRule(baseVersion, routes);
        var note = $"From the request log (request {entry.Id.ToString(CultureInfo.InvariantCulture)}).";

        switch (action)
        {
            case LogAction.Block:
                model = RuleFormModel.ForNewRule(baseVersion, routes, "block-ips");
                model.Name = UniqueName(model.Name, names);
                model.Conditions[0].Values = entry.ClientIp;
                model.Description = $"Block these IP addresses and ranges. {note}";
                return model;

            case LogAction.Allow:
                var blocking = configuration.Rules.FirstOrDefault(r => string.Equals(r.Name, entry.RuleName, StringComparison.OrdinalIgnoreCase));
                model.Name = UniqueName($"allow-{Slug(entry.RuleName ?? "request", "request")}-exception", names);
                model.Action = RuleAction.Allow;
                model.Description = $"False positive of '{entry.RuleName}'. {note}";

                // Rules run lowest priority first: the exception must come before the rule that blocked. Allow also
                // skips rate limits, so for a rate limit any priority works.
                model.Priority = blocking is null ? 5 : Math.Max(0, blocking.Priority - 1);
                model.Conditions = entry.Event is "RateLimited" or "RateLimitDetected"
                    ? [new ConditionFormModel { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = entry.ClientIp }]
                    :
                    [
                        new ConditionFormModel { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = entry.Path },
                        new ConditionFormModel { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Values = entry.ClientIp },
                    ];
                break;

            default:
                model.Name = UniqueName($"rule-{Slug(entry.Path, "root")}", names);
                model.Action = RuleAction.Block;
                model.Description = note;
                model.Conditions = [new ConditionFormModel { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = entry.Path }];
                break;
        }

        foreach (var choice in model.RouteChoices)
        {
            choice.Selected = string.Equals(choice.Name, entry.RouteName, StringComparison.OrdinalIgnoreCase);
        }

        return model;
    }

    /// <summary>
    /// Adds the entry's client IP to an existing IP block list in the editor. Returns false when it is already listed.
    /// </summary>
    public static bool AddToBlockList(RuleFormModel model, RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentNullException.ThrowIfNull(entry);

        var list = model.Conditions.FirstOrDefault(c => c.Field == ConditionField.ClientIp && c.Operator == ConditionOperator.InCidr && !c.Negate);
        if (list is null)
        {
            return false;
        }

        var address = System.Net.IPAddress.Parse(entry.ClientIp);
        if (list.ValueList.Any(v => StrictCidr.TryParse(v, out var range, out _) && range.Contains(address)))
        {
            return false;
        }

        list.Values = string.IsNullOrWhiteSpace(list.Values) ? entry.ClientIp : list.Values.TrimEnd() + Environment.NewLine + entry.ClientIp;
        return true;
    }

    /// <summary>A detection exclusion for the entry's path and route, switching off the detected category.</summary>
    public static ExclusionFormModel NewExclusion(RequestEvent entry, GatewayConfiguration configuration, long baseVersion)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(configuration);

        var model = ExclusionFormModel.ForNew(baseVersion, configuration.Routes.Select(r => r.Name));
        model.PathPrefix = entry.Path;
        model.Reason = $"False positive: {entry.Detail ?? entry.RuleName} (request log {entry.Id.ToString(CultureInfo.InvariantCulture)}).";
        if (model.Reason.Length > ExclusionFormModel.MaxReasonLength)
        {
            model.Reason = model.Reason[..ExclusionFormModel.MaxReasonLength];
        }

        foreach (var route in model.RouteChoices)
        {
            route.Selected = string.Equals(route.Name, entry.RouteName, StringComparison.OrdinalIgnoreCase);
        }

        if (AttackCategoryOf(entry) is { } category)
        {
            model.Categories.First(c => c.Category == category).Selected = true;
        }

        return model;
    }

    /// <summary>The attack category of an attack-detection entry (its detail starts with it), or null.</summary>
    public static AttackCategory? AttackCategoryOf(RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (entry.Event is not ("AttackBlocked" or "AttackDetected") || entry.Detail is null)
        {
            return null;
        }

        var first = entry.Detail.Split(' ', 2)[0];
        return Enum.TryParse<AttackCategory>(first, out var category) && Enum.IsDefined(category) ? category : null;
    }

    /// <summary>The first enabled IP block list: a Block rule whose only condition is "client IP is in".</summary>
    public static WafRule? FindBlockList(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return configuration.Rules
            .Where(r => r.Enabled && r.Action == RuleAction.Block && r.Routes.Count == 0 && r.Conditions.Count == 1)
            .Where(r => r.Conditions[0] is { Field: ConditionField.ClientIp, Operator: ConditionOperator.InCidr, Negate: false })
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    public static string Label(AttackCategory category) => category switch
    {
        AttackCategory.SqlInjection => "SQL injection",
        AttackCategory.CrossSiteScripting => "cross-site scripting",
        AttackCategory.PathTraversal => "path traversal",
        AttackCategory.CommandInjection => "command injection",
        _ => "attack tool",
    };

    /// <summary>"shop-example-org" for "shop.example.org"; letters, digits and '-' only, at most 40 characters.</summary>
    internal static string Slug(string text, string fallback)
    {
        var slug = new StringBuilder();
        foreach (var c in text.ToLowerInvariant())
        {
            slug.Append(c is (>= 'a' and <= 'z') or (>= '0' and <= '9') ? c : '-');
        }

        var result = string.Join('-', slug.ToString().Split('-', StringSplitOptions.RemoveEmptyEntries));
        result = result.Length > 40 ? result[..40].TrimEnd('-') : result;
        return result.Length == 0 ? fallback : result;
    }

    /// <summary><paramref name="name"/>, or name-2, name-3, … when it is taken.</summary>
    internal static string UniqueName(string name, IEnumerable<string> existing)
    {
        var taken = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);
        var candidate = name;
        for (var i = 2; taken.Contains(candidate); i++)
        {
            candidate = $"{name}-{i.ToString(CultureInfo.InvariantCulture)}";
        }

        return candidate;
    }
}

/// <summary>One attack category checkbox of the exclusion editor.</summary>
public sealed class CategoryChoice
{
    public AttackCategory Category { get; set; }

    public bool Selected { get; set; }
}

/// <summary>Form model of the detection exclusion editor ("allow a false positive").</summary>
internal sealed class ExclusionFormModel : IValidatableObject
{
    public const int MaxReasonLength = 300;

    public long BaseVersion { get; set; }

    [Required(ErrorMessage = "Enter a path, e.g. /cms/editor; use / for every path.")]
    public string PathPrefix { get; set; } = "/";

    [StringLength(MaxReasonLength, ErrorMessage = "Keep the reason under 300 characters.")]
    public string? Reason { get; set; }

    // The form binder sets lists to null when nothing was posted for them.
    public List<RouteChoice> RouteChoices { get => field; set => field = value ?? []; } = [];

    public List<CategoryChoice> Categories { get => field; set => field = value ?? []; } = [];

    public static ExclusionFormModel ForNew(long baseVersion, IEnumerable<string> routeNames) => new()
    {
        BaseVersion = baseVersion,
        RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r })],
        Categories = [.. Enum.GetValues<AttackCategory>().Select(c => new CategoryChoice { Category = c })],
    };

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(PathPrefix) && PathPrefix.Trim()[0] != '/')
        {
            yield return new ValidationResult("The path must start with /, e.g. /cms/editor.", [nameof(PathPrefix)]);
        }
    }

    public DetectionExclusion ToExclusion()
    {
        var exclusion = new DetectionExclusion
        {
            PathPrefix = PathPrefix.Trim(),
            Reason = string.IsNullOrWhiteSpace(Reason) ? null : Reason.Trim(),
        };

        foreach (var route in RouteChoices.Where(r => r.Selected))
        {
            exclusion.Routes.Add(route.Name);
        }

        foreach (var category in Categories.Where(c => c.Selected))
        {
            exclusion.Categories.Add(category.Category);
        }

        return exclusion;
    }
}
