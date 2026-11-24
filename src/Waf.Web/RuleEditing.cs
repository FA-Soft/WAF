using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Net;

namespace FASoft.Waf.Web;

/// <summary>One condition row of the rule / rate-limit editor.</summary>
public sealed class ConditionFormModel
{
    public ConditionField Field { get; set; } = ConditionField.Path;

    /// <summary>Only for <see cref="ConditionField.Header"/>.</summary>
    public string? HeaderName { get; set; }

    public ConditionOperator Operator { get; set; } = ConditionOperator.StartsWith;

    /// <summary>One value per line (IP lists may also use commas or spaces).</summary>
    public string? Values { get; set; }

    public bool Negate { get; set; }

    public bool CaseSensitive { get; set; }

    /// <summary>
    /// An untouched row (no values, default choices); such rows are ignored. A row whose field, operator or "not"
    /// was changed, e.g. a template's empty IP list, is not empty: dropping it silently would change what the rule
    /// does (an "only these IPs" rule would block everyone).
    /// </summary>
    public bool IsEmpty => string.IsNullOrWhiteSpace(Values) && string.IsNullOrWhiteSpace(HeaderName)
        && Field == ConditionField.Path && Operator == ConditionOperator.StartsWith && !Negate;

    public IReadOnlyList<string> ValueList => Field == ConditionField.ClientIp
        ? (Values ?? string.Empty).Split(['\n', '\r', ',', ' ', '\t', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : [.. (Values ?? string.Empty).Split('\n').Select(v => v.TrimEnd('\r')).Where(v => v.Trim().Length > 0)];

    public static ConditionFormModel From(RuleCondition condition)
    {
        ArgumentNullException.ThrowIfNull(condition);

        return new ConditionFormModel
        {
            Field = condition.Field,
            HeaderName = condition.HeaderName,
            Operator = condition.Operator,
            Values = string.Join(Environment.NewLine, condition.Values),
            Negate = condition.Negate,
            CaseSensitive = condition.CaseSensitive,
        };
    }

    public RuleCondition ToCondition()
    {
        var condition = new RuleCondition
        {
            Field = Field,
            HeaderName = Field == ConditionField.Header ? HeaderName?.Trim() : null,
            Operator = Operator,
            Negate = Negate,
            CaseSensitive = CaseSensitive,
        };

        foreach (var value in ValueList)
        {
            condition.Values.Add(value);
        }

        return condition;
    }

    /// <summary>Checks that need no configuration: every IP list entry, header name presence.</summary>
    public IEnumerable<string> Problems(int number)
    {
        if (IsEmpty)
        {
            yield break;
        }

        if (Field == ConditionField.ClientIp)
        {
            foreach (var entry in ValueList)
            {
                if (!StrictCidr.TryParse(entry, out _, out var reason))
                {
                    yield return $"Condition {number}: '{entry}': {reason}.";
                }
            }
        }

        if (Field == ConditionField.Header && string.IsNullOrWhiteSpace(HeaderName))
        {
            yield return Text.F("Condition {0}: enter the name of the header, e.g. X-Api-Key.", number);
        }

        if (ValueList.Count == 0)
        {
            yield return Text.F("Condition {0}: enter at least one value.", number);
        }
    }
}

/// <summary>A route that a rule or rate limit can be limited to.</summary>
public sealed class RouteChoice
{
    public string Name { get; set; } = string.Empty;

    public bool Selected { get; set; }
}

/// <summary>Plain-language labels for the editor's drop-downs.</summary>
internal static class ConditionLabels
{
    public static readonly (ConditionField Value, string Label)[] Fields =
    [
        (ConditionField.Path, Text.N("the path")),
        (ConditionField.ClientIp, Text.N("the client IP")),
        (ConditionField.Host, Text.N("the host name")),
        (ConditionField.QueryString, Text.N("the query string")),
        (ConditionField.Method, Text.N("the method")),
        (ConditionField.UserAgent, Text.N("the user agent")),
        (ConditionField.Header, Text.N("a header")),
    ];

    public static readonly (ConditionOperator Value, string Label)[] Operators =
    [
        (ConditionOperator.StartsWith, Text.N("starts with")),
        (ConditionOperator.Equals, Text.N("is")),
        (ConditionOperator.EndsWith, Text.N("ends with")),
        (ConditionOperator.Contains, Text.N("contains")),
        (ConditionOperator.Regex, Text.N("matches the pattern")),
        (ConditionOperator.InCidr, Text.N("is in the IP list")),
    ];

    public static readonly (RuleAction Value, string Label)[] Actions =
    [
        (RuleAction.Block, Text.N("Block the request (403)")),
        (RuleAction.Allow, Text.N("Allow it and skip the other checks")),
        (RuleAction.LogOnly, Text.N("Only log it")),
    ];
}

/// <summary>Form model of the rule editor.</summary>
internal sealed class RuleFormModel : IValidatableObject
{
    public long BaseVersion { get; set; }

    public bool IsNew { get; set; } = true;

    /// <summary>Set by the editor's extra buttons ("add-condition", "remove-condition-N"); null for Save.</summary>
    public string? Command { get; set; }

    [Required(ErrorMessage = "Give the rule a name, e.g. block-admin.")]
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    // Checkboxes default to false (an unticked box is not posted); new rules start ticked via the factories.
    public bool Enabled { get; set; }

    public bool DetectionOnly { get; set; }

    [Range(0, 1_000_000, ErrorMessage = "Use a priority of 0 or more; lower numbers run first.")]
    public int Priority { get; set; } = 100;

    public RuleAction Action { get; set; } = RuleAction.Block;

    // The form binder sets lists to null when nothing was posted for them (e.g. there are no routes).
    public List<RouteChoice> RouteChoices { get => field; set => field = value ?? []; } = [];

    public List<ConditionFormModel> Conditions { get => field; set => field = value ?? []; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(Name) && !FASoft.Waf.Core.Routing.ProxyRouteValidator.IsValidName(Name.Trim()))
        {
            yield return new ValidationResult("Use only letters, digits, '-', '_' and '.' in the name (no spaces).", [nameof(Name)]);
        }

        var conditions = Conditions.Where(c => !c.IsEmpty).ToList();
        if (conditions.Count == 0)
        {
            yield return new ValidationResult("Add at least one condition. To match every request, use: the path · starts with · /.", [nameof(Conditions)]);
        }

        for (var i = 0; i < Conditions.Count; i++)
        {
            foreach (var problem in Conditions[i].Problems(i + 1))
            {
                yield return new ValidationResult(problem, [nameof(Conditions)]);
            }
        }
    }

    /// <summary>A new rule with one empty condition, or pre-filled from a <see cref="TemplateLibrary"/> template.</summary>
    public static RuleFormModel ForNewRule(long baseVersion, IEnumerable<string> routeNames, string? template = null)
    {
        var model = new RuleFormModel
        {
            BaseVersion = baseVersion,
            Enabled = true,
            RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r })],
            Conditions = [new ConditionFormModel()],
        };

        TemplateLibrary.FindRule(template)?.Apply(model);
        return model;
    }

    public static RuleFormModel FromRule(WafRule rule, long baseVersion, IEnumerable<string> routeNames)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var scoped = new HashSet<string>(rule.Routes, StringComparer.OrdinalIgnoreCase);
        return new RuleFormModel
        {
            BaseVersion = baseVersion,
            IsNew = false,
            Name = rule.Name,
            Description = rule.Description,
            Enabled = rule.Enabled,
            DetectionOnly = rule.DetectionOnly,
            Priority = rule.Priority,
            Action = rule.Action,
            RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r, Selected = scoped.Contains(r) })],
            Conditions = [.. rule.Conditions.Select(ConditionFormModel.From)],
        };
    }

    public WafRule ToRule()
    {
        var rule = new WafRule
        {
            Name = Name.Trim(),
            Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
            Enabled = Enabled,
            DetectionOnly = DetectionOnly,
            Priority = Priority,
            Action = Action,
        };

        foreach (var route in RouteChoices.Where(r => r.Selected))
        {
            rule.Routes.Add(route.Name);
        }

        foreach (var condition in Conditions.Where(c => !c.IsEmpty))
        {
            rule.Conditions.Add(condition.ToCondition());
        }

        return rule;
    }
}

/// <summary>Form model of the rate-limit editor.</summary>
internal sealed class RateLimitFormModel : IValidatableObject
{
    public static readonly (int Seconds, string Label)[] WindowUnits =
    [
        (1, "seconds"),
        (60, "minutes"),
        (3600, "hours"),
        (86_400, "days"),
    ];

    public long BaseVersion { get; set; }

    public bool IsNew { get; set; } = true;

    public string? Command { get; set; }

    [Required(ErrorMessage = "Give the limit a name, e.g. login-attempts.")]
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public bool Enabled { get; set; }

    public bool DetectionOnly { get; set; }

    [Range(1, 1_000_000, ErrorMessage = "Allow between 1 and 1,000,000 requests.")]
    public int PermitLimit { get; set; } = 100;

    [Range(1, 86_400, ErrorMessage = "Use a window between 1 and 86400.")]
    public int WindowAmount { get; set; } = 1;

    /// <summary>Seconds per <see cref="WindowAmount"/> unit: 1, 60, 3600 or 86400.</summary>
    public int WindowUnitSeconds { get; set; } = 60;

    public RateLimitKey Key { get; set; } = RateLimitKey.ClientIp;

    // The form binder sets lists to null when nothing was posted for them (e.g. there are no routes).
    public List<RouteChoice> RouteChoices { get => field; set => field = value ?? []; } = [];

    public List<ConditionFormModel> Conditions { get => field; set => field = value ?? []; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(Name) && !FASoft.Waf.Core.Routing.ProxyRouteValidator.IsValidName(Name.Trim()))
        {
            yield return new ValidationResult("Use only letters, digits, '-', '_' and '.' in the name (no spaces).", [nameof(Name)]);
        }

        if (!WindowUnits.Any(u => u.Seconds == WindowUnitSeconds))
        {
            yield return new ValidationResult("Choose seconds, minutes, hours or days.", [nameof(WindowUnitSeconds)]);
        }
        else if ((long)WindowAmount * WindowUnitSeconds > GatewayConfigurationValidator.MaxWindowSeconds)
        {
            yield return new ValidationResult("The window can be at most one day.", [nameof(WindowAmount)]);
        }

        for (var i = 0; i < Conditions.Count; i++)
        {
            foreach (var problem in Conditions[i].Problems(i + 1))
            {
                yield return new ValidationResult(problem, [nameof(Conditions)]);
            }
        }
    }

    /// <summary>A new limit, or pre-filled from a <see cref="TemplateLibrary"/> template.</summary>
    public static RateLimitFormModel ForNewLimit(long baseVersion, IEnumerable<string> routeNames, string? template = null)
    {
        var model = new RateLimitFormModel
        {
            BaseVersion = baseVersion,
            Enabled = true,
            RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r })],
            Conditions = [new ConditionFormModel()],
        };

        TemplateLibrary.FindRateLimit(template)?.Apply(model);
        return model;
    }

    public static RateLimitFormModel FromLimit(RateLimitRule limit, long baseVersion, IEnumerable<string> routeNames)
    {
        ArgumentNullException.ThrowIfNull(limit);

        var unit = WindowUnits.Select(u => u.Seconds).Where(s => limit.WindowSeconds % s == 0).Max();
        var scoped = new HashSet<string>(limit.Routes, StringComparer.OrdinalIgnoreCase);
        return new RateLimitFormModel
        {
            BaseVersion = baseVersion,
            IsNew = false,
            Name = limit.Name,
            Description = limit.Description,
            Enabled = limit.Enabled,
            DetectionOnly = limit.DetectionOnly,
            PermitLimit = limit.PermitLimit,
            WindowAmount = limit.WindowSeconds / unit,
            WindowUnitSeconds = unit,
            Key = limit.Key,
            RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r, Selected = scoped.Contains(r) })],
            Conditions = limit.Conditions.Count == 0 ? [new ConditionFormModel()] : [.. limit.Conditions.Select(ConditionFormModel.From)],
        };
    }

    public RateLimitRule ToLimit()
    {
        var limit = new RateLimitRule
        {
            Name = Name.Trim(),
            Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
            Enabled = Enabled,
            DetectionOnly = DetectionOnly,
            PermitLimit = PermitLimit,
            WindowSeconds = WindowAmount * WindowUnitSeconds,
            Key = Key,
        };

        foreach (var route in RouteChoices.Where(r => r.Selected))
        {
            limit.Routes.Add(route.Name);
        }

        foreach (var condition in Conditions.Where(c => !c.IsEmpty))
        {
            limit.Conditions.Add(condition.ToCondition());
        }

        return limit;
    }
}

/// <summary>Handles the editors' "add condition" / "remove condition N" buttons.</summary>
internal static class ConditionCommands
{
    public const string Add = "add-condition";
    public const string RemovePrefix = "remove-condition-";

    /// <summary>Applies <paramref name="command"/> to the list; true when it was a condition command (do not save).</summary>
    public static bool TryApply(string? command, List<ConditionFormModel> conditions)
    {
        ArgumentNullException.ThrowIfNull(conditions);

        if (command == Add)
        {
            conditions.Add(new ConditionFormModel());
            return true;
        }

        if (command?.StartsWith(RemovePrefix, StringComparison.Ordinal) == true
            && int.TryParse(command[RemovePrefix.Length..], System.Globalization.CultureInfo.InvariantCulture, out var index))
        {
            if (index >= 0 && index < conditions.Count)
            {
                conditions.RemoveAt(index);
            }

            if (conditions.Count == 0)
            {
                conditions.Add(new ConditionFormModel());
            }

            return true;
        }

        return false;
    }
}
