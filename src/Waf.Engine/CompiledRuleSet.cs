using Waf.Core.Configuration;

namespace Waf.Engine;

/// <summary>
/// An immutable, pre-compiled set of WAF rules. Create one with <see cref="Compile"/>; swap it in with
/// <see cref="RuleSetProvider"/>. Safe for concurrent use.
/// </summary>
/// <remarks>
/// Evaluation order: priority (lowest first), then name. The first matching Allow or Block rule decides.
/// LogOnly rules record a match and evaluation continues. A Block rule in detection-only mode (per rule,
/// or globally) is recorded as a would-be block and evaluation continues as if it had not matched.
/// When no rule decides, the request is allowed.
/// </remarks>
public sealed class CompiledRuleSet
{
    private readonly CompiledRule[] _rules;

    private CompiledRuleSet(CompiledRule[] rules, bool detectionOnly)
    {
        _rules = rules;
        DetectionOnly = detectionOnly;
    }

    /// <summary>A rule set without rules: every request is allowed.</summary>
    public static CompiledRuleSet Empty { get; } = new([], detectionOnly: false);

    /// <summary>Global detection-only mode.</summary>
    public bool DetectionOnly { get; }

    /// <summary>Names of the enabled rules in evaluation order.</summary>
    public IReadOnlyList<string> RuleNames => [.. _rules.Select(r => r.Name)];

    /// <summary>Compiles the rules and global settings of a configuration.</summary>
    /// <exception cref="ArgumentException">The configuration is not valid.</exception>
    public static CompiledRuleSet Compile(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var errors = GatewayConfigurationValidator.Validate(configuration);
        if (errors.Count > 0)
        {
            throw new ArgumentException("The configuration is not valid: " + string.Join(" ", errors), nameof(configuration));
        }

        var rules = configuration.Rules
            .Where(r => r.Enabled)
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Select(r => new CompiledRule(r))
            .ToArray();

        return new CompiledRuleSet(rules, configuration.Settings.DetectionOnly);
    }

    public WafDecision Evaluate(IWafRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        List<RuleMatch>? matches = null;

        foreach (var rule in _rules)
        {
            if (!rule.AppliesTo(request.RouteName) || !rule.Matches(request))
            {
                continue;
            }

            switch (rule.Action)
            {
                case RuleAction.LogOnly:
                    (matches ??= []).Add(rule.Match(detectionOnly: false));
                    break;

                case RuleAction.Block when rule.DetectionOnly || DetectionOnly:
                    (matches ??= []).Add(rule.Match(detectionOnly: true));
                    break;

                case RuleAction.Block:
                case RuleAction.Allow:
                    var deciding = rule.Match(detectionOnly: false);
                    (matches ??= []).Add(deciding);
                    var verdict = rule.Action == RuleAction.Block ? WafVerdict.Block : WafVerdict.Allow;
                    return new WafDecision(verdict, deciding, matches);
            }
        }

        return matches is null ? WafDecision.AllowedByDefault : new WafDecision(WafVerdict.Allow, null, matches);
    }

    private sealed class CompiledRule
    {
        private readonly CompiledCondition[] _conditions;
        private readonly HashSet<string>? _routes;
        private readonly RuleMatch _match;
        private readonly RuleMatch _detectionOnlyMatch;

        public CompiledRule(WafRule rule)
        {
            Name = rule.Name;
            Action = rule.Action;
            DetectionOnly = rule.DetectionOnly;
            _conditions = [.. rule.Conditions.Select(CompiledCondition.Compile)];
            _routes = rule.Routes.Count == 0 ? null : new HashSet<string>(rule.Routes, StringComparer.OrdinalIgnoreCase);
            _match = new RuleMatch(Name, Action, DetectionOnly: false);
            _detectionOnlyMatch = new RuleMatch(Name, Action, DetectionOnly: true);
        }

        public string Name { get; }

        public RuleAction Action { get; }

        public bool DetectionOnly { get; }

        public bool AppliesTo(string? routeName) =>
            _routes is null || (routeName is not null && _routes.Contains(routeName));

        public bool Matches(IWafRequest request)
        {
            foreach (var condition in _conditions)
            {
                if (!condition.Matches(request))
                {
                    return false;
                }
            }

            return true;
        }

        public RuleMatch Match(bool detectionOnly) => detectionOnly ? _detectionOnlyMatch : _match;
    }
}
