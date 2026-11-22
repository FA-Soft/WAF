using Waf.Core.Configuration;

namespace Waf.Engine;

/// <summary>The final verdict for a request.</summary>
public enum WafVerdict
{
    /// <summary>Forward the request.</summary>
    Allow,

    /// <summary>Reject the request.</summary>
    Block,
}

/// <summary>A rule that matched a request.</summary>
/// <param name="RuleName">Name of the rule.</param>
/// <param name="Action">The rule's configured action.</param>
/// <param name="DetectionOnly">True when a Block was not enforced because of detection-only mode.</param>
public sealed record RuleMatch(string RuleName, RuleAction Action, bool DetectionOnly);

/// <summary>Outcome of evaluating the rule set against a request.</summary>
public sealed class WafDecision
{
    private static readonly RuleMatch[] NoMatches = [];

    internal WafDecision(WafVerdict verdict, RuleMatch? decidingRule, IReadOnlyList<RuleMatch>? matches)
    {
        Verdict = verdict;
        DecidingRule = decidingRule;
        Matches = matches ?? NoMatches;
    }

    /// <summary>Allowed because no rule decided; shared instance, no allocation.</summary>
    public static WafDecision AllowedByDefault { get; } = new(WafVerdict.Allow, null, null);

    /// <summary>Allow or Block.</summary>
    public WafVerdict Verdict { get; }

    /// <summary>The Allow or Block rule that decided, or null when the default (allow) applied.</summary>
    public RuleMatch? DecidingRule { get; }

    /// <summary>
    /// All matching rules in evaluation order: LogOnly matches, detection-only Blocks and the deciding rule.
    /// </summary>
    public IReadOnlyList<RuleMatch> Matches { get; }

    /// <summary>True when at least one Block was suppressed by detection-only mode.</summary>
    public bool WouldHaveBlocked => Matches.Any(m => m.DetectionOnly);

    public bool IsBlocked => Verdict == WafVerdict.Block;
}
