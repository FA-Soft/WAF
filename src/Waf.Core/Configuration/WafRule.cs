namespace FASoft.Waf.Core.Configuration;

/// <summary>
/// A WAF rule: when all its conditions match a request, its action is applied.
/// </summary>
/// <remarks>
/// Rules are evaluated in <see cref="Priority"/> order (lowest first, then by name); the first matching
/// Allow or Block rule decides. LogOnly rules only record a match and evaluation continues.
/// </remarks>
public sealed class WafRule
{
    /// <summary>Unique rule name (letters, digits, '-', '_' and '.').</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional explanation shown in the UI and logs.</summary>
    public string? Description { get; set; }

    /// <summary>Disabled rules are kept but never evaluated.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Evaluation order: lower numbers run first.</summary>
    public int Priority { get; set; } = 100;

    /// <summary>What to do when the rule matches.</summary>
    public RuleAction Action { get; set; } = RuleAction.Block;

    /// <summary>
    /// Detection-only for this rule: a Block is logged but not enforced. The global
    /// <see cref="GatewaySettings.DetectionOnly"/> setting applies to all rules.
    /// </summary>
    public bool DetectionOnly { get; set; }

    /// <summary>Names of the routes this rule applies to. Empty means all routes.</summary>
    public IList<string> Routes { get; } = [];

    /// <summary>Conditions; all of them must match (AND). At least one is required.</summary>
    public IList<RuleCondition> Conditions { get; } = [];
}

/// <summary>A test on one part of the request.</summary>
public sealed class RuleCondition
{
    /// <summary>The part of the request to test.</summary>
    public ConditionField Field { get; set; }

    /// <summary>Header name; required when <see cref="Field"/> is <see cref="ConditionField.Header"/>.</summary>
    public string? HeaderName { get; set; }

    /// <summary>How to compare.</summary>
    public ConditionOperator Operator { get; set; }

    /// <summary>Values to compare with; the condition matches when any value matches (OR).</summary>
    public IList<string> Values { get; } = [];

    /// <summary>Compare text case-sensitively (default: case-insensitive).</summary>
    public bool CaseSensitive { get; set; }

    /// <summary>Invert the result: the condition matches when none of the values match.</summary>
    public bool Negate { get; set; }
}

/// <summary>What a matching rule does.</summary>
public enum RuleAction
{
    /// <summary>Let the request through and stop evaluating further rules.</summary>
    Allow,

    /// <summary>Reject the request (HTTP 403) and stop evaluating further rules.</summary>
    Block,

    /// <summary>Only record the match; evaluation continues with the next rule.</summary>
    LogOnly,
}

/// <summary>The part of a request a condition tests.</summary>
public enum ConditionField
{
    /// <summary>The client IP address (after trusted-proxy resolution).</summary>
    ClientIp,

    /// <summary>The Host header, without port.</summary>
    Host,

    /// <summary>The URL path, e.g. <c>/admin/users</c>.</summary>
    Path,

    /// <summary>The query string without the leading '?'.</summary>
    QueryString,

    /// <summary>The HTTP method, e.g. GET.</summary>
    Method,

    /// <summary>A request header, named by <see cref="RuleCondition.HeaderName"/>.</summary>
    Header,

    /// <summary>The User-Agent header.</summary>
    UserAgent,
}

/// <summary>How a condition compares the request value with its values.</summary>
public enum ConditionOperator
{
    /// <summary>Exact match.</summary>
    Equals,

    /// <summary>The request value starts with the value.</summary>
    StartsWith,

    /// <summary>The request value ends with the value.</summary>
    EndsWith,

    /// <summary>The request value contains the value.</summary>
    Contains,

    /// <summary>Regular expression (.NET non-backtracking engine: no backreferences or lookarounds).</summary>
    Regex,

    /// <summary>The client IP is in one of the IP addresses or CIDR ranges.</summary>
    InCidr,
}
