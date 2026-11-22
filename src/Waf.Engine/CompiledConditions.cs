using System.Buffers;
using System.Net;
using System.Text.RegularExpressions;
using Waf.Core.Configuration;
using Waf.Core.Net;

namespace Waf.Engine;

/// <summary>A condition prepared for fast evaluation.</summary>
internal abstract class CompiledCondition(bool negate)
{
    public bool Matches(IWafRequest request) => Test(request) != negate;

    protected abstract bool Test(IWafRequest request);

    public static CompiledCondition Compile(RuleCondition condition)
    {
        if (condition.Field == ConditionField.ClientIp)
        {
            return new IpCondition(condition);
        }

        Func<IWafRequest, string?> selector = condition.Field switch
        {
            ConditionField.Host => r => r.Host,
            ConditionField.Path => r => r.Path,
            ConditionField.QueryString => r => r.QueryString,
            ConditionField.Method => r => r.Method,
            ConditionField.UserAgent => r => r.GetHeader("User-Agent"),
            ConditionField.Header => HeaderSelector(condition.HeaderName!),
            _ => throw new ArgumentOutOfRangeException(nameof(condition), condition.Field, "Unknown field."),
        };

        return condition.Operator == ConditionOperator.Regex
            ? new RegexCondition(condition, selector)
            : new TextCondition(condition, selector);
    }

    private static Func<IWafRequest, string?> HeaderSelector(string name) => r => r.GetHeader(name);
}

/// <summary>Client IP in one of a set of networks.</summary>
internal sealed class IpCondition : CompiledCondition
{
    private readonly IPNetwork[] _networks;

    public IpCondition(RuleCondition condition)
        : base(condition.Negate)
    {
        _networks = [.. condition.Values.Select(v => StrictCidr.TryParse(v, out var network)
            ? network
            : throw new ArgumentException($"'{v}' is not a valid IP address or range.", nameof(condition)))];
    }

    protected override bool Test(IWafRequest request)
    {
        var ip = ClientIpResolver.Normalize(request.ClientIp);
        foreach (var network in _networks)
        {
            if (network.Contains(ip))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Equals / StartsWith / EndsWith / Contains on a text field. A missing value never matches.</summary>
internal sealed class TextCondition : CompiledCondition
{
    private readonly Func<IWafRequest, string?> _selector;
    private readonly ConditionOperator _operator;
    private readonly StringComparison _comparison;
    private readonly string[] _values;
    private readonly HashSet<string>? _exact;
    private readonly SearchValues<string>? _contains;

    public TextCondition(RuleCondition condition, Func<IWafRequest, string?> selector)
        : base(condition.Negate)
    {
        _selector = selector;
        _operator = condition.Operator;
        _comparison = condition.CaseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        _values = [.. condition.Values];

        if (_operator == ConditionOperator.Equals)
        {
            _exact = new HashSet<string>(_values, condition.CaseSensitive ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);
        }
        else if (_operator == ConditionOperator.Contains)
        {
            _contains = SearchValues.Create(_values, _comparison);
        }
    }

    protected override bool Test(IWafRequest request)
    {
        var value = _selector(request);
        if (value is null)
        {
            return false;
        }

        switch (_operator)
        {
            case ConditionOperator.Equals:
                return _exact!.Contains(value);

            case ConditionOperator.Contains:
                return value.AsSpan().ContainsAny(_contains!);

            case ConditionOperator.StartsWith:
                foreach (var candidate in _values)
                {
                    if (value.StartsWith(candidate, _comparison))
                    {
                        return true;
                    }
                }

                return false;

            case ConditionOperator.EndsWith:
                foreach (var candidate in _values)
                {
                    if (value.EndsWith(candidate, _comparison))
                    {
                        return true;
                    }
                }

                return false;

            default:
                throw new InvalidOperationException($"Operator {_operator} is not a text operator.");
        }
    }
}

/// <summary>
/// Regular expressions, combined into one alternation and run on the non-backtracking engine
/// (linear time in the input, so no ReDoS). A missing value never matches.
/// </summary>
internal sealed class RegexCondition : CompiledCondition
{
    private readonly Func<IWafRequest, string?> _selector;
    private readonly Regex _regex;

    public RegexCondition(RuleCondition condition, Func<IWafRequest, string?> selector)
        : base(condition.Negate)
    {
        _selector = selector;
        var options = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant;
        if (!condition.CaseSensitive)
        {
            options |= RegexOptions.IgnoreCase;
        }

        var pattern = condition.Values.Count == 1
            ? condition.Values[0]
            : string.Join('|', condition.Values.Select(v => $"(?:{v})"));
        _regex = new Regex(pattern, options);
    }

    protected override bool Test(IWafRequest request) =>
        _selector(request) is { } value && _regex.IsMatch(value);
}
