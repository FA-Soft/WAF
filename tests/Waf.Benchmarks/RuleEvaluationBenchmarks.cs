using System.Globalization;
using System.Net;
using BenchmarkDotNet.Attributes;
using Waf.Core.Configuration;
using Waf.Core.Routing;
using Waf.Engine;

namespace Waf.Benchmarks;

/// <summary>
/// Cost of evaluating one request against rule sets of different sizes.
/// Run: <c>dotnet run -c Release --project tests/Waf.Benchmarks -- --filter *RuleEvaluation* --inProcess</c>
/// (<c>--inProcess</c> is needed until BenchmarkDotNet recognises the .NET 11 runtime; add <c>--job short</c> for a quick run).
/// </summary>
[MemoryDiagnoser]
public class RuleEvaluationBenchmarks
{
    private CompiledRuleSet _rules = CompiledRuleSet.Empty;
    private readonly BenchmarkRequest _clean = new() { Path = "/products/42", QueryString = "color=red" };
    private readonly BenchmarkRequest _blockedEarly = new() { Path = "/admin/users", ClientIp = IPAddress.Parse("198.51.100.20") };
    private readonly BenchmarkRequest _blockedLate = new() { Path = "/products/42", UserAgent = "sqlmap/1.7" };

    /// <summary>Number of rules in the set (each with one or two conditions).</summary>
    [Params(10, 100, 1000)]
    public int RuleCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var configuration = new GatewayConfiguration();
        var route = new ProxyRouteOptions { Name = "website" };
        route.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = 8080 });
        configuration.Routes.Add(route);

        // Priority 1: office-only admin (IP allowlist on /admin).
        configuration.Rules.Add(Rule("office-only-admin", 1, RuleAction.Block,
            Condition(ConditionField.Path, ConditionOperator.StartsWith, false, "/admin"),
            Condition(ConditionField.ClientIp, ConditionOperator.InCidr, true, "203.0.113.0/24")));

        // Filler rules that do not match the benchmark requests: a realistic mix of operators.
        for (var i = 0; configuration.Rules.Count < RuleCount - 1; i++)
        {
            var n = i.ToString(CultureInfo.InvariantCulture);
            configuration.Rules.Add((i % 5) switch
            {
                0 => Rule($"ip-{n}", 10 + i, RuleAction.Block, Condition(ConditionField.ClientIp, ConditionOperator.InCidr, false, $"10.{i % 256}.0.0/16", $"2001:db8:{i % 65536:x}::/48")),
                1 => Rule($"path-{n}", 10 + i, RuleAction.Block, Condition(ConditionField.Path, ConditionOperator.StartsWith, false, $"/blocked-{n}", $"/old-{n}")),
                2 => Rule($"contains-{n}", 10 + i, RuleAction.LogOnly, Condition(ConditionField.QueryString, ConditionOperator.Contains, false, $"token{n}=", $"secret{n}=")),
                3 => Rule($"regex-{n}", 10 + i, RuleAction.Block, Condition(ConditionField.Path, ConditionOperator.Regex, false, $@"^/api/v{n}/\d+$")),
                _ => Rule($"method-{n}", 10 + i, RuleAction.Block,
                    Condition(ConditionField.Method, ConditionOperator.Equals, false, "TRACE"),
                    Condition(ConditionField.Header, ConditionOperator.Equals, false, $"x{n}", "X-Debug")),
            });
        }

        // Last: bad user agents.
        configuration.Rules.Add(Rule("bad-agents", 100_000, RuleAction.Block,
            Condition(ConditionField.UserAgent, ConditionOperator.Contains, false, "sqlmap", "nikto", "masscan", "nmap")));

        _rules = CompiledRuleSet.Compile(configuration);
    }

    /// <summary>Typical request: no rule matches, every rule is evaluated.</summary>
    [Benchmark(Baseline = true)]
    public WafDecision NoMatch() => _rules.Evaluate(_clean);

    /// <summary>The first rule blocks.</summary>
    [Benchmark]
    public WafDecision BlockedByFirstRule() => _rules.Evaluate(_blockedEarly);

    /// <summary>Only the last rule blocks.</summary>
    [Benchmark]
    public WafDecision BlockedByLastRule() => _rules.Evaluate(_blockedLate);

    private static WafRule Rule(string name, int priority, RuleAction action, params RuleCondition[] conditions)
    {
        var rule = new WafRule { Name = name, Priority = priority, Action = action };
        foreach (var condition in conditions)
        {
            rule.Conditions.Add(condition);
        }

        return rule;
    }

    private static RuleCondition Condition(ConditionField field, ConditionOperator op, bool negate, params string[] values)
    {
        var condition = new RuleCondition { Field = field, Operator = op, Negate = negate };
        if (field == ConditionField.Header)
        {
            condition.HeaderName = values[^1];
            values = values[..^1];
        }

        foreach (var value in values)
        {
            condition.Values.Add(value);
        }

        return condition;
    }

    private sealed class BenchmarkRequest : IWafRequest
    {
        public IPAddress ClientIp { get; init; } = IPAddress.Parse("198.51.100.20");
        public string Host { get; init; } = "www.example.com";
        public string Path { get; init; } = "/";
        public string QueryString { get; init; } = string.Empty;
        public string Method { get; init; } = "GET";
        public string? RouteName { get; init; } = "website";
        public string? UserAgent { get; init; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

        public string? GetHeader(string name) =>
            string.Equals(name, "User-Agent", StringComparison.OrdinalIgnoreCase) ? UserAgent : null;
    }
}
