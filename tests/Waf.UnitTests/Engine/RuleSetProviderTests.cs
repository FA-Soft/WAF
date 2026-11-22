using System.Text.Json;
using Waf.Core.Configuration;
using Waf.Engine;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Engine;

public class RuleSetProviderTests
{
    [Fact]
    public void Swap_activates_the_new_set_and_returns_the_old_one()
    {
        var blocking = Compile(Rule("block", RuleAction.Block, 10));
        var provider = new RuleSetProvider(CompiledRuleSet.Empty);

        Assert.False(provider.Evaluate(new FakeRequest()).IsBlocked);

        var previous = provider.Swap(blocking);

        Assert.Same(CompiledRuleSet.Empty, previous);
        Assert.Same(blocking, provider.Current);
        Assert.True(provider.Evaluate(new FakeRequest()).IsBlocked);
    }

    [Fact]
    public async Task Concurrent_swaps_never_produce_a_mixed_result()
    {
        // Set A: one LogOnly rule then Block. Set B: one LogOnly rule then Allow. A request evaluated against a
        // half-updated set would show A's log rule with B's verdict (or vice versa).
        var setA = Compile(Rule("a-log", RuleAction.LogOnly, 1), Rule("a-block", RuleAction.Block, 2));
        var setB = Compile(Rule("b-log", RuleAction.LogOnly, 1), Rule("b-allow", RuleAction.Allow, 2));
        var provider = new RuleSetProvider(setA);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(1));

        var swapper = Task.Run(() =>
        {
            var useA = false;
            while (!stop.IsCancellationRequested)
            {
                provider.Swap(useA ? setA : setB);
                useA = !useA;
            }
        }, TestContext.Current.CancellationToken);

        var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            var request = new FakeRequest();
            while (!stop.IsCancellationRequested)
            {
                var decision = provider.Evaluate(request);
                var names = string.Join(",", decision.Matches.Select(m => m.RuleName));
                Assert.True(names is "a-log,a-block" or "b-log,b-allow", names);
            }
        }, TestContext.Current.CancellationToken)).ToArray();

        await Task.WhenAll([swapper, .. readers]);
    }

    [Theory]
    [InlineData("203.0.113.10", "/admin", null)]                   // office IP may open /admin
    [InlineData("198.51.100.20", "/admin/users", "office-only-admin")]
    [InlineData("198.51.100.20", "/products", null)]
    public void Example_configuration_office_rule(string clientIp, string path, string? decidingRule)
    {
        var json = File.ReadAllText(FindRepoFile("schemas/gateway-config.example.json"));
        var configuration = GatewayConfigurationJson.Parse(json).Configuration!;
        var rules = CompiledRuleSet.Compile(configuration);

        var decision = rules.Evaluate(new FakeRequest { ClientIp = System.Net.IPAddress.Parse(clientIp), Path = path, RouteName = "website" });

        Assert.Equal(decidingRule, decision.DecidingRule?.RuleName);
        Assert.Equal(decidingRule is not null, decision.IsBlocked);
    }

    private static string FindRepoFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return Path.Combine(directory!.FullName, relativePath);
    }

    [Fact]
    public void Decision_matches_are_serializable_for_logging()
    {
        var decision = Compile(Rule("log", RuleAction.LogOnly, 1)).Evaluate(new FakeRequest());

        Assert.Contains("\"RuleName\":\"log\"", JsonSerializer.Serialize(decision.Matches), StringComparison.Ordinal);
    }
}
