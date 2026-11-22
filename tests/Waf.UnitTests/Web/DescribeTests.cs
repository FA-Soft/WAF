using Waf.Core.Configuration;
using Waf.Core.Routing;
using Waf.Web;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Web;

public class DescribeTests
{
    [Fact]
    public void Route_match_reads_as_a_sentence()
    {
        var match = new RouteMatchOptions { PathPrefix = "/api" };
        match.Hosts.Add("api.example.com");
        match.Hosts.Add("api2.example.com");
        match.Methods.Add("get");

        Assert.Equal("Requests for api.example.com or api2.example.com under /api (GET)", Describe.Match(match));
        Assert.Equal("Every request", Describe.Match(new RouteMatchOptions()));
    }

    [Fact]
    public void Long_values_are_shortened()
    {
        var pattern = "^(" + new string('a', 80) + ")$";

        var text = Describe.Condition(When(ConditionField.Path, ConditionOperator.Regex, pattern));

        Assert.Equal("the path matches the pattern " + pattern[..59] + "…", text);
    }

    [Fact]
    public void Destinations_are_listed_as_urls()
    {
        Assert.Equal(
            "http://10.0.0.5:8080, https://[fd00::10]:8443",
            Describe.Destinations([
                new ProxyDestinationOptions { Address = "10.0.0.5", Port = 8080 },
                new ProxyDestinationOptions { Scheme = "HTTPS", Address = "fd00::10", Port = 8443 },
            ]));
    }

    [Fact]
    public void Conditions_read_as_plain_language()
    {
        var header = When(ConditionField.Header, ConditionOperator.Regex, negate: true, caseSensitive: true, headerName: "X-Api-Key", "^[a-z]+$");

        Assert.Equal(
            "The path starts with /admin and the client IP is not in 203.0.113.0/24 or 198.51.100.7 and the X-Api-Key header does not match the pattern ^[a-z]+$",
            Describe.Conditions([
                When(ConditionField.Path, ConditionOperator.StartsWith, "/admin"),
                WhenNot(ConditionField.ClientIp, ConditionOperator.InCidr, "203.0.113.0/24", "198.51.100.7"),
                header,
            ]));
    }

    [Fact]
    public void Actions_mention_detection_only()
    {
        var block = Rule("b", RuleAction.Block, 1);

        Assert.Equal("Block", Describe.Action(block, globalDetectionOnly: false));
        Assert.Equal("Block (detection only: logged, not enforced)", Describe.Action(block, globalDetectionOnly: true));
        Assert.Equal("Allow (skip further checks)", Describe.Action(Rule("a", RuleAction.Allow, 1), false));
        Assert.Equal("Log only", Describe.Action(Rule("l", RuleAction.LogOnly, 1), false));
    }

    [Theory]
    [InlineData(60, RateLimitKey.ClientIp, "5 requests per minute per client IP")]
    [InlineData(3600, RateLimitKey.Route, "5 requests per hour per route for all clients together")]
    [InlineData(90, RateLimitKey.ClientIpAndRoute, "5 requests per 90 seconds per client IP and route")]
    public void Rate_limits_read_as_plain_language(int window, RateLimitKey key, string expected)
    {
        Assert.Equal(expected, Describe.RateLimit(new RateLimitRule { Name = "x", PermitLimit = 5, WindowSeconds = window, Key = key }));
    }

    [Fact]
    public void Enabled_detections_are_listed()
    {
        var settings = new AttackDetectionSettings { CommandInjection = false };

        Assert.Equal(["SQL injection", "Cross-site scripting", "Path traversal", "Attack tools"], Describe.EnabledDetections(settings));
        Assert.Empty(Describe.EnabledDetections(new AttackDetectionSettings { Enabled = false }));
    }
}
