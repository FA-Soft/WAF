using System.Net;
using Waf.Core.Configuration;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Engine;

public class ConditionTests
{
    private static bool Blocks(RuleCondition condition, FakeRequest request) =>
        Compile(Rule("r", RuleAction.Block, 10, condition)).Evaluate(request).IsBlocked;

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("11.0.0.1", false)]
    [InlineData("192.168.1.10", true)]
    [InlineData("192.168.1.11", false)]
    [InlineData("::ffff:10.1.2.3", true)]
    [InlineData("2001:db8::1234", true)]
    [InlineData("2001:db9::1", false)]
    public void Ip_deny_list_matches_cidr_ranges_and_single_addresses(string clientIp, bool blocked)
    {
        var condition = When(ConditionField.ClientIp, ConditionOperator.InCidr, "10.0.0.0/8", "192.168.1.10", "2001:db8::/32");

        Assert.Equal(blocked, Blocks(condition, FakeRequest.From(clientIp)));
    }

    [Theory]
    [InlineData("203.0.113.50", false)]
    [InlineData("198.51.100.20", true)]
    public void Ip_allow_list_is_a_negated_block(string clientIp, bool blocked)
    {
        // Block everyone NOT in the office range.
        var condition = WhenNot(ConditionField.ClientIp, ConditionOperator.InCidr, "203.0.113.0/24");

        Assert.Equal(blocked, Blocks(condition, FakeRequest.From(clientIp)));
    }

    [Theory]
    [InlineData(ConditionOperator.Equals, "/login", "/login", true)]
    [InlineData(ConditionOperator.Equals, "/login", "/login/x", false)]
    [InlineData(ConditionOperator.Equals, "/login", "/LOGIN", true)]
    [InlineData(ConditionOperator.StartsWith, "/admin", "/Admin/users", true)]
    [InlineData(ConditionOperator.StartsWith, "/admin", "/shop/admin", false)]
    [InlineData(ConditionOperator.EndsWith, ".php", "/index.PHP", true)]
    [InlineData(ConditionOperator.EndsWith, ".php", "/index.html", false)]
    [InlineData(ConditionOperator.Contains, "/../", "/a/../etc/passwd", true)]
    [InlineData(ConditionOperator.Contains, "/../", "/a/b", false)]
    [InlineData(ConditionOperator.Regex, @"^/api/v\d+/", "/API/v2/users", true)]
    [InlineData(ConditionOperator.Regex, @"^/api/v\d+/", "/api/vX/users", false)]
    public void Path_operators_are_case_insensitive_by_default(ConditionOperator op, string value, string path, bool blocked)
    {
        Assert.Equal(blocked, Blocks(When(ConditionField.Path, op, value), new FakeRequest { Path = path }));
    }

    [Theory]
    [InlineData(ConditionOperator.Equals, "/Login", "/login", false)]
    [InlineData(ConditionOperator.StartsWith, "/Admin", "/admin", false)]
    [InlineData(ConditionOperator.Contains, "Secret", "/secret", false)]
    [InlineData(ConditionOperator.Regex, "^/Admin", "/admin", false)]
    [InlineData(ConditionOperator.Regex, "^/Admin", "/Admin", true)]
    public void Case_sensitive_comparison_can_be_requested(ConditionOperator op, string value, string path, bool blocked)
    {
        var condition = When(ConditionField.Path, op, negate: false, caseSensitive: true, headerName: null, value);

        Assert.Equal(blocked, Blocks(condition, new FakeRequest { Path = path }));
    }

    [Theory]
    [InlineData("/wp-login.php", true)]
    [InlineData("/xmlrpc.php", true)]
    [InlineData("/index.html", false)]
    public void Any_of_several_values_matches(string path, bool blocked)
    {
        Assert.Equal(blocked, Blocks(When(ConditionField.Path, ConditionOperator.Contains, "wp-login", "xmlrpc"), new FakeRequest { Path = path }));
    }

    [Theory]
    [InlineData("/a", true)]
    [InlineData("/b", true)]
    [InlineData("/c", false)]
    public void Several_regex_values_are_alternatives(string path, bool blocked)
    {
        Assert.Equal(blocked, Blocks(When(ConditionField.Path, ConditionOperator.Regex, "^/a$", "^/b$"), new FakeRequest { Path = path }));
    }

    [Theory]
    [InlineData("post", true)]
    [InlineData("POST", true)]
    [InlineData("GET", false)]
    public void Method_equals_ignores_case(string method, bool blocked)
    {
        Assert.Equal(blocked, Blocks(When(ConditionField.Method, ConditionOperator.Equals, "POST"), new FakeRequest { Method = method }));
    }

    [Fact]
    public void Host_and_query_string_fields_are_tested()
    {
        Assert.True(Blocks(When(ConditionField.Host, ConditionOperator.EndsWith, ".internal"), new FakeRequest { Host = "db.internal" }));
        Assert.True(Blocks(When(ConditionField.QueryString, ConditionOperator.Contains, "debug=1"), new FakeRequest { QueryString = "a=1&debug=1" }));
        Assert.False(Blocks(When(ConditionField.QueryString, ConditionOperator.Contains, "debug=1"), new FakeRequest()));
    }

    [Fact]
    public void User_agent_field_reads_the_header()
    {
        var condition = When(ConditionField.UserAgent, ConditionOperator.Contains, "sqlmap");
        var request = new FakeRequest();
        request.Headers["User-Agent"] = "sqlmap/1.7";

        Assert.True(Blocks(condition, request));
        Assert.False(Blocks(condition, new FakeRequest()));
    }

    [Fact]
    public void Missing_header_never_matches_and_matches_when_negated()
    {
        var present = When(ConditionField.Header, ConditionOperator.Equals, negate: false, caseSensitive: false, headerName: "X-Debug", "1");
        var absent = When(ConditionField.Header, ConditionOperator.Equals, negate: true, caseSensitive: false, headerName: "X-Debug", "1");

        Assert.False(Blocks(present, new FakeRequest()));
        Assert.True(Blocks(absent, new FakeRequest()));
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("too-short", true)]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", false)]
    public void Required_api_key_rule_blocks_missing_or_malformed_keys(string? apiKey, bool blocked)
    {
        // From schemas/gateway-config.example.json: block unless X-Api-Key is 32 letters/digits.
        var condition = When(ConditionField.Header, ConditionOperator.Regex, negate: true, caseSensitive: true, headerName: "X-Api-Key", "^[A-Za-z0-9]{32}$");
        var request = new FakeRequest();
        if (apiKey is not null)
        {
            request.Headers["X-Api-Key"] = apiKey;
        }

        Assert.Equal(blocked, Blocks(condition, request));
    }

    [Fact]
    public void Ipv4_client_does_not_match_ipv6_range()
    {
        Assert.False(Blocks(When(ConditionField.ClientIp, ConditionOperator.InCidr, "::/0"), FakeRequest.From("10.0.0.1")));
        Assert.True(Blocks(When(ConditionField.ClientIp, ConditionOperator.InCidr, "0.0.0.0/0"), new FakeRequest { ClientIp = IPAddress.Parse("10.0.0.1") }));
    }
}
