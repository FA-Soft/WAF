using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine;
using FASoft.Waf.Web;
using static FASoft.Waf.UnitTests.Engine.RuleBuilder;

namespace FASoft.Waf.UnitTests.Web;

public class RequestTesterTests
{
    private static WafEngine Engine(Action<GatewayConfiguration>? configure = null, params WafRule[] rules)
    {
        var configuration = Config(rules);
        configure?.Invoke(configuration);
        return WafEngine.Build(configuration);
    }

    [Fact]
    public void Clean_request_is_allowed_and_explains_rate_limits_are_not_counted()
    {
        var result = RequestTester.Run(Engine(), new TestRequestModel { Path = "/products", Route = "website" });

        Assert.False(result.Blocked);
        Assert.Equal("Allowed: the request would be forwarded.", result.Summary);
        Assert.Contains(result.Details, d => d.Contains("Rate limits are not counted", StringComparison.Ordinal));
    }

    [Fact]
    public void Request_without_route_mentions_404()
    {
        Assert.Contains("404", RequestTester.Run(Engine(), new TestRequestModel()).Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Blocking_rule_is_named()
    {
        var engine = Engine(null, Rule("no-admin", RuleAction.Block, 1, When(ConditionField.Path, ConditionOperator.StartsWith, "/admin")));

        var result = RequestTester.Run(engine, new TestRequestModel { Path = "/admin/users" });

        Assert.True(result.Blocked);
        Assert.Equal("Blocked (403) by rule 'no-admin'.", result.Summary);
    }

    [Fact]
    public void Client_ip_route_and_headers_are_used()
    {
        var office = Rule("office", RuleAction.Allow, 1, When(ConditionField.ClientIp, ConditionOperator.InCidr, "203.0.113.0/24"));
        office.Routes.Add("website");
        var engine = Engine(null, office, Rule("tools", RuleAction.Block, 2, When(ConditionField.UserAgent, ConditionOperator.Contains, "curl")));

        var allowed = RequestTester.Run(engine, new TestRequestModel { ClientIp = "203.0.113.9", Route = "website", Headers = "User-Agent: curl/8" });
        var blocked = RequestTester.Run(engine, new TestRequestModel { ClientIp = "198.51.100.1", Route = "website", Headers = "User-Agent: curl/8" });

        Assert.Equal("Allowed by rule 'office'. Attack detection and rate limits are skipped for this request.", allowed.Summary);
        Assert.Equal("Blocked (403) by rule 'tools'.", blocked.Summary);
    }

    [Fact]
    public void Attack_in_the_query_is_explained()
    {
        var result = RequestTester.Run(Engine(), new TestRequestModel { Path = "/search", Query = "?q=1' UNION SELECT password FROM users--" });

        Assert.True(result.Blocked);
        Assert.Equal("Blocked (403): sql injection detected.", result.Summary);
        Assert.Contains(result.Details, d => d.StartsWith("SQL injection detected in QueryString 'q'", StringComparison.Ordinal));
    }

    [Fact]
    public void Body_is_inspected_when_body_inspection_is_on()
    {
        var engine = Engine(c => c.Settings.AttackDetection.InspectBody = true);

        var result = RequestTester.Run(engine, new TestRequestModel { Method = "POST", ContentType = "application/x-www-form-urlencoded", Body = "comment=<script>alert(1)</script>" });

        Assert.True(result.Blocked);
    }

    [Fact]
    public void Detection_only_explains_that_nothing_would_be_blocked()
    {
        var tryOut = Rule("try", RuleAction.Block, 1);
        tryOut.DetectionOnly = true;
        var engine = Engine(c => c.Settings.DetectionOnly = true, tryOut);

        var result = RequestTester.Run(engine, new TestRequestModel { Query = "q=<script>alert(1)</script>" });

        Assert.False(result.Blocked);
        Assert.Contains("detection-only mode is on", result.Summary, StringComparison.Ordinal);
        Assert.Contains(result.Details, d => d.Contains("Rule 'try' would block this request", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("admin", "10.0.0.1", "", "The path must start with /")]
    [InlineData("/", "10", "", "This is not a valid IP address")]
    [InlineData("/", "10.0.0.1", "no colon here", "Header line 1 needs the form 'Name: value'.")]
    public void Model_validation_gives_plain_language_errors(string path, string ip, string headers, string expected)
    {
        var model = new TestRequestModel { Path = path, ClientIp = ip, Headers = headers };

        var errors = model.Validate(new ValidationContext(model)).Select(e => e.ErrorMessage).ToList();

        Assert.Contains(errors, e => e!.StartsWith(expected, StringComparison.Ordinal));
    }
}
