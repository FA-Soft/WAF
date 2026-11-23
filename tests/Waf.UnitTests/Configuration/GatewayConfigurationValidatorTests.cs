using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.UnitTests.Configuration;

public class GatewayConfigurationValidatorTests
{
    private static GatewayConfiguration ConfigWithRoute()
    {
        var configuration = new GatewayConfiguration();
        var route = new ProxyRouteOptions { Name = "website" };
        route.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = 8080 });
        configuration.Routes.Add(route);
        return configuration;
    }

    private static RuleCondition Condition(ConditionField field, ConditionOperator op, params string[] values)
    {
        var condition = new RuleCondition { Field = field, Operator = op };
        foreach (var value in values)
        {
            condition.Values.Add(value);
        }

        return condition;
    }

    private static WafRule Rule(string name, params RuleCondition[] conditions)
    {
        var rule = new WafRule { Name = name };
        foreach (var condition in conditions)
        {
            rule.Conditions.Add(condition);
        }

        return rule;
    }

    private static IReadOnlyList<string> ValidateRule(WafRule rule)
    {
        var configuration = ConfigWithRoute();
        configuration.Rules.Add(rule);
        return GatewayConfigurationValidator.Validate(configuration);
    }

    private static WafRule PathRule(string name = "r") =>
        Rule(name, Condition(ConditionField.Path, ConditionOperator.StartsWith, "/admin"));

    [Fact]
    public void Empty_configuration_is_valid()
    {
        Assert.Empty(GatewayConfigurationValidator.Validate(new GatewayConfiguration()));
    }

    [Fact]
    public void Unsupported_schema_version_is_rejected()
    {
        var errors = GatewayConfigurationValidator.Validate(new GatewayConfiguration { SchemaVersion = 2 });

        Assert.Equal(["SchemaVersion 2 is not supported (expected 1)."], errors);
    }

    [Fact]
    public void Route_errors_are_included()
    {
        var configuration = ConfigWithRoute();
        configuration.Routes[0].Destinations.Clear();

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.StartsWith("Route 'website':", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.10.0/24")]
    [InlineData("fd00::/8")]
    public void Valid_trusted_proxies_are_accepted(string proxy)
    {
        var configuration = new GatewayConfiguration();
        configuration.Settings.TrustedProxies.Add(proxy);

        Assert.Empty(GatewayConfigurationValidator.Validate(configuration));
    }

    [Fact]
    public void Trusted_proxy_with_host_bits_is_explained()
    {
        var configuration = new GatewayConfiguration();
        configuration.Settings.TrustedProxies.Add("192.168.10.1/24");

        Assert.Equal(
            ["Trusted proxy '192.168.10.1/24': host bits are set (did you mean 192.168.10.0/24 or 192.168.10.1/32?)."],
            GatewayConfigurationValidator.Validate(configuration));
    }

    [Fact]
    public void Valid_rule_is_accepted()
    {
        Assert.Empty(ValidateRule(PathRule()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("block admin")]
    public void Rule_name_is_required_and_restricted(string name)
    {
        Assert.NotEmpty(ValidateRule(PathRule(name)));
    }

    [Fact]
    public void Duplicate_rule_names_are_rejected()
    {
        var configuration = ConfigWithRoute();
        configuration.Rules.Add(PathRule("same"));
        configuration.Rules.Add(PathRule("SAME"));

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e == "Rule 'SAME': the name is used by more than one rule.");
    }

    [Fact]
    public void Rule_without_conditions_is_rejected_with_a_hint()
    {
        Assert.Contains(ValidateRule(new WafRule { Name = "all" }), e => e.Contains("to match every request, use Path StartsWith '/'", StringComparison.Ordinal));
    }

    [Fact]
    public void Negative_priority_is_rejected()
    {
        var rule = PathRule();
        rule.Priority = -1;

        Assert.Contains(ValidateRule(rule), e => e.Contains("priority must be 0 or higher", StringComparison.Ordinal));
    }

    [Fact]
    public void Undefined_action_is_rejected()
    {
        var rule = PathRule();
        rule.Action = (RuleAction)42;

        Assert.Contains(ValidateRule(rule), e => e.Contains("action must be Allow, Block or LogOnly", StringComparison.Ordinal));
    }

    [Fact]
    public void Rule_route_scope_must_reference_existing_routes()
    {
        var rule = PathRule();
        rule.Routes.Add("website");
        rule.Routes.Add("shop");

        Assert.Equal(["Rule 'r': route 'shop' does not exist."], ValidateRule(rule));
    }

    [Theory]
    [InlineData(ConditionField.ClientIp, ConditionOperator.InCidr, "10.0.0.0/8")]
    [InlineData(ConditionField.Method, ConditionOperator.Equals, "POST")]
    [InlineData(ConditionField.Host, ConditionOperator.EndsWith, ".example.com")]
    [InlineData(ConditionField.QueryString, ConditionOperator.Contains, "debug=1")]
    [InlineData(ConditionField.UserAgent, ConditionOperator.Regex, "(?i)curl|wget")]
    [InlineData(ConditionField.Path, ConditionOperator.Equals, "/login")]
    public void Valid_conditions_are_accepted(ConditionField field, ConditionOperator op, string value)
    {
        Assert.Empty(ValidateRule(Rule("r", Condition(field, op, value))));
    }

    [Theory]
    [InlineData(ConditionField.ClientIp, ConditionOperator.Equals, "use InCidr")]
    [InlineData(ConditionField.Method, ConditionOperator.Contains, "use Equals")]
    [InlineData(ConditionField.Path, ConditionOperator.InCidr, "use Equals or StartsWith or EndsWith or Contains or Regex")]
    public void Operator_must_fit_the_field(ConditionField field, ConditionOperator op, string hint)
    {
        Assert.Contains(ValidateRule(Rule("r", Condition(field, op, "x"))), e => e.Contains(hint, StringComparison.Ordinal));
    }

    [Fact]
    public void Condition_needs_values()
    {
        Assert.Contains(ValidateRule(Rule("r", Condition(ConditionField.Path, ConditionOperator.Equals))), e => e.Contains("at least one value", StringComparison.Ordinal));
    }

    [Fact]
    public void Condition_values_must_not_be_empty()
    {
        Assert.Contains(ValidateRule(Rule("r", Condition(ConditionField.Path, ConditionOperator.Equals, ""))), e => e.Contains("values must not be empty", StringComparison.Ordinal));
    }

    [Fact]
    public void Invalid_cidr_value_is_explained()
    {
        var errors = ValidateRule(Rule("r", Condition(ConditionField.ClientIp, ConditionOperator.InCidr, "10.0.0.1/8")));

        Assert.Equal(["Rule 'r': '10.0.0.1/8': host bits are set (did you mean 10.0.0.0/8 or 10.0.0.1/32?)."], errors);
    }

    [Fact]
    public void Invalid_method_value_is_rejected()
    {
        Assert.Contains(ValidateRule(Rule("r", Condition(ConditionField.Method, ConditionOperator.Equals, "GET POST"))), e => e.Contains("not a valid HTTP method", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("(a")]              // syntax error
    [InlineData(@"(a)\1")]          // backreference: not supported by the non-backtracking engine
    [InlineData("foo(?=bar)")]      // lookahead: not supported either
    public void Unsupported_regex_is_rejected(string pattern)
    {
        var errors = ValidateRule(Rule("r", Condition(ConditionField.Path, ConditionOperator.Regex, pattern)));

        Assert.Contains(errors, e => e.Contains("is not a supported regular expression", StringComparison.Ordinal));
    }

    [Fact]
    public void Overly_long_regex_is_rejected()
    {
        var pattern = new string('a', GatewayConfigurationValidator.MaxRegexLength + 1);

        Assert.Contains(ValidateRule(Rule("r", Condition(ConditionField.Path, ConditionOperator.Regex, pattern))), e => e.Contains("longer than 1000", StringComparison.Ordinal));
    }

    [Fact]
    public void Header_field_requires_a_valid_header_name()
    {
        var missing = Condition(ConditionField.Header, ConditionOperator.Equals, "x");
        var invalid = Condition(ConditionField.Header, ConditionOperator.Equals, "x");
        invalid.HeaderName = "X Api Key";
        var valid = Condition(ConditionField.Header, ConditionOperator.Equals, "x");
        valid.HeaderName = "X-Api-Key";

        Assert.Contains(ValidateRule(Rule("r", missing)), e => e.Contains("HeaderName is required", StringComparison.Ordinal));
        Assert.Contains(ValidateRule(Rule("r", invalid)), e => e.Contains("HeaderName is required", StringComparison.Ordinal));
        Assert.Empty(ValidateRule(Rule("r", valid)));
    }

    [Fact]
    public void Header_name_on_other_fields_is_rejected()
    {
        var condition = Condition(ConditionField.Path, ConditionOperator.Equals, "/x");
        condition.HeaderName = "X-Test";

        Assert.Contains(ValidateRule(Rule("r", condition)), e => e.Contains("HeaderName is only used with the Header field", StringComparison.Ordinal));
    }

    [Fact]
    public void Errors_name_the_condition_when_a_rule_has_several()
    {
        var rule = Rule("r", Condition(ConditionField.Path, ConditionOperator.Equals, "/x"), Condition(ConditionField.Method, ConditionOperator.Equals, "G T"));

        Assert.Contains(ValidateRule(rule), e => e.StartsWith("Rule 'r', condition #2:", StringComparison.Ordinal));
    }

    private static GatewayConfiguration ConfigWithCertificate(CertificateBinding certificate, bool acme = true)
    {
        var configuration = new GatewayConfiguration();
        if (acme)
        {
            configuration.Settings.Acme.Email = "admin@example.com";
            configuration.Settings.Acme.AcceptTermsOfService = true;
        }

        configuration.Certificates.Add(certificate);
        return configuration;
    }

    [Theory]
    [InlineData("www.example.com", CertificateSource.LetsEncrypt, null, null)]
    [InlineData("api.example.com", CertificateSource.File, "certs/api.pfx", null)]
    [InlineData("*.example.com", CertificateSource.File, "certs/wild.pem", "certs/wild.key")]
    public void Valid_certificates_are_accepted(string host, CertificateSource source, string? certificatePath, string? keyPath)
    {
        var configuration = ConfigWithCertificate(new CertificateBinding { HostName = host, Source = source, CertificatePath = certificatePath, KeyPath = keyPath });

        Assert.Empty(GatewayConfigurationValidator.Validate(configuration));
    }

    [Theory]
    [InlineData("", CertificateSource.File, "a.pfx", null, "a valid host name is required")]
    [InlineData("10.0.0.5", CertificateSource.File, "a.pfx", null, "a valid host name is required")]
    [InlineData("*.example.com", CertificateSource.LetsEncrypt, null, null, "cannot issue wildcard certificates")]
    [InlineData("www.example.com", CertificateSource.LetsEncrypt, "a.pfx", null, "only used with Source 'File'")]
    [InlineData("www.example.com", CertificateSource.File, null, null, "CertificatePath is required")]
    [InlineData("www.example.com", CertificateSource.File, "a.pfx", "a.key", "a PFX file contains the key")]
    public void Invalid_certificates_are_explained(string host, CertificateSource source, string? certificatePath, string? keyPath, string expected)
    {
        var configuration = ConfigWithCertificate(new CertificateBinding { HostName = host, Source = source, CertificatePath = certificatePath, KeyPath = keyPath });

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void Duplicate_certificate_host_names_are_rejected()
    {
        var configuration = ConfigWithCertificate(new CertificateBinding { HostName = "www.example.com" });
        configuration.Certificates.Add(new CertificateBinding { HostName = "WWW.example.com", Source = CertificateSource.File, CertificatePath = "a.pfx" });

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.Contains("more than one certificate", StringComparison.Ordinal));
    }

    [Fact]
    public void Lets_encrypt_requires_email_and_accepted_terms()
    {
        var configuration = ConfigWithCertificate(new CertificateBinding { HostName = "www.example.com" }, acme: false);
        configuration.Settings.Acme.Email = "not-an-email";

        var errors = GatewayConfigurationValidator.Validate(configuration);

        Assert.Contains(errors, e => e.Contains("a valid contact e-mail is required", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("AcceptTermsOfService to true", StringComparison.Ordinal));
    }

    [Fact]
    public void Acme_settings_are_not_required_without_lets_encrypt_certificates()
    {
        var configuration = ConfigWithCertificate(new CertificateBinding { HostName = "a.example.com", Source = CertificateSource.File, CertificatePath = "a.pfx" }, acme: false);

        Assert.Empty(GatewayConfigurationValidator.Validate(configuration));
    }
}
