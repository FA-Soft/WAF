using System.Text.Json.Nodes;
using FASoft.Waf.Ai;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Ai;

/// <summary>
/// A sentence becomes a proposal, and a proposal is checked strictly before anyone can approve it: only the allowed
/// sections, the configuration schema (no unknown properties, valid values), secrets kept, and full validation.
/// </summary>
public sealed class ConfigurationProposalTests
{
    private const string Secret = "s3cret-key-value";

    private const string OfficeRule = """
        { "Name": "office-only-admin", "Priority": 10, "Action": "Block",
          "Conditions": [
            { "Field": "Path", "Operator": "StartsWith", "Values": [ "/admin" ] },
            { "Field": "ClientIp", "Operator": "InCidr", "Values": [ "203.0.113.0/24" ], "Negate": true } ] }
        """;

    /// <summary>Two routes and a rule with a secret header value (an API key).</summary>
    private static GatewayConfiguration Running()
    {
        var configuration = RuleBuilder.Config(RuleBuilder.Rule("require-api-key", RuleAction.Block, 20,
            RuleBuilder.When(ConditionField.Header, ConditionOperator.Equals, negate: true, caseSensitive: true, "X-Api-Key", Secret)));
        configuration.Settings.Acme.Email = "owner@private.example";
        return configuration;
    }

    /// <summary>The rules as the model sees them (secrets replaced), plus <paramref name="extra"/>.</summary>
    private static JsonArray SummaryRules(GatewayConfiguration running, params string[] extra)
    {
        var rules = JsonNode.Parse(ConfigurationSummary.Create(running))!["Rules"]!.AsArray().DeepClone().AsArray();
        foreach (var rule in extra)
        {
            rules.Add(JsonNode.Parse(rule));
        }

        return rules;
    }

    private static string Proposal(JsonArray rules) => new JsonObject { ["Rules"] = rules }.ToJsonString();

    [Fact]
    public void The_request_carries_the_rules_the_schema_and_the_sanitized_summary()
    {
        var running = Running();

        var request = ConfigurationProposal.Request("Only the office may open /admin.", running);

        Assert.Equal(ConfigurationSummary.Create(running), request.Configuration);
        Assert.DoesNotContain(Secret, request.Configuration + request.Instructions, StringComparison.Ordinal);
        Assert.Contains(ConfigurationSecrets.Placeholder, request.Instructions, StringComparison.Ordinal);
        Assert.Contains("<schema>", request.Instructions, StringComparison.Ordinal);
        Assert.Contains("\"InCidr\"", request.Instructions, StringComparison.Ordinal); // enumeration values from the schema
        var schema = JsonNode.Parse(request.ResponseSchema!)!.AsObject();
        Assert.False(schema["additionalProperties"]!.GetValue<bool>());
        Assert.Equal(["summary", "configuration"], schema["required"]!.AsArray().Select(n => n!.GetValue<string>()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_request_is_not_sent(string prompt) =>
        Assert.Single(ConfigurationProposal.CheckPrompt(prompt));

    [Fact]
    public void A_very_long_request_is_not_sent() =>
        Assert.Contains("longer than", Assert.Single(ConfigurationProposal.CheckPrompt(new string('a', ConfigurationProposal.MaxPromptLength + 1))), StringComparison.Ordinal);

    [Fact]
    public void An_answer_is_read_with_its_summary_and_sections()
    {
        var result = ConfigurationProposal.ReadAnswer("""{"summary":" Blocks /admin. ","configuration":"{\"Rules\":[]}"}""");

        Assert.Empty(result.Errors);
        Assert.Equal(new ProposalAnswer("Blocks /admin.", """{"Rules":[]}"""), result.Answer);
    }

    [Fact]
    public void An_answer_without_sections_proposes_no_change()
    {
        var result = ConfigurationProposal.ReadAnswer("""{"summary":"Which host do you mean?","configuration":""}""");

        Assert.Equal(new ProposalAnswer("Which host do you mean?", null), result.Answer);
    }

    [Theory]
    [InlineData("Sure! Here is the change.")]
    [InlineData("[]")]
    [InlineData("""{"summary":"x"}""")]
    [InlineData("""{"summary":"x","configuration":{"Rules":[]}}""")]
    [InlineData("""{"summary":"x","configuration":"","extra":true}""")]
    [InlineData("""{"summary":1,"configuration":""}""")]
    [InlineData("""{"summary":"x","configuration":"", }""")]
    public void An_answer_in_another_format_is_rejected(string text)
    {
        var result = ConfigurationProposal.ReadAnswer(text);

        Assert.Null(result.Answer);
        Assert.Contains("not in the expected format", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"Certificates":[]}""", "'Certificates'")]
    [InlineData("""{"SchemaVersion":1}""", "'SchemaVersion'")]
    [InlineData("""{"Settings":{"Acme":{"Email":"x@example.com"}}}""", "the setting 'Acme'")]
    [InlineData("""{"Rules":{}}""", "must be a list")]
    [InlineData("""{"Settings":[]}""", "must be an object")]
    [InlineData("""{}""", "contains no changes")]
    [InlineData("""[]""", "not a JSON object")]
    [InlineData("""{"Rules":[],"rules":[]}""", "more than once")]
    [InlineData("""{"Rules":[],"Rules":[]}""", "not valid JSON")]
    [InlineData("""{"Rules":[] /* comment */}""", "not valid JSON")]
    public void Sections_the_assistant_may_not_change_are_refused(string proposal, string expected)
    {
        var review = AiAssistant.Review(proposal, Running());

        Assert.Null(review.Candidate);
        Assert.Contains(review.Errors, e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_valid_proposal_shows_its_changes_and_keeps_the_secrets()
    {
        var running = Running();

        var review = AiAssistant.Review(Proposal(SummaryRules(running, OfficeRule)), running);

        Assert.Empty(review.Errors);
        var change = Assert.Single(review.Changes);
        Assert.Equal((ChangeKind.Added, ConfigurationSection.Rule, "office-only-admin"), (change.Kind, change.Section, change.Name));
        var candidate = review.Candidate!;
        Assert.Equal(Secret, candidate.Rules.Single(r => r.Name == "require-api-key").Conditions[0].Values.Single()); // filled in from the running configuration
        Assert.Equal("owner@private.example", candidate.Settings.Acme.Email); // sections that were not proposed stay as they are
        Assert.Equal(running.Routes.Count, candidate.Routes.Count);
    }

    [Fact]
    public void A_setting_can_be_changed_on_its_own()
    {
        var review = AiAssistant.Review("""{"Settings":{"DetectionOnly":true}}""", Running());

        var change = Assert.Single(review.Changes);
        Assert.Equal((ConfigurationSection.Settings, "DetectionOnly"), (change.Section, change.Name));
        Assert.True(review.Candidate!.Settings.DetectionOnly);
    }

    [Theory]
    [InlineData("\"Actoin\": \"Block\"", "Actoin")]
    [InlineData("\"Action\": \"Deny\"", "$.Rules[1].Action")]
    [InlineData("\"Action\": null", "null is not allowed")]
    public void A_rule_that_does_not_follow_the_schema_is_rejected(string action, string expected)
    {
        var running = Running();
        var rule = OfficeRule.Replace("\"Action\": \"Block\"", action, StringComparison.Ordinal);

        var review = AiAssistant.Review(Proposal(SummaryRules(running, rule)), running);

        Assert.Null(review.Candidate);
        Assert.Contains(review.Errors, e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_rule_that_fails_validation_is_rejected()
    {
        var running = Running();
        var rule = OfficeRule.Replace("203.0.113.0/24", "300.1.2.3/99", StringComparison.Ordinal);

        var review = AiAssistant.Review(Proposal(SummaryRules(running, rule)), running);

        Assert.Null(review.Candidate);
        Assert.Contains(review.Errors, e => e.Contains("300.1.2.3/99", StringComparison.Ordinal));
    }

    [Fact]
    public void A_secret_placeholder_that_moved_is_rejected()
    {
        var running = Running();
        var rules = SummaryRules(running);
        rules[0]!["Conditions"]![0]!["HeaderName"] = "X-Other-Key";

        var review = AiAssistant.Review(Proposal(rules), running);

        Assert.Null(review.Candidate);
        Assert.Contains(review.Errors, e => e.Contains("secret value", StringComparison.Ordinal));
    }

    [Fact]
    public void A_placeholder_can_never_become_a_value()
    {
        var running = Running();
        var rule = OfficeRule.Replace("/admin", ConfigurationSecrets.Placeholder, StringComparison.Ordinal)
            .Replace("\"Field\": \"Path\"", "\"Field\": \"Header\", \"HeaderName\": \"X-New\"", StringComparison.Ordinal);

        var review = AiAssistant.Review(Proposal(SummaryRules(running, rule)), running);

        Assert.Null(review.Candidate);
    }

    [Fact]
    public void A_proposal_that_changes_nothing_is_rejected()
    {
        var running = Running();

        var review = AiAssistant.Review(Proposal(SummaryRules(running)), running);

        Assert.Equal(["The proposal does not change anything."], review.Errors);
    }
}
