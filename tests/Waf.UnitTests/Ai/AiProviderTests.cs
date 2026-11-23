using System.Net;
using System.Text;
using System.Text.Json;
using FASoft.Waf.Ai;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.UnitTests.Engine;

namespace FASoft.Waf.UnitTests.Ai;

/// <summary>
/// What the AI provider sends: only fixed instructions, the administrator's prompt and the sanitized configuration
/// summary. Checked on the exact HTTP request the Anthropic SDK would send (captured, never sent).
/// </summary>
public sealed class AiProviderTests
{
    private const string ApiKey = "sk-ant-api03-test-key-0000000000";
    private const string HeaderSecret = "s3cret-api-key-value-123";
    private const string AcmeEmail = "owner@private.example";
    private const string CertificatePath = @"C:\secret-store\site.pfx";
    private const string Thumbprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A configuration full of things that must never leave the gateway.</summary>
    private static GatewayConfiguration Sensitive()
    {
        var configuration = RuleBuilder.Config(new WafRule
        {
            Name = "require-api-key",
            Conditions =
            {
                new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Negate = true, Values = { HeaderSecret } },
            },
        });
        configuration.Settings.Acme.Email = AcmeEmail;
        configuration.Settings.Acme.AcceptTermsOfService = true;
        configuration.Certificates.Add(new CertificateBinding { HostName = "www.example.com", Source = CertificateSource.File, CertificatePath = CertificatePath, KeyPath = CertificatePath + ".key" });
        configuration.Certificates.Add(new CertificateBinding { HostName = "api.example.com", Source = CertificateSource.Uploaded, Thumbprint = Thumbprint });
        configuration.Routes[0].Match.Hosts.Add("www.example.com");
        return configuration;
    }

    private static void AssertNothingSensitive(string text)
    {
        foreach (var secret in new[] { HeaderSecret, AcmeEmail, "secret-store", "site.pfx", Thumbprint, ApiKey })
        {
            Assert.DoesNotContain(secret, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Records every request and answers with a fixed response, instead of calling Anthropic.</summary>
    private sealed class CapturingHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request, request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken)));
            var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.Add("x-should-retry", "false"); // no SDK retries in tests
            response.Headers.Add("request-id", "req_test");
            return response;
        }
    }

    private static string MessageJson(string text = "Proposal", string stopReason = "end_turn") => $$$"""
        {"id":"msg_test","type":"message","role":"assistant","model":"claude-opus-5-5",
         "content":[{"type":"text","text":"{{{text}}}"}],"stop_reason":"{{{stopReason}}}","stop_sequence":null,
         "usage":{"input_tokens":120,"output_tokens":30}}
        """;

    private static (AnthropicAiProvider Provider, CapturingHandler Handler) Provider(HttpStatusCode status, string body)
    {
        var handler = new CapturingHandler(status, body);
        return (new AnthropicAiProvider(ApiKey, new HttpClient(handler)), handler);
    }

    [Fact]
    public void The_summary_leaves_out_secrets_and_private_details()
    {
        var configuration = Sensitive();

        var summary = ConfigurationSummary.Create(configuration);

        AssertNothingSensitive(summary);
        Assert.Contains(ConfigurationSecrets.Placeholder, summary, StringComparison.Ordinal);
        Assert.Contains("require-api-key", summary, StringComparison.Ordinal); // the rule itself is there
        Assert.Contains("www.example.com", summary, StringComparison.Ordinal);
        Assert.Contains("\"Source\": \"Uploaded\"", summary, StringComparison.Ordinal);
        Assert.Equal(HeaderSecret, configuration.Rules[0].Conditions[0].Values[0]); // the caller's object is untouched
    }

    [Fact]
    public void The_summary_holds_only_allowlisted_settings()
    {
        using var summary = JsonDocument.Parse(ConfigurationSummary.Create(Sensitive()));

        var settings = summary.RootElement.GetProperty("Settings").EnumerateObject().Select(p => p.Name).Order().ToList();
        Assert.Equal(["AttackDetection", "DetectionOnly", "Hsts", "LogRetention", "TrustedProxies"], settings);
        Assert.Equal(["SchemaVersion", "Settings", "Routes", "Rules", "RateLimits", "Certificates"],
            summary.RootElement.EnumerateObject().Select(p => p.Name));
        foreach (var certificate in summary.RootElement.GetProperty("Certificates").EnumerateArray())
        {
            Assert.Equal(["HostName", "Source"], certificate.EnumerateObject().Select(p => p.Name));
        }
    }

    [Fact]
    public async Task Only_instructions_prompt_and_summary_are_sent()
    {
        var (provider, handler) = Provider(HttpStatusCode.OK, MessageJson());
        using (provider)
        {
            var request = new AiRequest("You help configure a web application firewall.", "Block /admin for everyone but 203.0.113.0/24.", ConfigurationSummary.Create(Sensitive()));

            var completion = await provider.CompleteAsync(request, Ct);

            Assert.Equal(("Proposal", "claude-opus-5-5", 120L, 30L), (completion.Text, completion.Model, completion.InputTokens, completion.OutputTokens));
            var (sent, body) = Assert.Single(handler.Requests);
            Assert.Equal(HttpMethod.Post, sent.Method);
            Assert.Equal("/v1/messages", sent.RequestUri!.AbsolutePath);
            // The key goes only in the credential header (API version 2026-10-21: Authorization: Bearer).
            Assert.Equal(("Bearer", ApiKey), (sent.Headers.Authorization!.Scheme, sent.Headers.Authorization.Parameter));
            Assert.DoesNotContain(sent.Headers.Where(h => h.Key != "Authorization").SelectMany(h => h.Value), v => v.Contains(ApiKey, StringComparison.Ordinal));
            Assert.Contains("server-side-fallback-2026-07-01", string.Join(",", sent.Headers.GetValues("anthropic-beta")), StringComparison.Ordinal);

            // The body: model, system prompt and one user message, with nothing sensitive in it.
            AssertNothingSensitive(body);
            using var json = JsonDocument.Parse(body);
            var root = json.RootElement;
            Assert.Equal("claude-opus-5-5", root.GetProperty("model").GetString());
            Assert.Equal(request.Instructions, root.GetProperty("system").GetString());
            var message = Assert.Single(root.GetProperty("messages").EnumerateArray());
            Assert.Equal("user", message.GetProperty("role").GetString());
            var content = message.GetProperty("content").GetString()!;
            Assert.Contains(request.Prompt, content, StringComparison.Ordinal);
            Assert.Contains(request.Configuration, content, StringComparison.Ordinal);
            Assert.Equal(
                ["fallbacks", "max_tokens", "messages", "model", "output_config", "system"],
                root.EnumerateObject().Select(p => p.Name).Order().ToList()); // no other fields (no logs, no extras)
        }
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, AiFailure.InvalidKey)]
    [InlineData(HttpStatusCode.Forbidden, AiFailure.InvalidKey)]
    [InlineData(HttpStatusCode.TooManyRequests, AiFailure.RateLimited)]
    [InlineData(HttpStatusCode.ServiceUnavailable, AiFailure.Unavailable)]
    [InlineData(HttpStatusCode.BadRequest, AiFailure.Failed)]
    public async Task Errors_are_explained(HttpStatusCode status, AiFailure expected)
    {
        var (provider, _) = Provider(status, """{"type":"error","error":{"type":"some_error","message":"details"}}""");
        using (provider)
        {
            var ex = await Assert.ThrowsAsync<AiProviderException>(() => provider.CompleteAsync(new AiRequest("i", "p", "{}"), Ct));
            Assert.Equal(expected, ex.Failure);
            Assert.DoesNotContain(ApiKey, ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_refusal_is_reported()
    {
        var (provider, _) = Provider(HttpStatusCode.OK, MessageJson(string.Empty, "refusal"));
        using (provider)
        {
            var ex = await Assert.ThrowsAsync<AiProviderException>(() => provider.CompleteAsync(new AiRequest("i", "p", "{}"), Ct));
            Assert.Equal(AiFailure.Refused, ex.Failure);
        }
    }

    [Fact]
    public async Task Checking_the_key_reads_the_model_and_sends_no_configuration()
    {
        var (provider, handler) = Provider(HttpStatusCode.OK, """{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-01-01T00:00:00Z"}""");
        using (provider)
        {
            await provider.CheckAsync(Ct);

            var (sent, body) = Assert.Single(handler.Requests);
            Assert.Equal(HttpMethod.Get, sent.Method);
            Assert.Equal("/v1/models/claude-opus-5-5", sent.RequestUri!.AbsolutePath);
            Assert.Empty(body);
        }
    }

    [Fact]
    public void A_route_without_secrets_is_sent_as_it_is()
    {
        var configuration = new GatewayConfiguration();
        var route = new ProxyRouteOptions { Name = "api", Https = { RedirectHttp = true } };
        route.Match.Hosts.Add("api.example.com");
        route.Destinations.Add(new ProxyDestinationOptions { Address = "10.0.0.5", Port = 8080 });
        configuration.Routes.Add(route);

        var summary = ConfigurationSummary.Create(configuration);

        Assert.Contains("10.0.0.5", summary, StringComparison.Ordinal); // backend addresses are needed to propose route changes
        Assert.Contains("\"RedirectHttp\": true", summary, StringComparison.Ordinal);
    }
}
