using System.Net;
using System.Text.Json;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// From a sentence to a running change and back, through the admin UI and the real Anthropic SDK, against a fake
/// Anthropic API: ask, review the differences, approve (a new version), undo (a rollback).
/// </summary>
public sealed class AiProposalUiTests
{
    private const string ApiKey = "sk-ant-api03-integration-key-PROP";
    private const string Prompt = "Only the office network 203.0.113.0/24 may open /admin.";

    private const string OfficeRule = """
        {"Rules":[{"Name":"office-only-admin","Priority":10,"Action":"Block","Conditions":[
          {"Field":"Path","Operator":"StartsWith","Values":["/admin"]},
          {"Field":"ClientIp","Operator":"InCidr","Values":["203.0.113.0/24"],"Negate":true}]}]}
        """;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        public FakeAnthropic Anthropic { get; private set; } = null!;

        protected override async ValueTask BeforeStartAsync()
        {
            await base.BeforeStartAsync();
            Anthropic = await FakeAnthropic.StartAsync();
        }

        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("website", [("http", A.Port)]).ToArray(),
            $"--{AiProviderFactory.AnthropicBaseUrlSetting}={Anthropic.BaseUrl}",
        ];

        protected override async ValueTask AfterStopAsync()
        {
            await base.AfterStopAsync();
            if (Anthropic is not null)
            {
                await Anthropic.DisposeAsync();
            }
        }

        public AiAssistant Assistant => App.Services.GetRequiredService<AiAssistant>();

        public IGatewayConfigurationService Configurations => App.Services.GetRequiredService<IGatewayConfigurationService>();

        public async Task<long> LatestVersionAsync() => (await Store.GetLatestAsync(Ct))!.Version;
    }

    private static async Task<Gateway> StartAsync(bool withKey = true)
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        if (withKey)
        {
            Assert.Empty(await gateway.Assistant.SaveKeyAsync(ApiKey, AuditActor.System("test"), Ct));
        }

        return gateway;
    }

    private static Task<string> AskAsync(Gateway gateway, string prompt = Prompt) =>
        gateway.PostAsync("/ai", "ai-ask", new() { ["Ask.Prompt"] = prompt });

    /// <summary>Posts form <paramref name="handler"/> although the page does not show it (as a crafted request would).</summary>
    private static async Task<HttpStatusCode> ForcePostAsync(Gateway gateway, string path, string handler, Dictionary<string, string>? fields = null)
    {
        fields ??= [];
        fields["_handler"] = handler;
        using var response = await gateway.PostPlainFormAsync(path, path, fields);
        return response.StatusCode;
    }

    [Fact]
    public async Task A_sentence_becomes_a_reviewed_change_that_can_be_undone()
    {
        await using var gateway = await StartAsync();
        gateway.Anthropic.Answer = FakeAnthropic.Proposal("Blocks /admin for everyone outside 203.0.113.0/24.", OfficeRule);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/admin"));

        // Ask: the proposal is shown with its differences; nothing is applied yet.
        var review = await AskAsync(gateway);
        Assert.Contains("AI proposal 1", review, StringComparison.Ordinal);
        Assert.Contains("What will change", review, StringComparison.Ordinal);
        Assert.Contains("office-only-admin", review, StringComparison.Ordinal);
        Assert.Contains("Blocks /admin for everyone outside 203.0.113.0/24.", review, StringComparison.Ordinal);
        Assert.Contains("Apply these changes", review, StringComparison.Ordinal);
        Assert.Equal(1, await gateway.LatestVersionAsync());
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/admin"));

        // What went to Anthropic: the prompt, the summary and the structured output format.
        var sent = Assert.Single(gateway.Anthropic.Requests);
        using (var body = JsonDocument.Parse(sent))
        {
            Assert.Equal("json_schema", body.RootElement.GetProperty("output_config").GetProperty("format").GetProperty("type").GetString());
            Assert.Contains(Prompt, body.RootElement.GetProperty("messages")[0].GetProperty("content").GetString(), StringComparison.Ordinal);
        }

        Assert.DoesNotContain(ApiKey, sent, StringComparison.Ordinal);
        Assert.DoesNotContain(GatewayFixture.AdminPassword, sent, StringComparison.Ordinal);

        // Approve: a new version, recorded as coming from the AI assistant, and the rule works.
        var applied = await gateway.PostAsync("/ai/proposals/1", "ai-approve", []);
        Assert.Contains("Applied: version 2 is active now.", applied, StringComparison.Ordinal);
        var version = (await gateway.Store.GetLatestAsync(Ct))!;
        Assert.Equal((2L, GatewayFixture.AdminUserName), (version.Version, version.Author));
        Assert.StartsWith("AI proposal 1: Blocks /admin", version.Comment, StringComparison.Ordinal);
        var entry = Assert.Single((await gateway.AuditLog.ReadPageAsync(new AuditFilter { Version = 2 }, null, null, 10, Ct)).Items);
        Assert.Equal((AuditActions.ConfigSaved, AiAssistant.AuditSource), (entry.Action, entry.Source));
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/admin"));

        // A proposal is applied once: the button is gone, and a crafted post is refused.
        Assert.DoesNotContain("Apply these changes", applied, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadRequest, await ForcePostAsync(gateway, "/ai/proposals/1", "ai-approve"));
        Assert.Equal(2, await gateway.LatestVersionAsync());

        // Undo: a rollback to version 1, stored as version 3.
        var undone = await gateway.PostAsync("/ai/proposals/1", "ai-undo", []);
        Assert.Contains("Undone: version 3 restored the configuration of version 1.", undone, StringComparison.Ordinal);
        Assert.Empty((await gateway.Store.GetLatestAsync(Ct))!.Configuration.Rules);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/admin"));

        var list = await gateway.GetPageAsync("/ai");
        Assert.Contains("Undone", list, StringComparison.Ordinal);
        Assert.Contains(Prompt, list, StringComparison.Ordinal);
        var actions = (await gateway.AuditLog.ReadPageAsync(new AuditFilter(), null, null, 50, Ct)).Items.Select(e => e.Action).ToList();
        Assert.Contains(AuditActions.AiProposalRequested, actions);
    }

    [Fact]
    public async Task An_invalid_proposal_is_rejected_and_cannot_be_applied()
    {
        await using var gateway = await StartAsync();
        gateway.Anthropic.Answer = FakeAnthropic.Proposal("Adds a rule.", OfficeRule.Replace("\"Block\"", "\"Deny\"", StringComparison.Ordinal));

        var review = await AskAsync(gateway);

        Assert.Contains("rejected by the checks", review, StringComparison.Ordinal);
        Assert.Contains("$.Rules[0].Action", review, StringComparison.Ordinal);
        Assert.DoesNotContain("Apply these changes", review, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.BadRequest, await ForcePostAsync(gateway, "/ai/proposals/1", "ai-approve"));
        Assert.Equal(1, await gateway.LatestVersionAsync());

        var discarded = await gateway.PostAsync("/ai/proposals/1", "ai-discard", []);
        Assert.Contains("The proposal is discarded.", discarded, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_proposal_for_an_older_configuration_cannot_be_applied()
    {
        await using var gateway = await StartAsync();
        gateway.Anthropic.Answer = FakeAnthropic.Proposal("Adds a rule.", OfficeRule);
        await AskAsync(gateway);

        // Someone else changes the configuration in between.
        var configuration = (await gateway.Store.GetLatestAsync(Ct))!.Configuration;
        configuration.Settings.DetectionOnly = true;
        Assert.True((await gateway.Configurations.ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        var page = await gateway.GetPageAsync("/ai/proposals/1");
        Assert.Contains("can no longer be applied", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Apply these changes", page, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.BadRequest, await ForcePostAsync(gateway, "/ai/proposals/1", "ai-approve"));
        Assert.Equal(2, await gateway.LatestVersionAsync());

        var discarded = await gateway.PostAsync("/ai/proposals/1", "ai-discard", []);
        Assert.Contains("The proposal is discarded.", discarded, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_a_key_the_assistant_is_off_and_sends_nothing()
    {
        await using var gateway = await StartAsync(withKey: false);

        var page = await gateway.GetPageAsync("/ai");
        Assert.Contains("The AI assistant is off", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Ask for a proposal", page, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.BadRequest, await ForcePostAsync(gateway, "/ai", "ai-ask", new() { ["Ask.Prompt"] = Prompt }));
        Assert.Empty(gateway.Anthropic.Requests);
        Assert.Empty(await gateway.Assistant.RecentProposalsAsync(10, Ct));
    }

    [Fact]
    public async Task A_missing_proposal_is_not_found()
    {
        await using var gateway = await StartAsync(withKey: false);

        using var response = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/ai/proposals/42"), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
