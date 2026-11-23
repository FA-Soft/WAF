using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>The AI assistant page: off by default, a key turns it on (encrypted, audited), removing it turns it off.</summary>
public sealed class AiSettingsUiTests
{
    private const string ApiKey = "sk-ant-api03-integration-key-QRST";
    private const string HeaderSecret = "do-not-send-this-9876";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)]).ToArray();

        public AiAssistant Assistant => App.Services.GetRequiredService<AiAssistant>();

        public IGatewayConfigurationService Configurations => App.Services.GetRequiredService<IGatewayConfigurationService>();
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        return gateway;
    }

    [Fact]
    public async Task The_assistant_is_off_until_a_key_is_saved_and_off_again_when_it_is_removed()
    {
        await using var gateway = await StartAsync();

        var page = await gateway.GetPageAsync("/ai");
        Assert.Contains("No API key: the AI features are off", page, StringComparison.Ordinal);
        Assert.Null(await gateway.Assistant.CreateProviderAsync(Ct));

        // A malformed key is refused.
        var refused = await gateway.PostAsync("/ai", "ai-key", new() { ["Key.ApiKey"] = "not-a-key" });
        Assert.Contains("does not look like an Anthropic API key", refused, StringComparison.Ordinal);
        Assert.Null(await gateway.Assistant.GetStatusAsync(Ct));

        // A key turns it on; the page shows only its last four characters.
        var saved = await gateway.PostAsync("/ai", "ai-key", new() { ["Key.ApiKey"] = ApiKey });
        Assert.Contains("The API key is saved", saved, StringComparison.Ordinal);
        Assert.Contains("…QRST", saved, StringComparison.Ordinal);
        Assert.DoesNotContain(ApiKey, saved, StringComparison.Ordinal);
        Assert.Contains("claude-opus-5-5", saved, StringComparison.Ordinal);
        using (var provider = await gateway.Assistant.CreateProviderAsync(Ct))
        {
            Assert.NotNull(provider);
        }

        // Removing it turns everything off again.
        var removed = await gateway.PostAsync("/ai", "ai-remove", []);
        Assert.Contains("The API key is removed", removed, StringComparison.Ordinal);
        Assert.Contains("No API key: the AI features are off", removed, StringComparison.Ordinal);
        Assert.Null(await gateway.Assistant.CreateProviderAsync(Ct));

        var entries = (await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 50, Ct)).Items;
        Assert.Contains(entries, e => e.Action == AuditActions.AiKeySaved && e.UserName == GatewayFixture.AdminUserName && e.Summary.EndsWith("ending in QRST).", StringComparison.Ordinal));
        Assert.Contains(entries, e => e.Action == AuditActions.AiKeyRemoved);
        Assert.All(entries, e => Assert.DoesNotContain(ApiKey, e.Summary + e.Details, StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_key_is_encrypted_and_never_part_of_versions_or_backups()
    {
        await using var gateway = await StartAsync();
        await gateway.PostAsync("/ai", "ai-key", new() { ["Key.ApiKey"] = ApiKey });

        foreach (var file in Directory.GetFiles(gateway.DataDirectory, "*.db*"))
        {
            // The running gateway keeps the databases open: read them alongside it.
            await using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            await stream.CopyToAsync(copy, Ct);
            Assert.DoesNotContain(ApiKey, System.Text.Encoding.UTF8.GetString(copy.ToArray()), StringComparison.Ordinal);
        }

        foreach (var version in await gateway.Store.GetAllAsync(Ct))
        {
            Assert.DoesNotContain(ApiKey, GatewayConfigurationJson.Serialize(version.Configuration), StringComparison.Ordinal);
        }

        // Not even a backup with secrets carries it: the key belongs to this machine.
        using var archive = new MemoryStream();
        var backup = await gateway.Store.CreateBackupAsync(includeSecrets: true, Ct);
        BackupArchive.Write(archive, backup);
        archive.Position = 0;
        using var zip = new System.IO.Compression.ZipArchive(archive, System.IO.Compression.ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            using var reader = new StreamReader(entry.Open());
            Assert.DoesNotContain(ApiKey, await reader.ReadToEndAsync(Ct), StringComparison.Ordinal);
        }

        // Restoring a backup replaces the configuration history, not the key.
        Assert.True((await gateway.Configurations.RestoreBackupAsync(backup, AuditActor.System("test"), Ct)).Succeeded);
        Assert.Equal("QRST", (await gateway.Assistant.GetStatusAsync(Ct))?.KeyHint);
    }

    [Fact]
    public async Task The_page_shows_the_sanitized_summary_that_would_be_sent()
    {
        await using var gateway = await StartAsync();
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "require-api-key",
            Conditions = { new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Negate = true, Values = { HeaderSecret } } },
        });
        configuration.Settings.Acme.Email = "owner@private.example";
        Assert.True((await gateway.Configurations.ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        var page = await gateway.GetPageAsync("/ai");

        Assert.Contains("require-api-key", page, StringComparison.Ordinal);
        Assert.Contains(ConfigurationSecrets.Placeholder, page, StringComparison.Ordinal);
        Assert.DoesNotContain(HeaderSecret, page, StringComparison.Ordinal);
        Assert.DoesNotContain("owner@private.example", page, StringComparison.Ordinal);
    }
}
