using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.IntegrationTests.Proxy;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// Export/import, full backup/restore and the version history, driven through the admin UI of running gateways.
/// Every gateway starts with one catch-all route to backend A (version 1); <see cref="AddApiKeyRuleAsync"/> adds
/// a rule with a secret.
/// </summary>
public sealed partial class BackupUiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs().Add("website", [("http", A.Port)]).ToArray();
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        return gateway;
    }

    private static IGatewayConfigurationService Service(Gateway gateway) =>
        gateway.App.Services.GetRequiredService<IGatewayConfigurationService>();

    private static async Task<StoredConfiguration> ActiveAsync(Gateway gateway) =>
        (await gateway.Store.GetLastKnownGoodAsync(Ct))!;

    /// <summary>Version 2: requests to /api need X-Api-Key "s3cret".</summary>
    private static async Task AddApiKeyRuleAsync(Gateway gateway)
    {
        var configuration = (await ActiveAsync(gateway)).Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "require-api-key",
            Conditions =
            {
                new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/api" } },
                new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Negate = true, Values = { "s3cret" } },
            },
        });
        Assert.True((await Service(gateway).ActivateAsync(configuration, AuditActor.System("test"), "API key rule.", Ct)).Succeeded);
    }

    private static async Task<(string FileName, byte[] Content)> DownloadAsync(Gateway gateway, string path, Dictionary<string, string> fields)
    {
        using var response = await gateway.PostPlainFormAsync(path, "/backup", fields);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (response.Content.Headers.ContentDisposition!.FileNameStar ?? response.Content.Headers.ContentDisposition.FileName!,
            await response.Content.ReadAsByteArrayAsync(Ct));
    }

    private static Dictionary<string, string> Secrets(bool include) => include ? new() { ["includeSecrets"] = "true" } : [];

    private static string PreviewTag(string html) => PreviewTagPattern().Match(html).Groups["tag"].Value;

    private static async Task<string> ImportAsync(Gateway gateway, byte[] file)
    {
        var preview = await gateway.PostMultipartAsync("/import", "import-config", new() { ["Model.Command"] = "preview" }, "configFile", "config.json", file);
        if (!preview.Contains("value=\"apply\"", StringComparison.Ordinal))
        {
            return preview;
        }

        // The preview put the file's contents in the form; apply sends them back with the tag that was shown.
        var json = WebUtility.HtmlDecode(JsonTextareaPattern().Match(preview).Groups["json"].Value);
        return await gateway.PostAsync("/import", "import-config", new()
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = PreviewTag(preview),
            ["Model.Json"] = json,
        });
    }

    [Fact]
    public async Task Downloads_require_the_antiforgery_token()
    {
        await using var gateway = await StartAsync();

        using var response = await gateway.PostPlainFormAsync(AdminDownloads.ConfigurationPath, "/backup", [], withToken: false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Export_leaves_secrets_out_unless_asked()
    {
        await using var gateway = await StartAsync();
        await AddApiKeyRuleAsync(gateway);
        Assert.Contains("1 secret value (header conditions", await gateway.GetPageAsync("/backup"), StringComparison.Ordinal);

        var (name, without) = await DownloadAsync(gateway, AdminDownloads.ConfigurationPath, Secrets(false));
        var (_, with) = await DownloadAsync(gateway, AdminDownloads.ConfigurationPath, Secrets(true));

        Assert.Matches(@"^waf-config-v2-\d{8}\.json$", name);
        Assert.DoesNotContain("s3cret", Encoding.UTF8.GetString(without), StringComparison.Ordinal);
        Assert.Contains(ConfigurationSecrets.Placeholder, Encoding.UTF8.GetString(without), StringComparison.Ordinal);
        Assert.Contains("s3cret", Encoding.UTF8.GetString(with), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Export_and_import_on_another_gateway_yields_the_identical_configuration()
    {
        await using var source = await StartAsync();
        await AddApiKeyRuleAsync(source);
        await using var target = await StartAsync();
        var (_, file) = await DownloadAsync(source, AdminDownloads.ConfigurationPath, Secrets(true));

        var html = await ImportAsync(target, file);

        Assert.Contains("Configuration imported (version 2).", html, StringComparison.Ordinal);
        Assert.Equal((await ActiveAsync(source)).Sha256, (await ActiveAsync(target)).Sha256);
        Assert.Equal(HttpStatusCode.Forbidden, await target.SendAsync("/api/x"));
    }

    [Fact]
    public async Task Export_without_secrets_imports_back_unchanged_but_not_where_the_secret_is_unknown()
    {
        await using var source = await StartAsync();
        await AddApiKeyRuleAsync(source);
        var (_, file) = await DownloadAsync(source, AdminDownloads.ConfigurationPath, Secrets(false));

        var same = await ImportAsync(source, file);
        Assert.Contains("Nothing to change: the file is identical to the running configuration.", same, StringComparison.Ordinal);

        await using var other = await StartAsync();
        var refused = await ImportAsync(other, file);
        Assert.Contains("the secret value was left out of the file", refused, StringComparison.Ordinal);
        Assert.Equal(1, (await ActiveAsync(other)).Version);
    }

    [Fact]
    public async Task Import_shows_a_preview_and_refuses_an_out_of_date_one()
    {
        await using var gateway = await StartAsync();
        var edited = (await ActiveAsync(gateway)).Configuration;
        edited.Settings.DetectionOnly = true;
        var file = Encoding.UTF8.GetBytes(GatewayConfigurationJson.Serialize(edited));

        var preview = await gateway.PostMultipartAsync("/import", "import-config", new() { ["Model.Command"] = "preview" }, "configFile", "c.json", file);
        Assert.Contains("Change setting: Detection-only mode", preview, StringComparison.Ordinal);
        Assert.Equal(1, (await ActiveAsync(gateway)).Version);

        var stale = await gateway.PostAsync("/import", "import-config", new()
        {
            ["Model.Command"] = "apply",
            ["Model.PreviewTag"] = "0123456789abcdef",
            ["Model.Json"] = Encoding.UTF8.GetString(file),
        });
        Assert.Contains("changed since the preview", stale, StringComparison.Ordinal);
        Assert.Equal(1, (await ActiveAsync(gateway)).Version);

        var invalid = await gateway.PostAsync("/import", "import-config", new() { ["Model.Command"] = "preview", ["Model.Json"] = "{\"Routs\": []}" });
        Assert.Contains("This file cannot be imported", invalid, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Backup_and_restore_on_another_gateway_yields_the_same_history()
    {
        await using var source = await StartAsync();
        await AddApiKeyRuleAsync(source);
        var (name, backup) = await DownloadAsync(source, AdminDownloads.BackupPath, Secrets(true));
        Assert.Matches(@"^waf-backup-\d{8}-\d{6}\.zip$", name);

        await using var target = await StartAsync();
        var html = await target.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", name, backup);

        Assert.Contains("Backup restored.", html, StringComparison.Ordinal);
        var expected = await source.Store.GetAllAsync(Ct);
        var actual = await target.Store.GetAllAsync(Ct);
        Assert.Equal(expected.Select(v => (v.Version, v.Author, v.Comment, v.Sha256)), actual.Select(v => (v.Version, v.Author, v.Comment, v.Sha256)));
        Assert.Equal(2, (await ActiveAsync(target)).Version);
        Assert.Single(Directory.GetFiles(target.DataDirectory, "config.before-restore-*.db"));
        Assert.Equal(HttpStatusCode.Forbidden, await target.SendAsync("/api/x")); // the restored rule is running
    }

    [Fact]
    public async Task Restore_needs_confirmation_and_a_backup_with_known_secrets()
    {
        await using var source = await StartAsync();
        await AddApiKeyRuleAsync(source);
        var (name, backup) = await DownloadAsync(source, AdminDownloads.BackupPath, Secrets(false));
        await using var target = await StartAsync();

        var unconfirmed = await target.PostMultipartAsync("/backup", "restore-backup", [], "backupFile", name, backup);
        Assert.Contains("to confirm", unconfirmed, StringComparison.Ordinal);

        var refused = await target.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", name, backup);
        Assert.Contains("The backup was not restored.", refused, StringComparison.Ordinal);
        Assert.Contains("Version 2: Rule &#x27;require-api-key&#x27;", refused, StringComparison.Ordinal);
        Assert.Single(await target.Store.GetAllAsync(Ct));

        var garbage = await target.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", "x.zip", Encoding.UTF8.GetBytes("no zip"));
        Assert.Contains("damaged or not a WAF Gateway backup", garbage, StringComparison.Ordinal);

        // On the gateway that knows the secret, the same backup restores fine.
        var restored = await source.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", name, backup);
        Assert.Contains("Backup restored.", restored, StringComparison.Ordinal);
        Assert.Contains("s3cret", (await ActiveAsync(source)).Configuration.Rules[0].Conditions[1].Values);
    }

    [Fact]
    public async Task An_earlier_version_can_be_restored_from_the_history()
    {
        await using var gateway = await StartAsync();
        await AddApiKeyRuleAsync(gateway);
        Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/api/x"));

        var page = await gateway.GetPageAsync("/history/1");
        Assert.Contains("Remove rule &#x27;require-api-key&#x27;", page, StringComparison.Ordinal);
        Assert.Contains("Add rule &#x27;require-api-key&#x27;", await gateway.GetPageAsync("/history/2"), StringComparison.Ordinal);

        var html = await gateway.PostAsync("/history/1", "restore-version", new() { ["RestoreForm.BaseVersion"] = "2" });

        Assert.Contains("Version 1 restored as version 3.", html, StringComparison.Ordinal);
        Assert.Equal((await gateway.Store.GetAsync(1, Ct))!.Sha256, (await ActiveAsync(gateway)).Sha256);
        Assert.Equal(HttpStatusCode.OK, await gateway.SendAsync("/api/x"));

        // A stale page (based on version 2) cannot overwrite the newer state.
        var stale = await gateway.PostAsync("/history/2", "restore-version", new() { ["RestoreForm.BaseVersion"] = "2" });
        Assert.Contains("changed in the meantime", stale, StringComparison.Ordinal);
        Assert.Equal(3, (await ActiveAsync(gateway)).Version);
    }

    [GeneratedRegex("""name="Model.PreviewTag" value="(?<tag>[0-9a-f]*)""")]
    private static partial Regex PreviewTagPattern();

    [GeneratedRegex("""<textarea[^>]*name="Model.Json"[^>]*>(?<json>[^<]*)</textarea>""")]
    private static partial Regex JsonTextareaPattern();
}
