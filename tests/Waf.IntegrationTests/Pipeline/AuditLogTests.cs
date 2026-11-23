using System.Net;
using Waf.Data;
using Waf.IntegrationTests.Proxy;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>The audit log: who changed what and when, against a running gateway.</summary>
public sealed class AuditLogTests
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

    private static async Task<List<AuditEntry>> EntriesAsync(Gateway gateway, AuditFilter? filter = null) =>
        [.. (await gateway.AuditLog.ReadPageAsync(filter ?? new AuditFilter(), null, null, AuditLogStore.MaxPageSize, Ct)).Items.Reverse()];

    /// <summary>The acceptance criterion: every stored configuration version links to an audit entry.</summary>
    private static async Task AssertEveryVersionIsAuditedAsync(Gateway gateway)
    {
        var versions = (await gateway.Store.GetAllAsync(Ct)).Select(v => v.Version).ToList();
        var audited = (await gateway.AuditLog.GetForVersionsAsync(versions, Ct)).Select(e => e.ConfigurationVersionId!.Value).ToHashSet();
        Assert.All(versions, v => Assert.Contains(v, audited));
    }

    private static Dictionary<string, string> RouteFields(string name, string host, string destination) => new()
    {
        ["Model.BaseVersion"] = "1",
        ["Model.IsNew"] = "true",
        ["Model.Name"] = name,
        ["Model.Hosts"] = host,
        ["Model.PathPrefix"] = "/",
        ["Model.Destinations"] = destination,
        ["Model.HealthCheckIntervalSeconds"] = "10",
        ["Model.HealthCheckTimeoutSeconds"] = "5",
        ["Model.PreserveHost"] = "True",
        ["Model.Enabled"] = "True",
    };

    [Fact]
    public async Task A_change_in_the_admin_ui_records_who_made_it_and_what_changed()
    {
        await using var gateway = await StartAsync();

        await gateway.PostAsync("/routes/new", "route-edit", RouteFields("shop", "shop.example.com", $"http://127.0.0.1:{gateway.B.Port}"));

        var version = (await gateway.Store.GetLatestAsync(Ct))!;
        Assert.Equal((2L, GatewayFixture.AdminUserName), (version.Version, version.Author));

        var entry = Assert.Single(await EntriesAsync(gateway, new AuditFilter { Version = 2 }));
        Assert.Equal(AuditCategory.Configuration, entry.Category);
        Assert.Equal(AuditActions.ConfigSaved, entry.Action);
        Assert.Equal(GatewayFixture.AdminUserName, entry.UserName);
        Assert.Equal(AdminActor.AdminUi, entry.Source);
        Assert.Equal("127.0.0.1", entry.ClientIp);
        Assert.Equal("Version 2: Route 'shop' added.", entry.Summary);
        Assert.Equal("Route 'shop' added", entry.Details);

        // The first version, imported from appsettings at startup, has its entry too.
        var first = Assert.Single(await EntriesAsync(gateway, new AuditFilter { Version = 1 }));
        Assert.Equal(("appsettings import", "system"), (first.UserName, first.Source));
        await AssertEveryVersionIsAuditedAsync(gateway);
    }

    [Fact]
    public async Task Audit_page_lists_and_filters_entries_and_history_links_to_them()
    {
        await using var gateway = await StartAsync();
        await gateway.PostAsync("/routes/new", "route-edit", RouteFields("shop", "shop.example.com", $"http://127.0.0.1:{gateway.B.Port}"));

        var page = await gateway.GetPageAsync("/audit");
        Assert.Contains("Version 2: Route &#x27;shop&#x27; added.", page, StringComparison.Ordinal);
        Assert.Contains("Signed in.", page, StringComparison.Ordinal);
        Assert.Contains("href=\"history/2\"", page, StringComparison.Ordinal);

        var configurationOnly = await gateway.GetPageAsync("/audit?category=Configuration");
        Assert.Contains("Version 2:", configurationOnly, StringComparison.Ordinal);
        Assert.DoesNotContain("Signed in.", configurationOnly, StringComparison.Ordinal);

        var versionOne = await gateway.GetPageAsync("/audit?version=1");
        Assert.Contains("Version 1:", versionOne, StringComparison.Ordinal);
        Assert.DoesNotContain("Version 2:", versionOne, StringComparison.Ordinal);

        var history = await gateway.GetPageAsync("/history");
        Assert.Contains("href=\"audit?version=2\"", history, StringComparison.Ordinal);
        Assert.Contains("href=\"audit?version=1\"", history, StringComparison.Ordinal);

        var details = await gateway.GetPageAsync("/history/2");
        Assert.Contains("href=\"audit?version=2\"", details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sign_ins_sign_outs_and_security_changes_are_recorded()
    {
        await using var gateway = await StartAsync();

        using (var logout = await gateway.PostPlainFormAsync(AdminIdentity.LogoutPath, "/", []))
        {
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        await gateway.SignInAsync(gateway.Admin);
        await gateway.PostAsync("/account", "end-sessions", []);
        const string NewPassword = "a brand new long password";
        await gateway.PostAsync("/account", "change-password", new()
        {
            ["Model.CurrentPassword"] = GatewayFixture.AdminPassword,
            ["Model.NewPassword"] = NewPassword,
            ["Model.ConfirmPassword"] = NewPassword,
        });

        var entries = await EntriesAsync(gateway);
        Assert.Equal(
            [
                AuditActions.AdminCreated, AuditActions.SignedIn, AuditActions.SignedOut, AuditActions.SignedIn,
                AuditActions.SessionsEnded, AuditActions.PasswordChanged,
            ],
            entries.Where(e => e.Category is AuditCategory.SignIn or AuditCategory.Security).Select(e => e.Action));
        Assert.All(entries.Where(e => e.Category != AuditCategory.Configuration), e => Assert.Equal(GatewayFixture.AdminUserName, e.UserName));
    }

    [Fact]
    public async Task Restoring_a_backup_keeps_the_audit_log_and_every_version_linked()
    {
        await using var source = await StartAsync();
        await source.PostAsync("/routes/new", "route-edit", RouteFields("shop", "shop.example.com", $"http://127.0.0.1:{source.B.Port}"));
        using var download = await source.PostPlainFormAsync(AdminDownloads.BackupPath, "/backup", new() { ["includeSecrets"] = "true" });
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        var backup = await download.Content.ReadAsByteArrayAsync(Ct);
        Assert.Contains(await EntriesAsync(source), e => e.Action == AuditActions.BackupDownloaded && e.Summary.Contains("with secrets", StringComparison.Ordinal));

        // The target's own version 1 has other content (another backend port) than the backup's version 1.
        await using var target = await StartAsync();
        var before = await EntriesAsync(target);
        var html = await target.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", "backup.zip", backup);
        Assert.Contains("Backup restored.", html, StringComparison.Ordinal);

        var after = await EntriesAsync(target);
        Assert.Equal(before.Select(e => e.Id), after.Take(before.Count).Select(e => e.Id)); // nothing removed
        var added = after.Skip(before.Count).ToList();
        Assert.Equal(
            new List<(string, long?)> { (AuditActions.ConfigRestored, 1), (AuditActions.ConfigRestored, 2), (AuditActions.BackupRestored, null) },
            added.Select(e => (e.Action, e.ConfigurationVersionId)));
        Assert.All(added, e => Assert.Equal(GatewayFixture.AdminUserName, e.UserName));
        Assert.Contains("Originally stored by admin", added[1].Details, StringComparison.Ordinal);
        await AssertEveryVersionIsAuditedAsync(target);
    }
}
