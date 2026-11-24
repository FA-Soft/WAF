using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// Targets on a running gateway: routes forward to "target · port label", a change to the target applies to every
/// route that uses it at once, the request log names the label, and the admin pages manage targets.
/// </summary>
public sealed class TargetTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// Target "lab" at 127.0.0.1 with port labels "web" (backend A) and "alt" (backend B); routes "site" and "shop" both
    /// use lab · web. Seeded from appsettings (command-line arguments), like a fresh install.
    /// </summary>
    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
        [
            "--Gateway:Targets:0:Name=lab",
            "--Gateway:Targets:0:Address=127.0.0.1",
            "--Gateway:Targets:0:Ports:0:Name=web",
            $"--Gateway:Targets:0:Ports:0:Port={A.Port.ToString(CultureInfo.InvariantCulture)}",
            "--Gateway:Targets:0:Ports:1:Name=alt",
            $"--Gateway:Targets:0:Ports:1:Port={B.Port.ToString(CultureInfo.InvariantCulture)}",
            .. Route(0, "site"),
            .. Route(1, "shop"),
        ];

        private static string[] Route(int index, string name) =>
        [
            $"--Gateway:Routes:{index}:Name={name}",
            $"--Gateway:Routes:{index}:Match:Hosts:0={name}.example.com",
            $"--Gateway:Routes:{index}:Destinations:0:Target=lab",
            $"--Gateway:Routes:{index}:Destinations:0:TargetPort=web",
        ];

        /// <summary>Which backend answers a request for <paramref name="host"/>: "A" or "B".</summary>
        public async Task<string> BackendForAsync(string host)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}/hello"));
            request.Headers.Host = host;
            using var response = await Public.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend;
        }
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        return gateway;
    }

    private static Dictionary<string, string> TargetFields(long version, string name, string address, params (string Label, int Port)[] ports)
    {
        var fields = new Dictionary<string, string>
        {
            ["Model.BaseVersion"] = version.ToString(CultureInfo.InvariantCulture),
            ["Model.IsNew"] = "true",
            ["Model.Name"] = name,
            ["Model.Address"] = address,
        };
        for (var i = 0; i < ports.Length; i++)
        {
            fields[$"Model.Ports[{i}].Name"] = ports[i].Label;
            fields[$"Model.Ports[{i}].Port"] = ports[i].Port.ToString(CultureInfo.InvariantCulture);
        }

        return fields;
    }

    [Fact]
    public async Task Routes_forward_to_the_target_and_follow_a_change_made_in_one_place()
    {
        await using var gateway = await StartAsync();
        Assert.Equal("A", await gateway.BackendForAsync("site.example.com"));
        Assert.Equal("A", await gateway.BackendForAsync("shop.example.com"));

        // The label "web" now points to backend B's port: both routes follow, without a restart.
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Targets[0].Ports[0].Port = gateway.B.Port;
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        Assert.Equal("B", await gateway.BackendForAsync("site.example.com"));
        Assert.Equal("B", await gateway.BackendForAsync("shop.example.com"));
    }

    [Fact]
    public async Task The_request_log_names_the_target_and_its_address()
    {
        await using var gateway = await StartAsync();
        await gateway.BackendForAsync("site.example.com");

        var monitor = gateway.App.Services.GetRequiredService<IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (monitor.Statistics!.Written < 1)
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out waiting for the request log.");
            await Task.Delay(50, Ct);
        }

        var options = new DbContextOptionsBuilder<EventDbContext>()
            .UseSqlite(SqliteRequestLogStore.ConnectionString(new StoragePaths(gateway.DataDirectory, gateway.DataDirectory)))
            .Options;
        await using var db = new EventDbContext(options);
        var entry = await db.RequestEvents.AsNoTracking().SingleAsync(Ct);
        SqliteConnection.ClearAllPools();

        Assert.Equal($"lab · web (http://127.0.0.1:{gateway.A.Port}/)", entry.Destination);
    }

    [Fact]
    public async Task Targets_are_added_used_by_a_route_and_protected_against_deletion_in_the_admin_ui()
    {
        await using var gateway = await StartAsync();

        // Add a target: B under the label "web".
        var saved = await gateway.PostAsync("/targets/new", "target-edit", TargetFields(1, "backend-b", "127.0.0.1", ("web", gateway.B.Port)));
        Assert.Contains("Target &#x27;backend-b&#x27; added (version 2).", saved, StringComparison.Ordinal);
        Assert.Contains($"http://127.0.0.1:{gateway.B.Port}", saved, StringComparison.Ordinal);

        // The route editor offers it, and "Add" puts its line into the backends without saving.
        var editor = await gateway.GetPageAsync("/routes/site/edit");
        Assert.Contains($"<option value=\"backend-b/web\">backend-b · web (http://127.0.0.1:{gateway.B.Port})</option>", WebUtility.HtmlDecode(editor), StringComparison.Ordinal);
        var fields = AdminGateway.ScrapeForm(editor, "route-edit");
        Assert.Equal("lab/web", fields["Model.Destinations"]);
        fields["Model.Command"] = "add-target";
        fields["Model.AddTarget"] = "backend-b/web";
        var shown = await gateway.PostAsync("/routes/site/edit", "route-edit", fields);
        Assert.Contains("lab/web" + Environment.NewLine + "backend-b/web", WebUtility.HtmlDecode(shown), StringComparison.Ordinal);
        Assert.Equal(2, (await gateway.Store.GetLatestAsync(Ct))!.Version); // nothing saved

        // Save the route with only the new target.
        fields = AdminGateway.ScrapeForm(shown, "route-edit");
        fields.Remove("Model.Command");
        fields["Model.Destinations"] = "backend-b/web";
        fields["Model.BaseVersion"] = "2";
        await gateway.PostAsync("/routes/site/edit", "route-edit", fields);
        Assert.Equal("B", await gateway.BackendForAsync("site.example.com"));
        Assert.Equal("A", await gateway.BackendForAsync("shop.example.com"));

        // The list shows where routes go; a target in use cannot be deleted.
        var list = await gateway.GetPageAsync("/targets");
        Assert.Contains("site", list, StringComparison.Ordinal);
        var delete = await gateway.GetPageAsync("/targets/backend-b/delete");
        Assert.Contains("This target cannot be deleted yet", delete, StringComparison.Ordinal);
        Assert.Contains("Route &#x27;site&#x27; (port web)", delete, StringComparison.Ordinal);
        Assert.DoesNotContain("Delete target</button>", delete, StringComparison.Ordinal);

        var routes = await gateway.GetPageAsync("/routes");
        Assert.Contains($"backend-b · web (http://127.0.0.1:{gateway.B.Port})", WebUtility.HtmlDecode(routes), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_route_to_an_unknown_target_is_refused_with_a_plain_message()
    {
        await using var gateway = await StartAsync();
        var editor = await gateway.GetPageAsync("/routes/site/edit");
        var fields = AdminGateway.ScrapeForm(editor, "route-edit");
        fields["Model.Destinations"] = "lab/nothing";

        var page = WebUtility.HtmlDecode(await gateway.PostAsync("/routes/site/edit", "route-edit", fields));

        Assert.Contains("The route was not saved.", page, StringComparison.Ordinal);
        Assert.Contains("Route 'site': target 'lab' has no port 'nothing' (it has: web, alt).", page, StringComparison.Ordinal);
        Assert.Equal(1, (await gateway.Store.GetLatestAsync(Ct))!.Version);
    }

    [Fact]
    public async Task A_target_nobody_uses_is_deleted_and_audited()
    {
        await using var gateway = await StartAsync();
        await gateway.PostAsync("/targets/new", "target-edit", TargetFields(1, "spare", "10.0.0.9", ("web", 80)));

        var page = await gateway.PostAsync("/targets/spare/delete", "target-delete", new Dictionary<string, string> { ["BaseVersion"] = "2" });

        Assert.Contains("Target &#x27;spare&#x27; deleted (version 3).", page, StringComparison.Ordinal);
        Assert.Null(TargetResolver.Find((await gateway.Store.GetLatestAsync(Ct))!.Configuration.Targets, "spare"));
        var entry = Assert.Single((await gateway.AuditLog.ReadPageAsync(new AuditFilter { Version = 3 }, null, null, 10, Ct)).Items);
        Assert.Contains("Target 'spare' removed", entry.Details, StringComparison.Ordinal);
    }
}
