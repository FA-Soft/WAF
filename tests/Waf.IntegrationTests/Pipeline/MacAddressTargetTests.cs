using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using FASoft.Waf.Data;
using FASoft.Waf.Host.Hosting.Neighbors;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// Targets with a MAC address on a running gateway, with a neighbour table the test controls: routes follow the device's
/// address without new configuration versions, and a device that is gone gets no traffic.
/// </summary>
public sealed class MacAddressTargetTests
{
    private const string Mac = "aa:bb:cc:dd:ee:01";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The neighbour table the gateway reads in these tests.</summary>
    private sealed class FakeNeighbors : INeighborTable
    {
        private readonly Lock _lock = new();
        private List<NeighborEntry> _entries = [];

        public int Probes { get; private set; }

        public int Sweeps { get; private set; }

        public void Set(params NeighborEntry[] entries)
        {
            lock (_lock)
            {
                _entries = [.. entries];
            }
        }

        public Task<IReadOnlyList<NeighborEntry>> ReadAsync(CancellationToken cancellationToken)
        {
            lock (_lock)
            {
                return Task.FromResult<IReadOnlyList<NeighborEntry>>([.. _entries]);
            }
        }

        public Task ProbeAsync(IEnumerable<IPAddress> addresses, CancellationToken cancellationToken)
        {
            Probes++;
            return Task.CompletedTask;
        }

        public Task SweepAsync(CancellationToken cancellationToken)
        {
            Sweeps++;
            return Task.CompletedTask;
        }
    }

    /// <summary>Target "lab", known only by its MAC address, with port "web" on backend A's port; route "site" uses it.</summary>
    private sealed class Gateway : AdminGateway
    {
        public FakeNeighbors Neighbors { get; } = new();

        protected override IEnumerable<string> ExtraArgs =>
        [
            "--Gateway:Targets:0:Name=lab",
            $"--Gateway:Targets:0:MacAddress={Mac}",
            "--Gateway:Targets:0:Ports:0:Name=web",
            $"--Gateway:Targets:0:Ports:0:Port={A.Port.ToString(CultureInfo.InvariantCulture)}",
            "--Gateway:Routes:0:Name=site",
            "--Gateway:Routes:0:Match:Hosts:0=site.example.com",
            "--Gateway:Routes:0:Destinations:0:Target=lab",
            "--Gateway:Routes:0:Destinations:0:TargetPort=web",
            // The test runs the rounds itself, with short waits.
            "--Gateway:TargetResolver:Enabled=false",
            "--Gateway:TargetResolver:ProbeWait=00:00:00.010",
            "--Gateway:TargetResolver:GracePeriod=00:00:01",
            "--Gateway:TargetResolver:SweepInterval=00:00:00",
        ];

        protected override void ConfigureServices(IServiceCollection services) => services.AddSingleton<INeighborTable>(Neighbors);

        public TargetAddressBook Book => App.Services.GetRequiredService<TargetAddressBook>();

        /// <summary>One round of the resolver, with every target due.</summary>
        public async Task ResolveAsync()
        {
            Book.MakeAllDue();
            await App.Services.GetServices<IHostedService>().OfType<TargetAddressResolver>().Single().RunOnceAsync(Ct);
        }

        public async Task<HttpResponseMessage> SiteAsync()
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}/hello"));
            request.Headers.Host = "site.example.com";
            return await Public.SendAsync(request, Ct);
        }
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        return gateway;
    }

    private static async Task<List<AuditEntry>> AuditAsync(Gateway gateway, string action) =>
        [.. (await gateway.AuditLog.ReadPageAsync(new AuditFilter(), null, null, AuditLogStore.MaxPageSize, Ct)).Items.Where(e => e.Action == action)];

    [Fact]
    public async Task Routes_follow_the_device_and_get_no_traffic_once_it_is_gone()
    {
        await using var gateway = await StartAsync();

        // Not looked up yet and no configured address: nowhere to send it.
        using (var before = await gateway.SiteAsync())
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, before.StatusCode);
        }

        // Found: the route forwards to it, without a new configuration version.
        gateway.Neighbors.Set(new NeighborEntry(IPAddress.Loopback, Mac, NeighborState.Reachable));
        await gateway.ResolveAsync();
        using (var found = await gateway.SiteAsync())
        {
            Assert.Equal(HttpStatusCode.OK, found.StatusCode);
            Assert.Equal("A", (await found.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend);
        }

        Assert.Equal(1, (await gateway.Store.GetLatestAsync(Ct))!.Version);
        var moved = Assert.Single(await AuditAsync(gateway, AuditActions.TargetAddressChanged));
        Assert.Equal($"Target 'lab' ({Mac}) is at 127.0.0.1.", moved.Summary);
        var targets = await gateway.GetPageAsync("/targets");
        Assert.Contains($"MAC {Mac}", targets, StringComparison.Ordinal);
        Assert.Contains("127.0.0.1", targets, StringComparison.Ordinal);

        // Only a stale entry: the resolver contacts it to confirm, and keeps the address.
        gateway.Neighbors.Set(new NeighborEntry(IPAddress.Loopback, Mac, NeighborState.Stale));
        await gateway.ResolveAsync();
        Assert.True(gateway.Neighbors.Probes > 0);

        // Gone: after the grace period (1 s here), and a sweep of the network that finds nothing, no more traffic.
        gateway.Neighbors.Set();
        await Task.Delay(1100, Ct);
        await gateway.ResolveAsync();
        Assert.True(gateway.Neighbors.Sweeps > 0);
        using (var gone = await gateway.SiteAsync())
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, gone.StatusCode);
        }

        Assert.Single(await AuditAsync(gateway, AuditActions.TargetUnavailable));
        Assert.Contains("Target 'lab' is not found", WebUtility.HtmlDecode(await gateway.GetPageAsync("/")), StringComparison.Ordinal);
        Assert.Contains("Not found: no traffic", await gateway.GetPageAsync("/targets"), StringComparison.Ordinal);
        Assert.Equal(1, (await gateway.Store.GetLatestAsync(Ct))!.Version);

        // Back again.
        gateway.Neighbors.Set(new NeighborEntry(IPAddress.Loopback, Mac, NeighborState.Reachable));
        await gateway.ResolveAsync();
        using var back = await gateway.SiteAsync();
        Assert.Equal(HttpStatusCode.OK, back.StatusCode);
    }

    [Fact]
    public async Task The_editor_looks_up_the_mac_address_of_an_ip_address()
    {
        await using var gateway = await StartAsync();
        gateway.Neighbors.Set(new NeighborEntry(IPAddress.Parse("192.168.1.20"), "aa:bb:cc:dd:ee:20", NeighborState.Reachable));

        var page = WebUtility.HtmlDecode(await gateway.PostAsync("/targets/new", "target-edit", new Dictionary<string, string>
        {
            ["Model.BaseVersion"] = "1",
            ["Model.IsNew"] = "true",
            ["Model.Name"] = "nas",
            ["Model.Address"] = "192.168.1.20",
            ["Model.Command"] = "lookup-mac",
            ["Model.Ports[0].Name"] = "web",
            ["Model.Ports[0].Port"] = "5000",
        }));

        Assert.Contains("192.168.1.20 answers with MAC address aa:bb:cc:dd:ee:20.", page, StringComparison.Ordinal);
        Assert.Contains("value=\"aa:bb:cc:dd:ee:20\"", page, StringComparison.Ordinal);
        Assert.Equal(1, (await gateway.Store.GetLatestAsync(Ct))!.Version); // nothing saved

        var unknown = WebUtility.HtmlDecode(await gateway.PostAsync("/targets/new", "target-edit", new Dictionary<string, string>
        {
            ["Model.BaseVersion"] = "1",
            ["Model.IsNew"] = "true",
            ["Model.Name"] = "nas",
            ["Model.Address"] = "192.168.1.99",
            ["Model.Command"] = "lookup-mac",
        }));
        Assert.Contains("192.168.1.99 did not answer, or is not on the gateway's own network", unknown, StringComparison.Ordinal);
    }
}
