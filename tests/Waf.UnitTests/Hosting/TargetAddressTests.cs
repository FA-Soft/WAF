using System.Buffers.Binary;
using System.ComponentModel.DataAnnotations;
using System.Net;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Host.Hosting.Neighbors;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Hosting;

/// <summary>
/// Targets with a MAC address: reading the neighbour table on Linux and Windows, choosing the address, the grace period
/// before a target counts as unavailable, and how that reaches the routes.
/// </summary>
public sealed class TargetAddressTests
{
    private const string Mac = "aa:bb:cc:dd:ee:01";

    [Theory]
    [InlineData("AA:BB:CC:DD:EE:01")]
    [InlineData("aa-bb-cc-dd-ee-01")]
    [InlineData("aabb.ccdd.ee01")]
    [InlineData(" aabbccddee01 ")]
    public void Mac_addresses_are_read_in_the_usual_notations(string text)
    {
        Assert.True(MacAddress.TryNormalize(text, out var mac));
        Assert.Equal(Mac, mac);
    }

    [Theory]
    [InlineData("aa:bb:cc:dd:ee")]
    [InlineData("aa:bb-cc:dd:ee:01")]
    [InlineData("gg:bb:cc:dd:ee:01")]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("ff:ff:ff:ff:ff:ff")]
    [InlineData("")]
    public void Other_text_is_not_a_mac_address(string text)
    {
        Assert.False(MacAddress.TryNormalize(text, out _));
    }

    [Fact]
    public void Linux_ip_neigh_output_is_read_with_its_states()
    {
        const string Output = """
            192.168.1.20 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
            192.168.1.21 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE
            192.168.1.22 dev eth0 lladdr aa:bb:cc:dd:ee:03 DELAY
            192.168.1.23 dev eth0  FAILED
            192.168.1.24 dev eth0 lladdr aa:bb:cc:dd:ee:04 FAILED
            fd00::20 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE
            192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff PERMANENT
            """;

        var entries = SystemNeighborTable.ParseIpNeigh(Output);

        Assert.Equal(
            [("192.168.1.20", Mac, NeighborState.Reachable), ("192.168.1.21", "aa:bb:cc:dd:ee:02", NeighborState.Stale),
             ("192.168.1.22", "aa:bb:cc:dd:ee:03", NeighborState.Probing), ("fd00::20", Mac, NeighborState.Stale),
             ("192.168.1.1", "aa:bb:cc:dd:ee:ff", NeighborState.Reachable)],
            entries.Select(e => (e.Address.ToString(), e.MacAddress, e.State)));
    }

    [Fact]
    public void Linux_proc_net_arp_is_read_when_ip_is_missing()
    {
        const string Content = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.1.20     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
            192.168.1.23     0x1         0x0         00:00:00:00:00:00     *        eth0
            """;

        var entry = Assert.Single(SystemNeighborTable.ParseProcNetArp(Content));

        Assert.Equal(("192.168.1.20", Mac, NeighborState.Stale), (entry.Address.ToString(), entry.MacAddress, entry.State));
    }

    /// <summary>A MIB_IPNET_ROW2 as Windows lays it out: address, interface, MAC address, state.</summary>
    private static byte[] WindowsRow(IPAddress address, byte[] mac, int state)
    {
        var row = new byte[SystemNeighborTable.RowSize];
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(row, 2);
            address.GetAddressBytes().CopyTo(row, 4);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(row, 23);
            address.GetAddressBytes().CopyTo(row, 8);
        }

        mac.CopyTo(row, 40);
        BinaryPrimitives.WriteInt32LittleEndian(row.AsSpan(72), mac.Length);
        BinaryPrimitives.WriteInt32LittleEndian(row.AsSpan(76), state);
        return row;
    }

    [Fact]
    public void The_windows_table_is_read_with_its_states()
    {
        byte[] mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        byte[][] rows =
        [
            WindowsRow(IPAddress.Parse("192.168.1.20"), mac, 5),      // reachable
            WindowsRow(IPAddress.Parse("fd00::20"), mac, 4),          // stale
            WindowsRow(IPAddress.Parse("192.168.1.30"), mac, 1),      // incomplete: left out
            WindowsRow(IPAddress.Parse("192.168.1.31"), new byte[6], 5), // no MAC address: left out
        ];

        var entries = SystemNeighborTable.ParseWindowsRows([.. rows.SelectMany(r => r)], rows.Length);

        Assert.Equal(
            [("192.168.1.20", Mac, NeighborState.Reachable), ("fd00::20", Mac, NeighborState.Stale)],
            entries.Select(e => (e.Address.ToString(), e.MacAddress, e.State)));
    }

    [Fact]
    public async Task This_machines_table_can_be_read()
    {
        // Whatever is in it: every entry is well formed, and reading needs no privileges.
        var entries = await new SystemNeighborTable().ReadAsync(TestContext.Current.CancellationToken);

        Assert.All(entries, e => Assert.True(MacAddress.TryNormalize(e.MacAddress, out var mac) && mac == e.MacAddress));
    }

    [Fact]
    public void A_sweep_covers_small_local_networks_only()
    {
        var own = IPAddress.Parse("192.168.1.10");

        var addresses = SystemNeighborTable.SweepAddresses([(own, 24), (IPAddress.Parse("10.0.0.5"), 16), (IPAddress.Parse("169.254.3.4"), 24)]).ToList();

        Assert.Equal(253, addresses.Count); // .1 to .254 without the gateway's own address; the /16 and link-local are skipped
        Assert.DoesNotContain(own, addresses);
        Assert.Equal(IPAddress.Parse("192.168.1.1"), addresses[0]);
        Assert.Equal(IPAddress.Parse("192.168.1.254"), addresses[^1]);
    }

    [Fact]
    public void The_freshest_entry_wins_then_the_address_in_use_then_ipv4()
    {
        static NeighborEntry Entry(string address, NeighborState state, string mac = Mac) => new(IPAddress.Parse(address), mac, state);

        Assert.Equal("192.168.1.37", TargetAddressBook.Choose(
            [Entry("192.168.1.20", NeighborState.Stale), Entry("192.168.1.37", NeighborState.Reachable)], Mac, "192.168.1.20")!.Address.ToString());
        Assert.Equal("192.168.1.20", TargetAddressBook.Choose(
            [Entry("192.168.1.37", NeighborState.Stale), Entry("192.168.1.20", NeighborState.Stale)], Mac, "192.168.1.20")!.Address.ToString());
        Assert.Equal("192.168.1.20", TargetAddressBook.Choose(
            [Entry("fd00::20", NeighborState.Reachable), Entry("192.168.1.20", NeighborState.Reachable)], Mac, null)!.Address.ToString());
        Assert.Null(TargetAddressBook.Choose([Entry("fe80::1", NeighborState.Reachable), Entry("192.168.1.9", NeighborState.Reachable, "aa:bb:cc:dd:ee:09")], Mac, null));
    }

    private static BackendTarget Nas(string? mac = Mac, string address = "192.168.1.20") => new()
    {
        Name = "nas",
        Address = address,
        MacAddress = mac,
        Ports = { new TargetPort { Name = "web", Port = 5000 } },
    };

    [Fact]
    public void The_address_follows_the_device_and_a_lost_device_gets_no_traffic_after_the_grace_period()
    {
        var time = new ManualTimeProvider();
        var book = new TargetAddressBook(new FakeNeighbors(), new TargetResolverOptions { GracePeriod = TimeSpan.FromMinutes(10) }, time);
        var nas = Nas();
        book.Sync([nas]);

        Assert.Equal("192.168.1.20", book.CurrentAddress(nas)); // configured address until the first look-up
        Assert.Equal(TargetAddressChange.None, book.Record("nas", Mac, "192.168.1.20"));
        Assert.Equal(TargetAddressChange.Moved, book.Record("nas", Mac, "192.168.1.37"));
        Assert.Equal("192.168.1.37", book.CurrentAddress(nas));

        time.Advance(TimeSpan.FromMinutes(9));
        Assert.Equal(TargetAddressChange.None, book.Record("nas", Mac, null)); // not found, still within the grace period
        Assert.Equal("192.168.1.37", book.CurrentAddress(nas));

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(TargetAddressChange.Unavailable, book.Record("nas", Mac, null));
        Assert.Null(book.CurrentAddress(nas));
        Assert.False(Assert.Single(book.Statuses).Available);

        Assert.Equal(TargetAddressChange.Moved, book.Record("nas", Mac, "192.168.1.37")); // back
        Assert.Equal("192.168.1.37", book.CurrentAddress(nas));
        Assert.Equal("192.168.1.20", book.CurrentAddress(Nas(mac: null))); // an ordinary target: its own address
    }

    [Fact]
    public void Each_target_is_due_at_its_own_interval_and_removed_targets_are_forgotten()
    {
        var time = new ManualTimeProvider();
        var book = new TargetAddressBook(new FakeNeighbors(), new TargetResolverOptions(), time);
        var nas = Nas();
        nas.ResolveIntervalSeconds = 30;
        book.Sync([nas, Nas(mac: null)]);

        Assert.Single(book.Due()); // only the target with a MAC address
        book.Record("nas", Mac, "192.168.1.20");
        Assert.Empty(book.Due());
        time.Advance(TimeSpan.FromSeconds(30));
        Assert.Single(book.Due());

        book.Sync([]);
        Assert.Empty(book.Statuses);
    }

    [Fact]
    public void A_target_without_an_address_right_now_is_left_out_of_the_proxy()
    {
        var configuration = new GatewayConfiguration
        {
            Targets = { Nas(address: string.Empty) },
            Routes = { new ProxyRouteOptions { Name = "files", Destinations = { new ProxyDestinationOptions { Target = "nas", TargetPort = "web" } } } },
        };

        var routes = TargetResolver.Resolve(configuration, ConfiguredTargetAddresses.Instance);

        Assert.True(TargetResolver.IsUnresolved(routes[0].Destinations[0]));
        Assert.Empty(ProxyRouteValidator.Validate(routes)); // still a valid route
        var (_, clusters) = YarpConfigMapper.Map(routes);
        Assert.Empty(clusters[0].Destinations!); // no destination: the proxy answers 503
    }

    [Fact]
    public void A_target_needs_an_address_or_a_mac_address_and_the_interval_only_applies_with_one()
    {
        var withoutBoth = Nas(mac: null, address: string.Empty);
        var badMac = Nas(mac: "not-a-mac");
        var interval = Nas(mac: null);
        interval.ResolveIntervalSeconds = 30;
        var tooFast = Nas();
        tooFast.Name = "fast";
        tooFast.ResolveIntervalSeconds = 5;

        var errors = GatewayConfigurationValidator.Validate(new GatewayConfiguration { Targets = { withoutBoth } });
        Assert.Contains("Target 'nas': an address or a MAC address is required.", errors);
        Assert.Contains("Target 'nas': 'not-a-mac' is not a valid MAC address (use e.g. aa:bb:cc:dd:ee:ff).", GatewayConfigurationValidator.Validate(new GatewayConfiguration { Targets = { badMac } }));
        Assert.Contains("Target 'nas': 'ResolveIntervalSeconds' only applies with a MAC address.", GatewayConfigurationValidator.Validate(new GatewayConfiguration { Targets = { interval } }));
        Assert.Contains("Target 'fast': the MAC address look-up interval must be between 10 and 3600 seconds (was 5).", GatewayConfigurationValidator.Validate(new GatewayConfiguration { Targets = { tooFast } }));
        Assert.Empty(GatewayConfigurationValidator.Validate(new GatewayConfiguration { Targets = { Nas(address: string.Empty) } })); // MAC only is fine
    }

    [Fact]
    public void Targets_without_a_mac_address_keep_their_exact_json()
    {
        var json = GatewayConfigurationJson.Serialize(new GatewayConfiguration { Targets = { Nas(mac: null) } });

        Assert.DoesNotContain("MacAddress", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ResolveIntervalSeconds", json, StringComparison.Ordinal);
    }

    [Fact]
    public void The_target_form_normalizes_the_mac_address_and_needs_an_address_or_a_mac()
    {
        var form = new TargetFormModel { Name = "nas", MacAddress = "AA-BB-CC-DD-EE-01", ResolveIntervalSeconds = 30, Ports = [new TargetPortFormModel { Name = "web", Port = 5000 }] };

        var target = form.ToTarget();
        Assert.Equal((Mac, 30, string.Empty), (target.MacAddress, target.ResolveIntervalSeconds, target.Address));

        form.MacAddress = null;
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(form, new ValidationContext(form), results, validateAllProperties: true);
        Assert.Contains(results, r => r.ErrorMessage!.StartsWith("Enter the machine's IP address or host name", StringComparison.Ordinal));
        Assert.Null(form.ToTarget().ResolveIntervalSeconds); // no interval without a MAC address
    }

    /// <summary>A neighbour table for tests: entries set by the test; contacting and sweeping are counted.</summary>
    internal sealed class FakeNeighbors : INeighborTable
    {
        public List<NeighborEntry> Entries { get; } = [];

        public int Probes { get; private set; }

        public int Sweeps { get; private set; }

        public Task<IReadOnlyList<NeighborEntry>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<NeighborEntry>>([.. Entries]);

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
}
