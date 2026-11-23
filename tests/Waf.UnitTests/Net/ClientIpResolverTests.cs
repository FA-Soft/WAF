using System.Net;
using FASoft.Waf.Core.Net;

namespace FASoft.Waf.UnitTests.Net;

public class ClientIpResolverTests
{
    private static readonly TrustedProxies Proxies = TrustedProxies.Parse(["10.0.0.0/24", "fd00::/8"]);

    private static ClientIpResolution Resolve(string connectionIp, params string?[] forwardedFor) =>
        ClientIpResolver.Resolve(IPAddress.Parse(connectionIp), forwardedFor, Proxies);

    [Fact]
    public void Without_header_the_connection_ip_is_the_client()
    {
        var result = Resolve("203.0.113.7");

        Assert.Equal(IPAddress.Parse("203.0.113.7"), result.ClientIp);
        Assert.False(result.ViaTrustedProxy);
    }

    [Theory]
    [InlineData("6.6.6.6")]
    [InlineData("6.6.6.6, 10.0.0.1")]
    [InlineData("127.0.0.1")]
    public void Header_from_an_untrusted_connection_is_ignored(string spoofed)
    {
        var result = Resolve("198.51.100.20", spoofed);

        Assert.Equal(IPAddress.Parse("198.51.100.20"), result.ClientIp);
        Assert.False(result.ViaTrustedProxy);
    }

    [Fact]
    public void No_trusted_proxies_means_the_header_is_always_ignored()
    {
        var result = ClientIpResolver.Resolve(IPAddress.Parse("10.0.0.1"), ["203.0.113.7"], TrustedProxies.None);

        Assert.Equal(IPAddress.Parse("10.0.0.1"), result.ClientIp);
    }

    [Fact]
    public void Trusted_proxy_supplies_the_client_ip()
    {
        var result = Resolve("10.0.0.1", "203.0.113.7");

        Assert.Equal(IPAddress.Parse("203.0.113.7"), result.ClientIp);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), result.ConnectionIp);
        Assert.True(result.ViaTrustedProxy);
    }

    [Fact]
    public void Chain_of_trusted_proxies_is_followed()
    {
        // client -> 10.0.0.2 -> 10.0.0.1 -> gateway
        Assert.Equal(IPAddress.Parse("203.0.113.7"), Resolve("10.0.0.1", "203.0.113.7, 10.0.0.2").ClientIp);
    }

    [Fact]
    public void Spoofed_entries_left_of_the_real_client_are_ignored()
    {
        // The client sent "X-Forwarded-For: 1.1.1.1"; the trusted proxy appended the real client address.
        Assert.Equal(IPAddress.Parse("203.0.113.7"), Resolve("10.0.0.1", "1.1.1.1, 203.0.113.7").ClientIp);
    }

    [Fact]
    public void Client_cannot_pretend_to_be_a_trusted_proxy_further_left()
    {
        // 198.51.100.9 is not trusted, so whatever it claims (10.0.0.5, 1.1.1.1) is ignored.
        Assert.Equal(IPAddress.Parse("198.51.100.9"), Resolve("10.0.0.1", "1.1.1.1, 10.0.0.5, 198.51.100.9").ClientIp);
    }

    [Fact]
    public void Multiple_header_lines_are_combined_in_order()
    {
        Assert.Equal(IPAddress.Parse("203.0.113.7"), Resolve("10.0.0.1", "1.1.1.1", "203.0.113.7").ClientIp);
    }

    [Fact]
    public void When_every_hop_is_trusted_the_leftmost_is_the_client()
    {
        Assert.Equal(IPAddress.Parse("10.0.0.9"), Resolve("10.0.0.1", "10.0.0.9, 10.0.0.2").ClientIp);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("_hidden")]
    [InlineData("10")]
    [InlineData("")]
    public void Invalid_rightmost_entry_falls_back_to_the_proxy(string entry)
    {
        var result = Resolve("10.0.0.1", entry);

        Assert.Equal(IPAddress.Parse("10.0.0.1"), result.ClientIp);
        Assert.True(result.IgnoredInvalidEntry);
    }

    [Fact]
    public void Invalid_entry_deeper_in_the_chain_stops_at_the_last_valid_hop()
    {
        var result = Resolve("10.0.0.1", "203.0.113.7, garbage, 10.0.0.2");

        Assert.Equal(IPAddress.Parse("10.0.0.2"), result.ClientIp);
        Assert.True(result.IgnoredInvalidEntry);
    }

    [Theory]
    [InlineData("203.0.113.7:4711", "203.0.113.7")]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("[2001:db8::1]", "2001:db8::1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    public void Entry_formats_are_understood(string entry, string expected)
    {
        Assert.Equal(IPAddress.Parse(expected), Resolve("10.0.0.1", entry).ClientIp);
    }

    [Theory]
    [InlineData("203.0.113.7:")]
    [InlineData("203.0.113.7:99999")]
    [InlineData("[2001:db8::1")]
    [InlineData("[2001:db8::1]x")]
    [InlineData("1.2.3.4:80:80")]
    public void Malformed_ports_and_brackets_are_rejected(string entry)
    {
        Assert.False(ClientIpResolver.TryParseEntry(entry, out _));
    }

    [Fact]
    public void Ipv6_proxies_and_clients_are_supported()
    {
        Assert.Equal(IPAddress.Parse("2001:db8::5"), Resolve("fd00::1", "2001:db8::5").ClientIp);
    }

    [Fact]
    public void Ipv4_mapped_connection_address_matches_an_ipv4_trusted_proxy()
    {
        // Dual-mode (IPv6) listeners report IPv4 peers as ::ffff:a.b.c.d.
        var result = Resolve("::ffff:10.0.0.1", "203.0.113.7");

        Assert.Equal(IPAddress.Parse("203.0.113.7"), result.ClientIp);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), result.ConnectionIp);
    }

    [Fact]
    public void Ipv4_mapped_untrusted_connection_is_normalized()
    {
        Assert.Equal(IPAddress.Parse("198.51.100.20"), Resolve("::ffff:198.51.100.20").ClientIp);
    }

    [Fact]
    public void Number_of_examined_entries_is_bounded()
    {
        var hops = string.Join(", ", Enumerable.Repeat("10.0.0.2", 100));

        var result = Resolve("10.0.0.1", "203.0.113.7, " + hops);

        // Stops after MaxEntries trusted hops instead of walking an arbitrarily long header.
        Assert.Equal(IPAddress.Parse("10.0.0.2"), result.ClientIp);
    }
}
