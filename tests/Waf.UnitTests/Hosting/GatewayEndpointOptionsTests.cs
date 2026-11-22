using Waf.Core.Hosting;

namespace Waf.UnitTests.Hosting;

public class GatewayEndpointOptionsTests
{
    [Fact]
    public void Defaults_are_valid_and_match_documented_ports()
    {
        var options = new GatewayEndpointOptions();

        Assert.Empty(options.Validate());
        Assert.Equal(80, options.HttpPort);
        Assert.Equal(443, options.HttpsPort);
        Assert.Equal(8900, options.AdminPort);
        Assert.Equal("*", options.PublicBindAddress);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Out_of_range_port_is_rejected(int port)
    {
        var options = new GatewayEndpointOptions { HttpPort = port };

        Assert.Contains(options.Validate(), e => e.Contains("HttpPort must be between 1 and 65535", StringComparison.Ordinal));
    }

    [Fact]
    public void Http_and_https_ports_must_differ()
    {
        var options = new GatewayEndpointOptions { HttpPort = 8443, HttpsPort = 8443 };

        Assert.Contains(options.Validate(), e => e.Contains("must be different", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(80)]
    [InlineData(443)]
    public void Admin_port_must_differ_from_public_ports(int adminPort)
    {
        var options = new GatewayEndpointOptions { AdminPort = adminPort };

        Assert.Contains(options.Validate(), e => e.Contains("AdminPort", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("*")]
    [InlineData("0.0.0.0")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.10")]
    [InlineData("::")]
    [InlineData("fd00::10")]
    public void Valid_bind_addresses_are_accepted(string address)
    {
        Assert.Empty(new GatewayEndpointOptions { PublicBindAddress = address }.Validate());
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("300.1.1.1")]
    [InlineData("10")]
    [InlineData("0x0A000001")]
    public void Invalid_bind_addresses_are_rejected(string address)
    {
        Assert.Contains(
            new GatewayEndpointOptions { PublicBindAddress = address }.Validate(),
            e => e.Contains("PublicBindAddress", StringComparison.Ordinal));
    }
}
