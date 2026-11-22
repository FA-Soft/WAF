using System.Net;
using Waf.Core.Net;

namespace Waf.UnitTests.Net;

public class StrictIpAddressTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.10")]
    [InlineData("255.255.255.255")]
    [InlineData("127.0.0.1")]
    public void Dotted_decimal_ipv4_is_accepted(string text)
    {
        Assert.True(StrictIpAddress.TryParse(text, out var address));
        Assert.Equal(IPAddress.Parse(text), address);
    }

    [Theory]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fd00::10")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:10.0.0.5")]
    [InlineData("fe80::1%12")]
    public void Ipv6_is_accepted(string text)
    {
        Assert.True(StrictIpAddress.TryParse(text, out var address));
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, address.AddressFamily);
    }

    [Theory]
    [InlineData("10")]            // legacy shorthand for 0.0.0.10
    [InlineData("1.2")]           // legacy shorthand for 1.0.0.2
    [InlineData("10.1.2")]        // legacy shorthand for 10.1.0.2
    [InlineData("0x0A000001")]    // hexadecimal
    [InlineData("0x0A.0.0.1")]    // hexadecimal part
    [InlineData("010.0.0.1")]     // leading zero (octal in some parsers)
    [InlineData("256.0.0.1")]
    [InlineData("1.2.3.4.5")]
    [InlineData("1..2.3")]
    [InlineData("1.2.3.")]
    [InlineData(" 10.0.0.5")]
    [InlineData("10.0.0.5 ")]
    [InlineData("+1.2.3.4")]
    [InlineData("[::1]")]
    [InlineData("localhost")]
    [InlineData("")]
    [InlineData(null)]
    public void Ambiguous_or_invalid_input_is_rejected(string? text)
    {
        Assert.False(StrictIpAddress.TryParse(text, out var address));
        Assert.Null(address);
    }
}
