using System.Net;
using Waf.Core.Net;

namespace Waf.UnitTests.Net;

public class TrustedProxiesTests
{
    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.0.0.254", true)]
    [InlineData("10.0.1.1", false)]
    [InlineData("::ffff:10.0.0.7", true)]
    [InlineData("fd00::abcd", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("127.0.0.1", false)]
    public void Membership_is_checked_per_range(string address, bool expected)
    {
        var proxies = TrustedProxies.Parse(["10.0.0.0/24", "fd00::/8"]);

        Assert.Equal(expected, proxies.Contains(IPAddress.Parse(address)));
    }

    [Fact]
    public void Single_address_is_a_host_range()
    {
        var proxies = TrustedProxies.Parse(["192.168.1.10"]);

        Assert.True(proxies.Contains(IPAddress.Parse("192.168.1.10")));
        Assert.False(proxies.Contains(IPAddress.Parse("192.168.1.11")));
    }

    [Fact]
    public void Empty_list_trusts_nobody()
    {
        Assert.Same(TrustedProxies.None, TrustedProxies.Parse([]));
        Assert.False(TrustedProxies.None.Contains(IPAddress.Loopback));
    }

    [Fact]
    public void Invalid_entry_throws_with_reason()
    {
        var ex = Assert.Throws<ArgumentException>(() => TrustedProxies.Parse(["10.0.0.1/8"]));

        Assert.Contains("host bits are set", ex.Message, StringComparison.Ordinal);
    }
}
