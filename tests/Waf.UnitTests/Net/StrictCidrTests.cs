using Waf.Core.Net;

namespace Waf.UnitTests.Net;

public class StrictCidrTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData("192.168.1.0/24", "192.168.1.0/24")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    [InlineData("10.0.0.5", "10.0.0.5/32")]
    [InlineData("10.0.0.5/32", "10.0.0.5/32")]
    [InlineData("fd00::/8", "fd00::/8")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    [InlineData("::1", "::1/128")]
    public void Valid_ranges_are_parsed(string text, string expected)
    {
        Assert.True(StrictCidr.TryParse(text, out var network));
        Assert.Equal(expected, network.ToString());
    }

    [Theory]
    [InlineData("10.0.0.5/8", "host bits are set (did you mean 10.0.0.0/8 or 10.0.0.5/32?)")]
    [InlineData("10.0.0.0/33", "the prefix length must be a number from 0 to 32")]
    [InlineData("fd00::/129", "the prefix length must be a number from 0 to 128")]
    [InlineData("10.0.0.0/", "the prefix length must be a number from 0 to 32")]
    [InlineData("10.0.0.0/08", "the prefix length must be a number from 0 to 32")]
    [InlineData("10.0.0.0/-1", "the prefix length must be a number from 0 to 32")]
    [InlineData("10/8", "'10' is not a valid IP address")]
    [InlineData("10.0.0.0/8/8", "the prefix length must be a number from 0 to 32")]
    [InlineData("", "an address or range is required")]
    public void Invalid_ranges_are_rejected_with_a_reason(string text, string reason)
    {
        Assert.False(StrictCidr.TryParse(text, out _, out var error));
        Assert.Equal(reason, error);
    }
}
