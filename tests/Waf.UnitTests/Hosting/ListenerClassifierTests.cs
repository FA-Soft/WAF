using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Waf.Core.Hosting;
using Waf.Host.Hosting;

namespace Waf.UnitTests.Hosting;

public class ListenerClassifierTests
{
    private readonly ListenerClassifier _classifier =
        new(Options.Create(new GatewayEndpointOptions { AdminPort = 8900 }));

    private static DefaultHttpContext Request(string localAddress, int localPort, string? host = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalIpAddress = IPAddress.Parse(localAddress);
        context.Connection.LocalPort = localPort;
        if (host is not null)
        {
            context.Request.Host = new HostString(host);
        }

        return context;
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public void Loopback_on_admin_port_is_admin(string address)
    {
        Assert.True(_classifier.IsAdminListener(Request(address, 8900)));
    }

    [Theory]
    [InlineData("127.0.0.1", 80)]
    [InlineData("127.0.0.1", 443)]
    [InlineData("192.168.1.10", 8900)]
    [InlineData("::ffff:192.168.1.10", 8900)]
    public void Anything_else_is_public(string address, int port)
    {
        Assert.False(_classifier.IsAdminListener(Request(address, port)));
    }

    [Fact]
    public void Host_header_cannot_select_the_admin_pipeline()
    {
        Assert.False(_classifier.IsAdminListener(Request("127.0.0.1", 80, host: "localhost:8900")));
    }
}
