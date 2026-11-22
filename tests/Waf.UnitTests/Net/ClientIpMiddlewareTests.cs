using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Waf.Core.Net;
using Waf.Engine;
using Waf.Proxy;

namespace Waf.UnitTests.Net;

public class ClientIpMiddlewareTests
{
    private static async Task<HttpContext> RunAsync(string connectionIp, string? forwardedFor, params string[] trusted)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(connectionIp);
        if (forwardedFor is not null)
        {
            context.Request.Headers[ClientIpResolver.ForwardedForHeader] = forwardedFor;
        }

        var configuration = Waf.UnitTests.Engine.RuleBuilder.Config();
        foreach (var proxy in trusted)
        {
            configuration.Settings.TrustedProxies.Add(proxy);
        }

        var engines = new WafEngineHolder();
        engines.Activate(WafEngine.Build(configuration));

        var middleware = new ClientIpMiddleware(_ => Task.CompletedTask, engines, NullLogger<ClientIpMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        return context;
    }

    [Fact]
    public async Task Without_an_active_engine_nobody_is_trusted()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.1");
        context.Request.Headers[ClientIpResolver.ForwardedForHeader] = "203.0.113.7";

        await new ClientIpMiddleware(_ => Task.CompletedTask, new WafEngineHolder(), NullLogger<ClientIpMiddleware>.Instance).InvokeAsync(context);

        Assert.Equal(IPAddress.Parse("10.0.0.1"), context.Connection.RemoteIpAddress);
    }

    [Fact]
    public async Task Resolved_ip_replaces_remote_ip_and_feature_keeps_the_connection_ip()
    {
        var context = await RunAsync("10.0.0.1", "203.0.113.7", "10.0.0.1");

        Assert.Equal(IPAddress.Parse("203.0.113.7"), context.Connection.RemoteIpAddress);
        var feature = context.Features.Get<IClientIpFeature>();
        Assert.NotNull(feature);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), feature.ConnectionIp);
        Assert.True(feature.ViaTrustedProxy);
    }

    [Fact]
    public async Task Spoofed_header_from_untrusted_client_changes_nothing()
    {
        var context = await RunAsync("198.51.100.20", "6.6.6.6", "10.0.0.0/24");

        Assert.Equal(IPAddress.Parse("198.51.100.20"), context.Connection.RemoteIpAddress);
        Assert.False(context.Features.Get<IClientIpFeature>()!.ViaTrustedProxy);
    }

    [Fact]
    public async Task Ipv4_mapped_remote_ip_is_normalized()
    {
        var context = await RunAsync("::ffff:198.51.100.20", null);

        Assert.Equal(IPAddress.Parse("198.51.100.20"), context.Connection.RemoteIpAddress);
    }
}
