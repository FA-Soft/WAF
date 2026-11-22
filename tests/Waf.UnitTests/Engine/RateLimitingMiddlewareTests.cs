using System.Net;
using Microsoft.AspNetCore.Http;
using Waf.Core.Configuration;
using Waf.Engine;
using Waf.Engine.RateLimiting;
using Waf.Proxy;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Engine;

public class RateLimitingMiddlewareTests
{
    private sealed class CapturingSink : IWafEventSink
    {
        public List<WafEvent> Events { get; } = [];

        public void Publish(WafEvent wafEvent) => Events.Add(wafEvent);
    }

    private readonly CapturingSink _events = new();
    private readonly ManualTimeProvider _time = new();
    private int _nextCalls;

    private RateLimitingMiddleware Middleware(bool detectionOnly = false)
    {
        var configuration = Config();
        configuration.RateLimits.Add(new RateLimitRule { Name = "per-ip", PermitLimit = 1, WindowSeconds = 60, DetectionOnly = detectionOnly });
        return new RateLimitingMiddleware(_ => { _nextCalls++; return Task.CompletedTask; }, new RateLimiter(configuration, _time), _events, _time);
    }

    private static DefaultHttpContext Request()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        context.Request.Method = "POST";
        context.Request.Host = new HostString("www.example.com");
        context.Request.Path = "/login";
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Fact]
    public async Task Request_over_the_limit_gets_429_with_retry_after_and_an_event()
    {
        var middleware = Middleware();
        await middleware.InvokeAsync(Request());

        var limited = Request();
        await middleware.InvokeAsync(limited);

        Assert.Equal(1, _nextCalls);
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.Response.StatusCode);
        Assert.Equal("60", limited.Response.Headers.RetryAfter.ToString());
        limited.Response.Body.Position = 0;
        Assert.Equal("Too many requests. Please slow down.", await new StreamReader(limited.Response.Body).ReadToEndAsync(TestContext.Current.CancellationToken));

        var wafEvent = Assert.Single(_events.Events);
        Assert.Equal(WafEventKind.RateLimited, wafEvent.Kind);
        Assert.Equal("per-ip", wafEvent.RuleName);
        Assert.Equal(IPAddress.Parse("198.51.100.7"), wafEvent.ClientIp);
        Assert.Equal(("POST", "www.example.com", "/login", 429), (wafEvent.Method, wafEvent.Host, wafEvent.Path, wafEvent.StatusCode));
        Assert.Equal(_time.Now, wafEvent.Timestamp);
    }

    [Fact]
    public async Task Detection_only_passes_the_request_and_reports_it()
    {
        var middleware = Middleware(detectionOnly: true);
        await middleware.InvokeAsync(Request());

        var detected = Request();
        await middleware.InvokeAsync(detected);

        Assert.Equal(2, _nextCalls);
        Assert.Equal(StatusCodes.Status200OK, detected.Response.StatusCode);
        Assert.Equal(WafEventKind.RateLimitDetected, Assert.Single(_events.Events).Kind);
    }
}
