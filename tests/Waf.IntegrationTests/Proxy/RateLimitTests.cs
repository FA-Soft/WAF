using System.Net;

namespace Waf.IntegrationTests.Proxy;

/// <summary>
/// Gateway with a per-client limit of 3 requests per minute. 127.0.0.1 is a trusted proxy, so each test
/// can act as a different client via X-Forwarded-For.
/// </summary>
public sealed class RateLimitFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs =>
    [
        "--Gateway:Settings:TrustedProxies:0=127.0.0.1",
        "--Gateway:RateLimits:0:Name=per-client",
        "--Gateway:RateLimits:0:PermitLimit=3",
        "--Gateway:RateLimits:0:WindowSeconds=60",
        .. new RouteArgs().Add("catch-all", [("http", _backend!.Port)]).ToArray(),
    ];

    protected override async ValueTask AfterStopAsync()
    {
        if (_backend is not null)
        {
            await _backend.DisposeAsync();
        }
    }
}

public sealed class RateLimitTests(RateLimitFixture gateway) : IClassFixture<RateLimitFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    private async Task<HttpResponseMessage> SendAsClientAsync(string clientIp, string path = "/")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
        request.Headers.Add("X-Forwarded-For", clientIp);
        return await _http.SendAsync(request, Ct);
    }

    [Fact]
    public async Task Fourth_request_within_a_minute_gets_429_with_retry_after()
    {
        for (var i = 0; i < 3; i++)
        {
            using var ok = await SendAsClientAsync("203.0.113.10");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var limited = await SendAsClientAsync("203.0.113.10");

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter?.Delta);
        Assert.InRange(limited.Headers.RetryAfter!.Delta!.Value.TotalSeconds, 1, 60);
        Assert.Equal("Too many requests. Please slow down.", await limited.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Other_clients_are_not_affected()
    {
        for (var i = 0; i < 5; i++)
        {
            (await SendAsClientAsync("203.0.113.20")).Dispose();
        }

        using var other = await SendAsClientAsync("203.0.113.21");

        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task Requests_to_any_path_count()
    {
        // Every request counts, whatever the path: scanners probing for files are limited too.
        for (var i = 0; i < 3; i++)
        {
            (await SendAsClientAsync("203.0.113.30", $"/probe-{i}")).Dispose();
        }

        using var limited = await SendAsClientAsync("203.0.113.30", "/probe-x");

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task Admin_listener_is_not_rate_limited()
    {
        for (var i = 0; i < 10; i++)
        {
            using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/healthz"), Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
