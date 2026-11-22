using System.Net.Http.Json;

namespace Waf.IntegrationTests.Proxy;

/// <summary>
/// Gateway that trusts 127.0.0.1 as a proxy (the test client connects from there) and proxies
/// everything to one backend, which reports the X-Forwarded-For it received.
/// </summary>
public sealed class TrustedProxyFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs =>
    [
        "--Gateway:Settings:TrustedProxies:0=127.0.0.1",
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

public sealed class ClientIpTests(TrustedProxyFixture gateway) : IClassFixture<TrustedProxyFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    private async Task<BackendEcho> SendAsync(params string[] forwardedFor)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}/"));
        foreach (var value in forwardedFor)
        {
            request.Headers.Add("X-Forwarded-For", value);
        }

        using var response = await _http.SendAsync(request, Ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!;
    }

    [Fact]
    public async Task Without_header_the_connection_ip_is_forwarded()
    {
        Assert.Equal("127.0.0.1", (await SendAsync()).XForwardedFor);
    }

    [Fact]
    public async Task Client_ip_reported_by_a_trusted_proxy_is_forwarded()
    {
        Assert.Equal("203.0.113.7", (await SendAsync("203.0.113.7")).XForwardedFor);
    }

    [Fact]
    public async Task Spoofed_entries_before_the_real_client_are_dropped()
    {
        Assert.Equal("203.0.113.7", (await SendAsync("6.6.6.6, 203.0.113.7")).XForwardedFor);
    }

    [Fact]
    public async Task Ipv6_client_ip_is_forwarded()
    {
        Assert.Equal("2001:db8::5", (await SendAsync("2001:db8::5")).XForwardedFor);
    }

    [Fact]
    public async Task Invalid_entry_falls_back_to_the_proxy_address()
    {
        Assert.Equal("127.0.0.1", (await SendAsync("unknown")).XForwardedFor);
    }
}
