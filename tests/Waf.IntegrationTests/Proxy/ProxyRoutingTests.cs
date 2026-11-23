using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;

namespace FASoft.Waf.IntegrationTests.Proxy;

public sealed class ProxyRoutingTests(ProxyFixture gateway) : IClassFixture<ProxyFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    private async Task<HttpResponseMessage> SendAsync(string host, string path, HttpMethod? method = null, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
        request.Headers.Host = host;
        configure?.Invoke(request);
        return await _http.SendAsync(request, Ct);
    }

    private async Task<BackendEcho> EchoAsync(string host, string path, HttpMethod? method = null, Action<HttpRequestMessage>? configure = null)
    {
        using var response = await SendAsync(host, path, method, configure);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!;
    }

    [Fact]
    public async Task Requests_are_routed_by_host_to_different_backends()
    {
        Assert.Equal("A", (await EchoAsync("a.test", "/hello")).Backend);
        Assert.Equal("B", (await EchoAsync("b.test", "/hello")).Backend);
    }

    [Theory]
    [InlineData("/", "A")]
    [InlineData("/products/1", "A")]
    [InlineData("/apix", "A")]
    [InlineData("/api", "B")]
    [InlineData("/api/orders/7", "B")]
    public async Task Path_prefix_selects_the_more_specific_route(string path, string expectedBackend)
    {
        var echo = await EchoAsync("site.test", path);

        Assert.Equal(expectedBackend, echo.Backend);
        Assert.Equal(path, echo.Path);
    }

    [Fact]
    public async Task Method_condition_is_enforced()
    {
        Assert.Equal("POST", (await EchoAsync("post.test", "/submit", HttpMethod.Post)).Method);

        using var get = await SendAsync("post.test", "/submit");
        Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
    }

    [Fact]
    public async Task Unmatched_host_returns_404()
    {
        using var response = await SendAsync("unknown.test", "/");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Forwarded_headers_are_set_and_client_values_overwritten()
    {
        var echo = await EchoAsync("a.test", "/", configure: request =>
        {
            request.Headers.Add("X-Forwarded-For", "6.6.6.6");
            request.Headers.Add("X-Forwarded-Host", "evil.test");
            request.Headers.Add("Forwarded", "for=6.6.6.6");
        });

        Assert.Equal("127.0.0.1", echo.XForwardedFor);
        Assert.Equal("http", echo.XForwardedProto);
        Assert.Equal("a.test", echo.XForwardedHost);
        Assert.Null(echo.Forwarded);
    }

    [Fact]
    public async Task Original_host_is_preserved_by_default()
    {
        Assert.Equal("a.test", (await EchoAsync("a.test", "/")).Host);
    }

    [Fact]
    public async Task Backend_address_is_sent_as_host_when_preserve_host_is_off()
    {
        Assert.Equal($"127.0.0.1:{gateway.A.Port}", (await EchoAsync("rewrite.test", "/")).Host);
    }

    [Fact]
    public async Task WebSockets_are_proxied()
    {
        using var socket = new ClientWebSocket();
        await socket.ConnectAsync(new Uri($"ws://127.0.0.1:{gateway.HttpPort}/ws"), Ct);

        await socket.SendAsync(Encoding.UTF8.GetBytes("ping"), WebSocketMessageType.Text, endOfMessage: true, Ct);
        var buffer = new byte[256];
        var result = await socket.ReceiveAsync(buffer, Ct);

        Assert.Equal("A:ping", Encoding.UTF8.GetString(buffer, 0, result.Count));
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", Ct);
    }

    [Fact]
    public async Task Https_backend_with_self_signed_certificate_works_when_allowed()
    {
        Assert.Equal("TLS", (await EchoAsync("tls.test", "/")).Backend);
    }

    [Fact]
    public async Task Https_backend_with_untrusted_certificate_is_rejected_by_default()
    {
        using var response = await SendAsync("tls-strict.test", "/");

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task Unreachable_backend_returns_a_gateway_error()
    {
        using var response = await SendAsync("down.test", "/");

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable });
    }

    [Fact]
    public async Task Active_health_check_takes_a_dead_destination_out_of_rotation()
    {
        // Probes run every second; a destination is unhealthy after consecutive failed probes.
        var deadline = DateTime.UtcNow.AddSeconds(20);
        var consecutiveSuccesses = 0;
        while (consecutiveSuccesses < 20)
        {
            Assert.True(DateTime.UtcNow < deadline, "The dead destination was not taken out of rotation in time.");

            using var response = await SendAsync("lb.test", "/");
            if (response.StatusCode == HttpStatusCode.OK)
            {
                consecutiveSuccesses++;
            }
            else
            {
                consecutiveSuccesses = 0;
                await Task.Delay(250, Ct);
            }
        }
    }
}
