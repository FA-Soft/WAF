using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Waf.IntegrationTests;

public sealed class ListenerTests(GatewayFixture gateway) : IClassFixture<GatewayFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    [Fact]
    public async Task Admin_listener_answers_on_ipv4_loopback()
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/healthz"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Admin_listener_answers_on_ipv6_loopback()
    {
        Assert.SkipUnless(Socket.OSSupportsIPv6, "IPv6 is not available on this machine.");

        using var response = await _http.GetAsync(new Uri($"http://[::1]:{gateway.AdminPort}/healthz"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/")]
    public async Task Public_http_listener_does_not_expose_admin_endpoints(string path)
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Spoofed_host_header_on_public_listener_does_not_reach_admin()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}/healthz"));
        request.Headers.Host = $"localhost:{gateway.AdminPort}";

        using var response = await _http.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public void Admin_port_is_bound_to_loopback_only()
    {
        var addresses = gateway.App.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()?.Addresses ?? [];

        var admin = addresses.Select(a => new Uri(a)).Where(u => u.Port == gateway.AdminPort).ToList();

        Assert.NotEmpty(admin);
        Assert.All(admin, uri => Assert.True(IPAddress.IsLoopback(IPAddress.Parse(uri.Host.Trim('[', ']'))), uri.ToString()));
    }

    [Fact]
    public async Task Admin_port_refuses_connections_on_non_loopback_address()
    {
        var lanAddress = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));
        Assert.SkipWhen(lanAddress is null, "No non-loopback IPv4 address on this machine.");

        using var client = new TcpClient();
        var ex = await Assert.ThrowsAsync<SocketException>(
            () => client.ConnectAsync(lanAddress!, gateway.AdminPort, Ct).AsTask());

        Assert.Equal(SocketError.ConnectionRefused, ex.SocketErrorCode);
    }

    [Fact]
    public async Task Https_listener_rejects_handshake_without_certificate()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, gateway.HttpsPort, Ct);
        await using var tls = new SslStream(client.GetStream());

        // The server has no certificate to offer, so it aborts the handshake before any
        // certificate validation happens on the client side.
        await Assert.ThrowsAnyAsync<IOException>(() => tls.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions { TargetHost = "example.test" }, Ct));
    }

    [Fact]
    public async Task Server_header_is_not_sent()
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/healthz"), Ct);

        Assert.Empty(response.Headers.Server);
    }
}
