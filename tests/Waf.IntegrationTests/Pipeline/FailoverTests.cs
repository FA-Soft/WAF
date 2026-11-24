using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// A route with a primary and a failover destination on a running gateway: the failover takes over when the primary
/// stops (at once when it refuses connections), traffic returns when it is back, and a request that was sent is never
/// sent again.
/// </summary>
public sealed class FailoverTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Route "site": primary P on <see cref="PrimaryPort"/>, failover 1 is backend B.</summary>
    private sealed class Gateway(bool healthCheck) : AdminGateway
    {
        public int PrimaryPort { get; private set; }

        public BackendServer? Primary { get; set; }

        /// <summary>Instead of P: a server that accepts the connection, reads the request and hangs up without answering.</summary>
        public TcpListener? Broken { get; private set; }

        public bool BrokenPrimary { get; init; }

        protected override async ValueTask BeforeStartAsync()
        {
            await base.BeforeStartAsync();
            if (BrokenPrimary)
            {
                Broken = new TcpListener(IPAddress.Loopback, 0);
                Broken.Start();
                PrimaryPort = ((IPEndPoint)Broken.LocalEndpoint).Port;
                _ = HangUpAsync(Broken);
            }
            else
            {
                Primary = await BackendServer.StartAsync("P");
                PrimaryPort = Primary.Port;
            }
        }

        protected override async ValueTask AfterStopAsync()
        {
            await base.AfterStopAsync();
            Broken?.Dispose();
            if (Primary is not null)
            {
                await Primary.DisposeAsync();
            }
        }

        protected override IEnumerable<string> ExtraArgs =>
        [
            "--Gateway:Routes:0:Name=site",
            "--Gateway:Routes:0:Match:Hosts:0=site.example.com",
            "--Gateway:Routes:0:Destinations:0:Address=127.0.0.1",
            $"--Gateway:Routes:0:Destinations:0:Port={PrimaryPort.ToString(CultureInfo.InvariantCulture)}",
            "--Gateway:Routes:0:Destinations:1:Address=127.0.0.1",
            $"--Gateway:Routes:0:Destinations:1:Port={B.Port.ToString(CultureInfo.InvariantCulture)}",
            "--Gateway:Routes:0:Destinations:1:Failover=1",
            .. healthCheck
                ? (string[])["--Gateway:Routes:0:HealthCheck:Path=/health", "--Gateway:Routes:0:HealthCheck:IntervalSeconds=1", "--Gateway:Routes:0:HealthCheck:TimeoutSeconds=1"]
                : [],
            // Short times, so the test does not wait half a minute.
            "--Gateway:Failover:HoldTime=00:00:01",
            "--Gateway:Failover:RefusedPeriod=00:00:01",
        ];

        public IRouteFailoverMonitor Failover => App.Services.GetRequiredService<IRouteFailoverMonitor>();

        public async Task<HttpResponseMessage> SiteAsync(HttpMethod method, HttpContent? content = null)
        {
            using var request = new HttpRequestMessage(method, new Uri($"http://127.0.0.1:{HttpPort}/hello")) { Content = content };
            request.Headers.Host = "site.example.com";
            return await Public.SendAsync(request, Ct);
        }

        public async Task<string> ServedByAsync()
        {
            using var response = await SiteAsync(HttpMethod.Get);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend;
        }

        private static async Task HangUpAsync(TcpListener listener)
        {
            try
            {
                while (true)
                {
                    using var client = await listener.AcceptTcpClientAsync();
                    var buffer = new byte[16 * 1024];
                    _ = await client.GetStream().ReadAsync(buffer);
                    client.Client.LingerState = new LingerOption(true, 0); // reset: the request was received, no answer
                }
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SocketException or IOException)
            {
                // the listener was stopped
            }
        }
    }

    private static async Task<Gateway> StartAsync(bool healthCheck = true, bool brokenPrimary = false)
    {
        var gateway = new Gateway(healthCheck) { BrokenPrimary = brokenPrimary };
        await gateway.InitializeAsync();
        return gateway;
    }

    [Fact]
    public async Task The_failover_takes_over_while_the_primary_is_down_and_traffic_returns_when_it_is_back()
    {
        await using var gateway = await StartAsync();
        Assert.Equal("P", await gateway.ServedByAsync());
        Assert.Empty(gateway.Failover.Statuses);

        // The primary stops: it refuses connections, so the very next request (a POST with a body) goes to the
        // failover at once, before any health check noticed.
        var port = gateway.PrimaryPort;
        await gateway.Primary!.DisposeAsync();
        gateway.Primary = null;
        using (var post = await gateway.SiteAsync(HttpMethod.Post, new StringContent("name=value")))
        {
            Assert.Equal(HttpStatusCode.OK, post.StatusCode);
            var echo = (await post.Content.ReadFromJsonAsync<BackendEcho>(Ct))!;
            Assert.Equal(("B", "POST", 10L), (echo.Backend, echo.Method, echo.BodyLength));
        }

        Assert.Equal("B", await gateway.ServedByAsync());
        var status = Assert.Single(gateway.Failover.Statuses);
        Assert.Equal(("site", 1), (status.RouteName, status.Failover));
        Assert.Contains("On failover 1 since", await gateway.GetPageAsync("/routes"), StringComparison.Ordinal);
        Assert.Contains("is on failover", await gateway.GetPageAsync("/"), StringComparison.Ordinal);

        // The primary is back: once the health check finds it healthy and the hold time passed, traffic returns.
        gateway.Primary = await BackendServer.StartAsync("P", port: port);
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (await gateway.ServedByAsync() != "P")
        {
            Assert.True(DateTime.UtcNow < deadline, "Traffic did not return to the primary.");
            await Task.Delay(200, Ct);
        }

        Assert.Empty(gateway.Failover.Statuses);
        Assert.DoesNotContain("On failover", await gateway.GetPageAsync("/routes"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_request_that_reached_the_primary_is_not_sent_again()
    {
        // The primary accepts the connection and reads the POST, then hangs up: sending had started, so the request
        // must not be repeated on the failover (it may already have had its effect).
        await using var gateway = await StartAsync(healthCheck: false, brokenPrimary: true);

        using var post = await gateway.SiteAsync(HttpMethod.Post, new StringContent("order=1"));
        Assert.Equal(HttpStatusCode.BadGateway, post.StatusCode);
    }

    [Fact]
    public async Task Without_a_healthy_destination_the_route_answers_503()
    {
        await using var gateway = await StartAsync();
        await gateway.Primary!.DisposeAsync();
        gateway.Primary = null;
        await gateway.B.DisposeAsync();

        // Both refuse connections: the request fails over once, then there is nowhere left to go.
        using (var first = await gateway.SiteAsync(HttpMethod.Get))
        {
            Assert.Equal(HttpStatusCode.BadGateway, first.StatusCode);
        }

        // Both are marked down now: no destination at all.
        using var next = await gateway.SiteAsync(HttpMethod.Get);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, next.StatusCode);
    }
}
