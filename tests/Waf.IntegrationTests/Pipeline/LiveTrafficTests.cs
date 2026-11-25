using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Engine;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>The live traffic hub (SignalR) on the admin listener, against running gateways.</summary>
public sealed partial class LiveTrafficTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs()
                .Add("website", [("http", A.Port)], hosts: ["www.example.com"])
                .Add("api", [("http", B.Port)], hosts: ["api.example.com"])
                .ToArray();

        public LiveTrafficBroadcaster Broadcaster => App.Services.GetRequiredService<LiveTrafficBroadcaster>();

        public LiveTraffic Live => App.Services.GetRequiredService<LiveTraffic>();

        public Uri HubUrl => new($"http://127.0.0.1:{AdminPort}{TrafficHub.Path}");

        public Uri NegotiateUrl => new($"http://127.0.0.1:{AdminPort}{TrafficHub.Path}/negotiate?negotiateVersion=1");
    }

    /// <summary>A dashboard: a SignalR connection with the admin's cookie that collects the snapshots it gets.</summary>
    private sealed class Dashboard : IAsyncDisposable
    {
        private Dashboard(HubConnection connection) => Connection = connection;

        public HubConnection Connection { get; }

        public Channel<LiveTrafficSnapshot> Snapshots { get; } = Channel.CreateUnbounded<LiveTrafficSnapshot>();

        public TaskCompletionSource SessionEnded { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Closed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public static async Task<Dashboard> OpenAsync(Gateway gateway, string? route = null, HttpTransportType transport = HttpTransportType.WebSockets, CookieContainer? cookies = null)
        {
            var connection = new HubConnectionBuilder()
                .WithUrl(gateway.HubUrl, options =>
                {
                    options.Cookies = cookies ?? gateway.AdminCookies;
                    options.Transports = transport;
                })
                .AddJsonProtocol(options => options.PayloadSerializerOptions.Converters.Add(new JsonStringEnumConverter()))
                .Build();
            var dashboard = new Dashboard(connection);
            connection.On<LiveTrafficSnapshot>("snapshot", snapshot => dashboard.Snapshots.Writer.TryWrite(snapshot));
            connection.On("sessionEnded", () => dashboard.SessionEnded.TrySetResult());
            connection.Closed += _ =>
            {
                dashboard.Closed.TrySetResult();
                return Task.CompletedTask;
            };
            await connection.StartAsync(Ct);
            await connection.InvokeAsync("Watch", route, Ct);
            return dashboard;
        }

        /// <summary>Snapshots until their totals add up to <paramref name="requests"/>, per second.</summary>
        public async Task<Dictionary<long, LiveTrafficSnapshot>> ReadUntilAsync(long requests)
        {
            var seen = new Dictionary<long, LiveTrafficSnapshot>();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            while (seen.Values.Sum(s => s.Total) < requests)
            {
                var snapshot = await Snapshots.Reader.ReadAsync(timeout.Token);
                seen[snapshot.Second] = snapshot;
            }

            return seen;
        }

        public async ValueTask DisposeAsync() => await Connection.DisposeAsync();
    }

    private static async Task<HttpStatusCode> SendAsync(Gateway gateway, string host, string path = "/")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
        request.Headers.Host = host;
        using var response = await gateway.Public.SendAsync(request, Ct);
        return response.StatusCode;
    }

    [Fact]
    public async Task Two_dashboards_get_the_same_numbers_every_second()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await using var first = await Dashboard.OpenAsync(gateway);
        await using var second = await Dashboard.OpenAsync(gateway, transport: HttpTransportType.ServerSentEvents);

        for (var i = 0; i < 7; i++)
        {
            Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "www.example.com"));
        }

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.NotFound, await SendAsync(gateway, "unknown.example.com"));
        }

        var a = await first.ReadUntilAsync(10);
        var b = await second.ReadUntilAsync(10);
        foreach (var (time, snapshot) in a.Where(p => b.ContainsKey(p.Key)))
        {
            var other = b[time];
            Assert.Equal((snapshot.Total, snapshot.Good, snapshot.Bad, snapshot.Failed), (other.Total, other.Good, other.Bad, other.Failed));
        }

        Assert.Equal(7, a.Values.Sum(s => s.Good));
        Assert.Equal(3, a.Values.Sum(s => s.Bad));
        Assert.Equal(3, a.Values.SelectMany(s => s.Kinds).Where(k => k.Kind == TrafficKind.NoRoute).Sum(k => k.Count));
        var last = a.OrderBy(p => p.Key).Last().Value;
        Assert.Equal(new LiveSourceCount("127.0.0.1", 3), Assert.Single(last.TopSources));

        // Snapshots keep coming every second, also when nothing happens.
        var quiet = await first.Snapshots.Reader.ReadAsync(Ct);
        var next = await first.Snapshots.Reader.ReadAsync(Ct);
        Assert.Equal(quiet.Second + 1, next.Second);
    }

    [Fact]
    public async Task A_dashboard_can_watch_one_route()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await using var api = await Dashboard.OpenAsync(gateway, route: "api");
        await using var all = await Dashboard.OpenAsync(gateway);

        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "www.example.com"));
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "api.example.com"));
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "api.example.com"));

        var everything = await all.ReadUntilAsync(3);
        Assert.Equal(3, everything.Values.Sum(s => s.Total));
        var mine = await api.ReadUntilAsync(2);
        Assert.All(mine.Values, s => Assert.Equal("api", s.Route));
        Assert.Equal(2, mine.Values.Sum(s => s.Total));
        await Task.Delay(1500, Ct);
        Assert.Equal(2, mine.Values.Sum(s => s.Total) + DrainTotal(api));

        await Assert.ThrowsAnyAsync<Exception>(() => api.Connection.InvokeAsync("Watch", new string('x', 500), Ct));
    }

    private static long DrainTotal(Dashboard dashboard)
    {
        long total = 0;
        while (dashboard.Snapshots.Reader.TryRead(out var snapshot))
        {
            total += snapshot.Total;
        }

        return total;
    }

    [Fact]
    public async Task With_no_dashboard_open_no_snapshots_are_built()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.Equal(HttpStatusCode.OK, await SendAsync(gateway, "www.example.com"));
        await Task.Delay(2500, Ct);
        Assert.Equal(0, gateway.Broadcaster.SnapshotsBuilt);
        Assert.False(gateway.Live.IsWatched);

        await using (var dashboard = await Dashboard.OpenAsync(gateway))
        {
            Assert.True(gateway.Live.IsWatched);
            await dashboard.Snapshots.Reader.ReadAsync(Ct);
        }

        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (gateway.Broadcaster.Viewers > 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, Ct);
        }

        Assert.False(gateway.Live.IsWatched);
        var built = gateway.Broadcaster.SnapshotsBuilt;
        await Task.Delay(2500, Ct);
        Assert.Equal(built, gateway.Broadcaster.SnapshotsBuilt);
    }

    [Fact]
    public async Task The_hub_is_refused_without_a_session_from_another_site_and_on_the_public_ports()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        // Without signing in.
        using (var anonymous = new HttpClient())
        {
            using var response = await anonymous.PostAsync(gateway.NegotiateUrl, null, Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        var refused = await Assert.ThrowsAnyAsync<Exception>(() => Dashboard.OpenAsync(gateway, cookies: new CookieContainer()));
        Assert.Contains("401", refused.Message, StringComparison.Ordinal);
        await Assert.ThrowsAnyAsync<Exception>(() => Dashboard.OpenAsync(gateway, transport: HttpTransportType.WebSockets, cookies: new CookieContainer()));

        // Signed in, but the request comes from another site's page.
        foreach (var origin in new[] { "http://evil.example", $"http://127.0.0.1:{gateway.HttpPort}", "null" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, gateway.NegotiateUrl);
            request.Headers.Add("Origin", origin);
            using var response = await gateway.Admin.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        using (var request = new HttpRequestMessage(HttpMethod.Post, gateway.NegotiateUrl))
        {
            request.Headers.Add("Origin", $"http://127.0.0.1:{gateway.AdminPort}");
            using var response = await gateway.Admin.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("connectionToken", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }

        // The public port has no hub: without a route 404, with one the request simply goes to the backend.
        using (var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://127.0.0.1:{gateway.HttpPort}{TrafficHub.Path}/negotiate?negotiateVersion=1")))
        {
            request.Headers.Host = "unknown.example.com";
            using var response = await gateway.Public.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        using (var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://127.0.0.1:{gateway.HttpPort}{TrafficHub.Path}/negotiate?negotiateVersion=1")))
        {
            request.Headers.Host = "www.example.com";
            using var response = await gateway.Public.SendAsync(request, Ct);
            Assert.DoesNotContain("connectionToken", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_dashboard_is_disconnected_when_its_session_ends()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        gateway.Broadcaster.RevalidateInterval = TimeSpan.FromMilliseconds(200);
        await using var dashboard = await Dashboard.OpenAsync(gateway);
        await dashboard.Snapshots.Reader.ReadAsync(Ct);

        // "Sign out other sessions", a password change or a 2FA change: the security stamp changes.
        await using (var scope = gateway.App.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var admin = await users.FindByNameAsync(GatewayFixture.AdminUserName);
            await users.UpdateSecurityStampAsync(admin!);
        }

        await dashboard.SessionEnded.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        await dashboard.Closed.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Equal(0, gateway.Broadcaster.Viewers);
    }

    [Fact]
    public async Task The_dashboard_loads_the_client_from_the_gateway_under_the_strict_policy()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var response = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/"), Ct);
        var html = await response.Content.ReadAsStringAsync(Ct);
        Assert.Contains("id=\"live-traffic\"", html, StringComparison.Ordinal);
        var policy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("script-src 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("connect-src 'self'", policy, StringComparison.Ordinal);

        var scripts = ScriptPattern().Matches(html).Select(m => m.Groups["src"].Value).ToList();
        Assert.All(scripts, src => Assert.DoesNotContain("//", src, StringComparison.Ordinal)); // no other hosts
        // Served from the gateway itself: the client (checked byte for byte by LicenseTests) and the page script.
        Assert.Single(scripts, src => src.StartsWith("_content/Waf.Web/lib/signalr/signalr.min.", StringComparison.Ordinal));
        Assert.Single(scripts, src => src.StartsWith("_content/Waf.Web/live.", StringComparison.Ordinal));
    }

    [GeneratedRegex("<script src=\"(?<src>[^\"]+)\"")]
    private static partial Regex ScriptPattern();
}
