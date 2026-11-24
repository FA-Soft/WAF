using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace FASoft.Waf.UnitTests.Routing;

/// <summary>Failover destinations: configuration, the "primary, then failover" choice, the connect retry and the editor.</summary>
public class FailoverTests
{
    private readonly ManualTimeProvider _time = new();

    private FailoverMonitor Monitor(TimeSpan? hold = null) =>
        new(new FailoverOptions { HoldTime = hold ?? TimeSpan.FromSeconds(30) }, _time, NullLogger<FailoverMonitor>.Instance);

    private static DestinationState Destination(string id, int? failover = null) =>
        new(id, new DestinationModel(new DestinationConfig
        {
            Address = $"http://{id}:80/",
            Metadata = failover is { } f ? new Dictionary<string, string> { [YarpConfigMapper.FailoverMetadataKey] = f.ToString(System.Globalization.CultureInfo.InvariantCulture) } : null,
        }));

    private static void Down(DestinationState destination) => destination.Health.Active = DestinationHealth.Unhealthy;

    private static void Up(DestinationState destination) => destination.Health.Active = DestinationHealth.Healthy;

    private static string[] Ids(IEnumerable<DestinationState> destinations) => [.. destinations.Select(d => d.DestinationId)];

    private static ProxyRouteOptions Route(params ProxyDestinationOptions[] destinations)
    {
        var route = new ProxyRouteOptions { Name = "site" };
        foreach (var destination in destinations)
        {
            route.Destinations.Add(destination);
        }

        return route;
    }

    private static ProxyDestinationOptions At(string address, int? failover = null) => new() { Address = address, Port = 80, Failover = failover };

    [Fact]
    public void Healthy_primaries_share_the_traffic_and_failovers_get_none()
    {
        var all = new[] { Destination("p1"), Destination("p2"), Destination("f1", 1) };

        Assert.Equal(["p1", "p2"], Ids(Monitor().Choose("site", all)));
    }

    [Fact]
    public void Without_a_healthy_primary_the_lowest_healthy_failover_takes_over()
    {
        var p = Destination("p");
        var f1 = Destination("f1", 1);
        var f2a = Destination("f2a", 2);
        var f2b = Destination("f2b", 2);
        var monitor = Monitor();
        Down(p);

        Assert.Equal(["f1"], Ids(monitor.Choose("site", [p, f2a, f2b, f1])));
        var status = Assert.Single(monitor.Statuses);
        Assert.Equal(("site", 1, "http://f1:80/", _time.Now), (status.RouteName, status.Failover, status.Destinations, status.Since));

        // Failover 1 down too: failover 2, whose two destinations share the load; still "since" the first switch.
        Down(f1);
        _time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(["f2a", "f2b"], Ids(monitor.Choose("site", [p, f2a, f2b, f1])));
        Assert.Equal((2, _time.Now.AddMinutes(-1)), (monitor.Statuses[0].Failover, monitor.Statuses[0].Since));

        // Nothing healthy: no destination at all (503).
        Down(f2a);
        Down(f2b);
        Assert.Empty(monitor.Choose("site", [p, f2a, f2b, f1]));
    }

    [Fact]
    public void Traffic_returns_to_the_primary_only_after_the_hold_time()
    {
        var p = Destination("p");
        var f = Destination("f", 1);
        var monitor = Monitor(TimeSpan.FromSeconds(30));
        Down(p);
        Assert.Equal(["f"], Ids(monitor.Choose("site", [p, f])));

        // Back, but it has to stay healthy for the hold time; going down again restarts it.
        Up(p);
        Assert.Equal(["f"], Ids(monitor.Choose("site", [p, f])));
        _time.Advance(TimeSpan.FromSeconds(20));
        Down(p);
        Assert.Equal(["f"], Ids(monitor.Choose("site", [p, f])));
        Up(p);
        Assert.Equal(["f"], Ids(monitor.Choose("site", [p, f])));
        _time.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(["f"], Ids(monitor.Choose("site", [p, f])));

        _time.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(["p"], Ids(monitor.Choose("site", [p, f])));
        Assert.Empty(monitor.Statuses);
    }

    [Fact]
    public void A_failover_that_goes_down_during_the_hold_time_hands_back_to_the_primary_at_once()
    {
        var p = Destination("p");
        var f = Destination("f", 1);
        var monitor = Monitor();
        Down(p);
        monitor.Choose("site", [p, f]);

        Up(p);
        Down(f);
        Assert.Equal(["p"], Ids(monitor.Choose("site", [p, f])));
    }

    [Fact]
    public void A_destination_is_healthy_unless_a_health_check_marks_it_down()
    {
        var d = Destination("d");
        Assert.True(FailoverMonitor.IsHealthy(d)); // unknown: not checked yet

        d.Health.Passive = DestinationHealth.Unhealthy;
        Assert.False(FailoverMonitor.IsHealthy(d));
        d.Health.Passive = DestinationHealth.Unknown;
        d.Health.Active = DestinationHealth.Unhealthy;
        Assert.False(FailoverMonitor.IsHealthy(d));
    }

    private sealed class FakeError(ForwarderError error, Exception? exception) : IForwarderErrorFeature
    {
        public ForwarderError Error { get; } = error;

        public Exception? Exception { get; } = exception;
    }

    public static TheoryData<string, bool> Errors => new()
    {
        { "refused", true },
        { "unknown host", true },
        { "wrapped refused", true },
        { "response ended", false },
        { "body", false },
        { "timed out", false },
        { "none", false },
    };

    [Theory]
    [MemberData(nameof(Errors))]
    public void Only_a_connection_that_could_not_be_opened_is_retried(string kind, bool retried)
    {
        var refused = new HttpRequestException(HttpRequestError.ConnectionError, "refused", new SocketException((int)SocketError.ConnectionRefused));
        IForwarderErrorFeature? error = kind switch
        {
            "refused" => new FakeError(ForwarderError.Request, refused),
            "unknown host" => new FakeError(ForwarderError.Request, new HttpRequestException(HttpRequestError.NameResolutionError, "no such host")),
            "wrapped refused" => new FakeError(ForwarderError.Request, new InvalidOperationException("outer", refused)),
            // The backend took the request and hung up: it may have acted on it.
            "response ended" => new FakeError(ForwarderError.Request, new HttpRequestException(HttpRequestError.ResponseEnded, "ended")),
            "body" => new FakeError(ForwarderError.RequestBodyDestination, refused),
            "timed out" => new FakeError(ForwarderError.RequestTimedOut, new TaskCanceledException()),
            _ => null,
        };

        Assert.Equal(retried, FailoverMiddleware.IsConnectFailure(error));
    }

    [Fact]
    public async Task Connecting_gives_up_after_the_connect_timeout()
    {
        // A port that is bound but not listening refuses connections, and no other test can take it meanwhile.
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)reserved.LocalEndPoint!).Port;
        var started = TimeProvider.System.GetTimestamp();

        await Assert.ThrowsAnyAsync<SocketException>(async () =>
            await FailoverHttpClientFactory.ConnectAsync(new DnsEndPoint("127.0.0.1", port), TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken));
        Assert.True(TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void The_mapper_marks_failover_destinations_and_their_route()
    {
        var (_, clusters) = YarpConfigMapper.Map([Route(At("10.0.0.5"), At("10.0.0.6", failover: 1)), new ProxyRouteOptions { Name = "plain", Destinations = { At("10.0.0.7") } }]);

        var site = clusters.Single(c => c.ClusterId == "site");
        Assert.True(YarpConfigMapper.HasFailover(site));
        Assert.Null(YarpConfigMapper.FailoverOf(site.Destinations!["site-1"]));
        Assert.Equal(1, YarpConfigMapper.FailoverOf(site.Destinations["site-2"]));
        Assert.Equal("http://10.0.0.6:80/ · failover 1", YarpConfigMapper.DescribeDestination(site.Destinations["site-2"]));
        Assert.False(YarpConfigMapper.HasFailover(clusters.Single(c => c.ClusterId == "plain")));
    }

    [Fact]
    public void A_route_needs_a_primary_and_failover_numbers_from_1_to_99()
    {
        Assert.Empty(ProxyRouteValidator.Validate([Route(At("10.0.0.5"), At("10.0.0.6", 1), At("10.0.0.7", 1))]));
        Assert.Contains(
            "Route 'site': at least one destination must be a primary (without 'Failover'); failover destinations only take over from it.",
            ProxyRouteValidator.Validate([Route(At("10.0.0.6", 1))]));
        Assert.Contains(
            "Route 'site', destination #2: 'Failover' must be between 1 and 99 (was 0); leave it out for a primary destination.",
            ProxyRouteValidator.Validate([Route(At("10.0.0.5"), At("10.0.0.6", 0))]));
    }

    [Fact]
    public void Routes_without_failover_keep_their_exact_json()
    {
        var json = GatewayConfigurationJson.Serialize(new GatewayConfiguration { Routes = { Route(At("10.0.0.5")) } });

        Assert.DoesNotContain("Failover", json, StringComparison.Ordinal);
        Assert.Contains("\"Failover\": 1", GatewayConfigurationJson.Serialize(new GatewayConfiguration { Routes = { Route(At("10.0.0.5"), At("10.0.0.6", 1)) } }), StringComparison.Ordinal);
    }

    [Fact]
    public void A_target_destination_keeps_its_failover_number_when_resolved()
    {
        var configuration = new GatewayConfiguration
        {
            Targets = { new BackendTarget { Name = "nas", Address = "192.168.1.20", Ports = { new TargetPort { Name = "web", Port = 5000 } } } },
            Routes = { Route(At("10.0.0.5"), new ProxyDestinationOptions { Target = "nas", TargetPort = "web", Failover = 1 }) },
        };

        var resolved = TargetResolver.Resolve(configuration).Single().Destinations[1];
        Assert.Equal(("192.168.1.20", 5000, (int?)1), (resolved.Address, resolved.Port, resolved.Failover));
    }

    [Fact]
    public void The_editor_numbers_failover_lines_in_order_and_reads_them_back()
    {
        var form = new RouteFormModel { Name = "site", Destinations = "10.0.0.5:80", FailoverDestinations = "10.0.0.6:80\nnas/web" };

        var route = form.ToRoute();
        Assert.Equal([null, 1, 2], route.Destinations.Select(d => d.Failover));
        Assert.Equal(("10.0.0.6", "nas"), (route.Destinations[1].Address, route.Destinations[2].Target));

        var back = RouteFormModel.FromRoute(route, 1);
        Assert.Equal("http://10.0.0.5:80", back.Destinations);
        Assert.Equal($"http://10.0.0.6:80{Environment.NewLine}nas/web", back.FailoverDestinations);
        Assert.Equal("http://10.0.0.5:80, http://10.0.0.6:80 · failover 1, nas · web · failover 2", Describe.Destinations(route.Destinations));
    }

    [Fact]
    public void The_editor_refuses_a_failover_that_is_also_a_primary_and_adds_targets_as_failover()
    {
        var form = new RouteFormModel { Name = "site", Destinations = "http://10.0.0.5:80", FailoverDestinations = "10.0.0.5:80" };
        var errors = form.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(form)).Select(e => e.ErrorMessage).ToList();
        Assert.Contains("Failover line 1 ('10.0.0.5:80') is already a backend above; a failover is another address or target.", errors);

        var add = new RouteFormModel { Destinations = "10.0.0.5:80", Command = "add-target-failover", AddTarget = "nas/web" };
        Assert.True(add.TryApplyCommand());
        Assert.Equal(("10.0.0.5:80", "nas/web"), (add.Destinations, add.FailoverDestinations));
    }
}
