using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Proxy;
using FASoft.Waf.Web;
using static FASoft.Waf.UnitTests.Engine.RuleBuilder;

namespace FASoft.Waf.UnitTests.Web;

public class RouteEditingTests
{
    [Theory]
    [InlineData("http://10.0.0.5:8080", "http", "10.0.0.5", 8080)]
    [InlineData("https://backend.local", "https", "backend.local", 443)]
    [InlineData("10.0.0.5:8080", "http", "10.0.0.5", 8080)]
    [InlineData("backend", "http", "backend", 80)]
    [InlineData("http://[fd00::10]:8080", "http", "fd00::10", 8080)]
    [InlineData("  HTTP://IIS-Server:8081/  ", "http", "iis-server", 8081)]
    public void Backend_addresses_are_understood(string text, string scheme, string address, int port)
    {
        Assert.True(RouteFormModel.TryParseDestination(text, out var destination, out var error), error);
        Assert.Equal((scheme, address, port), (destination.Scheme, destination.Address, destination.Port));
    }

    [Theory]
    [InlineData("ftp://10.0.0.5", "only http:// and https://")]
    [InlineData("http://10.0.0.5:8080/app", "without a path")]
    [InlineData("http://user:pw@10.0.0.5", "without a path")]
    [InlineData("http://10:80", "'10' is not a valid IP address or host name")]
    [InlineData("0x0A000001:80", "'0x0A000001' is not a valid IP address or host name")]
    [InlineData("not an address", "not a valid address")]
    public void Wrong_backend_addresses_are_explained(string text, string expected)
    {
        Assert.False(RouteFormModel.TryParseDestination(text, out _, out var error));
        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Form_round_trips_a_route()
    {
        var route = new ProxyRouteOptions { Name = "api", Enabled = false, PreserveHost = false, AllowInvalidBackendCertificate = true };
        route.Match.Hosts.Add("api.example.com");
        route.Match.Hosts.Add("*.api.example.com");
        route.Match.PathPrefix = "/v1";
        route.Match.Methods.Add("GET");
        route.Match.Methods.Add("POST");
        route.Destinations.Add(new ProxyDestinationOptions { Scheme = "https", Address = "fd00::10", Port = 8443 });
        route.Destinations.Add(new ProxyDestinationOptions { Address = "10.0.0.6", Port = 8080 });
        route.HealthCheck = new RouteHealthCheckOptions { Path = "/health", IntervalSeconds = 15, TimeoutSeconds = 3 };

        var form = RouteFormModel.FromRoute(route, baseVersion: 7);
        var back = form.ToRoute();

        Assert.Equal(7, form.BaseVersion);
        Assert.False(form.IsNew);
        Assert.Equal("https://[fd00::10]:8443" + Environment.NewLine + "http://10.0.0.6:8080", form.Destinations);
        Assert.Equal(
            FASoft.Waf.Core.Configuration.GatewayConfigurationJson.Serialize(WithRoute(route)),
            FASoft.Waf.Core.Configuration.GatewayConfigurationJson.Serialize(WithRoute(back)));
    }

    [Fact]
    public void New_route_form_starts_enabled_and_preserving_the_host()
    {
        var form = RouteFormModel.ForNewRoute(3);

        Assert.True(form.IsNew && form.Enabled && form.PreserveHost);
        Assert.False(form.AllowInvalidBackendCertificate);
        Assert.Equal((3L, "/"), (form.BaseVersion, form.PathPrefix));
    }

    [Fact]
    public void Hosts_may_be_separated_by_lines_commas_or_spaces_and_no_method_means_any()
    {
        var route = new RouteFormModel { Name = "x", Hosts = "a.example.com, b.example.com\nc.example.com  d.example.com", Destinations = "10.0.0.5:80" }.ToRoute();

        Assert.Equal(["a.example.com", "b.example.com", "c.example.com", "d.example.com"], route.Match.Hosts);
        Assert.Empty(route.Match.Methods);
    }

    [Theory]
    [InlineData("my route", "/", "10.0.0.5:80", null, "Use only letters, digits")]
    [InlineData("web", "api", "10.0.0.5:80", null, "The path prefix must start with /")]
    [InlineData("web", "/", "10.0.0.5:80\nftp://x", null, "Backend line 2 ('ftp://x'): only http:// and https://")]
    [InlineData("web", "/", "10.0.0.5:80", "*example.com", "is not a valid host name")]
    public void Form_validation_gives_plain_language_errors(string name, string prefix, string destinations, string? hosts, string expected)
    {
        var form = new RouteFormModel { Name = name, PathPrefix = prefix, Destinations = destinations, Hosts = hosts };

        var errors = form.Validate(new ValidationContext(form)).Select(e => e.ErrorMessage).ToList();

        Assert.Contains(errors, e => e!.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void References_to_a_route_are_found()
    {
        var configuration = Config(Rule("r1", RuleAction.Block, 1));
        configuration.Rules[0].Routes.Add("website");
        var limit = new RateLimitRule { Name = "l1" };
        limit.Routes.Add("WEBSITE");
        configuration.RateLimits.Add(limit);
        var exclusion = new DetectionExclusion { PathPrefix = "/cms" };
        exclusion.Routes.Add("website");
        configuration.Settings.AttackDetection.Exclusions.Add(exclusion);

        Assert.Equal(["rule 'r1'", "rate limit 'l1'", "detection exclusion #1 (/cms)"], ConfigurationEditing.RouteReferences(configuration, "website"));
        Assert.Empty(ConfigurationEditing.RouteReferences(configuration, "api"));
    }

    [Fact]
    public void Clone_is_independent()
    {
        var original = Config();
        var copy = ConfigurationEditing.Clone(original);

        copy.Routes.Clear();

        Assert.Equal(2, original.Routes.Count);
    }

    [Fact]
    public void Disabled_routes_are_not_given_to_the_proxy()
    {
        var configuration = Config();
        configuration.Routes[1].Enabled = false;

        var (routes, clusters) = YarpConfigMapper.Map(configuration.Routes);

        Assert.Equal(["website"], routes.Select(r => r.RouteId));
        Assert.Single(clusters);
    }

    private static GatewayConfiguration WithRoute(ProxyRouteOptions route)
    {
        var configuration = new GatewayConfiguration();
        configuration.Routes.Add(route);
        return configuration;
    }
}
