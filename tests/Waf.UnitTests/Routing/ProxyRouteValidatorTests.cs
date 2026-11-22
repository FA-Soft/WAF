using Waf.Core.Routing;

namespace Waf.UnitTests.Routing;

public class ProxyRouteValidatorTests
{
    internal static ProxyRouteOptions ValidRoute(string name = "api")
    {
        var route = new ProxyRouteOptions { Name = name };
        route.Match.Hosts.Add("api.example.com");
        route.Destinations.Add(new ProxyDestinationOptions { Address = "10.0.0.5", Port = 8080 });
        return route;
    }

    private static IReadOnlyList<string> Validate(params ProxyRouteOptions[] routes) => ProxyRouteValidator.Validate(routes);

    [Fact]
    public void Valid_route_has_no_errors()
    {
        Assert.Empty(Validate(ValidRoute()));
    }

    [Fact]
    public void No_routes_is_valid()
    {
        Assert.Empty(Validate());
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("my route")]
    [InlineData("api/v1")]
    public void Invalid_names_are_rejected(string name)
    {
        Assert.NotEmpty(Validate(ValidRoute(name)));
    }

    [Fact]
    public void Duplicate_names_are_rejected_case_insensitively()
    {
        Assert.Contains(Validate(ValidRoute("api"), ValidRoute("API")), e => e.Contains("more than one route", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("*.example.com")]
    [InlineData("localhost")]
    [InlineData("10.0.0.5")]
    public void Valid_hosts_are_accepted(string host)
    {
        var route = ValidRoute();
        route.Match.Hosts.Clear();
        route.Match.Hosts.Add(host);

        Assert.Empty(Validate(route));
    }

    [Theory]
    [InlineData("")]
    [InlineData("exa mple.com")]
    [InlineData("*example.com")]
    [InlineData("http://example.com")]
    [InlineData("example.com/path")]
    public void Invalid_hosts_are_rejected(string host)
    {
        var route = ValidRoute();
        route.Match.Hosts.Add(host);

        Assert.Contains(Validate(route), e => e.Contains("not a valid host name", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/api")]
    [InlineData("/api/v1/")]
    public void Valid_path_prefixes_are_accepted(string prefix)
    {
        var route = ValidRoute();
        route.Match.PathPrefix = prefix;

        Assert.Empty(Validate(route));
    }

    [Theory]
    [InlineData("")]
    [InlineData("api")]
    [InlineData("/api/{id}")]
    [InlineData("/api?x=1")]
    [InlineData("/api/*")]
    [InlineData("//api")]
    public void Invalid_path_prefixes_are_rejected(string prefix)
    {
        var route = ValidRoute();
        route.Match.PathPrefix = prefix;

        Assert.Contains(Validate(route), e => e.Contains("path prefix", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("GET", true)]
    [InlineData("post", true)]
    [InlineData("PROPFIND", true)]
    [InlineData("GE T", false)]
    [InlineData("", false)]
    [InlineData("GET,POST", false)]
    public void Methods_must_be_letters(string method, bool valid)
    {
        var route = ValidRoute();
        route.Match.Methods.Add(method);

        Assert.Equal(valid, Validate(route).Count == 0);
    }

    [Fact]
    public void At_least_one_destination_is_required()
    {
        var route = ValidRoute();
        route.Destinations.Clear();

        Assert.Contains(Validate(route), e => e.Contains("at least one destination", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("http", "10.0.0.5", 8080, true)]
    [InlineData("HTTPS", "backend.local", 443, true)]
    [InlineData("https", "fd00::10", 8443, true)]
    [InlineData("http", "iis-server", 80, true)]
    [InlineData("ftp", "10.0.0.5", 21, false)]
    [InlineData("http", "10", 80, false)]
    [InlineData("http", "0x0A000001", 80, false)]
    [InlineData("http", "", 80, false)]
    [InlineData("http", "10.0.0.5", 0, false)]
    [InlineData("http", "10.0.0.5", 65536, false)]
    public void Destinations_are_validated(string scheme, string address, int port, bool valid)
    {
        var route = ValidRoute();
        route.Destinations.Clear();
        route.Destinations.Add(new ProxyDestinationOptions { Scheme = scheme, Address = address, Port = port });

        Assert.Equal(valid, Validate(route).Count == 0);
    }

    [Theory]
    [InlineData("/health", 10, 5, true)]
    [InlineData("health", 10, 5, false)]
    [InlineData("/health", 0, 5, false)]
    [InlineData("/health", 10, 0, false)]
    [InlineData(null, 0, 0, true)]
    public void Health_check_is_validated_only_when_a_path_is_set(string? path, int interval, int timeout, bool valid)
    {
        var route = ValidRoute();
        route.HealthCheck = new RouteHealthCheckOptions { Path = path, IntervalSeconds = interval, TimeoutSeconds = timeout };

        Assert.Equal(valid, Validate(route).Count == 0);
    }

    [Fact]
    public void Errors_name_the_route_and_destination()
    {
        var route = ValidRoute("shop");
        route.Destinations.Add(new ProxyDestinationOptions { Address = "bad host", Port = 80 });

        Assert.Contains(Validate(route), e => e.StartsWith("Route 'shop', destination #2:", StringComparison.Ordinal));
    }
}
