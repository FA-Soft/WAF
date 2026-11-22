using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Routing;
using Waf.Proxy;
using Yarp.ReverseProxy.Configuration;

namespace Waf.UnitTests.Routing;

public class YarpConfigMapperTests
{
    [Theory]
    [InlineData("/", "/{**rest}")]
    [InlineData("/api", "/api/{**rest}")]
    [InlineData("/api/", "/api/{**rest}")]
    [InlineData("/api/v1", "/api/v1/{**rest}")]
    public void Path_prefix_becomes_catch_all_template(string prefix, string expected)
    {
        Assert.Equal(expected, YarpConfigMapper.ToPathTemplate(prefix));
    }

    [Theory]
    [InlineData("http", "10.0.0.5", 8080, "http://10.0.0.5:8080/")]
    [InlineData("HTTPS", "backend.local", 443, "https://backend.local:443/")]
    [InlineData("http", "fd00::10", 80, "http://[fd00::10]:80/")]
    [InlineData("http", "fe80::1%12", 80, "http://[fe80::1%2512]:80/")]
    public void Destination_urls_are_well_formed(string scheme, string address, int port, string expected)
    {
        var url = YarpConfigMapper.ToDestinationUrl(new ProxyDestinationOptions { Scheme = scheme, Address = address, Port = port });

        Assert.Equal(expected, url);
        Assert.True(Uri.TryCreate(url, UriKind.Absolute, out _));
    }

    [Fact]
    public void Route_and_cluster_carry_match_transforms_and_tls_settings()
    {
        var route = ProxyRouteValidatorTests.ValidRoute("shop");
        route.Match.PathPrefix = "/shop";
        route.Match.Methods.Add("get");
        route.PreserveHost = false;
        route.AllowInvalidBackendCertificate = true;
        route.Destinations.Add(new ProxyDestinationOptions { Address = "10.0.0.6", Port = 8080 });

        var (routes, clusters) = YarpConfigMapper.Map([route]);

        var yarpRoute = Assert.Single(routes);
        Assert.Equal("shop", yarpRoute.RouteId);
        Assert.Equal("shop", yarpRoute.ClusterId);
        Assert.Equal(["api.example.com"], yarpRoute.Match.Hosts);
        Assert.Equal("/shop/{**rest}", yarpRoute.Match.Path);
        Assert.Equal(["GET"], yarpRoute.Match.Methods);
        Assert.Contains(yarpRoute.Transforms!, t => t.TryGetValue("RequestHeaderOriginalHost", out var v) && v == "false");
        Assert.Contains(yarpRoute.Transforms!, t => t.TryGetValue("X-Forwarded", out var v) && v == "Set");
        Assert.Contains(yarpRoute.Transforms!, t => t.TryGetValue("RequestHeaderRemove", out var v) && v == "Forwarded");

        var cluster = Assert.Single(clusters);
        Assert.Equal(2, cluster.Destinations!.Count);
        Assert.Equal("http://10.0.0.6:8080/", cluster.Destinations["shop-2"].Address);
        Assert.True(cluster.HttpClient!.DangerousAcceptAnyServerCertificate);
        Assert.True(cluster.HealthCheck!.Passive!.Enabled);
        Assert.Null(cluster.HealthCheck.Active);
    }

    [Fact]
    public void Empty_hosts_and_methods_match_anything()
    {
        var route = ProxyRouteValidatorTests.ValidRoute();
        route.Match.Hosts.Clear();

        var yarpRoute = Assert.Single(YarpConfigMapper.Map([route]).Routes);

        Assert.Null(yarpRoute.Match.Hosts);
        Assert.Null(yarpRoute.Match.Methods);
    }

    [Fact]
    public void Health_check_path_enables_active_checks()
    {
        var route = ProxyRouteValidatorTests.ValidRoute();
        route.HealthCheck = new RouteHealthCheckOptions { Path = "/health", IntervalSeconds = 15, TimeoutSeconds = 3 };

        var active = Assert.Single(YarpConfigMapper.Map([route]).Clusters).HealthCheck!.Active!;

        Assert.True(active.Enabled);
        Assert.Equal("/health", active.Path);
        Assert.Equal(TimeSpan.FromSeconds(15), active.Interval);
        Assert.Equal(TimeSpan.FromSeconds(3), active.Timeout);
        Assert.Equal("ConsecutiveFailures", active.Policy);
    }

    [Fact]
    public async Task Yarp_accepts_the_mapped_configuration()
    {
        var full = ProxyRouteValidatorTests.ValidRoute("full");
        full.Match.Hosts.Add("*.example.com");
        full.Match.PathPrefix = "/api";
        full.Match.Methods.Add("POST");
        full.HealthCheck = new RouteHealthCheckOptions { Path = "/health" };
        full.Destinations.Add(new ProxyDestinationOptions { Scheme = "https", Address = "fd00::10", Port = 8443 });

        var minimal = ProxyRouteValidatorTests.ValidRoute("minimal");
        minimal.Match.Hosts.Clear();

        var (routes, clusters) = YarpConfigMapper.Map([full, minimal]);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddReverseProxy();
        await using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<IConfigValidator>();

        foreach (var route in routes)
        {
            Assert.Empty(await validator.ValidateRouteAsync(route));
        }

        foreach (var cluster in clusters)
        {
            Assert.Empty(await validator.ValidateClusterAsync(cluster));
        }
    }

    [Fact]
    public void Routes_bind_from_configuration_including_lists()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Gateway:Routes:0:Name"] = "api",
            ["Gateway:Routes:0:Match:Hosts:0"] = "a.example.com",
            ["Gateway:Routes:0:Match:Hosts:1"] = "b.example.com",
            ["Gateway:Routes:0:Match:PathPrefix"] = "/api",
            ["Gateway:Routes:0:Match:Methods:0"] = "GET",
            ["Gateway:Routes:0:Destinations:0:Scheme"] = "https",
            ["Gateway:Routes:0:Destinations:0:Address"] = "10.0.0.5",
            ["Gateway:Routes:0:Destinations:0:Port"] = "8443",
            ["Gateway:Routes:0:PreserveHost"] = "false",
            ["Gateway:Routes:0:HealthCheck:Path"] = "/health",
        }).Build();

        var route = Assert.Single(Waf.Host.Hosting.GatewayConfigurationLoader.Load(configuration).Routes);

        Assert.Equal("api", route.Name);
        Assert.Equal(["a.example.com", "b.example.com"], route.Match.Hosts);
        Assert.Equal("/api", route.Match.PathPrefix);
        Assert.Equal(["GET"], route.Match.Methods);
        var destination = Assert.Single(route.Destinations);
        Assert.Equal(("https", "10.0.0.5", 8443), (destination.Scheme, destination.Address, destination.Port));
        Assert.False(route.PreserveHost);
        Assert.False(route.AllowInvalidBackendCertificate);
        Assert.Equal("/health", route.HealthCheck.Path);
        Assert.Equal(10, route.HealthCheck.IntervalSeconds);
    }
}
