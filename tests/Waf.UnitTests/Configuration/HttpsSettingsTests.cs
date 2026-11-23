using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Proxy;

namespace FASoft.Waf.UnitTests.Configuration;

/// <summary>HSTS settings, the HTTPS checks of the validator and the route metadata the redirect step reads.</summary>
public sealed class HttpsSettingsTests
{
    private static GatewayConfiguration Config(bool redirect, params string[] certificateHosts)
    {
        var configuration = new GatewayConfiguration();
        var route = new ProxyRouteOptions { Name = "site", Https = { RedirectHttp = redirect, Hsts = true } };
        route.Match.Hosts.Add("www.example.com");
        route.Match.Hosts.Add("shop.example.com");
        route.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = 8080 });
        configuration.Routes.Add(route);
        foreach (var host in certificateHosts)
        {
            configuration.Certificates.Add(new CertificateBinding { HostName = host, Source = CertificateSource.File, CertificatePath = "site.pem" });
        }

        return configuration;
    }

    [Theory]
    [InlineData(31_536_000, false, false, "max-age=31536000")]
    [InlineData(86_400, true, false, "max-age=86400; includeSubDomains")]
    [InlineData(63_072_000, true, true, "max-age=63072000; includeSubDomains; preload")]
    [InlineData(0, false, false, "max-age=0")]
    public void Hsts_header_value(int maxAge, bool subdomains, bool preload, string expected) =>
        Assert.Equal(expected, new HstsSettings { MaxAgeSeconds = maxAge, IncludeSubDomains = subdomains, Preload = preload }.HeaderValue());

    [Fact]
    public void Defaults_keep_plain_http_and_a_one_year_hsts()
    {
        var route = new ProxyRouteOptions();
        Assert.False(route.Https.RedirectHttp);
        Assert.False(route.Https.Hsts);
        Assert.Equal("max-age=31536000", new GatewaySettings().Hsts.HeaderValue());
    }

    [Theory]
    [InlineData(-1, false, false, "must be between 0 and 63072000")]
    [InlineData(63_072_001, false, false, "must be between 0 and 63072000")]
    [InlineData(31_536_000, false, true, "Preload needs IncludeSubDomains")]
    [InlineData(86_400, true, true, "Preload needs IncludeSubDomains")]
    public void Invalid_hsts_settings_are_explained(int maxAge, bool subdomains, bool preload, string expected)
    {
        var configuration = Config(redirect: false);
        configuration.Settings.Hsts = new HstsSettings { MaxAgeSeconds = maxAge, IncludeSubDomains = subdomains, Preload = preload };

        Assert.Contains(GatewayConfigurationValidator.Validate(configuration), e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_redirect_needs_a_certificate_for_every_host_name()
    {
        Assert.Contains(GatewayConfigurationValidator.Validate(Config(redirect: true, "www.example.com")),
            e => e.Contains("needs a certificate for shop.example.com", StringComparison.Ordinal));

        Assert.Empty(GatewayConfigurationValidator.Validate(Config(redirect: true, "www.example.com", "shop.example.com")));
        Assert.Empty(GatewayConfigurationValidator.Validate(Config(redirect: true, "*.example.com"))); // a wildcard covers both
        Assert.Empty(GatewayConfigurationValidator.Validate(Config(redirect: false))); // HSTS alone needs nothing

        var anyHost = Config(redirect: true, "www.example.com");
        anyHost.Routes[0].Match.Hosts.Clear();
        Assert.Contains(GatewayConfigurationValidator.Validate(anyHost), e => e.Contains("redirecting to HTTPS needs host names", StringComparison.Ordinal));
    }

    [Fact]
    public void Https_options_become_route_metadata()
    {
        var configuration = Config(redirect: true, "*.example.com");
        var plain = new ProxyRouteOptions { Name = "plain" };
        plain.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = 8081 });
        configuration.Routes.Add(plain);

        var (routes, _) = YarpConfigMapper.Map(configuration.Routes, "tag");

        var site = routes.Single(r => r.RouteId == "site").Metadata!;
        Assert.Equal("true", site[YarpConfigMapper.RedirectHttpMetadataKey]);
        Assert.Equal("true", site[YarpConfigMapper.HstsMetadataKey]);
        var plainMetadata = routes.Single(r => r.RouteId == "plain").Metadata!;
        Assert.False(plainMetadata.ContainsKey(YarpConfigMapper.RedirectHttpMetadataKey));
        Assert.False(plainMetadata.ContainsKey(YarpConfigMapper.HstsMetadataKey));
    }
}
