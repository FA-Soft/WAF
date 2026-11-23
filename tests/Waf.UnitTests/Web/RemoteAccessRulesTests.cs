using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

/// <summary>The remote admin URL and what must be true before it can be registered.</summary>
public sealed class RemoteAccessRulesTests
{
    [Theory]
    [InlineData("https://admin.example.com", "admin.example.com", null)]
    [InlineData("https://Admin.Example.com/", "admin.example.com", null)]
    [InlineData("https://admin.example.com:8443", "admin.example.com", 8443)]
    [InlineData("https://admin.example.com:443", "admin.example.com", null)]
    public void Valid_urls_are_normalized(string text, string host, int? port)
    {
        Assert.True(RemoteAdminUrl.TryParse(text, out var url, out _));
        Assert.Equal(new RemoteAdminUrl(host, port), url);
    }

    [Theory]
    [InlineData("", "full address")]
    [InlineData("admin.example.com", "full address")]
    [InlineData("http://admin.example.com", "HTTPS only")]
    [InlineData("https://203.0.113.5", "not an IP address")]
    [InlineData("https://localhost", "not an IP address")]
    [InlineData("https://admin.example.com/admin", "without a path")]
    [InlineData("https://admin.example.com/?a=b", "without a path")]
    [InlineData("https://user@admin.example.com", "without a path")]
    public void Invalid_urls_are_explained(string text, string expected)
    {
        Assert.False(RemoteAdminUrl.TryParse(text, out _, out var error));
        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Urls_print_as_registered() =>
        Assert.Equal(["https://admin.example.com", "https://admin.example.com:8443"],
            [new RemoteAdminUrl("admin.example.com", null).ToString(), new RemoteAdminUrl("admin.example.com", 8443).ToString()]);

    private static GatewayConfiguration Config(params string[] routeHosts)
    {
        var configuration = new GatewayConfiguration();
        var route = new ProxyRouteOptions { Name = "site" };
        foreach (var host in routeHosts)
        {
            route.Match.Hosts.Add(host);
        }

        configuration.Routes.Add(route);
        return configuration;
    }

    private static CertificateStatus Certificate(string host, CertificateState state = CertificateState.Ok) =>
        new(host, CertificateSource.Uploaded, state, null, null, null, null);

    private static readonly RemoteAdminUrl Admin = new("admin.example.com", null);

    [Fact]
    public void Everything_in_place_can_be_registered() =>
        Assert.Empty(RemoteAccessRules.Check(Admin, true, Config("www.example.com"), [Certificate("admin.example.com")], [80, 8900]));

    [Fact]
    public void A_wildcard_certificate_counts() =>
        Assert.Empty(RemoteAccessRules.Check(Admin, true, Config("www.example.com"), [Certificate("*.example.com")], [80, 8900]));

    [Fact]
    public void Each_missing_requirement_is_explained()
    {
        var problems = RemoteAccessRules.Check(new RemoteAdminUrl("admin.example.com", 80), false, Config("*.example.com"), [], [80, 8900]);

        Assert.Contains(problems, p => p.Contains("Turn on two-factor sign-in", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("Port 80 is already used", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("is used by route 'site'", StringComparison.Ordinal)); // a wildcard route covers it
        Assert.Contains(problems, p => p.Contains("There is no certificate for admin.example.com", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(CertificateState.Pending)]
    [InlineData(CertificateState.Missing)]
    [InlineData(CertificateState.Expired)]
    [InlineData(CertificateState.WrongHost)]
    public void A_certificate_that_does_not_work_yet_is_not_enough(CertificateState state) =>
        Assert.Contains(RemoteAccessRules.Check(Admin, true, Config(), [Certificate("admin.example.com", state)], [80]),
            p => p.Contains("is not usable yet", StringComparison.Ordinal));
}
