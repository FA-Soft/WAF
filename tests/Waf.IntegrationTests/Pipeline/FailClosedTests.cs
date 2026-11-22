using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Waf.Engine;
using Waf.IntegrationTests.Proxy;
using Waf.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>Gateway with a catch-all route; tests take the WAF engine out of service and back.</summary>
public sealed class FailClosedFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs => new RouteArgs().Add("catch-all", [("http", _backend!.Port)]).ToArray();

    internal WafEngineHolder Engines => App.Services.GetRequiredService<WafEngineHolder>();

    internal InMemoryAcmeChallengeStore AcmeStore => App.Services.GetRequiredService<InMemoryAcmeChallengeStore>();

    protected override async ValueTask AfterStopAsync()
    {
        if (_backend is not null)
        {
            await _backend.DisposeAsync();
        }
    }
}

public sealed class FailClosedTests(FailClosedFixture gateway) : IClassFixture<FailClosedFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    private Task<HttpResponseMessage> GetPublicAsync(string path) => _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"), Ct);

    private Task<HttpResponseMessage> GetAdminAsync(string path) => _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}{path}"), Ct);

    [Fact]
    public async Task Public_traffic_gets_503_while_the_engine_is_unavailable_and_recovers_after()
    {
        var engine = gateway.Engines.Current!;
        try
        {
            gateway.Engines.MarkUnavailable("test: engine taken out of service");

            using var refused = await GetPublicAsync("/products");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
            Assert.Equal(TimeSpan.FromSeconds(30), refused.Headers.RetryAfter?.Delta);
            Assert.Equal(FailClosedGuardMiddleware.UnavailableMessage, await refused.Content.ReadAsStringAsync(Ct));

            // The admin listener stays reachable and tells why.
            using var health = await GetAdminAsync("/healthz");
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            Assert.Equal("Degraded", await health.Content.ReadAsStringAsync(Ct));
        }
        finally
        {
            gateway.Engines.Activate(engine);
        }

        using var recovered = await GetPublicAsync("/products");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);

        using var healthy = await GetAdminAsync("/healthz");
        Assert.Equal("Healthy", await healthy.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Acme_challenges_are_answered_even_while_the_engine_is_unavailable()
    {
        var engine = gateway.Engines.Current!;
        gateway.AcmeStore.Add("token123", "token123.key-thumbprint");
        try
        {
            gateway.Engines.MarkUnavailable("test");

            using var response = await GetPublicAsync("/.well-known/acme-challenge/token123");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("token123.key-thumbprint", await response.Content.ReadAsStringAsync(Ct));
        }
        finally
        {
            gateway.Engines.Activate(engine);
            gateway.AcmeStore.Remove("token123");
        }
    }
}
