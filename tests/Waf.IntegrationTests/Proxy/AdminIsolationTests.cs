using System.Net;
using System.Net.Http.Json;

namespace Waf.IntegrationTests.Proxy;

/// <summary>Gateway with a catch-all route: every host and path on the public listener is proxied.</summary>
public sealed class CatchAllFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs =>
        new RouteArgs().Add("catch-all", [("http", _backend!.Port)]).ToArray();

    protected override async ValueTask AfterStopAsync()
    {
        if (_backend is not null)
        {
            await _backend.DisposeAsync();
        }
    }
}

public sealed class AdminIsolationTests(CatchAllFixture gateway) : IClassFixture<CatchAllFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    [Fact]
    public async Task Admin_listener_is_never_proxied_even_with_a_catch_all_route()
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/healthz"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Public_listener_proxies_admin_paths_to_the_backend()
    {
        var echo = await _http.GetFromJsonAsync<BackendEcho>(new Uri($"http://127.0.0.1:{gateway.HttpPort}/healthz"), Ct);

        Assert.Equal("A", echo!.Backend);
        Assert.Equal("/healthz", echo.Path);
    }
}
