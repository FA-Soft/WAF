using System.Net;
using System.Net.Http.Json;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// Gateway with the full pipeline: a catch-all route, a Block rule for /blocked, an Allow rule for
/// trusted clients (header X-Trusted: yes), attack detection with body inspection.
/// </summary>
public sealed class PipelineFixture : GatewayFixture
{
    private BackendServer? _backend;

    protected override async ValueTask BeforeStartAsync() => _backend = await BackendServer.StartAsync("A");

    protected override IEnumerable<string> ExtraArgs =>
    [
        .. new RouteArgs().Add("catch-all", [("http", _backend!.Port)]).ToArray(),
        "--Gateway:Rules:0:Name=trusted",
        "--Gateway:Rules:0:Priority=1",
        "--Gateway:Rules:0:Action=Allow",
        "--Gateway:Rules:0:Conditions:0:Field=Header",
        "--Gateway:Rules:0:Conditions:0:HeaderName=X-Trusted",
        "--Gateway:Rules:0:Conditions:0:Operator=Equals",
        "--Gateway:Rules:0:Conditions:0:Values:0=yes",
        "--Gateway:Rules:1:Name=no-blocked",
        "--Gateway:Rules:1:Action=Block",
        "--Gateway:Rules:1:Conditions:0:Field=Path",
        "--Gateway:Rules:1:Conditions:0:Operator=StartsWith",
        "--Gateway:Rules:1:Conditions:0:Values:0=/blocked",
        "--Gateway:Settings:AttackDetection:InspectBody=true",
    ];

    protected override async ValueTask AfterStopAsync()
    {
        if (_backend is not null)
        {
            await _backend.DisposeAsync();
        }
    }
}

public sealed class PipelineTests(PipelineFixture gateway) : IClassFixture<PipelineFixture>, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _http.Dispose();

    private Uri Public(string pathAndQuery) => new($"http://127.0.0.1:{gateway.HttpPort}{pathAndQuery}");

    [Fact]
    public async Task Clean_request_is_proxied()
    {
        var echo = await _http.GetFromJsonAsync<BackendEcho>(Public("/products/42?color=red"), Ct);

        Assert.Equal("/products/42", echo!.Path);
    }

    [Fact]
    public async Task Block_rule_returns_403_without_reaching_the_backend()
    {
        using var response = await _http.GetAsync(Public("/blocked/area"), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("Forbidden. The request was blocked by the web application firewall.", await response.Content.ReadAsStringAsync(Ct));
    }

    [Theory]
    [InlineData("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--")]
    [InlineData("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]
    [InlineData("/files?name=..%2F..%2F..%2Fetc%2Fpasswd")]
    [InlineData("/ping?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd")]
    public async Task Attacks_are_blocked(string pathAndQuery)
    {
        using var response = await _http.GetAsync(Public(pathAndQuery), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Scanner_user_agent_is_blocked()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Public("/"));
        request.Headers.TryAddWithoutValidation("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)");

        using var response = await _http.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Trusted_client_allowed_by_rule_skips_attack_detection()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Public("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
        request.Headers.Add("X-Trusted", "yes");

        using var response = await _http.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Attack_in_a_form_body_is_blocked()
    {
        using var content = new FormUrlEncodedContent([new("user", "admin"), new("pass", "x' or '1'='1")]);

        using var response = await _http.PostAsync(Public("/login"), content, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Clean_body_is_forwarded_in_full_even_beyond_the_inspection_limit()
    {
        var large = new string('a', 200_000); // larger than the 64 KB inspection limit
        using var content = new StringContent(large, System.Text.Encoding.UTF8, "text/plain");

        using var response = await _http.PostAsync(Public("/upload"), content, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(large.Length, (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.BodyLength);
    }

    [Fact]
    public async Task Admin_listener_is_exempt_from_rules_and_detection()
    {
        using var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/healthz?q=%3Cscript%3E&x=/blocked"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync(Ct));
    }
}
