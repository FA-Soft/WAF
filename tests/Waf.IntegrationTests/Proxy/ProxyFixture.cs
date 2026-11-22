using System.Security.Cryptography.X509Certificates;

namespace Waf.IntegrationTests.Proxy;

/// <summary>
/// Gateway with routes to two HTTP backends (A, B), one HTTPS backend with a self-signed
/// certificate, and a port where nothing listens.
/// </summary>
public sealed class ProxyFixture : GatewayFixture
{
    private BackendServer? _a;
    private BackendServer? _b;
    private BackendServer? _tls;
    private X509Certificate2? _certificate;

    public BackendServer A => _a ?? throw new InvalidOperationException("Not started.");
    public BackendServer B => _b ?? throw new InvalidOperationException("Not started.");
    public BackendServer Tls => _tls ?? throw new InvalidOperationException("Not started.");

    /// <summary>A loopback port with no listener: connections are refused.</summary>
    public int DeadPort { get; } = FreePort();

    protected override async ValueTask BeforeStartAsync()
    {
        _certificate = BackendServer.CreateSelfSignedCertificate();
        _a = await BackendServer.StartAsync("A");
        _b = await BackendServer.StartAsync("B");
        _tls = await BackendServer.StartAsync("TLS", _certificate);
    }

    protected override IEnumerable<string> ExtraArgs => new RouteArgs()
        .Add("host-a", [("http", A.Port)], hosts: ["a.test"])
        .Add("host-b", [("http", B.Port)], hosts: ["b.test"])
        .Add("site-root", [("http", A.Port)], hosts: ["site.test"])
        .Add("site-api", [("http", B.Port)], hosts: ["site.test"], pathPrefix: "/api")
        .Add("post-only", [("http", B.Port)], hosts: ["post.test"], methods: ["POST"])
        .Add("no-preserve-host", [("http", A.Port)], hosts: ["rewrite.test"], preserveHost: false)
        .Add("websocket", [("http", A.Port)], pathPrefix: "/ws")
        .Add("tls-allowed", [("https", Tls.Port)], hosts: ["tls.test"], allowInvalidBackendCertificate: true)
        .Add("tls-strict", [("https", Tls.Port)], hosts: ["tls-strict.test"])
        .Add("balanced", [("http", A.Port), ("http", DeadPort)], hosts: ["lb.test"], healthPath: "/health", healthIntervalSeconds: 1)
        .Add("down", [("http", DeadPort)], hosts: ["down.test"])
        .ToArray();

    protected override async ValueTask AfterStopAsync()
    {
        foreach (var backend in new[] { _a, _b, _tls })
        {
            if (backend is not null)
            {
                await backend.DisposeAsync();
            }
        }

        _certificate?.Dispose();
    }
}
