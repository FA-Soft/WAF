using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Waf.Host.Hosting;

namespace Waf.IntegrationTests;

/// <summary>
/// Starts the real gateway (Kestrel, not TestServer) on free loopback ports.
/// Derived fixtures can start backends first and add configuration such as routes.
/// </summary>
public class GatewayFixture : IAsyncLifetime
{
    private WebApplication? _app;

    public int HttpPort { get; } = FreePort();
    public int HttpsPort { get; } = FreePort();
    public int AdminPort { get; } = FreePort();

    internal WebApplication App => _app ?? throw new InvalidOperationException("Gateway not started.");

    public string[] Args =>
    [
        $"--Gateway:Endpoints:HttpPort={HttpPort}",
        $"--Gateway:Endpoints:HttpsPort={HttpsPort}",
        $"--Gateway:Endpoints:AdminPort={AdminPort}",
        // Public listeners on loopback in tests: avoids firewall prompts and exposure.
        "--Gateway:Endpoints:PublicBindAddress=127.0.0.1",
    ];

    /// <summary>Extra command-line style configuration, e.g. routes.</summary>
    protected virtual IEnumerable<string> ExtraArgs => [];

    /// <summary>Runs before the gateway starts, e.g. to start backends.</summary>
    protected virtual ValueTask BeforeStartAsync() => ValueTask.CompletedTask;

    /// <summary>Runs after the gateway stopped, e.g. to stop backends.</summary>
    protected virtual ValueTask AfterStopAsync() => ValueTask.CompletedTask;

    public async ValueTask InitializeAsync()
    {
        await BeforeStartAsync();
        _app = GatewayApplication.Build([.. Args, .. ExtraArgs]);
        await _app.StartAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync(CancellationToken.None);
            await _app.DisposeAsync();
        }

        await AfterStopAsync();
        GC.SuppressFinalize(this);
    }

    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
