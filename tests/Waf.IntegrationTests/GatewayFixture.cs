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

    public int HttpPort { get; private set; } = FreePort();
    public int HttpsPort { get; private set; } = FreePort();
    public int AdminPort { get; private set; } = FreePort();

    internal WebApplication App => _app ?? throw new InvalidOperationException("Gateway not started.");

    /// <summary>A fresh, empty data folder for this gateway (config.db is created there).</summary>
    public string DataDirectory { get; } = NewDataDirectory();

    public string[] Args =>
    [
        $"--Gateway:Storage:DataDirectory={DataDirectory}",
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

        // FreePort releases the port before the gateway binds it; in that gap another test's outgoing connection
        // can take it (the OS hands out the same ephemeral ports). Then retry with new ports.
        for (var attempt = 1; ; attempt++)
        {
            _app = GatewayApplication.Build([.. Args, .. ExtraArgs]);
            try
            {
                await _app.StartAsync(TestContext.Current.CancellationToken);
                return;
            }
            catch (IOException ex) when (attempt < 5 && ex.Message.Contains("address already in use", StringComparison.OrdinalIgnoreCase))
            {
                await _app.DisposeAsync();
                _app = null;
                HttpPort = FreePort();
                HttpsPort = FreePort();
                AdminPort = FreePort();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync(CancellationToken.None);
            await _app.DisposeAsync();
        }

        await AfterStopAsync();
        DeleteDataDirectory(DataDirectory);
        GC.SuppressFinalize(this);
    }

    /// <summary>Path of a new, not yet existing folder under the temp directory.</summary>
    public static string NewDataDirectory() => Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));

    /// <summary>Deletes a test data folder; SQLite connection pools are cleared first so no file is locked.</summary>
    public static void DeleteDataDirectory(string path)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort: a leftover temp folder must not fail the test run.
        }
    }

    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
