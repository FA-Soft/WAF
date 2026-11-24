using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Host.Hosting;

namespace FASoft.Waf.IntegrationTests;

/// <summary>
/// Starts the real gateway (Kestrel, not TestServer) on free loopback ports.
/// Derived fixtures can start backends first and add configuration such as routes.
/// </summary>
public partial class GatewayFixture : IAsyncLifetime
{
    private WebApplication? _app;

    public GatewayFixture() => (HttpPort, HttpsPort, AdminPort) = ThreeFreePorts();

    public int HttpPort { get; private set; }
    public int HttpsPort { get; private set; }
    public int AdminPort { get; private set; }

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

    /// <summary>Changes to the gateway's services before it is built, e.g. a fake neighbour table.</summary>
    protected virtual void ConfigureServices(IServiceCollection services)
    {
    }

    /// <summary>Runs before the gateway starts, e.g. to start backends.</summary>
    protected virtual ValueTask BeforeStartAsync() => ValueTask.CompletedTask;

    /// <summary>Runs after the gateway started, e.g. to sign in to the admin UI.</summary>
    protected virtual ValueTask AfterStartAsync() => ValueTask.CompletedTask;

    /// <summary>Runs after the gateway stopped, e.g. to stop backends.</summary>
    protected virtual ValueTask AfterStopAsync() => ValueTask.CompletedTask;

    public async ValueTask InitializeAsync()
    {
        await BeforeStartAsync();

        // FreePort releases the port before the gateway binds it; in that gap another test's outgoing connection
        // can take it (the OS hands out the same ephemeral ports). Then retry with new ports.
        for (var attempt = 1; ; attempt++)
        {
            _app = GatewayApplication.Build([.. Args, .. ExtraArgs], ConfigureServices);
            try
            {
                await _app.StartAsync(TestContext.Current.CancellationToken);
                break;
            }
            catch (IOException ex) when (attempt < 5 && ex.Message.Contains("address already in use", StringComparison.OrdinalIgnoreCase))
            {
                await _app.DisposeAsync();
                _app = null;
                (HttpPort, HttpsPort, AdminPort) = ThreeFreePorts();
            }
        }

        await AfterStartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync(CancellationToken.None);
            await _app.DisposeAsync();
        }

        await AfterStopAsync();
        _accountGate.Dispose();
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

/// <summary>Three different free ports: all three listeners stay open until the last is chosen, so the OS cannot hand out one twice.</summary>
    private static (int, int, int) ThreeFreePorts()
    {
        var listeners = Enumerable.Range(0, 3).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToList();
        try
        {
            listeners.ForEach(l => l.Start());
            var ports = listeners.Select(l => ((IPEndPoint)l.LocalEndpoint).Port).ToList();
            return (ports[0], ports[1], ports[2]);
        }
        finally
        {
            listeners.ForEach(l => l.Dispose());
        }
    }

    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
    /// <summary>User name of the admin account that <see cref="SignInAsync"/> creates.</summary>
    public const string AdminUserName = "admin";

    /// <summary>Password of that account.</summary>
    public const string AdminPassword = "correct horse battery staple";

    private readonly SemaphoreSlim _accountGate = new(1, 1);
    private bool _adminCreated;

    /// <summary>
    /// Signs <paramref name="client"/> (with a cookie container) in to the admin UI. The first call creates the admin
    /// account, from this machine, as on a fresh install.
    /// </summary>
    public async Task SignInAsync(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        await _accountGate.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            var (path, handler) = _adminCreated ? ("/account/login", "login") : ("/account/setup", "setup");
            var page = await client.GetStringAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), TestContext.Current.CancellationToken);
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = SignInTokenPattern().Match(page).Groups["token"].Value,
                ["_handler"] = handler,
                ["Model.UserName"] = AdminUserName,
                ["Model.Password"] = AdminPassword,
                ["Model.ConfirmPassword"] = AdminPassword,
            });
            using var response = await client.PostAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), content, TestContext.Current.CancellationToken);
            var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            if (response.StatusCode != HttpStatusCode.OK || !html.Contains("Sign out", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Signing in to the admin UI failed ({(int)response.StatusCode}): {html}");
            }

            _adminCreated = true;
        }
        finally
        {
            _accountGate.Release();
        }
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex SignInTokenPattern();
}
