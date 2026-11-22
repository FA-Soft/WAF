using System.Net;
using System.Net.Sockets;
using Waf.Host.Hosting;

namespace Waf.IntegrationTests;

public class StartupFailureTests
{
    [Fact]
    public async Task Run_returns_failure_exit_code_when_public_port_is_taken()
    {
        using var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        var takenPort = ((IPEndPoint)blocker.LocalEndpoint).Port;

        var exitCode = await GatewayApplication.RunAsync(
        [
            $"--Gateway:Storage:DataDirectory={GatewayFixture.NewDataDirectory()}",
            $"--Gateway:Endpoints:HttpPort={takenPort}",
            $"--Gateway:Endpoints:HttpsPort={GatewayFixture.FreePort()}",
            $"--Gateway:Endpoints:AdminPort={GatewayFixture.FreePort()}",
            "--Gateway:Endpoints:PublicBindAddress=127.0.0.1",
        ]);

        Assert.Equal(GatewayApplication.StartupFailureExitCode, exitCode);
    }

    [Fact]
    public async Task Run_returns_failure_exit_code_for_invalid_route()
    {
        var exitCode = await GatewayApplication.RunAsync(
        [
            $"--Gateway:Storage:DataDirectory={GatewayFixture.NewDataDirectory()}",
            $"--Gateway:Endpoints:HttpPort={GatewayFixture.FreePort()}",
            $"--Gateway:Endpoints:HttpsPort={GatewayFixture.FreePort()}",
            $"--Gateway:Endpoints:AdminPort={GatewayFixture.FreePort()}",
            "--Gateway:Endpoints:PublicBindAddress=127.0.0.1",
            "--Gateway:Routes:0:Name=broken",
            "--Gateway:Routes:0:Destinations:0:Address=10",
            "--Gateway:Routes:0:Destinations:0:Port=80",
        ]);

        Assert.Equal(GatewayApplication.StartupFailureExitCode, exitCode);
    }

    [Fact]
    public async Task Run_returns_failure_exit_code_when_the_data_folder_cannot_be_created()
    {
        // A file where the data folder should be: the folder cannot be created.
        var blocker = Path.Combine(Path.GetTempPath(), "waf-tests", $"not-a-folder-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.GetDirectoryName(blocker)!);
        await File.WriteAllTextAsync(blocker, "x", TestContext.Current.CancellationToken);
        try
        {
            var exitCode = await GatewayApplication.RunAsync(
            [
                $"--Gateway:Storage:DataDirectory={Path.Combine(blocker, "data")}",
                $"--Gateway:Endpoints:HttpPort={GatewayFixture.FreePort()}",
                $"--Gateway:Endpoints:HttpsPort={GatewayFixture.FreePort()}",
                $"--Gateway:Endpoints:AdminPort={GatewayFixture.FreePort()}",
                "--Gateway:Endpoints:PublicBindAddress=127.0.0.1",
            ]);

            Assert.Equal(GatewayApplication.StartupFailureExitCode, exitCode);
        }
        finally
        {
            File.Delete(blocker);
        }
    }

    [Fact]
    public async Task Run_returns_failure_exit_code_for_invalid_configuration()
    {
        var exitCode = await GatewayApplication.RunAsync(
        [
            $"--Gateway:Storage:DataDirectory={GatewayFixture.NewDataDirectory()}",
            "--Gateway:Endpoints:HttpPort=8080",
            "--Gateway:Endpoints:AdminPort=8080",
        ]);

        Assert.Equal(GatewayApplication.StartupFailureExitCode, exitCode);
    }
}
