using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Waf.Data;
using Waf.Host.Hosting;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

public sealed class StorageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<StoredConfiguration?> LatestAsync(GatewayFixture gateway) =>
        await gateway.App.Services.GetRequiredService<ConfigurationStore>().GetLatestAsync(Ct);

    [Fact]
    public async Task Fresh_install_creates_the_database_and_stores_the_configuration()
    {
        await using var backend = await BackendServer.StartAsync("A");
        await using var gateway = new RoutedGateway(backend.Port, "first");
        await gateway.InitializeAsync();

        Assert.True(File.Exists(Path.Combine(gateway.DataDirectory, "config.db")));
        var stored = await LatestAsync(gateway);
        Assert.NotNull(stored);
        Assert.Equal(1, stored.Version);
        Assert.Equal(ConfigurationBootstrap.ImportAuthor, stored.Author);
        Assert.Equal("first", Assert.Single(stored.Configuration.Routes).Name);

        using var http = new HttpClient();
        using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{gateway.HttpPort}/"), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Restart_with_the_same_configuration_adds_no_version_and_a_change_adds_one()
    {
        await using var backend = await BackendServer.StartAsync("A");
        var dataDirectory = GatewayFixture.NewDataDirectory();
        try
        {
            await RunOnceAsync(backend.Port, "first", dataDirectory);
            await RunOnceAsync(backend.Port, "first", dataDirectory);
            var afterSecondStart = await RunOnceAsync(backend.Port, "renamed", dataDirectory);

            Assert.Equal(2, afterSecondStart.Version);
            Assert.Equal("renamed", Assert.Single(afterSecondStart.Configuration.Routes).Name);
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(dataDirectory);
        }
    }

    [Fact]
    public async Task Administrator_settings_file_in_the_config_folder_is_loaded()
    {
        await using var backend = await BackendServer.StartAsync("A");
        var dataDirectory = GatewayFixture.NewDataDirectory();
        Directory.CreateDirectory(dataDirectory);
        await File.WriteAllTextAsync(Path.Combine(dataDirectory, "appsettings.json"), $$"""
            {
              "Gateway": {
                "Routes": [
                  { "Name": "from-admin-file", "Destinations": [ { "Address": "127.0.0.1", "Port": {{backend.Port}} } ] }
                ]
              }
            }
            """, Ct);

        var gateway = new RoutedGateway(backendPort: null, routeName: null, dataDirectory);
        await gateway.InitializeAsync();
        try
        {
            Assert.Equal("from-admin-file", Assert.Single((await LatestAsync(gateway))!.Configuration.Routes).Name);

            using var http = new HttpClient();
            using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{gateway.HttpPort}/"), Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            await gateway.StopKeepingDataAsync();
            GatewayFixture.DeleteDataDirectory(dataDirectory);
        }
    }

    private static async Task<StoredConfiguration> RunOnceAsync(int backendPort, string routeName, string dataDirectory)
    {
        var gateway = new RoutedGateway(backendPort, routeName, dataDirectory);
        await gateway.InitializeAsync();
        try
        {
            return (await LatestAsync(gateway))!;
        }
        finally
        {
            await gateway.StopKeepingDataAsync();
        }
    }

    /// <summary>Gateway with one catch-all route, optionally on an existing data folder.</summary>
    private sealed class RoutedGateway(int? backendPort, string? routeName, string? dataDirectory = null) : GatewayFixture
    {
        protected override IEnumerable<string> ExtraArgs =>
        [
            .. routeName is null ? Array.Empty<string>() : new RouteArgs().Add(routeName, [("http", backendPort!.Value)]).ToArray(),
            .. dataDirectory is null ? Array.Empty<string>() : [$"--Gateway:Storage:DataDirectory={dataDirectory}"],
        ];

        /// <summary>Stops the gateway but keeps a shared data folder for the next start.</summary>
        public async Task StopKeepingDataAsync()
        {
            await App.StopAsync(CancellationToken.None);
            await App.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }
    }
}
