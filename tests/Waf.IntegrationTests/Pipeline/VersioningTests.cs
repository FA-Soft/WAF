using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Core.Routing;
using Waf.Data;
using Waf.Engine;
using Waf.Host.Hosting;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// Activation, rejection and rollback of configurations on a running gateway. Every test uses its own
/// gateway and database, so tests cannot affect each other.
/// </summary>
public sealed class VersioningTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Gateway with backends A and B and one catch-all route to A.</summary>
    private sealed class Gateway : GatewayFixture
    {
        private readonly string? _dataDirectory;
        private readonly bool _invalidRoute;
        private readonly bool _ownsBackends;

        /// <param name="dataDirectory">Existing data folder to (re)use; a fresh one when null.</param>
        /// <param name="invalidRoute">Start with a broken route in appsettings.</param>
        /// <param name="shareBackendsWith">Reuse the backends of another gateway (so stored routes stay valid).</param>
        public Gateway(string? dataDirectory = null, bool invalidRoute = false, Gateway? shareBackendsWith = null)
        {
            _dataDirectory = dataDirectory;
            _invalidRoute = invalidRoute;
            _ownsBackends = shareBackendsWith is null;
            if (shareBackendsWith is not null)
            {
                A = shareBackendsWith.A;
                B = shareBackendsWith.B;
            }
        }

        public BackendServer A { get; private set; } = null!;

        public BackendServer B { get; private set; } = null!;

        public HttpClient Http { get; } = new() { Timeout = TimeSpan.FromSeconds(10) };

        public GatewayConfigurationService Configurations => App.Services.GetRequiredService<GatewayConfigurationService>();

        public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

        protected override async ValueTask BeforeStartAsync()
        {
            if (_ownsBackends)
            {
                A = await BackendServer.StartAsync("A");
                B = await BackendServer.StartAsync("B");
            }
        }

        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("catch-all", [("http", A.Port)]).ToArray(),
            .. _invalidRoute ? ["--Gateway:Routes:0:Destinations:0:Address=10"] : Array.Empty<string>(),
            .. _dataDirectory is null ? Array.Empty<string>() : [$"--Gateway:Storage:DataDirectory={_dataDirectory}"],
        ];

        public async Task<HttpResponseMessage> GetAsync(string path, string? host = null, string? forwardedFor = null)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}{path}"));
            if (host is not null)
            {
                request.Headers.Host = host;
            }

            if (forwardedFor is not null)
            {
                request.Headers.Add("X-Forwarded-For", forwardedFor);
            }

            return await Http.SendAsync(request, Ct);
        }

        /// <summary>A modifiable copy of the running configuration.</summary>
        public async Task<GatewayConfiguration> ActiveCopyAsync() => (await Configurations.GetActiveAsync(Ct))!.Configuration;

        protected override async ValueTask AfterStopAsync()
        {
            Http.Dispose();
            if (_ownsBackends)
            {
                await A.DisposeAsync();
                await B.DisposeAsync();
            }
        }

        /// <summary>Stops the gateway; keeps the data folder and, if <paramref name="keepBackends"/>, the backends.</summary>
        public async Task StopKeepingDataAsync(bool keepBackends = false)
        {
            await App.StopAsync(CancellationToken.None);
            await App.DisposeAsync();
            Http.Dispose();
            if (_ownsBackends && !keepBackends)
            {
                await A.DisposeAsync();
                await B.DisposeAsync();
            }

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }
    }

    private static WafRule BlockPath(string name, string prefix)
    {
        var rule = new WafRule { Name = name, Action = RuleAction.Block };
        var condition = new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith };
        condition.Values.Add(prefix);
        rule.Conditions.Add(condition);
        return rule;
    }

    [Fact]
    public async Task Valid_change_is_stored_activated_and_becomes_last_known_good()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var change = await gateway.ActiveCopyAsync();
        change.Rules.Add(BlockPath("no-secret", "/secret"));

        var result = await gateway.Configurations.ActivateAsync(change, "frank", "Block /secret", Ct);

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        Assert.Equal(2, result.Version!.Version);
        Assert.Equal(("frank", "Block /secret"), (result.Version.Author, result.Version.Comment));
        Assert.Equal(2, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version);
        using var blocked = await gateway.GetAsync("/secret/file");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
    }

    [Fact]
    public async Task Invalid_change_is_rejected_and_never_becomes_active()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var engineBefore = gateway.App.Services.GetRequiredService<WafEngineHolder>().Current;
        var change = await gateway.ActiveCopyAsync();
        change.Rules.Add(BlockPath("no-secret", "/secret"));
        change.Rules.Add(new WafRule { Name = "broken" }); // no conditions: invalid

        var result = await gateway.Configurations.ActivateAsync(change, "frank", null, Ct);

        Assert.False(result.Succeeded);
        Assert.Null(result.Version);
        Assert.Contains(result.Errors, e => e.Contains("Rule 'broken': at least one condition", StringComparison.Ordinal));
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
        Assert.Equal(1, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version);
        Assert.Same(engineBefore, gateway.App.Services.GetRequiredService<WafEngineHolder>().Current);
        using var stillAllowed = await gateway.GetAsync("/secret/file");
        Assert.Equal(HttpStatusCode.OK, stillAllowed.StatusCode); // the valid half was not applied either
    }

    [Fact]
    public async Task Route_changes_are_applied_to_the_running_proxy()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var change = await gateway.ActiveCopyAsync();
        var toB = new ProxyRouteOptions { Name = "b-site" };
        toB.Match.Hosts.Add("b.test");
        toB.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = gateway.B.Port });
        change.Routes.Add(toB);

        Assert.True((await gateway.Configurations.ActivateAsync(change, "frank", "Add b.test", Ct)).Succeeded);

        using var response = await gateway.GetAsync("/", host: "b.test");
        Assert.Equal("B", (await response.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend);
    }

    [Fact]
    public async Task Trusted_proxies_change_together_with_the_configuration()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using (var before = await gateway.GetAsync("/", forwardedFor: "203.0.113.7"))
        {
            Assert.Equal("127.0.0.1", (await before.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.XForwardedFor);
        }

        var change = await gateway.ActiveCopyAsync();
        change.Settings.TrustedProxies.Add("127.0.0.1");
        Assert.True((await gateway.Configurations.ActivateAsync(change, "frank", null, Ct)).Succeeded);

        using var after = await gateway.GetAsync("/", forwardedFor: "203.0.113.7");
        Assert.Equal("203.0.113.7", (await after.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.XForwardedFor);
    }

    [Fact]
    public async Task Rollback_restores_the_previous_behavior_as_a_new_version()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var change = await gateway.ActiveCopyAsync();
        change.Rules.Add(BlockPath("no-secret", "/secret"));
        await gateway.Configurations.ActivateAsync(change, "frank", "Block /secret", Ct);
        using (var blocked = await gateway.GetAsync("/secret"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        }

        var result = await gateway.Configurations.RollbackAsync(1, "frank", Ct);

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        Assert.Equal(3, result.Version!.Version);
        Assert.Equal("Rollback to version 1.", result.Version.Comment);
        Assert.Equal(3, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version);
        Assert.Equal(["Rollback to version 1.", "Block /secret", "Imported from appsettings at startup."],
            (await gateway.Configurations.GetHistoryAsync(10, Ct)).Select(v => v.Comment));
        using var restored = await gateway.GetAsync("/secret");
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
    }

    [Fact]
    public async Task Rollback_to_a_missing_version_changes_nothing()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var result = await gateway.Configurations.RollbackAsync(99, "frank", Ct);

        Assert.False(result.Succeeded);
        Assert.Equal(["Configuration version 99 does not exist."], result.Errors);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Invalid_appsettings_at_startup_falls_back_to_the_last_known_good()
    {
        var dataDirectory = GatewayFixture.NewDataDirectory();
        try
        {
            var first = new Gateway(dataDirectory);
            await first.InitializeAsync();
            var change = await first.ActiveCopyAsync();
            change.Rules.Add(BlockPath("no-secret", "/secret"));
            await first.Configurations.ActivateAsync(change, "frank", "Block /secret", Ct);
            await first.StopKeepingDataAsync(keepBackends: true);

            // Restart with a broken route in appsettings: the last-known-good (version 2) must run.
            var second = new Gateway(dataDirectory, invalidRoute: true, shareBackendsWith: first);
            await second.InitializeAsync();
            try
            {
                Assert.Equal(2, (await second.Store.GetLastKnownGoodAsync(Ct))!.Version);
                Assert.Equal(2, await second.Store.CountAsync(Ct)); // the invalid configuration was not stored
                using var proxied = await second.GetAsync("/");
                Assert.Equal(HttpStatusCode.OK, proxied.StatusCode);
                using var blocked = await second.GetAsync("/secret");
                Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
            }
            finally
            {
                await second.StopKeepingDataAsync();
                await first.A.DisposeAsync();
                await first.B.DisposeAsync();
            }
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(dataDirectory);
        }
    }
}
