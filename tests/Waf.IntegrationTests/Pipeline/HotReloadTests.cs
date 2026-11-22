using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Waf.Core.Configuration;
using Waf.Core.Routing;
using Waf.Data;
using Waf.Host.Hosting;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>Configuration changes on a running gateway: file reload, atomic swaps, in-flight requests.</summary>
public sealed class HotReloadTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// Gateway whose routes come from the administrator settings file in its data folder, so tests can change
    /// the configuration by rewriting that file. Backends A and B.
    /// </summary>
    private sealed class Gateway : GatewayFixture
    {
        public BackendServer A { get; private set; } = null!;

        public BackendServer B { get; private set; } = null!;

        public HttpClient Http { get; } = new() { Timeout = TimeSpan.FromSeconds(15) };

        public string SettingsFile => Path.Combine(DataDirectory, "appsettings.json");

        public GatewayConfigurationService Configurations => App.Services.GetRequiredService<GatewayConfigurationService>();

        public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

        public AppSettingsWatcher Watcher => App.Services.GetServices<IHostedService>().OfType<AppSettingsWatcher>().Single();

        public Waf.Engine.ConfigurationStatus Status => App.Services.GetRequiredService<Waf.Engine.ConfigurationStatus>();

        protected override async ValueTask BeforeStartAsync()
        {
            A = await BackendServer.StartAsync("A");
            B = await BackendServer.StartAsync("B");
            Directory.CreateDirectory(DataDirectory);
            await WriteSettingsAsync(blockSecret: false);
        }

        /// <summary>Writes the administrator settings: a catch-all route to A, optionally a rule blocking /secret.</summary>
        public Task WriteSettingsAsync(bool blockSecret, bool broken = false) => File.WriteAllTextAsync(SettingsFile, $$"""
            {
              "Gateway": {
                "Routes": [
                  { "Name": "catch-all", "Destinations": [ { "Address": "{{(broken ? "10" : "127.0.0.1")}}", "Port": {{A.Port}} } ] }
                ],
                "Rules": [
                  {{(blockSecret ? """{ "Name": "no-secret", "Action": "Block", "Conditions": [ { "Field": "Path", "Operator": "StartsWith", "Values": [ "/secret" ] } ] }""" : "")}}
                ]
              }
            }
            """);

        public Task<HttpResponseMessage> GetAsync(string path) =>
            Http.GetAsync(new Uri($"http://127.0.0.1:{HttpPort}{path}"));

        public async Task<string> HealthAsync()
        {
            using var response = await Http.GetAsync(new Uri($"http://127.0.0.1:{AdminPort}/healthz"));
            return await response.Content.ReadAsStringAsync();
        }

        protected override async ValueTask AfterStopAsync()
        {
            Http.Dispose();
            await A.DisposeAsync();
            await B.DisposeAsync();
        }
    }

    /// <summary>Polls until <paramref name="condition"/> holds (file watchers are asynchronous).</summary>
    private static async Task EventuallyAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!await condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting until {what}.");
            await Task.Delay(100, Ct);
        }
    }

    private static async Task<HttpStatusCode> StatusAsync(Gateway gateway, string path)
    {
        using var response = await gateway.GetAsync(path);
        return response.StatusCode;
    }

    [Fact]
    public async Task Edited_settings_file_is_reported_but_not_applied_until_imported()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        Assert.Null(gateway.Status.AppSettingsNotice);

        await gateway.WriteSettingsAsync(blockSecret: true);

        await EventuallyAsync(() => Task.FromResult(gateway.Status.AppSettingsNotice is not null), "the edit is noticed");
        Assert.True(gateway.Status.AppSettingsNotice!.CanImport);
        Assert.Equal(HttpStatusCode.OK, await StatusAsync(gateway, "/secret")); // not applied: the database is the truth
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));

        var result = await gateway.Configurations.ImportAppSettingsAsync("test", Ct);

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        Assert.Equal((2, "Imported from appsettings."), (result.Version!.Version, result.Version.Comment));
        Assert.Equal(HttpStatusCode.Forbidden, await StatusAsync(gateway, "/secret"));
        Assert.Null(gateway.Status.AppSettingsNotice);

        await gateway.Watcher.CheckAsync(Ct); // the imported file is no longer "edited"
        Assert.Null(gateway.Status.AppSettingsNotice);
    }

    [Fact]
    public async Task Invalid_settings_file_is_reported_with_its_errors_and_can_be_dismissed()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        await gateway.WriteSettingsAsync(blockSecret: true, broken: true);

        await EventuallyAsync(() => Task.FromResult(gateway.Status.AppSettingsNotice is not null), "the edit is noticed");
        var notice = gateway.Status.AppSettingsNotice!;
        Assert.False(notice.CanImport);
        Assert.Contains(notice.Errors, e => e.Contains("'10' is not a valid IP address", StringComparison.Ordinal));
        Assert.False((await gateway.Configurations.ImportAppSettingsAsync("test", Ct)).Succeeded);
        Assert.Equal(HttpStatusCode.OK, await StatusAsync(gateway, "/"));

        await gateway.Configurations.DismissAppSettingsAsync(Ct);

        Assert.Null(gateway.Status.AppSettingsNotice);
        await gateway.Watcher.CheckAsync(Ct); // dismissed: stays quiet until the file is edited again
        Assert.Null(gateway.Status.AppSettingsNotice);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Unchanged_settings_file_gives_no_notice()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var engine = gateway.App.Services.GetRequiredService<Waf.Engine.WafEngineHolder>().Current;

        await gateway.Watcher.CheckAsync(Ct);

        Assert.Null(gateway.Status.AppSettingsNotice);
        Assert.Equal(1, await gateway.Store.CountAsync(Ct));
        Assert.Same(engine, gateway.App.Services.GetRequiredService<Waf.Engine.WafEngineHolder>().Current);
    }

    [Fact]
    public async Task In_flight_request_completes_on_the_configuration_it_started_with()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var slow = gateway.GetAsync("/slow?ms=1500");
        await Task.Delay(300, Ct); // the request is now inside backend A

        var change = (await gateway.Configurations.GetActiveAsync(Ct))!.Configuration;
        change.Routes[0].Destinations[0].Port = gateway.B.Port;
        Assert.True((await gateway.Configurations.ActivateAsync(change, "test", "Move to B", Ct)).Succeeded);

        using (var inFlight = await slow)
        {
            Assert.Equal(HttpStatusCode.OK, inFlight.StatusCode);
            Assert.Equal("A", (await inFlight.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend);
        }

        using var after = await gateway.GetAsync("/");
        Assert.Equal("B", (await after.Content.ReadFromJsonAsync<BackendEcho>(Ct))!.Backend);
    }

    [Fact]
    public async Task Load_during_repeated_swaps_has_no_errors_and_never_mixes_routes_and_rules()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var baseline = (await gateway.Configurations.GetActiveAsync(Ct))!.Configuration;

        // Variant with a route for /guarded to backend B, together with a rule that blocks everything on that
        // route. In any consistent configuration a request to /guarded never reaches B: either the route is
        // absent (catch-all → A) or the rule blocks it (403). B answering means routes and rules were mixed.
        var guarded = (await gateway.Configurations.GetActiveAsync(Ct))!.Configuration;
        var route = new ProxyRouteOptions { Name = "guarded" };
        route.Match.PathPrefix = "/guarded";
        route.Destinations.Add(new ProxyDestinationOptions { Address = "127.0.0.1", Port = gateway.B.Port });
        guarded.Routes.Add(route);
        var rule = new WafRule { Name = "block-guarded", Action = RuleAction.Block };
        rule.Routes.Add("guarded");
        var any = new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith };
        any.Values.Add("/");
        rule.Conditions.Add(any);
        guarded.Rules.Add(rule);

        var failures = new ConcurrentQueue<string>();
        var counts = new ConcurrentDictionary<string, int>();
        using var stop = new CancellationTokenSource();

        var clients = Enumerable.Range(0, 8).Select(i => Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                var path = i % 2 == 0 ? "/guarded/x" : "/products";
                try
                {
                    using var response = await gateway.GetAsync(path);
                    if (response.StatusCode == HttpStatusCode.Forbidden && path.StartsWith("/guarded", StringComparison.Ordinal))
                    {
                        counts.AddOrUpdate("blocked", 1, (_, n) => n + 1);
                        continue;
                    }

                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        failures.Enqueue($"{path}: {(int)response.StatusCode}");
                        continue;
                    }

                    var backend = (await response.Content.ReadFromJsonAsync<BackendEcho>())!.Backend;
                    counts.AddOrUpdate(backend, 1, (_, n) => n + 1);
                    if (backend == "B")
                    {
                        failures.Enqueue($"{path} reached B: new route was judged without its rule");
                    }
                }
                catch (HttpRequestException ex)
                {
                    failures.Enqueue($"{path}: {ex.Message}");
                }
            }
        })).ToArray();

        for (var swap = 0; swap < 40; swap++)
        {
            var next = swap % 2 == 0 ? guarded : baseline;
            var result = await gateway.Configurations.ActivateAsync(next, "load-test", $"swap {swap}", Ct);
            Assert.True(result.Succeeded, string.Join(" ", result.Errors));
            await Task.Delay(25, Ct);
        }

        await stop.CancelAsync();
        await Task.WhenAll(clients);

        Assert.Empty(failures);
        Assert.True(counts.GetValueOrDefault("A") > 0 && counts.GetValueOrDefault("blocked") > 0,
            $"Both configurations should have served traffic: {string.Join(", ", counts)}");
    }
}
