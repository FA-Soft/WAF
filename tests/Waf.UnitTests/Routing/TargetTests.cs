using System.Text.Json.Nodes;
using FASoft.Waf.Ai;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Routing;

/// <summary>
/// Targets: named machines with labelled ports, which route destinations use instead of an address. Checked, resolved
/// to addresses at activation, compared, exported and offered to the AI assistant like the rest of the configuration.
/// </summary>
public sealed class TargetTests
{
    private static BackendTarget Nas(string address = "192.168.1.20") => new()
    {
        Name = "nas",
        Address = address,
        Ports = { new TargetPort { Name = "web", Port = 5000 }, new TargetPort { Name = "admin", Port = 5001, Scheme = "https" } },
    };

    private static ProxyRouteOptions Route(string name, params ProxyDestinationOptions[] destinations)
    {
        var route = new ProxyRouteOptions { Name = name, Match = { Hosts = { $"{name}.example.com" } } };
        foreach (var destination in destinations)
        {
            route.Destinations.Add(destination);
        }

        return route;
    }

    private static ProxyDestinationOptions To(string target, string port) => new() { Target = target, TargetPort = port };

    private static GatewayConfiguration Configuration(params ProxyRouteOptions[] routes)
    {
        var configuration = new GatewayConfiguration { Targets = { Nas() } };
        foreach (var route in routes)
        {
            configuration.Routes.Add(route);
        }

        return configuration;
    }

    [Fact]
    public void Target_destinations_resolve_to_the_targets_address_port_and_scheme()
    {
        var plain = Route("plain", new ProxyDestinationOptions { Address = "10.0.0.5", Port = 8080 });
        var configuration = Configuration(Route("files", To("NAS", "Web"), To("nas", "admin")), plain);

        var routes = TargetResolver.Resolve(configuration);

        var files = routes[0].Destinations;
        Assert.Equal(("http", "192.168.1.20", 5000, "nas", "web"), (files[0].Scheme, files[0].Address, files[0].Port, files[0].Target, files[0].TargetPort));
        Assert.Equal(("https", "192.168.1.20", 5001), (files[1].Scheme, files[1].Address, files[1].Port));
        Assert.Same(plain, routes[1]); // routes without targets are passed on as they are
        Assert.Empty(configuration.Routes[0].Destinations[0].Address); // the configuration itself is unchanged
        Assert.Empty(ProxyRouteValidator.Validate(routes)); // resolved routes are ordinary routes for the proxy
    }

    [Fact]
    public void Changing_the_address_in_one_place_changes_every_route_that_uses_it()
    {
        var configuration = Configuration(Route("files", To("nas", "web")), Route("backup", To("nas", "admin")));
        configuration.Targets[0].Address = "192.168.1.37";

        Assert.All(TargetResolver.Resolve(configuration), route => Assert.Equal("192.168.1.37", route.Destinations[0].Address));
    }

    [Fact]
    public void A_valid_configuration_with_targets_passes_validation()
    {
        Assert.Empty(GatewayConfigurationValidator.Validate(Configuration(Route("files", To("nas", "web")))));
    }

    [Theory]
    [InlineData("files", "nas", "nothing", "Route 'files': target 'nas' has no port 'nothing' (it has: web, admin).")]
    [InlineData("files", "printer", "web", "Route 'files': there is no target 'printer'.")]
    [InlineData("files", "nas", "", "Route 'files': a target destination needs both 'Target' and 'TargetPort'.")]
    public void Unknown_targets_and_ports_are_named_in_the_error(string route, string target, string port, string expected)
    {
        var errors = GatewayConfigurationValidator.Validate(Configuration(Route(route, To(target, port))));

        Assert.Contains(expected, errors);
    }

    [Fact]
    public void A_destination_with_a_target_and_an_address_is_refused()
    {
        var destination = To("nas", "web");
        destination.Address = "10.0.0.5";
        destination.Port = 80;

        var errors = GatewayConfigurationValidator.Validate(Configuration(Route("files", destination)));

        Assert.Contains(errors, e => e.Contains("use either a target or an address", StringComparison.Ordinal));
    }

    [Fact]
    public void Targets_and_their_ports_are_checked()
    {
        var configuration = new GatewayConfiguration
        {
            Targets =
            {
                Nas(),
                Nas("not an address"),
                new BackendTarget { Name = "bad name!", Address = "10.0.0.9" },
                new BackendTarget
                {
                    Name = "printer",
                    Address = "10.0.0.8",
                    Ports = { new TargetPort { Name = "web", Port = 0 }, new TargetPort { Name = "WEB", Port = 80, Scheme = "ftp" } },
                },
            },
        };

        var errors = GatewayConfigurationValidator.Validate(configuration);

        Assert.Contains("Target 'nas': the name is used by more than one target.", errors);
        Assert.Contains("Target 'nas': 'not an address' is not a valid IP address or host name.", errors);
        Assert.Contains("Target 'bad name!': the name may only contain letters, digits, '-', '_' and '.'.", errors);
        Assert.Contains("Target 'bad name!': at least one port is required.", errors);
        Assert.Contains("Target 'printer', port 'web': port must be between 1 and 65535 (was 0).", errors);
        Assert.Contains("Target 'printer', port 'WEB': the label is used by more than one port of this target.", errors);
        Assert.Contains("Target 'printer', port 'WEB': scheme must be 'http' or 'https' (was 'ftp').", errors);
    }

    [Fact]
    public void Configurations_without_targets_keep_their_exact_json()
    {
        // Stored versions are compared by the hash of their JSON: an upgrade must not change it.
        var json = GatewayConfigurationJson.Serialize(new GatewayConfiguration { Routes = { Route("plain", new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 }) } });

        Assert.DoesNotContain("Target", json, StringComparison.Ordinal);
        Assert.DoesNotContain("UsesTarget", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Targets_survive_export_and_import_unchanged()
    {
        var json = GatewayConfigurationJson.Serialize(Configuration(Route("files", To("nas", "web"))));

        var parsed = GatewayConfigurationJson.Parse(json);

        Assert.Empty(parsed.Errors);
        Assert.Equal(json, GatewayConfigurationJson.Serialize(parsed.Configuration!));
        Assert.Contains("\"TargetPort\": \"web\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("UsesTarget", json, StringComparison.Ordinal);
    }

    [Fact]
    public void A_changed_target_is_a_change_of_its_own()
    {
        var before = Configuration(Route("files", To("nas", "web")));
        var after = Configuration(Route("files", To("nas", "web")));
        after.Targets[0].Address = "192.168.1.37";

        var change = Assert.Single(ConfigurationDiff.Compare(before, after));

        Assert.Equal((ChangeKind.Changed, ConfigurationSection.Target, "nas"), (change.Kind, change.Section, change.Name));
        Assert.Equal("Change target 'nas'", Describe.ChangeTitle(change));
        Assert.Equal("192.168.1.37: web http://192.168.1.37:5000, admin https://192.168.1.37:5001", Describe.ChangeDetail(change, before, after));
    }

    [Fact]
    public void Route_descriptions_show_the_label_and_the_address_it_stands_for()
    {
        var configuration = Configuration();

        Assert.Equal("nas · web (http://192.168.1.20:5000), http://10.0.0.5:80",
            Describe.Destinations([To("nas", "web"), new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 }], configuration.Targets));
        Assert.Equal("printer · web", Describe.Destinations([To("printer", "web")], configuration.Targets));
    }

    [Fact]
    public void The_ai_summary_has_targets_only_when_there_are_any()
    {
        using var with = System.Text.Json.JsonDocument.Parse(ConfigurationSummary.Create(Configuration(Route("files", To("nas", "web")))));
        using var without = System.Text.Json.JsonDocument.Parse(ConfigurationSummary.Create(new GatewayConfiguration()));

        Assert.Equal("192.168.1.20", with.RootElement.GetProperty("Targets")[0].GetProperty("Address").GetString());
        Assert.False(without.RootElement.TryGetProperty("Targets", out _));
    }

    [Fact]
    public void The_ai_assistant_may_change_targets()
    {
        var proposal = new JsonObject { ["Targets"] = JsonNode.Parse(GatewayConfigurationJson.Serialize(new GatewayConfiguration { Targets = { Nas("192.168.1.37") } }))!["Targets"]!.DeepClone() };

        var merged = ConfigurationProposal.Merge(proposal.ToJsonString(), Configuration(Route("files", To("nas", "web"))));

        Assert.Empty(merged.Errors);
        Assert.Equal("192.168.1.37", GatewayConfigurationJson.Parse(merged.Json!).Configuration!.Targets[0].Address);
    }
}
