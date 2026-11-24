using System.ComponentModel.DataAnnotations;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

/// <summary>The target editor, and targets in the route editor ("nas/web" lines and "Add a target").</summary>
public sealed class TargetEditingTests
{
    [Theory]
    [InlineData("nas/web", "nas", "web")]
    [InlineData("  nas / admin ", "nas", "admin")]
    [InlineData("nas · web", "nas", "web")]
    public void Route_editor_lines_name_a_target_and_port_label(string line, string target, string port)
    {
        Assert.True(RouteFormModel.TryParseDestination(line, out var destination, out var error), error);

        Assert.Equal((target, port, string.Empty, 0), (destination.Target, destination.TargetPort, destination.Address, destination.Port));
        Assert.Equal($"{target}/{port}", RouteFormModel.FormatDestination(destination));
    }

    [Theory]
    [InlineData("10.0.0.5:8080")]
    [InlineData("http://nas:8080")]
    [InlineData("backend")]
    public void Addresses_are_still_addresses(string line)
    {
        Assert.True(RouteFormModel.TryParseDestination(line, out var destination, out _));
        Assert.False(destination.UsesTarget);
    }

    [Theory]
    [InlineData("http://nas/web")]
    [InlineData("nas/web/extra")]
    [InlineData("nas/")]
    public void Other_slashes_are_not_targets(string line)
    {
        Assert.False(RouteFormModel.TryParseTarget(line, out _, out _));
    }

    [Fact]
    public void Add_a_target_appends_its_line_once_without_saving()
    {
        var form = new RouteFormModel { Destinations = "http://10.0.0.5:80", Command = "add-target", AddTarget = "nas/web" };

        Assert.True(form.TryApplyCommand());
        form.Command = "add-target";
        form.AddTarget = "NAS/web";
        Assert.True(form.TryApplyCommand());

        Assert.Equal(["http://10.0.0.5:80", "nas/web"], form.Destinations.Split(Environment.NewLine));
        Assert.Null(form.Command);
        Assert.False(new RouteFormModel { Command = null }.TryApplyCommand()); // Save
    }

    [Fact]
    public void The_target_form_checks_its_ports()
    {
        var form = new TargetFormModel
        {
            Name = "nas",
            Address = "192.168.1.20",
            Ports = [new TargetPortFormModel { Name = "web", Port = 5000 }, new TargetPortFormModel { Name = "WEB", Port = 70000 }],
        };

        var results = new List<ValidationResult>();
        Validator.TryValidateObject(form, new ValidationContext(form), results, validateAllProperties: true);

        Assert.Equal(
            ["Port 2: the label 'WEB' is used twice.", "Port 2: the port must be a number from 1 to 65535."],
            results.Select(r => r.ErrorMessage));
    }

    [Fact]
    public void Empty_port_rows_are_ignored_and_https_sets_the_scheme()
    {
        var form = new TargetFormModel
        {
            Name = " nas ",
            Address = "NAS.local",
            Ports = [new TargetPortFormModel { Name = "admin", Port = 5001, Https = true }, new TargetPortFormModel()],
        };

        var target = form.ToTarget();

        Assert.Equal(("nas", "nas.local"), (target.Name, target.Address));
        var port = Assert.Single(target.Ports);
        Assert.Equal(("admin", 5001, "https"), (port.Name, port.Port, port.Scheme));
    }

    [Fact]
    public void Port_rows_are_added_and_removed_without_saving()
    {
        var form = TargetFormModel.ForNewTarget(1);
        form.Command = "add-port";
        Assert.True(form.TryApplyCommand());
        Assert.Equal(2, form.Ports.Count);

        form.Command = "remove-port-0";
        Assert.True(form.TryApplyCommand());
        form.Command = "remove-port-0";
        Assert.True(form.TryApplyCommand());

        Assert.Single(form.Ports); // never zero rows
    }

    [Fact]
    public void Renaming_a_target_or_a_port_label_renames_it_in_its_routes()
    {
        var configuration = new GatewayConfiguration
        {
            Targets = { new BackendTarget { Name = "nas", Address = "192.168.1.20", Ports = { new TargetPort { Name = "web", Port = 5000 } } } },
            Routes =
            {
                new ProxyRouteOptions { Name = "files", Destinations = { new ProxyDestinationOptions { Target = "nas", TargetPort = "web" } } },
                new ProxyRouteOptions { Name = "other", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } },
            },
        };
        var form = TargetFormModel.FromTarget(configuration.Targets[0], 4);
        form.Name = "storage";
        form.Ports[0].Name = "http";

        Assert.Null(TargetEditing.Apply(configuration, form));

        var destination = configuration.Routes[0].Destinations[0];
        Assert.Equal(("storage", "http"), (destination.Target, destination.TargetPort));
        Assert.Equal("storage", Assert.Single(configuration.Targets).Name);
        Assert.Empty(GatewayConfigurationValidator.Validate(configuration));
        Assert.Equal(["Route 'files' (port http)"], TargetEditing.References(configuration, "STORAGE"));
    }

    [Fact]
    public void A_name_that_is_taken_is_refused()
    {
        var configuration = new GatewayConfiguration
        {
            Targets =
            {
                new BackendTarget { Name = "nas", Address = "192.168.1.20", Ports = { new TargetPort { Name = "web", Port = 5000 } } },
                new BackendTarget { Name = "iis", Address = "127.0.0.1", Ports = { new TargetPort { Name = "web", Port = 8080 } } },
            },
        };
        var renamed = TargetFormModel.FromTarget(configuration.Targets[1], 4);
        renamed.Name = "NAS";

        Assert.Equal("A target named 'NAS' already exists. Choose another name.", TargetEditing.Apply(configuration, renamed));
        Assert.Equal("A target named 'nas' already exists. Choose another name.", TargetEditing.Apply(configuration, new TargetFormModel { Name = "nas", Address = "10.0.0.1" }));
    }
}
