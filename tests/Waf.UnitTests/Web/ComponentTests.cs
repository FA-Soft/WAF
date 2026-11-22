using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Waf.Engine;
using Waf.Web.Components;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Web;

public sealed class ComponentTests : BunitContext
{
    [Fact]
    public void HelpTip_is_an_accessible_disclosure_that_works_without_javascript()
    {
        var help = Render<HelpTip>(parameters => parameters
            .Add(p => p.Title, "Routes")
            .AddChildContent("<p>A route decides which backend receives a request.</p>"));

        var summary = help.Find("details.help > summary");
        Assert.Equal("Help: Routes", summary.GetAttribute("aria-label"));
        Assert.Contains("A route decides which backend receives a request.", help.Find(".help-body").TextContent, StringComparison.Ordinal);
        Assert.Null(help.Find("details").GetAttribute("open")); // closed until the user opens it
    }

    [Fact]
    public void FormField_links_label_help_and_input()
    {
        var field = Render<FormField<string>>(parameters => parameters
            .Add(p => p.Id, "path")
            .Add(p => p.Label, "Path")
            .Add(p => p.Help, "The part after the host name.")
            .Add(p => p.Optional, true)
            .AddChildContent("<input id=\"path\" aria-describedby=\"path-help\" />"));

        Assert.Equal("path", field.Find("label").GetAttribute("for"));
        Assert.Contains("(optional)", field.Find("label").TextContent, StringComparison.Ordinal);
        Assert.Equal("The part after the host name.", field.Find("#path-help").TextContent);
        Assert.Equal("path-help", field.Find("input").GetAttribute("aria-describedby"));
    }

    [Fact]
    public void FormField_without_help_renders_no_help_text()
    {
        var field = Render<FormField<string>>(parameters => parameters.Add(p => p.Id, "x").Add(p => p.Label, "X"));

        Assert.Empty(field.FindAll(".field-help"));
        Assert.DoesNotContain("(optional)", field.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public void State_badge_shows_unavailable_detection_only_and_protecting()
    {
        var engines = new WafEngineHolder();
        Services.AddSingleton(engines);

        engines.MarkUnavailable("broken configuration");
        var badge = Render<WafStateBadge>();
        Assert.Contains("Unavailable", badge.Find(".badge-danger").TextContent, StringComparison.Ordinal);
        Assert.Equal("broken configuration", badge.Find(".badge").GetAttribute("title"));

        var detectionOnly = Config();
        detectionOnly.Settings.DetectionOnly = true;
        engines.Activate(WafEngine.Build(detectionOnly));
        Assert.Equal("Detection only", Render<WafStateBadge>().Find(".badge-warning").TextContent);

        engines.Activate(WafEngine.Build(Config()));
        Assert.Equal("Protecting", Render<WafStateBadge>().Find(".badge-ok").TextContent);
    }
}
