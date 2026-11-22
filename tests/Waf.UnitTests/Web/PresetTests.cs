using System.Text.RegularExpressions;
using Waf.Core.Configuration;
using Waf.Web;

namespace Waf.UnitTests.Web;

public class PresetTests
{
    private static GatewayConfiguration Example()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        var json = File.ReadAllText(Path.Combine(directory!.FullName, "schemas", "gateway-config.example.json"));
        return GatewayConfigurationJson.Parse(json).Configuration!;
    }

    private static PresetFormModel Inputs(Preset preset, GatewayConfiguration configuration)
    {
        var model = Presets.NewModel(preset, configuration.Routes.Select(r => r.Name));
        model.AllowedIps = "203.0.113.0/24\n2001:db8::/48";
        return model;
    }

    public static TheoryData<string> PresetIds => [.. Presets.All.Select(p => p.Id)];

    [Theory]
    [MemberData(nameof(PresetIds))]
    public void Every_preset_gives_a_valid_configuration_and_is_idempotent(string id)
    {
        var preset = Presets.Find(id)!;
        var running = Example();
        running.Settings.AttackDetection.CommandInjection = false;

        var preview = Presets.Preview(preset, Inputs(preset, running), running);

        Assert.Empty(preview.InputProblems);
        Assert.Empty(preview.ValidationErrors);
        Assert.NotEmpty(preview.Changes);
        Assert.True(preview.CanApply);
        Assert.Matches("^[0-9a-f]{16}$", preview.Tag);

        var again = Presets.Preview(preset, Inputs(preset, running), preview.Candidate!);
        Assert.Empty(again.Changes);
        Assert.False(again.CanApply);
    }

    [Fact]
    public void Preview_does_not_change_the_running_configuration()
    {
        var running = Example();
        var before = GatewayConfigurationJson.Serialize(running);

        Presets.Preview(Presets.Find("block-common-attacks")!, new PresetFormModel(), running);

        Assert.Equal(before, GatewayConfigurationJson.Serialize(running));
    }

    [Fact]
    public void Block_common_attacks_switches_on_detection_and_adds_two_rules()
    {
        var running = Example();
        running.Settings.AttackDetection.Enabled = false;

        var preview = Presets.Preview(Presets.Find("block-common-attacks")!, new PresetFormModel(), running);

        Assert.Equal(
            [(ChangeKind.Changed, "AttackDetection.Enabled"), (ChangeKind.Added, "block-sensitive-files"), (ChangeKind.Added, "block-unusual-methods")],
            preview.Changes.Select(c => (c.Kind, c.Name)));
    }

    [Theory]
    [InlineData("/.git/config", true)]
    [InlineData("/app/.env", true)]
    [InlineData("/.env.production", true)]
    [InlineData("/.htaccess", true)]
    [InlineData("/.hg/store", true)]
    [InlineData("/.DS_Store", true)]
    [InlineData("/index.php.bak", true)]
    [InlineData("/backup.zip", true)]
    [InlineData("/files/db.sql", true)]
    [InlineData("/downloads/manual.zip", false)]
    [InlineData("/bakery", false)]
    [InlineData("/.well-known/acme-challenge/x", false)]
    [InlineData("/environment", false)]
    [InlineData("/docs/.gitignore-guide", false)]
    public void Sensitive_files_pattern(string path, bool blocked)
    {
        Assert.Equal(blocked, Regex.IsMatch(path, Presets.SensitiveFilesPattern, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking));
    }

    [Fact]
    public void Lock_path_needs_valid_ip_addresses_and_a_path()
    {
        var preset = Presets.Find("lock-path")!;
        var model = Presets.NewModel(preset, []);
        model.PathPrefix = "admin";
        model.AllowedIps = "10.0.0.256";

        var preview = Presets.Preview(preset, model, Example());

        Assert.Null(preview.Candidate);
        Assert.False(preview.CanApply);
        Assert.Equal(2, preview.InputProblems.Count);
        Assert.Contains("must start with /", preview.InputProblems[0], StringComparison.Ordinal);
        Assert.StartsWith("'10.0.0.256'", preview.InputProblems[1], StringComparison.Ordinal);

        model.AllowedIps = null;
        Assert.Contains(Presets.Preview(preset, model, Example()).InputProblems, p => p.StartsWith("Enter at least one IP", StringComparison.Ordinal));
    }

    [Fact]
    public void Lock_path_rule_uses_the_inputs()
    {
        var preset = Presets.Find("lock-path")!;
        var model = Presets.NewModel(preset, ["website", "api"]);
        model.PathPrefix = " /Manage ";
        model.AllowedIps = "203.0.113.7, 198.51.100.0/24";
        model.DetectionOnly = true;
        model.RouteChoices[0].Selected = true;

        var rule = Presets.Preview(preset, model, Example()).Candidate!.Rules.Single(r => r.Name == "lock-manage");

        Assert.Equal("The path starts with /Manage and the client IP is not in 203.0.113.7 or 198.51.100.0/24", Describe.Conditions(rule.Conditions));
        Assert.True(rule.DetectionOnly);
        Assert.Equal(["website"], rule.Routes);
        Assert.Equal((RuleAction.Block, 10), (rule.Action, rule.Priority));
    }

    [Fact]
    public void Preview_tag_changes_with_the_inputs()
    {
        var preset = Presets.Find("protect-login")!;
        var running = Example();
        var model = Presets.NewModel(preset, []);
        var first = Presets.Preview(preset, model, running).Tag;

        model.PermitLimit = 5;

        Assert.NotEqual(first, Presets.Preview(preset, model, running).Tag);
        Assert.Equal(Presets.Preview(preset, model, running).Tag, Presets.Preview(preset, model, running).Tag);
    }

    [Fact]
    public void Existing_item_with_the_same_name_is_replaced_in_place()
    {
        var preset = Presets.Find("limit-per-client")!;
        var running = Example();
        var index = running.RateLimits.ToList().FindIndex(l => l.Name == "per-client");
        var model = Presets.NewModel(preset, []);
        model.PermitLimit = 120;

        var preview = Presets.Preview(preset, model, running);

        var change = Assert.Single(preview.Changes);
        Assert.Equal((ChangeKind.Changed, ConfigurationSection.RateLimit, "per-client"), (change.Kind, change.Section, change.Name));
        Assert.Equal(120, preview.Candidate!.RateLimits[index].PermitLimit);
        Assert.Equal(running.RateLimits.Count, preview.Candidate.RateLimits.Count);
    }

    [Theory]
    [InlineData("/admin", "lock-admin")]
    [InlineData("/", "lock-site")]
    [InlineData("/Beheer/Users_2", "lock-beheer-users-2")]
    public void Lock_rule_names(string path, string name)
    {
        Assert.Equal(name, Presets.LockRuleName(path));
    }

    [Fact]
    public void Changes_are_described_in_plain_language()
    {
        var running = Example();
        running.Settings.AttackDetection.SqlInjection = false;
        var preview = Presets.Preview(Presets.Find("block-common-attacks")!, new PresetFormModel(), running);

        var lines = preview.Changes.Select(c => $"{Describe.ChangeTitle(c)}: {Describe.ChangeDetail(c, running, preview.Candidate!)}").ToList();

        Assert.Equal("Change setting: SQL injection detection: off → on", lines[0]);
        Assert.Equal("Add rule 'block-unusual-methods': The method is TRACE or TRACK → Block (priority 20)", lines[2]);
    }
}
