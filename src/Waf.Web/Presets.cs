using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Net;

namespace FASoft.Waf.Web;

/// <summary>The inputs a preset asks for.</summary>
[Flags]
internal enum PresetInputs
{
    None = 0,
    PathPrefix = 1,
    AllowedIps = 2,
    PermitLimit = 4,
    DetectionOnly = 8,
    Routes = 16,
}

/// <summary>Form model of the preset page: the preset's inputs plus the preview the user saw.</summary>
internal sealed class PresetFormModel
{
    /// <summary>"preview" or "apply"; set by the button that was pressed.</summary>
    public string? Command { get; set; }

    /// <summary>The <see cref="PresetPreview.Tag"/> the user saw; Apply only works when it is still the same.</summary>
    public string? PreviewTag { get; set; }

    public string? PathPrefix { get; set; }

    /// <summary>IP addresses and ranges, one per line (or separated by commas or spaces).</summary>
    public string? AllowedIps { get; set; }

    public int PermitLimit { get; set; }

    // Checkbox: an unticked box is not posted, so the default must be false.
    public bool DetectionOnly { get; set; }

    // The form binder sets lists to null when nothing was posted for them (e.g. there are no routes).
    public List<RouteChoice> RouteChoices { get => field; set => field = value ?? []; } = [];

    public IReadOnlyList<string> SelectedRoutes => [.. RouteChoices.Where(r => r.Selected).Select(r => r.Name)];

    public IReadOnlyList<string> IpList =>
        (AllowedIps ?? string.Empty).Split(['\n', '\r', ',', ' ', '\t', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// A one-click preset: a ready-made change to the configuration (e.g. block common attacks). Applying it always
/// shows a preview of the exact changes first. Presets add or replace items by name, so applying one twice changes
/// nothing the second time.
/// </summary>
/// <param name="Id">Used in the URL: <c>presets/{id}</c>.</param>
/// <param name="Title">Short name.</param>
/// <param name="Summary">One sentence for the library.</param>
/// <param name="Details">What exactly it does, shown on the preset page.</param>
/// <param name="Inputs">The inputs the user fills in.</param>
/// <param name="Defaults">Fills the inputs of a new form.</param>
/// <param name="Apply">Changes the configuration (a copy); returns problems with the inputs, empty when they are fine.</param>
internal sealed record Preset(
    string Id,
    string Title,
    string Summary,
    string Details,
    PresetInputs Inputs,
    Action<PresetFormModel> Defaults,
    Func<PresetFormModel, GatewayConfiguration, IReadOnlyList<string>> Apply)
{
    public bool Asks(PresetInputs input) => (Inputs & input) == input;
}

/// <summary>What applying a preset would do to the running configuration.</summary>
/// <param name="Candidate">The configuration after applying; null when the inputs have problems.</param>
/// <param name="InputProblems">Problems with the user's inputs.</param>
/// <param name="ValidationErrors">Why the resulting configuration would be rejected.</param>
/// <param name="Changes">The differences with the running configuration.</param>
/// <param name="Tag">Identifies exactly this result, so Apply saves what the user saw and nothing else.</param>
internal sealed record PresetPreview(
    GatewayConfiguration? Candidate,
    IReadOnlyList<string> InputProblems,
    IReadOnlyList<string> ValidationErrors,
    IReadOnlyList<ConfigurationChange> Changes,
    string? Tag)
{
    public bool CanApply => Candidate is not null && InputProblems.Count == 0 && ValidationErrors.Count == 0 && Changes.Count > 0;
}

/// <summary>The one-click presets.</summary>
internal static class Presets
{
    /// <summary>
    /// Hidden files and leftovers that should never be public: version control and editor folders, .env files,
    /// backup copies (*.bak, *.old, …) and database or site dumps. Attack detection already catches some of these;
    /// the rule also covers the rest and keeps working when that detector is switched off or excluded.
    /// </summary>
    public const string SensitiveFilesPattern =
        @"(^|/)(\.git|\.svn|\.hg|\.bzr|\.env[^/]*|\.htaccess|\.htpasswd|\.DS_Store|\.idea|\.vscode)(/|$)"
        + @"|\.(bak|old|orig|swp)$"
        + @"|(^|/)(backup|dump|database|db)\.(sql|zip|tar|tgz|gz|7z|rar)$";

    public static readonly IReadOnlyList<Preset> All =
    [
        new(
            "block-common-attacks",
            "Block common attacks",
            "Switch on every attack detector and block probes for hidden files and unusual methods.",
            "Switches on detection of SQL injection, cross-site scripting, path traversal, command injection and attack tools, "
                + "and adds two rules: one blocks requests for hidden files and leftovers that should never be public (.git, .env, "
                + "backup copies such as index.php.bak, dumps such as backup.zip), "
                + "one blocks the TRACE and TRACK methods that are only used to probe servers.",
            PresetInputs.None,
            _ => { },
            (_, configuration) =>
            {
                var detection = configuration.Settings.AttackDetection;
                detection.Enabled = true;
                detection.SqlInjection = true;
                detection.CrossSiteScripting = true;
                detection.PathTraversal = true;
                detection.CommandInjection = true;
                detection.BadUserAgents = true;

                Upsert(configuration.Rules, Rule(
                    "block-sensitive-files", "Hidden files, backup copies and dumps must never be public.", 20,
                    new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.Regex, Values = { SensitiveFilesPattern } }));
                Upsert(configuration.Rules, Rule(
                    "block-unusual-methods", "TRACE and TRACK are only used to probe servers.", 20,
                    new RuleCondition { Field = ConditionField.Method, Operator = ConditionOperator.Equals, Values = { "TRACE", "TRACK" } }));
                return [];
            }),

        new(
            "lock-path",
            "Lock a path to your IP addresses",
            "Only your own IP addresses may open a path such as /admin; everyone else gets 403.",
            "Adds a rule that blocks the path for every client IP that is not in your list. Enter your office or VPN "
                + "addresses. Rules with a lower priority number, such as an IP allow list, still run first.",
            PresetInputs.PathPrefix | PresetInputs.AllowedIps | PresetInputs.DetectionOnly | PresetInputs.Routes,
            m => m.PathPrefix = "/admin",
            (m, configuration) =>
            {
                var problems = new List<string>();
                var path = CheckPath(m.PathPrefix, problems);
                var ips = m.IpList;
                if (ips.Count == 0)
                {
                    problems.Add("Enter at least one IP address or range that may still open the path, e.g. 203.0.113.0/24.");
                }

                foreach (var ip in ips)
                {
                    if (!StrictCidr.TryParse(ip, out _, out var reason))
                    {
                        problems.Add($"'{ip}': {reason}.");
                    }
                }

                if (problems.Count > 0)
                {
                    return problems;
                }

                var ipCondition = new RuleCondition { Field = ConditionField.ClientIp, Operator = ConditionOperator.InCidr, Negate = true };
                foreach (var ip in ips)
                {
                    ipCondition.Values.Add(ip);
                }

                var rule = Rule(
                    LockRuleName(path), $"Only our own IP addresses may open {path}.", 10,
                    new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { path } },
                    ipCondition);
                rule.DetectionOnly = m.DetectionOnly;
                AddRoutes(rule.Routes, m);
                Upsert(configuration.Rules, rule);
                return [];
            }),

        new(
            "protect-login",
            "Protect a login page",
            "Slow down password guessing: limit login attempts per client IP.",
            "Adds a rate limit on POST requests to the login path, counted per client IP. A client that sends more "
                + "attempts per minute than allowed gets 429 until it slows down.",
            PresetInputs.PathPrefix | PresetInputs.PermitLimit | PresetInputs.DetectionOnly | PresetInputs.Routes,
            m =>
            {
                m.PathPrefix = "/login";
                m.PermitLimit = 10;
            },
            (m, configuration) =>
            {
                var problems = new List<string>();
                var path = CheckPath(m.PathPrefix, problems);
                CheckLimit(m.PermitLimit, 1000, problems);
                if (problems.Count > 0)
                {
                    return problems;
                }

                var limit = Limit("login-attempts", "Slow down password guessing.", m);
                limit.Conditions.Add(new RuleCondition { Field = ConditionField.Method, Operator = ConditionOperator.Equals, Values = { "POST" } });
                limit.Conditions.Add(new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { path } });
                Upsert(configuration.RateLimits, limit);
                return [];
            }),

        new(
            "limit-per-client",
            "Limit requests per client",
            "Stop aggressive bots: each client IP gets a fair number of requests per minute.",
            "Adds a rate limit on all requests, counted per client IP (IPv6 per /64 network). People browsing a site "
                + "stay far below 300 requests per minute; scrapers and floods do not.",
            PresetInputs.PermitLimit | PresetInputs.DetectionOnly | PresetInputs.Routes,
            m => m.PermitLimit = 300,
            (m, configuration) =>
            {
                var problems = new List<string>();
                CheckLimit(m.PermitLimit, 1_000_000, problems);
                if (problems.Count > 0)
                {
                    return problems;
                }

                Upsert(configuration.RateLimits, Limit("per-client", "Fair use per visitor.", m));
                return [];
            }),
    ];

    public static Preset? Find(string? id) =>
        id is null ? null : All.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>A new form with the preset's defaults; no routes ticked.</summary>
    public static PresetFormModel NewModel(Preset preset, IEnumerable<string> routeNames)
    {
        ArgumentNullException.ThrowIfNull(preset);

        var model = new PresetFormModel { RouteChoices = [.. routeNames.Select(r => new RouteChoice { Name = r })] };
        preset.Defaults(model);
        return model;
    }

    /// <summary>Applies <paramref name="preset"/> to a copy of <paramref name="running"/> and compares the result.</summary>
    public static PresetPreview Preview(Preset preset, PresetFormModel model, GatewayConfiguration running)
    {
        ArgumentNullException.ThrowIfNull(preset);
        ArgumentNullException.ThrowIfNull(model);
        ArgumentNullException.ThrowIfNull(running);

        var candidate = ConfigurationEditing.Clone(running);
        var problems = preset.Apply(model, candidate);
        if (problems.Count > 0)
        {
            return new PresetPreview(null, problems, [], [], null);
        }

        var json = GatewayConfigurationJson.Serialize(candidate);
        var tag = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)))[..16];
        return new PresetPreview(candidate, [], GatewayConfigurationValidator.Validate(candidate), ConfigurationDiff.Compare(running, candidate), tag);
    }

    /// <summary>"lock-admin" for /admin, "lock-site" for /.</summary>
    public static string LockRuleName(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var slug = new StringBuilder();
        foreach (var c in path.ToLowerInvariant())
        {
            slug.Append(c is (>= 'a' and <= 'z') or (>= '0' and <= '9') ? c : '-');
        }

        var text = string.Join('-', slug.ToString().Split('-', StringSplitOptions.RemoveEmptyEntries));
        return text.Length == 0 ? "lock-site" : "lock-" + (text.Length > 50 ? text[..50].TrimEnd('-') : text);
    }

    private static string CheckPath(string? path, List<string> problems)
    {
        var trimmed = (path ?? string.Empty).Trim();
        if (trimmed.Length == 0 || trimmed[0] != '/')
        {
            problems.Add("The path must start with /, e.g. /admin.");
        }

        return trimmed;
    }

    private static void CheckLimit(int limit, int max, List<string> problems)
    {
        if (limit < 1 || limit > max)
        {
            problems.Add(string.Create(CultureInfo.InvariantCulture, $"Allow between 1 and {max:N0} requests per minute."));
        }
    }

    private static WafRule Rule(string name, string description, int priority, params RuleCondition[] conditions)
    {
        var rule = new WafRule { Name = name, Description = description, Priority = priority, Action = RuleAction.Block };
        foreach (var condition in conditions)
        {
            rule.Conditions.Add(condition);
        }

        return rule;
    }

    private static RateLimitRule Limit(string name, string description, PresetFormModel model)
    {
        var limit = new RateLimitRule
        {
            Name = name,
            Description = description,
            PermitLimit = model.PermitLimit,
            WindowSeconds = 60,
            Key = RateLimitKey.ClientIp,
            DetectionOnly = model.DetectionOnly,
        };
        AddRoutes(limit.Routes, model);
        return limit;
    }

    private static void AddRoutes(IList<string> routes, PresetFormModel model)
    {
        foreach (var route in model.SelectedRoutes)
        {
            routes.Add(route);
        }
    }

    private static void Upsert(IList<WafRule> rules, WafRule rule) => Upsert(rules, rule, r => r.Name);

    private static void Upsert(IList<RateLimitRule> limits, RateLimitRule limit) => Upsert(limits, limit, l => l.Name);

    /// <summary>Replaces the item with the same name (keeping its place), or adds it.</summary>
    private static void Upsert<T>(IList<T> items, T item, Func<T, string> name)
    {
        for (var i = 0; i < items.Count; i++)
        {
            if (string.Equals(name(items[i]), name(item), StringComparison.OrdinalIgnoreCase))
            {
                items[i] = item;
                return;
            }
        }

        items.Add(item);
    }
}
