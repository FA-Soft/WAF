using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Web;

/// <summary>
/// A starting point for a new route, rule or rate limit: it pre-fills the editor, which the user then reviews,
/// adjusts and saves. Nothing changes until the editor is saved.
/// </summary>
/// <param name="Id">Used in the editor URL, e.g. <c>rules/new?template=block-ips</c>.</param>
/// <param name="Title">Short name shown in the library.</param>
/// <param name="Description">What the template sets up, in one or two sentences.</param>
/// <param name="Apply">Fills a new form model.</param>
internal sealed record FormTemplate<TModel>(string Id, string Title, string Description, Action<TModel> Apply);

/// <summary>The template library: common routes, rules and rate limits.</summary>
internal static class TemplateLibrary
{
    /// <summary>Example values in templates must be replaced; these are the documentation addresses users recognise.</summary>
    public const string ExampleNote = "Replace the example host names and addresses with your own.";

    public static readonly IReadOnlyList<FormTemplate<RouteFormModel>> Routes =
    [
        new("website", "Website", "All requests for your site's host names go to one web server, e.g. IIS or nginx on your network.", m =>
        {
            m.Name = "website";
            m.Hosts = Lines("www.example.com", "example.com");
            m.PathPrefix = "/";
            m.Destinations = "http://192.168.1.10:80";
            m.HealthCheckPath = "/";
        }),
        new("api", "API under a path", "Requests under /api go to a separate API server; the rest of the site is unaffected.", m =>
        {
            m.Name = "api";
            m.Hosts = "www.example.com";
            m.PathPrefix = "/api";
            m.Destinations = "http://192.168.1.20:5000";
            m.HealthCheckPath = "/health";
        }),
        new("load-balanced", "Load-balanced servers", "Spread requests over two servers; a server that fails its health check gets no traffic until it recovers.", m =>
        {
            m.Name = "app";
            m.Hosts = "app.example.com";
            m.PathPrefix = "/";
            m.Destinations = Lines("http://192.168.1.31:8080", "http://192.168.1.32:8080");
            m.HealthCheckPath = "/health";
            m.HealthCheckIntervalSeconds = 10;
            m.HealthCheckTimeoutSeconds = 5;
        }),
        new("https-backend", "HTTPS backend with its own certificate", "Forward to a server that only speaks HTTPS with a self-signed certificate, such as a default IIS or a NAS.", m =>
        {
            m.Name = "intranet";
            m.Hosts = "intranet.example.com";
            m.PathPrefix = "/";
            m.Destinations = "https://192.168.1.40:443";
            m.AllowInvalidBackendCertificate = true;
        }),
    ];

    public static readonly IReadOnlyList<FormTemplate<RuleFormModel>> Rules =
    [
        new("block-ips", "IP block list", "Block requests from the IP addresses and ranges you list.", m =>
        {
            m.Name = "blocked-ips";
            m.Description = "Block these IP addresses and ranges.";
            m.Priority = 10;
            m.Action = RuleAction.Block;
            m.Conditions = [Condition(ConditionField.ClientIp, ConditionOperator.InCidr)];
        }),
        new("allow-ips", "IP allow list", "Always let the IP addresses and ranges you list through, without further checks (e.g. your monitoring).", m =>
        {
            m.Name = "trusted-ips";
            m.Description = "Always allow these IP addresses and ranges (no further checks).";
            m.Priority = 5;
            m.Action = RuleAction.Allow;
            m.Conditions = [Condition(ConditionField.ClientIp, ConditionOperator.InCidr)];
        }),
        new("lock-path", "Path only for your IP addresses", "Block a path such as /admin for everyone except the IP addresses you list.", m =>
        {
            m.Name = "lock-admin";
            m.Description = "Only our own networks may open /admin.";
            m.Priority = 10;
            m.Action = RuleAction.Block;
            m.Conditions =
            [
                Condition(ConditionField.Path, ConditionOperator.StartsWith, "/admin"),
                Condition(ConditionField.ClientIp, ConditionOperator.InCidr, negate: true),
            ];
        }),
        new("require-header", "Require an API key header", "Block requests that do not send the right X-Api-Key header. Enter the key(s) your clients use.", m =>
        {
            m.Name = "require-api-key";
            m.Description = "Clients must send a valid X-Api-Key header.";
            m.Priority = 20;
            m.Action = RuleAction.Block;
            m.Conditions =
            [
                new ConditionFormModel { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Negate = true, CaseSensitive = true },
            ];
        }),
        new("block-wordpress-probes", "Block WordPress probes", "Bots try WordPress login and admin pages on every site. Block them if your site does not run WordPress.", m =>
        {
            m.Name = "block-wordpress-probes";
            m.Description = "This site does not run WordPress.";
            m.Priority = 50;
            m.Action = RuleAction.Block;
            m.Conditions = [Condition(ConditionField.Path, ConditionOperator.StartsWith, "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-content", "/wp-includes")];
        }),
        new("block-crawlers", "Block SEO crawlers", "Keep commercial SEO crawlers out to save bandwidth. Search engines are not affected.", m =>
        {
            m.Name = "block-seo-crawlers";
            m.Description = "Commercial SEO crawlers only cost bandwidth.";
            m.Priority = 50;
            m.Action = RuleAction.Block;
            m.Conditions = [Condition(ConditionField.UserAgent, ConditionOperator.Contains, "AhrefsBot", "SemrushBot", "MJ12bot", "DotBot", "BLEXBot")];
        }),
        new("watch-path", "Log requests to a path", "Only record requests to a path, without blocking them, e.g. to see who uses an old URL.", m =>
        {
            m.Name = "watch-old-api";
            m.Description = "Who still uses the old API?";
            m.Priority = 100;
            m.Action = RuleAction.LogOnly;
            m.Conditions = [Condition(ConditionField.Path, ConditionOperator.StartsWith, "/api/v1")];
        }),
    ];

    public static readonly IReadOnlyList<FormTemplate<RateLimitFormModel>> RateLimits =
    [
        new("login", "Login attempts", "At most 10 login attempts per minute per client IP, against password guessing.", m =>
        {
            m.Name = "login-attempts";
            m.Description = "Slow down password guessing.";
            m.PermitLimit = 10;
            m.WindowAmount = 1;
            m.WindowUnitSeconds = 60;
            m.Key = RateLimitKey.ClientIp;
            m.Conditions =
            [
                Condition(ConditionField.Method, ConditionOperator.Equals, "POST"),
                Condition(ConditionField.Path, ConditionOperator.StartsWith, "/login"),
            ];
        }),
        new("per-client", "Requests per client", "At most 300 requests per minute per client IP: plenty for people, too little for aggressive bots.", m =>
        {
            m.Name = "per-client";
            m.Description = "Fair use per visitor.";
            m.PermitLimit = 300;
            m.WindowAmount = 1;
            m.WindowUnitSeconds = 60;
            m.Key = RateLimitKey.ClientIp;
        }),
        new("protect-backend", "Protect a backend", "At most 1000 requests per minute to a route for all clients together, so a small server is never overloaded. Tick the route to protect.", m =>
        {
            m.Name = "protect-backend";
            m.Description = "The backend handles about 1000 requests per minute.";
            m.PermitLimit = 1000;
            m.WindowAmount = 1;
            m.WindowUnitSeconds = 60;
            m.Key = RateLimitKey.Route;
        }),
    ];

    public static FormTemplate<RouteFormModel>? FindRoute(string? id) => Find(Routes, id);

    public static FormTemplate<RuleFormModel>? FindRule(string? id) => Find(Rules, id);

    public static FormTemplate<RateLimitFormModel>? FindRateLimit(string? id) => Find(RateLimits, id);

    private static FormTemplate<T>? Find<T>(IReadOnlyList<FormTemplate<T>> templates, string? id) =>
        id is null ? null : templates.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));

    private static ConditionFormModel Condition(ConditionField field, ConditionOperator op, params string[] values) =>
        new() { Field = field, Operator = op, Values = Lines(values) };

    private static ConditionFormModel Condition(ConditionField field, ConditionOperator op, bool negate) =>
        new() { Field = field, Operator = op, Negate = negate };

    private static string Lines(params string[] values) => string.Join(Environment.NewLine, values);
}
