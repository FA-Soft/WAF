using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Engine;
using FASoft.Waf.Engine.Detection;

namespace FASoft.Waf.Web;

/// <summary>Form model of the "Test a request" page.</summary>
internal sealed class TestRequestModel : IValidatableObject
{
    [Required(ErrorMessage = "Choose a method.")]
    public string Method { get; set; } = "GET";

    [Required(ErrorMessage = "Enter a host name, e.g. www.example.com.")]
    public string Host { get; set; } = "www.example.com";

    [Required(ErrorMessage = "Enter a path; it starts with /, e.g. /admin.")]
    public string Path { get; set; } = "/";

    public string? Query { get; set; }

    [Required(ErrorMessage = "Enter the client's IP address, e.g. 203.0.113.10.")]
    public string ClientIp { get; set; } = "203.0.113.10";

    /// <summary>Route the request is assumed to match; empty for "no route".</summary>
    public string? Route { get; set; }

    /// <summary>One header per line: <c>Name: value</c>.</summary>
    public string? Headers { get; set; }

    public string? ContentType { get; set; }

    public string? Body { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrEmpty(Path) && Path[0] != '/')
        {
            yield return new ValidationResult("The path must start with /, e.g. /admin.", [nameof(Path)]);
        }

        if (!string.IsNullOrEmpty(ClientIp) && !StrictIpAddress.TryParse(ClientIp.Trim(), out _))
        {
            yield return new ValidationResult("This is not a valid IP address. Use e.g. 203.0.113.10 or 2001:db8::1.", [nameof(ClientIp)]);
        }

        var line = 0;
        foreach (var header in (Headers ?? string.Empty).Split('\n'))
        {
            line++;
            if (header.Trim().Length > 0 && header.IndexOf(':', StringComparison.Ordinal) <= 0)
            {
                yield return new ValidationResult($"Header line {line} needs the form 'Name: value'.", [nameof(Headers)]);
            }
        }
    }
}

/// <summary>What the WAF would do with a test request, in plain language.</summary>
/// <param name="Blocked">True when the request would be rejected.</param>
/// <param name="Summary">One sentence, e.g. "Blocked by rule 'no-admin'."</param>
/// <param name="Details">Further observations (log-only matches, detection-only blocks, …).</param>
internal sealed record TestRequestResult(bool Blocked, string Summary, IReadOnlyList<string> Details);

/// <summary>
/// Runs a test request through the active WAF engine without sending it anywhere: rules and attack detection
/// are evaluated exactly as for real traffic; rate limits are not counted.
/// </summary>
internal static class RequestTester
{
    public static TestRequestResult Run(WafEngine engine, TestRequestModel model)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(model);

        var request = new SimulatedRequest(model);
        var details = new List<string>();

        var decision = engine.Rules.Evaluate(request);
        foreach (var match in decision.Matches)
        {
            if (match.Action == RuleAction.LogOnly)
            {
                details.Add($"Rule '{match.RuleName}' matched and would be logged.");
            }
            else if (match.DetectionOnly)
            {
                details.Add($"Rule '{match.RuleName}' would block this request, but it is in detection-only mode: logged, not blocked.");
            }
        }

        if (decision.IsBlocked)
        {
            return new TestRequestResult(true, $"Blocked (403) by rule '{decision.DecidingRule!.RuleName}'.", details);
        }

        if (decision.DecidingRule is not null)
        {
            return new TestRequestResult(false, $"Allowed by rule '{decision.DecidingRule.RuleName}'. Attack detection and rate limits are skipped for this request.", details);
        }

        var body = string.IsNullOrEmpty(model.Body) ? null : new RequestBody(model.ContentType ?? "text/plain", Encoding.UTF8.GetBytes(model.Body));
        var finding = engine.Detector.Inspect(request, body);
        if (finding is not null)
        {
            var where = finding.Name is null ? finding.Location.ToString() : $"{finding.Location} '{finding.Name}'";
            var text = $"{Category(finding.Category)} detected in {where} (signature {finding.SignatureId}): {finding.Snippet}";
            if (engine.DetectionOnly)
            {
                details.Add(text);
                return new TestRequestResult(false, "Allowed: an attack was detected, but detection-only mode is on, so it would only be logged.", details);
            }

            details.Add(text);
            return new TestRequestResult(true, $"Blocked (403): {Category(finding.Category).ToLowerInvariant()} detected.", details);
        }

        details.Add("Rate limits are not counted in a test; a real client could still get 429 when sending too many requests.");
        return new TestRequestResult(false, model.Route is null or "" ? "Allowed by the firewall. No route matches, so the gateway would answer 404." : "Allowed: the request would be forwarded.", details);
    }

    private static string Category(AttackCategory category) => category switch
    {
        AttackCategory.SqlInjection => "SQL injection",
        AttackCategory.CrossSiteScripting => "Cross-site scripting",
        AttackCategory.PathTraversal => "Path traversal",
        AttackCategory.CommandInjection => "Command injection",
        AttackCategory.BadUserAgent => "Attack tool",
        _ => category.ToString(),
    };

    private sealed class SimulatedRequest(TestRequestModel model) : IWafRequest
    {
        private readonly Dictionary<string, string> _headers = ParseHeaders(model.Headers);

        public IPAddress ClientIp { get; } = StrictIpAddress.TryParse(model.ClientIp.Trim(), out var ip) ? ip : IPAddress.None;

        public string Host => model.Host.Trim();

        public string Path => model.Path.Trim();

        public string QueryString => (model.Query ?? string.Empty).Trim().TrimStart('?');

        public string Method => model.Method.Trim().ToUpperInvariant();

        public string? RouteName => string.IsNullOrEmpty(model.Route) ? null : model.Route;

        public string? GetHeader(string name) => _headers.TryGetValue(name, out var value) ? value : null;

        private static Dictionary<string, string> ParseHeaders(string? text)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in (text ?? string.Empty).Split('\n'))
            {
                var colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon > 0)
                {
                    var name = line[..colon].Trim();
                    var value = line[(colon + 1)..].Trim();
                    headers[name] = headers.TryGetValue(name, out var existing) ? $"{existing}, {value}" : value;
                }
            }

            return headers;
        }
    }
}
