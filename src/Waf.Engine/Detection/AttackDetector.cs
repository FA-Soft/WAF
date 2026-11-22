using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Waf.Core.Configuration;

namespace Waf.Engine.Detection;

/// <summary>Where in the request a value was found.</summary>
public enum RequestLocation
{
    Path,
    QueryString,
    Header,
    Cookie,
    Body,
}

/// <summary>An attack found in a request.</summary>
/// <param name="Category">Kind of attack.</param>
/// <param name="SignatureId">The signature that matched (see <see cref="AttackSignatures"/>).</param>
/// <param name="Location">Part of the request.</param>
/// <param name="Name">Parameter, header or cookie name; null for the path and plain bodies.</param>
/// <param name="Snippet">The matching text (normalized, at most 100 characters), for logs.</param>
public sealed record AttackFinding(AttackCategory Category, string SignatureId, RequestLocation Location, string? Name, string Snippet);

/// <summary>A request body to inspect: its content type and (already size-limited) bytes.</summary>
public sealed record RequestBody(string? ContentType, ReadOnlyMemory<byte> Content);

/// <summary>
/// Inspects requests for attack payloads using <see cref="AttackSignatures"/>. Immutable and thread-safe;
/// build one per configuration.
/// </summary>
/// <remarks>
/// Inspected: the path; every query parameter name and value; the Referer, Cookie (per cookie) and
/// User-Agent headers; and, when <see cref="AttackDetectionSettings.InspectBody"/> is on, the body:
/// form fields one by one, JSON string values and property names one by one, other text as a whole.
/// Every value is normalized first (<see cref="InputNormalizer"/>). The first finding is returned.
/// </remarks>
public sealed class AttackDetector
{
    private const int MaxSnippetLength = 100;

    private static readonly AttackCategory[] ContentCategories =
        [AttackCategory.SqlInjection, AttackCategory.CrossSiteScripting, AttackCategory.PathTraversal, AttackCategory.CommandInjection];

    private static readonly AttackCategory[] HeaderCategories =
        [AttackCategory.SqlInjection, AttackCategory.CrossSiteScripting];

    private readonly Dictionary<AttackCategory, CategoryMatcher> _matchers;
    private readonly CompiledExclusion[] _exclusions;

    public AttackDetector(AttackDetectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        Settings = settings;
        var enabled = new HashSet<AttackCategory>();
        if (settings.Enabled)
        {
            if (settings.SqlInjection) { enabled.Add(AttackCategory.SqlInjection); }
            if (settings.CrossSiteScripting) { enabled.Add(AttackCategory.CrossSiteScripting); }
            if (settings.PathTraversal) { enabled.Add(AttackCategory.PathTraversal); }
            if (settings.CommandInjection) { enabled.Add(AttackCategory.CommandInjection); }
            if (settings.BadUserAgents) { enabled.Add(AttackCategory.BadUserAgent); }
        }

        _matchers = AttackSignatures.All
            .Where(s => enabled.Contains(s.Category))
            .GroupBy(s => s.Category)
            .ToDictionary(g => g.Key, g => new CategoryMatcher([.. g]));

        _exclusions = [.. settings.Exclusions.Select(e => new CompiledExclusion(e))];

        // One pattern over every enabled signature: a clean value is scanned once, not once per category.
        _anySignature = _matchers.Count == 0
            ? null
            : AttackSignatures.Compile(string.Join('|', AttackSignatures.All.Where(s => enabled.Contains(s.Category)).Select(s => $"(?:{s.Pattern})")));
    }

    private readonly Regex? _anySignature;

    /// <summary>The settings this detector was built from.</summary>
    public AttackDetectionSettings Settings { get; }

    /// <summary>True when at least one category is enabled.</summary>
    public bool IsEnabled => _matchers.Count > 0;

    /// <summary>Inspects a request (and optionally its body); returns the first finding or null.</summary>
    public AttackFinding? Inspect(IWafRequest request, RequestBody? body = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!IsEnabled)
        {
            return null;
        }

        var active = ActiveCategories(request);
        if (active.Count == 0)
        {
            return null;
        }

        return InspectValue(request.Path, RequestLocation.Path, null, active, ContentCategories, plusIsSpace: false)
            ?? InspectPairs(request.QueryString, '&', RequestLocation.QueryString, active, ContentCategories, plusIsSpace: true)
            ?? InspectValue(request.GetHeader("Referer"), RequestLocation.Header, "Referer", active, HeaderCategories, plusIsSpace: false)
            ?? InspectPairs(request.GetHeader("Cookie"), ';', RequestLocation.Cookie, active, HeaderCategories, plusIsSpace: false)
            ?? InspectValue(request.GetHeader("User-Agent"), RequestLocation.Header, "User-Agent", active, [AttackCategory.BadUserAgent, .. HeaderCategories], plusIsSpace: false)
            ?? (body is not null && Settings.InspectBody ? InspectBody(body, active) : null);
    }

    /// <summary>Inspects a single raw value for the given categories (all enabled ones when omitted).</summary>
    public AttackFinding? InspectValue(string? raw, RequestLocation location, string? name = null, IReadOnlyCollection<AttackCategory>? categories = null, bool plusIsSpace = false)
    {
        var all = _matchers.Keys.ToHashSet();
        return InspectValue(raw, location, name, all, categories ?? [.. all], plusIsSpace);
    }

    private HashSet<AttackCategory> ActiveCategories(IWafRequest request)
    {
        var active = _matchers.Keys.ToHashSet();
        foreach (var exclusion in _exclusions)
        {
            if (exclusion.Matches(request))
            {
                if (exclusion.Categories is null)
                {
                    return [];
                }

                active.ExceptWith(exclusion.Categories);
            }
        }

        return active;
    }

    private AttackFinding? InspectValue(
        string? raw, RequestLocation location, string? name, HashSet<AttackCategory> active, IReadOnlyCollection<AttackCategory> categories, bool plusIsSpace)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        var normalized = InputNormalizer.Normalize(raw, plusIsSpace);
        if (_anySignature is null || !_anySignature.IsMatch(normalized))
        {
            return null;
        }

        foreach (var category in categories)
        {
            if (active.Contains(category) && _matchers.TryGetValue(category, out var matcher)
                && matcher.Match(normalized) is { } hit)
            {
                return new AttackFinding(category, hit.Id, location, name, Snip(normalized, hit.Index, hit.Length));
            }
        }

        return null;
    }

    /// <summary>Inspects <c>name=value</c> pairs (query string, cookies, form bodies): names and values.</summary>
    private AttackFinding? InspectPairs(
        string? raw, char separator, RequestLocation location, HashSet<AttackCategory> active, IReadOnlyCollection<AttackCategory> categories, bool plusIsSpace)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        foreach (var pair in raw.Split(separator))
        {
            var equals = pair.IndexOf('=', StringComparison.Ordinal);
            var rawName = (equals < 0 ? pair : pair[..equals]).Trim();
            var rawValue = equals < 0 ? null : pair[(equals + 1)..];
            var name = InputNormalizer.Normalize(rawName, plusIsSpace);

            var finding = InspectValue(rawName, location, name, active, categories, plusIsSpace)
                ?? InspectValue(rawValue, location, name, active, categories, plusIsSpace);
            if (finding is not null)
            {
                return finding;
            }
        }

        return null;
    }

    private AttackFinding? InspectBody(RequestBody body, HashSet<AttackCategory> active)
    {
        var content = body.Content.Span;
        if (content.IsEmpty)
        {
            return null;
        }

        var contentType = body.ContentType?.ToLowerInvariant() ?? string.Empty;

        if (contentType.StartsWith("application/x-www-form-urlencoded", StringComparison.Ordinal))
        {
            return InspectPairs(Encoding.UTF8.GetString(content), '&', RequestLocation.Body, active, ContentCategories, plusIsSpace: true);
        }

        if (contentType.Contains("json", StringComparison.Ordinal))
        {
            return InspectJson(body.Content, active);
        }

        if (contentType.StartsWith("text/", StringComparison.Ordinal) || contentType.Contains("xml", StringComparison.Ordinal) || contentType.Length == 0)
        {
            return InspectValue(Encoding.UTF8.GetString(content), RequestLocation.Body, null, active, ContentCategories, plusIsSpace: false);
        }

        return null; // binary types (images, archives, multipart uploads) are not inspected
    }

    /// <summary>Inspects JSON string values and property names one by one, so JSON quoting is not mistaken for SQL.</summary>
    private AttackFinding? InspectJson(ReadOnlyMemory<byte> json, HashSet<AttackCategory> active)
    {
        var reader = new Utf8JsonReader(json.Span, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            MaxDepth = 64,
        });

        string? property = null;
        try
        {
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName or JsonTokenType.String)
                {
                    var value = reader.GetString();
                    var name = reader.TokenType == JsonTokenType.String ? property : null;
                    if (InspectValue(value, RequestLocation.Body, name, active, ContentCategories, plusIsSpace: false) is { } finding)
                    {
                        return finding;
                    }

                    if (reader.TokenType == JsonTokenType.PropertyName)
                    {
                        property = value;
                    }
                }
            }
        }
        catch (JsonException)
        {
            // Malformed or truncated (size-limited) JSON: inspect it as plain text instead.
            return InspectValue(Encoding.UTF8.GetString(json.Span), RequestLocation.Body, null, active, ContentCategories, plusIsSpace: false);
        }

        return null;
    }

    private static string Snip(string text, int index, int length)
    {
        var start = Math.Max(0, index - 10);
        var end = Math.Min(text.Length, index + Math.Max(length, 1) + 10);
        var snippet = text[start..end];
        return snippet.Length <= MaxSnippetLength ? snippet : snippet[..MaxSnippetLength];
    }

    /// <summary>All signatures of a category: one combined pattern for the fast check, then attribution.</summary>
    private sealed class CategoryMatcher
    {
        private readonly Regex _combined;
        private readonly (string Id, Regex Regex)[] _signatures;

        public CategoryMatcher(AttackSignature[] signatures)
        {
            _combined = AttackSignatures.Compile(string.Join('|', signatures.Select(s => $"(?:{s.Pattern})")));
            _signatures = [.. signatures.Select(s => (s.Id, AttackSignatures.Compile(s.Pattern)))];
        }

        public (string Id, int Index, int Length)? Match(string normalized)
        {
            if (!_combined.IsMatch(normalized))
            {
                return null;
            }

            foreach (var (id, regex) in _signatures)
            {
                var match = regex.Match(normalized);
                if (match.Success)
                {
                    return (id, match.Index, match.Length);
                }
            }

            return null;
        }
    }

    private sealed class CompiledExclusion(DetectionExclusion exclusion)
    {
        private readonly string _prefix = exclusion.PathPrefix.TrimEnd('/');
        private readonly HashSet<string>? _routes = exclusion.Routes.Count == 0 ? null : new HashSet<string>(exclusion.Routes, StringComparer.OrdinalIgnoreCase);

        public HashSet<AttackCategory>? Categories { get; } = exclusion.Categories.Count == 0 ? null : [.. exclusion.Categories];

        public bool Matches(IWafRequest request)
        {
            if (_routes is not null && (request.RouteName is null || !_routes.Contains(request.RouteName)))
            {
                return false;
            }

            var path = request.Path;
            return _prefix.Length == 0
                || (path.StartsWith(_prefix, StringComparison.OrdinalIgnoreCase)
                    && (path.Length == _prefix.Length || path[_prefix.Length] == '/'));
        }
    }
}
