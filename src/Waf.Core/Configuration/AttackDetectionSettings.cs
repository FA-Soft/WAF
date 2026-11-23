namespace FASoft.Waf.Core.Configuration;

/// <summary>
/// Built-in detection of common attack payloads (SQL injection, XSS, path traversal, command injection,
/// scanner user agents) in the path, query string, selected headers and optionally the body.
/// </summary>
public sealed class AttackDetectionSettings
{
    /// <summary>Master switch for all detectors.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Detect SQL injection (e.g. <c>' OR '1'='1</c>, <c>UNION SELECT</c>).</summary>
    public bool SqlInjection { get; set; } = true;

    /// <summary>Detect cross-site scripting (e.g. <c>&lt;script&gt;</c>, <c>onerror=</c>, <c>javascript:</c>).</summary>
    public bool CrossSiteScripting { get; set; } = true;

    /// <summary>Detect path traversal (e.g. <c>../../etc/passwd</c>).</summary>
    public bool PathTraversal { get; set; } = true;

    /// <summary>Detect OS command injection (e.g. <c>; cat /etc/passwd</c>, <c>$(id)</c>).</summary>
    public bool CommandInjection { get; set; } = true;

    /// <summary>Block known attack and scanner tools by User-Agent (e.g. sqlmap, nikto).</summary>
    public bool BadUserAgents { get; set; } = true;

    /// <summary>
    /// Also inspect request bodies (form fields, JSON string values, plain text). Off by default because it
    /// costs time and memory per request.
    /// </summary>
    public bool InspectBody { get; set; }

    /// <summary>Largest part of a body that is inspected, in bytes; anything beyond is not inspected.</summary>
    public int MaxBodyBytes { get; set; } = DefaultMaxBodyBytes;

    /// <summary>Default for <see cref="MaxBodyBytes"/>: 64 KB.</summary>
    public const int DefaultMaxBodyBytes = 64 * 1024;

    /// <summary>Places where detection is switched off, e.g. to allow a known false positive.</summary>
    public IList<DetectionExclusion> Exclusions { get; } = [];
}

/// <summary>Turns detection off for matching requests, for all or some categories.</summary>
public sealed class DetectionExclusion
{
    /// <summary>Path prefix (whole segments), e.g. <c>/cms/editor</c>. Default <c>/</c>: every path.</summary>
    public string PathPrefix { get; set; } = "/";

    /// <summary>Routes the exclusion applies to. Empty means all routes.</summary>
    public IList<string> Routes { get; } = [];

    /// <summary>Categories to switch off. Empty means all categories.</summary>
    public IList<AttackCategory> Categories { get; } = [];

    /// <summary>Optional note on why the exclusion exists.</summary>
    public string? Reason { get; set; }
}

/// <summary>Kind of attack.</summary>
public enum AttackCategory
{
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    CommandInjection,
    BadUserAgent,
}
