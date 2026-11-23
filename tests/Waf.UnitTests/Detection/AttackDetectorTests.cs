using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine.Detection;
using FASoft.Waf.UnitTests.Engine;

namespace FASoft.Waf.UnitTests.Detection;

public class AttackDetectorTests
{
    private static AttackDetector Detector(Action<AttackDetectionSettings>? configure = null)
    {
        var settings = new AttackDetectionSettings();
        configure?.Invoke(settings);
        return new AttackDetector(settings);
    }

    private static FakeRequest Request(string path = "/", string query = "", params (string Name, string Value)[] headers)
    {
        var request = new FakeRequest { Path = path, QueryString = query };
        foreach (var (name, value) in headers)
        {
            request.Headers[name] = value;
        }

        return request;
    }

    private static RequestBody Body(string contentType, string content) => new(contentType, Encoding.UTF8.GetBytes(content));

    [Fact]
    public void Clean_request_has_no_finding()
    {
        var request = Request("/products/42", "color=red&size=m", ("User-Agent", "Mozilla/5.0"), ("Cookie", "session=abc; theme=dark"), ("Referer", "https://example.com/"));

        Assert.Null(Detector().Inspect(request));
    }

    [Fact]
    public void Finding_names_category_signature_location_and_parameter()
    {
        var finding = Detector().Inspect(Request("/search", "page=2&q=1%27%20OR%20%271%27%3D%271"));

        Assert.NotNull(finding);
        Assert.Equal(AttackCategory.SqlInjection, finding.Category);
        Assert.Equal("sqli-quoted-tautology", finding.SignatureId);
        Assert.Equal(RequestLocation.QueryString, finding.Location);
        Assert.Equal("q", finding.Name);
        Assert.Contains("' or '1'='1", finding.Snippet, StringComparison.Ordinal);
    }

    [Fact]
    public void Query_parameter_names_are_inspected_too()
    {
        var finding = Detector().Inspect(Request("/", "%3Cscript%3E=1"));

        Assert.Equal(AttackCategory.CrossSiteScripting, finding?.Category);
    }

    [Fact]
    public void Path_is_inspected()
    {
        Assert.Equal(AttackCategory.PathTraversal, Detector().Inspect(Request("/static/../../etc/passwd"))?.Category);
    }

    [Fact]
    public void Each_cookie_is_inspected()
    {
        var finding = Detector().Inspect(Request(headers: ("Cookie", "theme=dark; pref=<script>alert(1)</script>")));

        Assert.Equal((AttackCategory.CrossSiteScripting, RequestLocation.Cookie, "pref"), (finding!.Category, finding.Location, finding.Name));
    }

    [Fact]
    public void Referer_is_inspected()
    {
        var finding = Detector().Inspect(Request(headers: ("Referer", "https://x.example/?q=' or 1=1--")));

        Assert.Equal((AttackCategory.SqlInjection, "Referer"), (finding!.Category, finding.Name));
    }

    [Fact]
    public void Scanner_user_agent_is_detected()
    {
        var finding = Detector().Inspect(Request(headers: ("User-Agent", "sqlmap/1.7")));

        Assert.Equal((AttackCategory.BadUserAgent, RequestLocation.Header, "User-Agent"), (finding!.Category, finding.Location, finding.Name));
    }

    [Fact]
    public void Other_headers_are_not_inspected()
    {
        Assert.Null(Detector().Inspect(Request(headers: ("X-Custom", "<script>alert(1)</script>"))));
    }

    [Fact]
    public void Categories_can_be_switched_off()
    {
        var request = Request("/", "q=<script>alert(1)</script>");

        Assert.Null(Detector(s => s.CrossSiteScripting = false).Inspect(request));
        Assert.Null(Detector(s => s.Enabled = false).Inspect(request));
        Assert.False(Detector(s => s.Enabled = false).IsEnabled);
    }

    [Fact]
    public void Exclusion_turns_off_all_categories_under_a_path()
    {
        var detector = Detector(s => s.Exclusions.Add(new DetectionExclusion { PathPrefix = "/cms/editor" }));

        Assert.Null(detector.Inspect(Request("/cms/editor/save", "html=<script>x</script>")));
        Assert.NotNull(detector.Inspect(Request("/cms/editorx", "html=<script>x</script>")));   // whole segments only
        Assert.NotNull(detector.Inspect(Request("/other", "html=<script>x</script>")));
    }

    [Fact]
    public void Exclusion_can_be_limited_to_categories_and_routes()
    {
        var exclusion = new DetectionExclusion { PathPrefix = "/" };
        exclusion.Categories.Add(AttackCategory.CrossSiteScripting);
        exclusion.Routes.Add("website");
        var detector = Detector(s => s.Exclusions.Add(exclusion));

        Assert.Null(detector.Inspect(Request("/", "x=<script>x</script>") with { RouteName = "website" }));
        Assert.NotNull(detector.Inspect(Request("/", "x=' or 1=1--") with { RouteName = "website" }));       // other category
        Assert.NotNull(detector.Inspect(Request("/", "x=<script>x</script>") with { RouteName = "api" }));   // other route
    }

    [Fact]
    public void Body_is_ignored_unless_enabled()
    {
        Assert.Null(Detector().Inspect(Request(), Body("text/plain", "<script>alert(1)</script>")));
    }

    [Fact]
    public void Form_body_fields_are_inspected()
    {
        var finding = Detector(s => s.InspectBody = true).Inspect(Request(), Body("application/x-www-form-urlencoded; charset=utf-8", "user=admin&pass=x%27+or+%271%27%3D%271"));

        Assert.Equal((AttackCategory.SqlInjection, RequestLocation.Body, "pass"), (finding!.Category, finding.Location, finding.Name));
    }

    [Fact]
    public void Json_string_values_are_inspected_individually()
    {
        var detector = Detector(s => s.InspectBody = true);

        var finding = detector.Inspect(Request(), Body("application/json", """{"name":"x","comment":"<img src=x onerror=alert(1)>"}"""));
        Assert.Equal((AttackCategory.CrossSiteScripting, "comment"), (finding!.Category, finding.Name));

        // JSON's own quotes and separators must not look like SQL injection.
        Assert.Null(detector.Inspect(Request(), Body("application/json", """{"a":"x","or":"y","b":1,"c":"1","d":[1,2],"e":{"f":"O'Brien"}}""")));
    }

    [Fact]
    public void Truncated_json_falls_back_to_text_inspection()
    {
        var finding = Detector(s => s.InspectBody = true).Inspect(Request(), Body("application/json", """{"q":"<script>alert(1)</scr"""));

        Assert.Equal(AttackCategory.CrossSiteScripting, finding?.Category);
    }

    [Fact]
    public void Plain_text_and_xml_bodies_are_inspected_whole()
    {
        var detector = Detector(s => s.InspectBody = true);

        Assert.NotNull(detector.Inspect(Request(), Body("text/plain", "; cat /etc/passwd")));
        Assert.NotNull(detector.Inspect(Request(), Body("application/xml", "<a><script>alert(1)</script></a>")));
    }

    [Fact]
    public void Binary_bodies_are_not_inspected()
    {
        Assert.Null(Detector(s => s.InspectBody = true).Inspect(Request(), Body("image/png", "<script>alert(1)</script>")));
    }

    [Fact]
    public void Every_signature_has_a_unique_id_and_compiles()
    {
        Assert.Equal(AttackSignatures.All.Count, AttackSignatures.All.Select(s => s.Id).Distinct().Count());
        Assert.All(AttackSignatures.All, s => Assert.NotNull(new System.Text.RegularExpressions.Regex(s.Pattern, System.Text.RegularExpressions.RegexOptions.NonBacktracking)));
        Assert.Equal(Enum.GetValues<AttackCategory>().Length, AttackSignatures.All.Select(s => s.Category).Distinct().Count());
    }

    /// <summary>
    /// A classic catastrophic-backtracking input must take time proportional to its length. Checked by growth
    /// (8x the input may take at most ~40x the time) rather than a wall-clock budget, so a slow or busy CI
    /// machine does not make the test flaky; exponential backtracking would exceed it by orders of magnitude.
    /// </summary>
    [Fact]
    public void Very_long_input_is_handled_in_linear_time()
    {
        var detector = Detector();
        static string Evil(int repeats) => "'" + string.Concat(Enumerable.Repeat("or a", repeats)) + "!";

        // Warm-up: the non-backtracking engine builds its matcher lazily on first use; don't measure that.
        detector.InspectValue(Evil(1_000), RequestLocation.QueryString);

        var small = Fastest(() => detector.InspectValue(Evil(5_000), RequestLocation.QueryString));
        var large = Fastest(() => detector.InspectValue(Evil(40_000), RequestLocation.QueryString));

        Assert.True(large < TimeSpan.FromSeconds(30), $"160 KB input took {large}");
        Assert.True(
            large <= (small * 8 * 5) + TimeSpan.FromMilliseconds(100),
            $"Not linear: 20 KB took {small.TotalMilliseconds:F1} ms, 160 KB took {large.TotalMilliseconds:F1} ms");
    }

    /// <summary>Best of three runs, to filter out scheduling noise.</summary>
    private static TimeSpan Fastest(Action action)
    {
        var best = TimeSpan.MaxValue;
        for (var i = 0; i < 3; i++)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            action();
            watch.Stop();
            best = watch.Elapsed < best ? watch.Elapsed : best;
        }

        return best;
    }
}
