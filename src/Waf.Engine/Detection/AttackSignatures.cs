using System.Text.RegularExpressions;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Engine.Detection;

/// <summary>A named pattern that indicates an attack.</summary>
public sealed record AttackSignature(string Id, AttackCategory Category, string Pattern, string Description);

/// <summary>
/// The built-in signatures. Patterns run against <see cref="InputNormalizer"/> output (decoded,
/// lower-case, whitespace collapsed) on the non-backtracking regex engine (linear time, no ReDoS).
/// </summary>
/// <remarks>
/// Patterns favour precision over recall: they look for attack structure (e.g. <c>union … select</c>,
/// a quote followed by <c>or … =</c>) rather than single keywords, so ordinary text such as
/// "select a size" or "O'Brien" is not flagged. Known false positives can be excluded per path.
/// </remarks>
public static class AttackSignatures
{
    private const string ShellCommandsStrong =
        "wget|curl|nc|ncat|netcat|bash|zsh|ksh|powershell|pwsh|cmd|cmd\\.exe|python[23]?|perl|ruby|certutil|bitsadmin|whoami|uname|ifconfig|ipconfig|nslookup|telnet|/bin/[a-z]+|/usr/bin/[a-z]+";

    private const string ShellCommandsWeak = "cat|ls|id|pwd|echo|ping|sleep|rm|chmod|chown|kill|net|sh";

    public static IReadOnlyList<AttackSignature> All { get; } =
    [
        // ---- SQL injection ----
        new("sqli-union-select", AttackCategory.SqlInjection,
            @"\bunion\b(\s+(all|distinct))?\s*\(?\s*select\b",
            "UNION SELECT: appends a second query to read other data."),
        new("sqli-quoted-tautology", AttackCategory.SqlInjection,
            @"['""`]\s*\)?\s*(or|and|\|\||&&|xor)\s*\(?\s*['""`]?[a-z0-9_ ]*['""`]?\s*(=|<>|!=|<=?|>=?|\blike\b|\bis\b)",
            "Quote followed by OR/AND comparison, e.g. ' OR '1'='1."),
        new("sqli-numeric-tautology", AttackCategory.SqlInjection,
            @"(^|[\s'""`)=])(or|and|xor|\|\||&&)\s+\(?\d+\)?\s*(=|<>|!=|<|>)\s*\(?\d+",
            "Always-true comparison such as OR 1=1."),
        new("sqli-comment-terminator", AttackCategory.SqlInjection,
            @"['""`]\s*\)*\s*(--|#|;\s*(--|#|$))",
            "Quote followed by a comment that cuts off the rest of the query, e.g. admin'--."),
        new("sqli-stacked-query", AttackCategory.SqlInjection,
            @";\s*(drop\s+(table|database|user)|delete\s+from|truncate\s+table|insert\s+into|update\s+[a-z0-9_.\[\]`""]+\s+set\b|exec(ute)?\s+(xp_|sp_|master\.)|declare\s+@|shutdown\b|alter\s+(table|user|login))",
            "A second, destructive statement after a semicolon."),
        new("sqli-time-based", AttackCategory.SqlInjection,
            @"\b(sleep|pg_sleep|benchmark)\s*\(\s*\d|waitfor\s+(delay|time)\s+'",
            "Time-based blind injection (SLEEP, BENCHMARK, WAITFOR DELAY)."),
        new("sqli-system-objects", AttackCategory.SqlInjection,
            @"\b(information_schema|sysobjects|syscolumns|sys\.tables|pg_catalog|xp_cmdshell|sp_executesql|sp_oacreate|load_file\s*\(|into\s+(out|dump)file)\b|@@(version|datadir|hostname)\b",
            "Access to database system objects or files."),
        new("sqli-char-encoding", AttackCategory.SqlInjection,
            @"\b(char|chr|nchar)\s*\(\s*\d+\s*(,\s*\d+\s*){2,}\)",
            "Strings built with CHAR(…) to hide keywords."),

        // ---- Cross-site scripting ----
        new("xss-script-tag", AttackCategory.CrossSiteScripting,
            @"<\s*/?\s*script\b",
            "<script> tag."),
        new("xss-event-handler-tag", AttackCategory.CrossSiteScripting,
            @"<\s*[a-z][a-z0-9-]*\b[^>]*[\s/""']on[a-z]{3,}\s*=",
            "HTML tag with an event handler, e.g. <img onerror=…>."),
        new("xss-event-handler-attribute", AttackCategory.CrossSiteScripting,
            @"['""`]([^'""`<>]{0,100}[\s/])?\s*on(error|load|unload|mouse[a-z]+|focus[a-z]*|blur|click|dblclick|key[a-z]+|submit|change|input|animation[a-z]+|transition[a-z]+|toggle|pointer[a-z]+|begin|end|wheel|copy|paste|drag[a-z]*|touch[a-z]+|scroll|resize|hashchange|message|pageshow)\s*=",
            "Breaking out of an attribute to add an event handler."),
        new("xss-script-uri", AttackCategory.CrossSiteScripting,
            @"\b(j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|livescript)\s*:\s*[a-z_$][a-z0-9_$.]*\s*[(\[=`]",
            "javascript: / vbscript: URL running code (also with whitespace inside the scheme, which browsers ignore)."),
        new("xss-dangerous-tag", AttackCategory.CrossSiteScripting,
            @"<\s*(iframe|frame|frameset|object|embed|applet|base)\b|<\s*meta\b[^>]*http-equiv|<\s*svg\b[^>]*>\s*<\s*(script|animate|set)\b",
            "Tags that load or run active content."),
        new("xss-data-html", AttackCategory.CrossSiteScripting,
            @"\bdata\s*:\s*(text/html|image/svg\+xml|application/(x-)?javascript)",
            "data: URL with HTML or script."),
        new("xss-dom-sink", AttackCategory.CrossSiteScripting,
            @"\bdocument\s*\.\s*(cookie|domain|write(ln)?)\b|\beval\s*\(|\bstring\s*\.\s*fromcharcode\s*\(|\bexpression\s*\(|\bsrcdoc\s*=|\binnerhtml\s*=",
            "Script constructs used to steal cookies or run code."),

        // ---- Path traversal ----
        new("traversal-dot-dot", AttackCategory.PathTraversal,
            @"(^|[/;=:])\.{2,}(/|;|$)",
            "Parent-directory steps (../) to escape the web root."),
        new("traversal-sensitive-file", AttackCategory.PathTraversal,
            @"/etc/(passwd|shadow|group|hosts|issue|sudoers)\b|/proc/(self|\d+)/|(^|/)(boot|win|system)\.ini\b|\bc:/windows/|/windows/(system32|win\.ini)|(^|/)\.(htaccess|htpasswd|git/|svn/|env\b|aws/|ssh/)|(^|/)web\.config\b|\bid_(rsa|dsa|ecdsa|ed25519)\b",
            "Request for a well-known sensitive file."),
        new("traversal-null-byte", AttackCategory.PathTraversal,
            @"\x00",
            "Null byte, used to cut off a file extension (file.php%00.jpg)."),

        // ---- Command injection ----
        new("cmd-chained-command", AttackCategory.CommandInjection,
            $@"(;|\|\|?|&&|\n|`|\$\()\s*({ShellCommandsStrong})\b",
            "Shell command chained after ;, |, && or in a substitution."),
        new("cmd-chained-weak-command", AttackCategory.CommandInjection,
            $@"(;|\|\|?|&&|`|\$\()\s*({ShellCommandsWeak})(\s+(-[a-z]|/|\.\.?/|[a-z0-9.]+\s*[;|&`)])|\s*[;|&`)]|\s*$)",
            "Common shell command with arguments after a separator, e.g. ; cat /etc/passwd."),
        new("cmd-substitution", AttackCategory.CommandInjection,
            @"(\$\(|`)\s*(\.?/[a-z]|[a-z0-9_.-]+\s+-{1,2}[a-z])",
            "Command substitution $(…) or `…` running a path or a command with options (known commands are covered by cmd-chained-*)."),
        new("cmd-shell-artifacts", AttackCategory.CommandInjection,
            @"/bin/(ba|z|da|k)?sh\b|/dev/(tcp|udp)/|\bcmd(\.exe)?\s*/[ck]\b|\bpowershell(\.exe)?\s+-(e|enc|encodedcommand|c|command|nop|w)\b|\$\{ifs\}|\bnc\s+-[a-z]*e\b",
            "Shell binaries, reverse-shell devices or encoded PowerShell."),

        // ---- Bad user agents ----
        new("ua-attack-tool", AttackCategory.BadUserAgent,
            @"\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|netsparker|w3af|dirbuster|dirb|gobuster|wpscan|joomscan|havij|fimap|nessus|openvas|arachni|skipfish|wfuzz|ffuf|feroxbuster|commix|jaeles|xsstrike|whatweb|zmeu|morfeus|paros|webinspect|appscan|hydra|medusa|interactsh)\b",
            "User-Agent of a known attack or vulnerability-scanning tool."),
    ];

    internal static Regex Compile(string pattern) =>
        new(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
}
