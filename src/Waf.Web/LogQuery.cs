using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>
/// The log viewer's query string (filters, page size, position), parsed the same way for the page and the live
/// view endpoint. Everything is in the URL, so a view can be bookmarked or shared.
/// </summary>
internal sealed record LogQuery
{
    public static readonly (string Value, string Label, TimeSpan? Span)[] Ranges =
    [
        ("15m", "Last 15 minutes", TimeSpan.FromMinutes(15)),
        ("1h", "Last hour", TimeSpan.FromHours(1)),
        ("24h", "Last 24 hours", TimeSpan.FromHours(24)),
        ("7d", "Last 7 days", TimeSpan.FromDays(7)),
        ("30d", "Last 30 days", TimeSpan.FromDays(30)),
        ("all", "Everything", null),
    ];

    public static readonly (LogView Value, string Label)[] Views =
    [
        (LogView.All, "All requests"),
        (LogView.Blocked, "Blocked (403, 429, 503)"),
        (LogView.WouldBlock, "Would be blocked (detection only)"),
        (LogView.Logged, "Matched a log-only rule"),
        (LogView.Forwarded, "Forwarded"),
        (LogView.NoRoute, "No route (404)"),
        (LogView.Errors, "Server errors (5xx)"),
    ];

    public static readonly int[] PageSizes = [25, 50, 100, 200];

    public const string DefaultRange = "24h";
    public const int DefaultSize = 50;

    public string Range { get; init; } = DefaultRange;
    public LogView Show { get; init; }
    public string? Ip { get; init; }
    public string? Host { get; init; }
    public string? Route { get; init; }
    public string? Rule { get; init; }
    public int? Status { get; init; }
    public string? Search { get; init; }
    public int Size { get; init; } = DefaultSize;
    public long? Before { get; init; }
    public long? After { get; init; }

    /// <summary>True when any filter other than the time range is set.</summary>
    public bool IsFiltered => Show != LogView.All || Ip is not null || Host is not null || Route is not null || Rule is not null || Status is not null || Search is not null;

    /// <summary>The newest entries are shown (not an older or newer page): the live view applies.</summary>
    public bool IsFirstPage => Before is null && After is null;

    public static LogQuery Parse(IQueryCollection query)
    {
        ArgumentNullException.ThrowIfNull(query);

        string? Text(string name, int max = 300) =>
            query[name].ToString().Trim() is { Length: > 0 } value ? (value.Length > max ? value[..max] : value) : null;
        long? Id(string name) => long.TryParse(query[name], NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id > 0 ? id : null;

        var range = Text("range");
        var size = int.TryParse(query["size"], NumberStyles.None, CultureInfo.InvariantCulture, out var s) && PageSizes.Contains(s) ? s : DefaultSize;
        return new LogQuery
        {
            Range = Ranges.Any(r => r.Value == range) ? range! : DefaultRange,
            Show = Enum.TryParse<LogView>(query["show"], ignoreCase: true, out var show) && Enum.IsDefined(show) ? show : LogView.All,
            Ip = Text("ip", 45),
            Host = Text("host", 255),
            Route = Text("route", 200),
            Rule = Text("rule", 200),
            Status = int.TryParse(query["status"], NumberStyles.None, CultureInfo.InvariantCulture, out var status) && status is >= 100 and <= 599 ? status : null,
            Search = Text("q", 200),
            Size = size,
            Before = Id("before"),
            After = Id("after"),
        };
    }

    public RequestLogFilter ToFilter(DateTimeOffset now) => new()
    {
        From = Ranges.First(r => r.Value == Range).Span is { } span ? now - span : null,
        Show = Show,
        ClientIp = Ip,
        Host = Host,
        Route = Route,
        Rule = Rule,
        Status = Status,
        Search = Search,
    };

    /// <summary>The query string of this view (without position), e.g. "range=1h&amp;show=Blocked".</summary>
    public Dictionary<string, string?> Parameters()
    {
        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal);
        void Add(string name, string? value, string? skipIf = null)
        {
            if (value is not null && value != skipIf)
            {
                parameters[name] = value;
            }
        }

        Add("range", Range, DefaultRange);
        Add("show", Show == LogView.All ? null : Show.ToString());
        Add("ip", Ip);
        Add("host", Host);
        Add("route", Route);
        Add("rule", Rule);
        Add("status", Status?.ToString(CultureInfo.InvariantCulture));
        Add("q", Search);
        Add("size", Size.ToString(CultureInfo.InvariantCulture), DefaultSize.ToString(CultureInfo.InvariantCulture));
        return parameters;
    }

    /// <summary>URL of <paramref name="path"/> with this view's filters plus <paramref name="extra"/>.</summary>
    public string Url(string path, params (string Name, string? Value)[] extra)
    {
        var parameters = Parameters();
        foreach (var (name, value) in extra)
        {
            parameters[name] = value;
        }

        return QueryHelpers.AddQueryString(path, parameters.Where(p => p.Value is not null));
    }

    /// <summary>This view with one filter replaced (for "show only this client" links).</summary>
    public string UrlWith(string name, string value) =>
        QueryHelpers.AddQueryString("logs", Parameters().Where(p => p.Key != name && p.Value is not null).Append(new(name, value)));
}

/// <summary>How log entries are shown, shared by the page and the live view.</summary>
internal static class LogFormat
{
    public static string Time(long timestampMs) =>
        DateTimeOffset.FromUnixTimeMilliseconds(timestampMs).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string Latency(double ms) =>
        ms >= 1000 ? (ms / 1000).ToString("0.0 s", CultureInfo.InvariantCulture) : ms.ToString("0.0 ms", CultureInfo.InvariantCulture);

    /// <summary>Label and badge class of what happened.</summary>
    public static (string Label, string Badge) Outcome(RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return entry.Action switch
        {
            "Forwarded" => ("Forwarded", "badge-ok"),
            "Blocked" => ("Blocked", "badge-danger"),
            "RateLimited" => ("Rate limited", "badge-danger"),
            "FailClosed" => ("Refused (WAF unavailable)", "badge-danger"),
            "NoRoute" => ("No route", "badge-muted"),
            "BackendUnavailable" => ("Backend unavailable", "badge-warning"),
            "Redirected" => ("Redirected to HTTPS", "badge-muted"),
            _ => ("Answered by the gateway", "badge-muted"),
        };
    }

    /// <summary>A second badge for detection-only and log-only matches; null otherwise.</summary>
    public static (string Label, string Badge)? Note(RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return entry.Event switch
        {
            "RuleDetected" or "AttackDetected" or "RateLimitDetected" => ("Would block", "badge-warning"),
            "RuleLogged" => ("Logged", "badge-muted"),
            _ => null,
        };
    }

    /// <summary>The entry as JSON-friendly fields for the live view (all text; the script sets textContent only).</summary>
    public static LiveRow ToLiveRow(RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var (label, badge) = Outcome(entry);
        var note = Note(entry);
        return new LiveRow(
            entry.Id,
            Time(entry.TimestampMs),
            entry.ClientIp,
            entry.Method,
            entry.Host,
            entry.Path,
            entry.RouteName,
            label,
            badge,
            note?.Label,
            note?.Badge,
            entry.RuleName,
            entry.StatusCode,
            Latency(entry.LatencyMs),
            $"logs/{entry.Id.ToString(CultureInfo.InvariantCulture)}");
    }
}

/// <summary>One row of the live view.</summary>
internal sealed record LiveRow(
    long Id, string Time, string ClientIp, string Method, string Host, string Path, string? Route,
    string Outcome, string OutcomeBadge, string? Note, string? NoteBadge, string? Rule, int Status, string Latency, string Url);
