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
        ("15m", Text.N("Last 15 minutes"), TimeSpan.FromMinutes(15)),
        ("1h", Text.N("Last hour"), TimeSpan.FromHours(1)),
        ("24h", Text.N("Last 24 hours"), TimeSpan.FromHours(24)),
        ("7d", Text.N("Last 7 days"), TimeSpan.FromDays(7)),
        ("30d", Text.N("Last 30 days"), TimeSpan.FromDays(30)),
        ("all", Text.N("Everything"), null),
    ];

    public static readonly (LogView Value, string Label)[] Views =
    [
        (LogView.All, Text.N("All requests")),
        (LogView.Blocked, Text.N("Blocked (403, 429, 503)")),
        (LogView.WouldBlock, Text.N("Would be blocked (detection only)")),
        (LogView.Logged, Text.N("Matched a log-only rule")),
        (LogView.Forwarded, Text.N("Forwarded")),
        (LogView.NoRoute, Text.N("No route (404)")),
        (LogView.Errors, Text.N("Server errors (5xx)")),
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

    /// <summary>Start of a fixed period (from the Performance page); overrides <see cref="Range"/>.</summary>
    public DateTimeOffset? From { get; init; }

    /// <summary>End of a fixed period (exclusive).</summary>
    public DateTimeOffset? To { get; init; }

    /// <summary>A fixed period is set instead of "the last …".</summary>
    public bool HasPeriod => From is not null || To is not null;

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
        DateTimeOffset? Moment(string name) =>
            long.TryParse(query[name], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds is > 0 and < 253402300800
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : null;

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
            From = Moment("from"),
            To = Moment("to"),
        };
    }

    public RequestLogFilter ToFilter(DateTimeOffset now) => new()
    {
        From = HasPeriod ? From : Ranges.First(r => r.Value == Range).Span is { } span ? now - span : null,
        To = To,
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
        Add("from", From?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        Add("to", To?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
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
            "Forwarded" => (Text.T("Forwarded"), "badge-ok"),
            "Blocked" => (Text.T("Blocked"), "badge-danger"),
            "RateLimited" => (Text.T("Rate limited"), "badge-danger"),
            "FailClosed" => (Text.T("Refused (WAF unavailable)"), "badge-danger"),
            "NoRoute" => (Text.T("No route"), "badge-muted"),
            "BackendUnavailable" => (Text.T("Backend unavailable"), "badge-warning"),
            "Redirected" => (Text.T("Redirected to HTTPS"), "badge-muted"),
            _ => (Text.T("Answered by the gateway"), "badge-muted"),
        };
    }

    /// <summary>A second badge for detection-only and log-only matches; null otherwise.</summary>
    public static (string Label, string Badge)? Note(RequestEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return entry.Event switch
        {
            "RuleDetected" or "AttackDetected" or "RateLimitDetected" => (Text.T("Would block"), "badge-warning"),
            "RuleLogged" => (Text.T("Logged"), "badge-muted"),
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
