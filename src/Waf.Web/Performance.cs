using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Web;

/// <summary>
/// The Performance page's address: the period and the filters. Everything is in the URL, so a view can be bookmarked
/// or shared; the CSV export reads the same parameters.
/// </summary>
internal sealed record PerformanceQuery
{
    public const string Live = "live";
    public const string Custom = "custom";

    /// <summary>Most types and sources in one filter.</summary>
    public const int MaxFilterValues = 20;

    /// <summary>How much the live view shows.</summary>
    public static readonly TimeSpan LiveWindow = TimeSpan.FromMinutes(5);

    public static readonly (string Value, string Label, TimeSpan Span)[] Periods =
    [
        ("1h", Text.N("Last hour"), TimeSpan.FromHours(1)),
        ("24h", Text.N("Last 24 hours"), TimeSpan.FromHours(24)),
        ("7d", Text.N("Last 7 days"), TimeSpan.FromDays(7)),
        ("30d", Text.N("Last 30 days"), TimeSpan.FromDays(30)),
        ("3m", Text.N("Last 3 months"), TimeSpan.FromDays(92)),
        ("1y", Text.N("Last year"), TimeSpan.FromDays(365)),
        ("3y", Text.N("Last 3 years"), TimeSpan.FromDays(1096)),
    ];

    /// <summary><see cref="Live"/>, one of <see cref="Periods"/> or <see cref="Custom"/>.</summary>
    public string Period { get; init; } = Live;

    public DateTimeOffset? From { get; init; }

    public DateTimeOffset? To { get; init; }

    public string? Route { get; init; }

    public IReadOnlyList<TrafficType> Types { get; init; } = [];

    public IReadOnlyList<string> Sources { get; init; } = [];

    /// <summary>Requested destinations (host and path, as <see cref="TrafficClassifier.Destination"/>).</summary>
    public IReadOnlyList<string> Destinations { get; init; } = [];

    /// <summary>Networks of sources ("203.0.113.0/24", "2001:db8:1::/48").</summary>
    public IReadOnlyList<string> Networks { get; init; } = [];

    /// <summary>Countries of sources (ISO codes).</summary>
    public IReadOnlyList<string> Countries { get; init; } = [];

    /// <summary>How the sources are listed: by address, network or country.</summary>
    public SourceLevel SourcesBy { get; init; }

    /// <summary>Also show the previous period of the same length.</summary>
    public bool Compare { get; init; }

    public bool IsLive => Period == Live;

    public bool IsFiltered => Route is not null || Types.Count > 0 || Sources.Count > 0 || Destinations.Count > 0 || Networks.Count > 0 || Countries.Count > 0;

    /// <summary>A source filter of any level is set (sources are counted without their route).</summary>
    public bool HasSourceFilter => Sources.Count > 0 || Networks.Count > 0 || Countries.Count > 0 || Destinations.Count > 0;

    public static PerformanceQuery Parse(IQueryCollection query)
    {
        ArgumentNullException.ThrowIfNull(query);

        var period = query["period"].ToString();
        var from = Moment(query["from"]);
        var to = Moment(query["to"]);
        if (period == Custom && (from is null || to is null || from >= to))
        {
            period = string.Empty;
        }

        var route = query["route"].ToString().Trim();
        return new PerformanceQuery
        {
            Period = period == Custom || Periods.Any(p => p.Value == period) ? period : Live,
            From = period == Custom ? from : null,
            To = period == Custom ? to : null,
            Route = route.Length is > 0 and <= TrafficClassifier.MaxNameLength && !route.Any(char.IsControl) ? route : null,
            Types = [.. query["type"].Select(TrafficType.Parse).OfType<TrafficType>().Distinct().Take(MaxFilterValues)],
            Sources = [.. query["source"]
                .SelectMany(s => (s ?? string.Empty).Split([',', ' '], StringSplitOptions.RemoveEmptyEntries))
                .Select(s => IPAddress.TryParse(s, out var ip) ? ip.ToString() : null)
                .OfType<string>()
                .Distinct(StringComparer.Ordinal)
                .Take(MaxFilterValues)],
            Destinations = [.. query["destination"]
                .Select(d => (d ?? string.Empty).Trim())
                .Where(d => d.Length is > 1 and <= TrafficClassifier.MaxDestinationLength && d.Contains('/', StringComparison.Ordinal) && !d.Any(char.IsControl))
                .Distinct(StringComparer.Ordinal)
                .Take(MaxFilterValues)],
            Networks = [.. query["network"]
                .Select(n => System.Net.IPNetwork.TryParse(n, out var network) && network.PrefixLength is 24 or 48 or 32 or 128 ? network.ToString() : null)
                .OfType<string>()
                .Distinct(StringComparer.Ordinal)
                .Take(MaxFilterValues)],
            Countries = [.. query["country"]
                .Select(c => (c ?? string.Empty).Trim().ToUpperInvariant())
                .Where(c => c.Length == 2 && c.All(char.IsAsciiLetterUpper))
                .Distinct(StringComparer.Ordinal)
                .Take(MaxFilterValues)],
            SourcesBy = Enum.TryParse<SourceLevel>(query["sources"], ignoreCase: true, out var level) && Enum.IsDefined(level) ? level : SourceLevel.Address,
            Compare = query["compare"] == "1",
        };
    }

    /// <summary>
    /// A moment: Unix seconds, or ISO 8601 (the custom range form's fields are converted by the page's script; without
    /// it, a time without an offset is taken as UTC).
    /// </summary>
    private static DateTimeOffset? Moment(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            return seconds is > 0 and < 253402300800 ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var moment)
            ? moment
            : null;
    }

    /// <summary>The period as [from, to) at <paramref name="now"/>.</summary>
    public (DateTimeOffset From, DateTimeOffset To) Range(DateTimeOffset now)
    {
        if (Period == Custom && From is { } from && To is { } to)
        {
            to = to > now ? now : to;
            from = from < now - MetricsRetention.MaxKeep ? now - MetricsRetention.MaxKeep : from;
            return (from, to > from ? to : from.AddSeconds(1));
        }

        var span = IsLive ? LiveWindow : Periods.First(p => p.Value == Period).Span;
        return (now - span, now);
    }

    /// <summary>The query string of this view, e.g. "period=24h&amp;type=NoRoute".</summary>
    public List<KeyValuePair<string, string?>> Parameters()
    {
        var parameters = new List<KeyValuePair<string, string?>>();
        if (!IsLive)
        {
            parameters.Add(new("period", Period));
        }

        if (Period == Custom)
        {
            parameters.Add(new("from", From!.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
            parameters.Add(new("to", To!.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        }

        if (Route is not null)
        {
            parameters.Add(new("route", Route));
        }

        parameters.AddRange(Types.Select(t => new KeyValuePair<string, string?>("type", t.ToString())));
        parameters.AddRange(Sources.Select(s => new KeyValuePair<string, string?>("source", s)));
        parameters.AddRange(Destinations.Select(d => new KeyValuePair<string, string?>("destination", d)));
        parameters.AddRange(Networks.Select(n => new KeyValuePair<string, string?>("network", n)));
        parameters.AddRange(Countries.Select(c => new KeyValuePair<string, string?>("country", c)));
        if (SourcesBy != SourceLevel.Address)
        {
            parameters.Add(new("sources", SourcesBy.ToString().ToLowerInvariant()));
        }
        if (Compare)
        {
            parameters.Add(new("compare", "1"));
        }

        return parameters;
    }

    public string Url(string path = "performance") => QueryHelpers.AddQueryString(path, Parameters());

    /// <summary>This view with the type filter replaced by one type ("show only this").</summary>
    public PerformanceQuery WithType(TrafficType type) => this with { Types = [type] };

    /// <summary>This view with the source filter replaced by one source (only one source filter applies at a time).</summary>
    public PerformanceQuery WithSource(string source) => WithoutSourceFilters() with { Sources = [source] };

    /// <summary>This view with the destination filter replaced by one destination.</summary>
    public PerformanceQuery WithDestination(string destination) => WithoutSourceFilters() with { Destinations = [destination] };

    /// <summary>This view with the network filter replaced by one network.</summary>
    public PerformanceQuery WithNetwork(string network) => WithoutSourceFilters() with { Networks = [network] };

    /// <summary>This view with the country filter replaced by one country.</summary>
    public PerformanceQuery WithCountry(string country) => WithoutSourceFilters() with { Countries = [country] };

    public PerformanceQuery WithoutSourceFilters() => this with { Sources = [], Destinations = [], Networks = [], Countries = [] };

    /// <summary>This view for a fixed period (the period of a history view kept as it is).</summary>
    public PerformanceQuery WithPeriod(DateTimeOffset from, DateTimeOffset to) => this with { Period = Custom, From = from, To = to };
}

/// <summary>What the Performance page shows for one view.</summary>
internal sealed record PerformanceReport(
    DateTimeOffset From,
    DateTimeOffset To,
    MetricsTier Tier,
    IReadOnlyList<TrafficBucket> Series,
    IReadOnlyList<TrafficBucket>? Previous,
    IReadOnlyList<TrafficKindTotal> Kinds,
    IReadOnlyList<LiveSourceCount> Sources,
    IReadOnlyList<LiveSourceCount>? Destinations = null,
    long SourceTotal = 0,
    long DestinationTotal = 0)
{
    /// <summary>The networks with the most bad requests.</summary>
    public IReadOnlyList<LiveSourceCount> TopNetworks { get; init; } = [];

    /// <summary>The countries with the most bad requests (with a country database).</summary>
    public IReadOnlyList<LiveSourceCount> TopCountries { get; init; } = [];

    public long NetworkTotal { get; init; }

    public long CountryTotal { get; init; }

    /// <summary>Response time percentiles per bucket (per minute and coarser).</summary>
    public IReadOnlyList<LatencyPoint> Latency { get; init; } = [];

    /// <summary>Response times over the whole period.</summary>
    public LatencySummary? LatencySummary { get; init; }

    /// <summary>What each backend did, per route.</summary>
    public IReadOnlyList<BackendSummary> Backends { get; init; } = [];

    /// <summary>Periods in which a route ran on a failover destination.</summary>
    public IReadOnlyList<FailoverPeriod> Failovers { get; init; } = [];

    /// <summary>The requested destinations with the most bad requests.</summary>
    public IReadOnlyList<LiveSourceCount> TopDestinations => Destinations ?? [];

    /// <summary>Sources listed.</summary>
    public const int TopSources = 20;

    public long Good => Series.Sum(b => b.Good);

    public long Bad => Series.Sum(b => b.Bad);

    public long Failed => Series.Sum(b => b.Failed);

    public long Total => Good + Bad + Failed;

    /// <summary>Average requests per second over the period.</summary>
    public double PerSecond => (To - From).TotalSeconds is var seconds and > 0 ? Total / seconds : 0;

    /// <summary>Highest requests per second inside the period, when known.</summary>
    public long? Peak => Series.Select(b => b.Peak).Where(p => p is not null).Max();

    public double Share(long part) => Total > 0 ? (double)part / Total : 0;

    public static async Task<PerformanceReport> BuildAsync(
        SqliteMetricsStore store, MetricsRetention retention, PerformanceQuery query, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(query);

        var (from, to) = query.Range(now);
        var tier = query.IsLive ? MetricsTier.Second : SqliteMetricsStore.ChooseTier(from, to, now, retention);
        var request = new TrafficQuery(
            from, to, tier, query.HasSourceFilter ? null : query.Route, query.Types, query.Sources, query.Destinations, query.Networks, query.Countries);
        var series = await store.ReadSeriesAsync(request, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<TrafficBucket>? previous = null;
        if (query.Compare && !query.IsLive)
        {
            var span = to - from;
            previous = await store.ReadSeriesAsync(request with { From = from - span, To = from }, cancellationToken).ConfigureAwait(false);
        }

        var kinds = await store.ReadKindsAsync(request, cancellationToken).ConfigureAwait(false);
        var sources = await store.ReadTopSourcesAsync(request, TopSources, cancellationToken).ConfigureAwait(false);
        var destinations = await store.ReadTopDestinationsAsync(request, TopSources, cancellationToken).ConfigureAwait(false);
        var sourceTotal = await store.ReadSourceTotalAsync(request, cancellationToken).ConfigureAwait(false);
        var destinationTotal = await store.ReadDestinationTotalAsync(request, cancellationToken).ConfigureAwait(false);
        // Response times and backends are kept per route only: the route filter applies, the others do not.
        var responses = new TrafficQuery(from, to, tier, query.Route);
        var (latency, latencySummary) = await store.ReadLatencyAsync(responses, cancellationToken).ConfigureAwait(false);
        var backends = await store.ReadBackendsAsync(responses, cancellationToken).ConfigureAwait(false);
        var failovers = await store.ReadFailoversAsync(from, to, query.Route, cancellationToken).ConfigureAwait(false);
        return new PerformanceReport(
            from, to, series.Count > 0 && series[0].Seconds > 1 && tier == MetricsTier.Second ? MetricsTier.Minute : tier,
            series, previous, kinds, sources, destinations, sourceTotal, destinationTotal)
        {
            TopNetworks = await store.ReadTopNetworksAsync(request, TopSources, cancellationToken).ConfigureAwait(false),
            TopCountries = await store.ReadTopCountriesAsync(request, TopSources, cancellationToken).ConfigureAwait(false),
            NetworkTotal = await store.ReadNetworkTotalAsync(request, cancellationToken).ConfigureAwait(false),
            CountryTotal = await store.ReadCountryTotalAsync(request, cancellationToken).ConfigureAwait(false),
            Latency = latency,
            LatencySummary = latencySummary,
            Backends = backends,
            Failovers = failovers,
        };
    }

    /// <summary>The chart's data, for the page's script: buckets as [start, good, bad, failed, peak], the previous period shifted onto this one.</summary>
    public string ChartJson(bool live, string? route, IReadOnlyList<(double Usual, double Alarm)>? usual = null)
    {
        var span = (long)(To - From).TotalSeconds;
        var data = new
        {
            live,
            route,
            tier = Tier.ToString(),
            buckets = Series.Select(b => new object?[] { b.Start, b.Seconds, b.Good, b.Bad, b.Failed, b.Peak }),
            previous = Previous?.Select(b => new object[] { b.Start + span, b.Seconds, b.Total }),
            failovers = FailoverBands(),
            usual = usual?.Select(u => new[] { Math.Round(u.Usual, 3), Math.Round(u.Alarm, 3) }),
        };
        return JsonSerializer.Serialize(data);
    }

    /// <summary>The response time chart's data: points as [start, p50, p95, p99, gateway p50] in milliseconds, and the failover bands.</summary>
    public string LatencyJson() => JsonSerializer.Serialize(new
    {
        points = Latency.Select(p => new object?[] { p.Start, Round(p.P50), Round(p.P95), Round(p.P99), Round(p.GatewayP50) }),
        failovers = FailoverBands(),
    });

    /// <summary>Failover periods as [start, end (null: still running), route, failover number].</summary>
    private IEnumerable<object?[]> FailoverBands() =>
        Failovers.Select(f => new object?[] { f.Start.ToUnixTimeSeconds(), f.End?.ToUnixTimeSeconds(), f.Route, f.Failover });

    private static double? Round(double? milliseconds) => milliseconds is { } value ? Math.Round(value, value < 10 ? 2 : 0) : null;

    /// <summary>The series as CSV (UTC times, invariant numbers).</summary>
    public string ToCsv()
    {
        var csv = new StringBuilder("start_utc,seconds,good,bad,failed,total,per_second,peak_per_second\r\n");
        foreach (var bucket in Series)
        {
            csv.Append(CultureInfo.InvariantCulture, $"{DateTimeOffset.FromUnixTimeSeconds(bucket.Start).UtcDateTime:yyyy-MM-ddTHH:mm:ssZ},{bucket.Seconds},{bucket.Good},{bucket.Bad},{bucket.Failed},{bucket.Total},{bucket.PerSecond:0.###},{bucket.Peak?.ToString(CultureInfo.InvariantCulture)}\r\n");
        }

        return csv.ToString();
    }
}

/// <summary>How the sources of bad traffic are listed.</summary>
internal enum SourceLevel
{
    /// <summary>Client IP addresses.</summary>
    Address,

    /// <summary>Networks: IPv4 /24, IPv6 /48.</summary>
    Network,

    /// <summary>Countries (with a country database).</summary>
    Country,
}

/// <summary>Names and request log links of the kinds of traffic.</summary>
internal static class PerformanceText
{
    public static string Tier(MetricsTier tier) => tier switch
    {
        MetricsTier.Second => Text.T("per second"),
        MetricsTier.Minute => Text.T("per minute"),
        MetricsTier.Hour => Text.T("per hour"),
        MetricsTier.Day => Text.T("per day"),
        MetricsTier.Week => Text.T("per week"),
        _ => Text.T("per month"),
    };

    public static string Kind(TrafficKind kind) => kind switch
    {
        TrafficKind.Forwarded => Text.T("Forwarded"),
        TrafficKind.Redirected => Text.T("Redirected to HTTPS"),
        TrafficKind.Answered => Text.T("Answered by the gateway"),
        TrafficKind.WouldBeBlocked => Text.T("Would be blocked"),
        TrafficKind.RuleBlocked => Text.T("Blocked by a rule"),
        TrafficKind.AttackBlocked => Text.T("Blocked by attack detection"),
        TrafficKind.RateLimited => Text.T("Rate limited"),
        TrafficKind.FailClosed => Text.T("Refused (WAF unavailable)"),
        TrafficKind.NoRoute => Text.T("No route"),
        TrafficKind.NoBackend => Text.T("No backend (503)"),
        TrafficKind.BackendError => Text.T("Backend error (502)"),
        TrafficKind.BackendTimeout => Text.T("Backend timeout (504)"),
        _ => Text.T("Gateway error (500)"),
    };

    /// <summary>The name shown for a kind's name: attack categories in plain language.</summary>
    public static string Name(TrafficKind kind, string name) =>
        kind is TrafficKind.AttackBlocked or TrafficKind.WouldBeBlocked
            && Enum.TryParse<FASoft.Waf.Core.Configuration.AttackCategory>(name, out var category) && Enum.IsDefined(category)
            ? LogActions.Label(category)
            : name;

    /// <summary>
    /// The text every address of an IPv4 /24 network starts with ("198.51.100."); null for other networks (IPv6
    /// addresses are written in shortened forms, so a prefix does not find them reliably).
    /// </summary>
    public static string? NetworkPrefix(string network)
    {
        if (!System.Net.IPNetwork.TryParse(network, out var parsed) || parsed.BaseAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || parsed.PrefixLength != 24)
        {
            return null;
        }

        var bytes = parsed.BaseAddress.GetAddressBytes();
        return string.Create(CultureInfo.InvariantCulture, $"{bytes[0]}.{bytes[1]}.{bytes[2]}.");
    }

    /// <summary>
    /// The request log showing the requests behind a number: same period and route, plus the kind (and source);
    /// null when the request log does not reach back to that period.
    /// </summary>
    public static string? LogUrl(
        DateTimeOffset from,
        DateTimeOffset to,
        DateTimeOffset? oldestLogged,
        string? route,
        TrafficType? type = null,
        string? source = null,
        string? destination = null,
        string? network = null)
    {
        if (oldestLogged is not { } oldest || to <= oldest)
        {
            return null;
        }

        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["from"] = from.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["to"] = ((to.ToUnixTimeMilliseconds() + 999) / 1000).ToString(CultureInfo.InvariantCulture), // rounded up: includes the running second
            ["route"] = route,
            ["ip"] = source,
        };

        // A network: the address prefix as search text ("198.51.100." for 198.51.100.0/24; the log has no range filter).
        if (network is not null && NetworkPrefix(network) is { } prefix)
        {
            parameters["q"] = prefix;
        }

        // A destination is "host/path": the host exactly, the path as search text (the log has no exact path filter).
        if (destination is not null && destination.IndexOf('/', StringComparison.Ordinal) is var slash and > 0)
        {
            parameters["host"] = destination[..slash];
            parameters["q"] = destination[slash..];
        }

        if (type is not null)
        {
            var attack = Enum.TryParse<FASoft.Waf.Core.Configuration.AttackCategory>(type.Name, out _);
            switch (type.Kind)
            {
                case TrafficKind.RuleBlocked or TrafficKind.RateLimited:
                    parameters["show"] = nameof(LogView.Blocked);
                    parameters["rule"] = type.Name;
                    break;
                case TrafficKind.AttackBlocked:
                    parameters["show"] = nameof(LogView.Blocked);
                    parameters["q"] = type.Name;
                    break;
                case TrafficKind.WouldBeBlocked:
                    parameters["show"] = nameof(LogView.WouldBlock);
                    parameters[attack ? "q" : "rule"] = type.Name;
                    break;
                case TrafficKind.FailClosed:
                    parameters["show"] = nameof(LogView.Blocked);
                    parameters["status"] = "503";
                    break;
                case TrafficKind.NoRoute:
                    parameters["show"] = nameof(LogView.NoRoute);
                    break;
                case TrafficKind.Forwarded:
                    parameters["show"] = nameof(LogView.Forwarded);
                    break;
                case TrafficKind.Redirected:
                    parameters["status"] = "308";
                    break;
                case TrafficKind.NoBackend:
                    parameters["status"] = "503";
                    break;
                case TrafficKind.BackendError:
                    parameters["status"] = "502";
                    break;
                case TrafficKind.BackendTimeout:
                    parameters["status"] = "504";
                    break;
                case TrafficKind.GatewayError:
                    parameters["status"] = "500";
                    break;
            }
        }

        return QueryHelpers.AddQueryString("logs", parameters.Where(p => p.Value is not null));
    }
}
