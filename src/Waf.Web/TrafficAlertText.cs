using System.Globalization;
using Microsoft.AspNetCore.WebUtilities;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Web;

/// <summary>What a notice of unusual traffic says, and where its links go.</summary>
internal static class TrafficAlertText
{
    public static string Metric(AlertMetric metric) => metric switch
    {
        AlertMetric.Bad => Text.T("Bad traffic"),
        AlertMetric.Failed => Text.T("Failed requests"),
        _ => Text.T("Traffic"),
    };

    /// <summary>"Bad traffic is 20× higher than usual since 10:42 UTC." (or "was", for one that ended).</summary>
    public static string Headline(TrafficAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var since = Describe.Time(alert.Start);
        var peak = alert.Peak.ToString(alert.Peak < 10 ? "N1" : "N0", CultureInfo.CurrentCulture);
        if (alert.Ratio is { } ratio)
        {
            var times = ratio.ToString(ratio < 10 ? "N1" : "N0", CultureInfo.CurrentCulture);
            return alert.End is null
                ? Text.T("{0} is {1}× higher than usual since {2} (up to {3} per second).", Metric(alert.Metric), times, since, peak)
                : Text.T("{0} was up to {1}× higher than usual from {2} ({3} per second).", Metric(alert.Metric), times, since, peak);
        }

        return alert.End is null
            ? Text.T("{0}: up to {1} per second since {2}, where there usually is almost none.", Metric(alert.Metric), peak, since)
            : Text.T("{0}: up to {1} per second from {2}, where there usually is almost none.", Metric(alert.Metric), peak, since);
    }

    /// <summary>"Mostly SQL injection, from 203.0.113.0/24."; null when nothing stands out.</summary>
    public static string? Mostly(TrafficAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var kind = alert.Kind is { } k
            ? alert.Name is { } name ? $"{PerformanceText.Kind(k)}: {PerformanceText.Name(k, name)}" : PerformanceText.Kind(k)
            : null;
        return (kind, alert.Network) switch
        {
            (not null, not null) => Text.T("Mostly {0}, from {1}.", kind, alert.Network),
            (not null, null) => Text.T("Mostly {0}.", kind),
            (null, not null) => Text.T("Mostly from {0}.", alert.Network),
            _ => null,
        };
    }

    /// <summary>The Performance page for the notice's time, narrowed to what most of it was.</summary>
    public static string ViewUrl(TrafficAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var from = alert.Start.AddMinutes(-15);
        var to = (alert.End ?? DateTimeOffset.UtcNow).AddMinutes(15);
        var query = new PerformanceQuery
        {
            Period = PerformanceQuery.Custom,
            From = from,
            To = to,
            Types = alert.Kind is { } kind ? [new TrafficType(kind, alert.Name)] : [],
            Networks = alert.Network is { } network ? [network] : [],
            SourcesBy = alert.Network is null ? SourceLevel.Address : SourceLevel.Network,
        };
        return query.Url();
    }

    /// <summary>The request log for the notice's time (bad: blocked requests; failed: server errors).</summary>
    public static string LogUrl(TrafficAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["from"] = alert.Start.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["to"] = alert.End?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["show"] = alert.Metric switch { AlertMetric.Bad => nameof(LogView.Blocked), AlertMetric.Failed => nameof(LogView.Errors), _ => null },
            ["q"] = alert.Network is { } network ? PerformanceText.NetworkPrefix(network) : null,
        };
        return QueryHelpers.AddQueryString("logs", parameters.Where(p => p.Value is not null));
    }
}
