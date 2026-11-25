namespace FASoft.Waf.Engine;

/// <summary>Which time of a forwarded request a latency count is about.</summary>
public enum LatencySeries
{
    /// <summary>From arrival until the response was complete.</summary>
    Total = 0,

    /// <summary>The time spent forwarding to the backend.</summary>
    Backend = 1,

    /// <summary>What the gateway itself adds: the total minus the backend's time.</summary>
    Gateway = 2,
}

/// <summary>
/// What a backend did with a forwarded request: the class of its status code, or the error the gateway answered
/// with when it did not answer. The numbers are stored in <c>metrics.db</c> (errors use the <see cref="TrafficKind"/>
/// numbers).
/// </summary>
public enum BackendMetric
{
    Status2xx = 2,
    Status3xx = 3,
    Status4xx = 4,
    Status5xx = 5,

    /// <summary>No backend available (503).</summary>
    NoBackend = 20,

    /// <summary>The backend refused the connection or answered invalidly (502).</summary>
    BackendError = 21,

    /// <summary>The backend did not answer in time (504).</summary>
    BackendTimeout = 22,
}

/// <summary>Requests of one route in one bin of the response time histogram, within one bucket.</summary>
public sealed record LatencyCount(long BucketStart, string Route, LatencySeries Series, int Bin, long Count);

/// <summary>Requests of one route to one backend with one result, within one bucket.</summary>
/// <param name="Destination">The backend as the request log shows it, e.g. "nas · web (http://192.168.1.20:5000/)"; empty when none was available.</param>
public sealed record BackendCount(long BucketStart, string Route, string Destination, BackendMetric Metric, long Count);

/// <summary>
/// The response time histogram: fixed bins, each 25 % wider than the one before, from 0.5 ms to about 2 minutes. A
/// percentile read from it is within about 12 % of the exact value, at every resolution, without storing each request.
/// </summary>
public static class LatencyHistogram
{
    /// <summary>Upper edge of bin 0, in milliseconds.</summary>
    public const double FirstEdgeMs = 0.5;

    /// <summary>Each bin's upper edge is this much higher than the previous one.</summary>
    public const double Ratio = 1.25;

    /// <summary>Number of bins; the last one also holds everything slower.</summary>
    public const int Bins = 57;

    private static readonly double LogRatio = Math.Log(Ratio);

    /// <summary>The bin of a time in milliseconds.</summary>
    public static int Bin(double milliseconds)
    {
        if (double.IsNaN(milliseconds) || milliseconds <= FirstEdgeMs)
        {
            return 0;
        }

        var bin = (int)Math.Ceiling(Math.Log(milliseconds / FirstEdgeMs) / LogRatio - 1e-9);
        return Math.Clamp(bin, 0, Bins - 1);
    }

    /// <summary>Upper edge of <paramref name="bin"/>, in milliseconds.</summary>
    public static double UpperEdge(int bin) => FirstEdgeMs * Math.Pow(Ratio, bin);

    /// <summary>The value a bin stands for: the geometric middle of its edges (half the first edge for bin 0).</summary>
    public static double Estimate(int bin) => bin == 0 ? FirstEdgeMs / 2 : FirstEdgeMs * Math.Pow(Ratio, bin - 0.5);

    /// <summary>
    /// The <paramref name="percentile"/> (0 to 1) of a histogram given as counts per bin; null when it is empty.
    /// </summary>
    public static double? Percentile(IReadOnlyList<long> counts, double percentile)
    {
        ArgumentNullException.ThrowIfNull(counts);
        var total = counts.Sum();
        if (total == 0)
        {
            return null;
        }

        var rank = Math.Max(1, (long)Math.Ceiling(percentile * total));
        long seen = 0;
        for (var bin = 0; bin < counts.Count; bin++)
        {
            seen += counts[bin];
            if (seen >= rank)
            {
                return Estimate(bin);
            }
        }

        return Estimate(counts.Count - 1);
    }

    /// <summary>The backend result of a status code the backend answered with.</summary>
    public static BackendMetric StatusClass(int statusCode) => statusCode switch
    {
        < 300 => BackendMetric.Status2xx,
        < 400 => BackendMetric.Status3xx,
        < 500 => BackendMetric.Status4xx,
        _ => BackendMetric.Status5xx,
    };
}

/// <summary>What <see cref="TrafficCounter.TakeCompleted"/> takes: the completed buckets of every kind of count.</summary>
public sealed record TrafficTake(
    List<TrafficCount> Counts,
    List<SourceCount> Sources,
    List<SourceCount> Destinations,
    List<LatencyCount> Latencies,
    List<BackendCount> Backends)
{
    public bool IsEmpty => Counts.Count == 0 && Sources.Count == 0 && Destinations.Count == 0 && Latencies.Count == 0 && Backends.Count == 0;

    /// <summary>The first three parts, for callers that need only those.</summary>
    public void Deconstruct(out List<TrafficCount> counts, out List<SourceCount> sources, out List<SourceCount> destinations)
    {
        counts = Counts;
        sources = Sources;
        destinations = Destinations;
    }
}
