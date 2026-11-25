using BenchmarkDotNet.Attributes;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Benchmarks;

/// <summary>
/// Cost of counting one request for the traffic counts (classification plus the in-memory counter).
/// Run: <c>dotnet run -c Release --project tests/Waf.Benchmarks -- --filter *TrafficCounter* --inProcess</c>
/// </summary>
[MemoryDiagnoser]
public class TrafficCounterBenchmarks
{
    private readonly TrafficCounter _counter = new(maxCells: 10_000_000);

    private readonly RequestLogEntry _forwarded = new(
        DateTimeOffset.UtcNow, "203.0.113.7", "GET", "www.example.com", "/shop", "website",
        RequestAction.Forwarded, null, null, null, "http://10.0.0.5:8080/", 200, 2.5);

    private readonly RequestLogEntry _blocked = new(
        DateTimeOffset.UtcNow, "203.0.113.7", "GET", "www.example.com", "/search", "website",
        RequestAction.Blocked, WafEventKind.AttackBlocked, "sqli-1", "SqlInjection in QueryString 'q': ' union select", null, 403, 0.4);

    /// <summary>A forwarded request: one counter.</summary>
    [Benchmark(Baseline = true)]
    public bool Forwarded() => Count(_forwarded);

    /// <summary>A blocked request: its counter and its source's counter.</summary>
    [Benchmark]
    public bool Blocked() => Count(_blocked);

    private bool Count(RequestLogEntry entry)
    {
        var (kind, name) = TrafficClassifier.Classify(entry, failed: false);
        return _counter.Add(entry.Timestamp, kind, name, entry.RouteName, entry.ClientIp);
    }
}
