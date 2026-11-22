using System.Net;
using System.Text;
using BenchmarkDotNet.Attributes;
using Waf.Core.Configuration;
using Waf.Engine;
using Waf.Engine.Detection;

namespace Waf.Benchmarks;

/// <summary>
/// Cost of attack detection per request.
/// Run: <c>dotnet run -c Release --project tests/Waf.Benchmarks -- --filter *AttackDetection* --inProcess</c>
/// </summary>
[MemoryDiagnoser]
public class AttackDetectionBenchmarks
{
    private readonly AttackDetector _detector = new(new AttackDetectionSettings { InspectBody = true });

    private readonly DetectionRequest _typical = new()
    {
        Path = "/shop/products/42/reviews",
        QueryString = "page=2&sort=rating&color=dark%20blue&utm_source=newsletter&utm_campaign=autumn-sale",
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        Cookie = "session=6f1c2b8e9a4d4e0f8c1b2a3d4e5f6a7b; theme=dark; consent=1",
        Referer = "https://www.example.com/shop/products/42",
    };

    private readonly DetectionRequest _attack = new()
    {
        Path = "/search",
        QueryString = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
        UserAgent = "Mozilla/5.0",
    };

    private readonly RequestBody _jsonBody = new("application/json", Encoding.UTF8.GetBytes(
        "{\"items\":[" + string.Join(',', Enumerable.Range(0, 400).Select(i => $"{{\"id\":{i},\"name\":\"Product {i}\",\"description\":\"A plain description of product number {i}.\"}}")) + "]}"));

    /// <summary>Typical clean GET: path, 5 query parameters, cookies, referer, user agent.</summary>
    [Benchmark(Baseline = true)]
    public AttackFinding? CleanRequest() => _detector.Inspect(_typical);

    /// <summary>Request with a URL-encoded UNION SELECT in the query.</summary>
    [Benchmark]
    public AttackFinding? AttackRequest() => _detector.Inspect(_attack);

    /// <summary>Clean request plus a ~40 KB JSON body (1200 string values).</summary>
    [Benchmark]
    public AttackFinding? CleanRequestWithJsonBody() => _detector.Inspect(_typical, _jsonBody);

    private sealed class DetectionRequest : IWafRequest
    {
        public IPAddress ClientIp { get; init; } = IPAddress.Loopback;
        public string Host { get; init; } = "www.example.com";
        public string Path { get; init; } = "/";
        public string QueryString { get; init; } = string.Empty;
        public string Method { get; init; } = "GET";
        public string? RouteName { get; init; } = "website";
        public string? UserAgent { get; init; }
        public string? Cookie { get; init; }
        public string? Referer { get; init; }

        public string? GetHeader(string name) => name switch
        {
            "User-Agent" => UserAgent,
            "Cookie" => Cookie,
            "Referer" => Referer,
            _ => null,
        };
    }
}
