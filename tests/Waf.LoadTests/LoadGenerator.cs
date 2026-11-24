using System.Diagnostics;
using System.Net;

namespace FASoft.Waf.LoadTests;

/// <summary>What one run measured. Latencies in milliseconds, over the measured period only (not the warm-up).</summary>
internal sealed record LoadResult(
    string Scenario, string Target, int Concurrency, TimeSpan Duration, long Requests, long Errors,
    double P50, double P95, double P99, double Max, string? FirstError)
{
    public double RequestsPerSecond => Requests / Duration.TotalSeconds;
}

/// <summary>
/// Closed-loop load: <c>concurrency</c> workers each send the next request as soon as the previous answer is read
/// (one keep-alive connection per worker). Throughput is therefore what the target sustains at that concurrency.
/// </summary>
internal static class LoadGenerator
{
    public static async Task<LoadResult> RunAsync(
        Uri baseUrl, string? host, Scenario scenario, int concurrency, TimeSpan duration, TimeSpan warmUp, CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler
        {
            MaxConnectionsPerServer = concurrency,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        var start = Stopwatch.GetTimestamp();
        var measureFrom = start + (long)(warmUp.TotalSeconds * Stopwatch.Frequency);
        var stopAt = measureFrom + (long)(duration.TotalSeconds * Stopwatch.Frequency);
        var workers = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(() => WorkerAsync(client, baseUrl, host, scenario, measureFrom, stopAt, cancellationToken), cancellationToken))
            .ToArray();
        var results = await Task.WhenAll(workers).ConfigureAwait(false);

        var latencies = results.SelectMany(r => r.Latencies).ToArray();
        Array.Sort(latencies);
        double Percentile(double p) =>
            latencies.Length == 0 ? 0 : TicksToMs(latencies[Math.Min(latencies.Length - 1, (int)Math.Ceiling(p * latencies.Length) - 1)]);

        return new LoadResult(
            scenario.Description, baseUrl.Authority, concurrency, duration,
            latencies.Length, results.Sum(r => r.Errors),
            Percentile(0.50), Percentile(0.95), Percentile(0.99), latencies.Length == 0 ? 0 : TicksToMs(latencies[^1]),
            results.Select(r => r.FirstError).FirstOrDefault(e => e is not null));
    }

    private static double TicksToMs(long ticks) => ticks * 1000.0 / Stopwatch.Frequency;

    private sealed record WorkerResult(List<long> Latencies, long Errors, string? FirstError);

    private static async Task<WorkerResult> WorkerAsync(
        HttpClient client, Uri baseUrl, string? host, Scenario scenario, long measureFrom, long stopAt, CancellationToken cancellationToken)
    {
        var latencies = new List<long>(capacity: 100_000);
        long errors = 0;
        string? firstError = null;
        var buffer = new byte[16 * 1024];

        while (!cancellationToken.IsCancellationRequested)
        {
            var sent = Stopwatch.GetTimestamp();
            if (sent >= stopAt)
            {
                break;
            }

            string? error = null;
            try
            {
                using var request = scenario.CreateRequest(baseUrl, host);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                await using (body.ConfigureAwait(false))
                {
                    while (await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false) > 0)
                    {
                        // Read the whole answer, as a browser would.
                    }
                }

                if (response.StatusCode != scenario.Expected)
                {
                    error = $"HTTP {(int)response.StatusCode} instead of {(int)scenario.Expected}";
                }
            }
            catch (HttpRequestException ex)
            {
                error = ex.Message;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                error = "timeout: " + ex.Message;
            }

            if (sent < measureFrom)
            {
                continue; // warm-up
            }

            latencies.Add(Stopwatch.GetTimestamp() - sent);
            if (error is not null)
            {
                errors++;
                firstError ??= error;
            }
        }

        return new WorkerResult(latencies, errors, firstError);
    }
}
