using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace FASoft.Waf.LoadTests;

/// <summary>
/// waf-loadtest: load tests of a published gateway.
/// <list type="bullet">
/// <item><c>suite --gateway &lt;WafGateway file&gt;</c>: starts the backend and the gateway on this machine, measures each
/// scenario directly and through the gateway, and prints a Markdown report (docs/performance.md shows how to read it).</item>
/// <item><c>backend</c> and <c>run</c>: the same parts separately, for a gateway on another machine (a Raspberry Pi).</item>
/// </list>
/// </summary>
internal static class Program
{
    private const string Usage = """
        waf-loadtest suite --gateway <path to WafGateway[.exe|.dll]> [--seconds 20] [--warmup 5] [--concurrency 32]
                           [--no-request-log] [--no-body-inspection] [--output report.md]
            Starts a backend and the gateway (temporary data folder, ports 18080/18900, backend 18500) on this
            machine and measures every scenario directly and through the gateway.

        waf-loadtest backend [--address 127.0.0.1|any] [--port 18500]
            Runs only the backend, until Ctrl+C.

        waf-loadtest run --url http://gateway:80/ [--host name] [--scenario clean|post|attack] [--direct]
                         [--seconds 20] [--warmup 5] [--concurrency 32]
            Sends one scenario to a running gateway (--direct: to the backend, every answer 200).
        """;

    public static async Task<int> Main(string[] args)
    {
        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancel.Cancel();
        };

        try
        {
            var options = Options.Parse(args.Skip(1));
            return args.FirstOrDefault() switch
            {
                "suite" => await SuiteAsync(options, cancel.Token).ConfigureAwait(false),
                "backend" => await BackendAsync(options, cancel.Token).ConfigureAwait(false),
                "run" => await RunAsync(options, cancel.Token).ConfigureAwait(false),
                _ => Fail(Usage),
            };
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message + Environment.NewLine + Environment.NewLine + Usage);
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }

    private static async Task<int> BackendAsync(Options options, CancellationToken cancellationToken)
    {
        var address = options.Get("address", "127.0.0.1") == "any" ? IPAddress.Any : IPAddress.Parse(options.Get("address", "127.0.0.1"));
        var app = await Backend.StartAsync(address, options.Int("port", 18500)).ConfigureAwait(false);
        await using (app.ConfigureAwait(false))
        {
            Console.WriteLine($"Backend listening on {address}:{options.Int("port", 18500)}. Ctrl+C stops it.");
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Stop.
            }

            await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAsync(Options options, CancellationToken cancellationToken)
    {
        var url = new Uri(options.Required("url"));
        var scenario = Scenario.Find(options.Get("scenario", "clean"));
        if (options.Flag("direct"))
        {
            scenario = scenario.Direct();
        }

        var result = await LoadGenerator.RunAsync(
            url, options.Value("host"), scenario, options.Int("concurrency", 32),
            TimeSpan.FromSeconds(options.Int("seconds", 20)), TimeSpan.FromSeconds(options.Int("warmup", 5)), cancellationToken).ConfigureAwait(false);

        Console.WriteLine(Report.Header);
        Console.WriteLine(Report.Row(result, url.Authority, cpu: null));
        Report.WriteErrors(Console.Out, [result]);
        return result.Errors == 0 ? 0 : 1;
    }

    private static async Task<int> SuiteAsync(Options options, CancellationToken cancellationToken)
    {
        const int BackendPort = 18500, HttpPort = 18080, AdminPort = 18900;
        var gatewayFile = options.Required("gateway");
        var concurrency = options.Int("concurrency", 32);
        var duration = TimeSpan.FromSeconds(options.Int("seconds", 20));
        var warmUp = TimeSpan.FromSeconds(options.Int("warmup", 5));
        var requestLog = !options.Flag("no-request-log");
        var inspectBody = !options.Flag("no-body-inspection");
        var rows = new List<(LoadResult Result, string Through, double? Cpu)>();

        Console.Error.WriteLine($"Backend on 127.0.0.1:{BackendPort}.");
        var backend = await Backend.StartAsync(IPAddress.Loopback, BackendPort).ConfigureAwait(false);
        await using (backend.ConfigureAwait(false))
        {
            var backendUrl = new Uri($"http://127.0.0.1:{BackendPort}/");
            foreach (var scenario in new[] { Scenario.Clean, Scenario.Post })
            {
                Console.Error.WriteLine($"Directly: {scenario.Description}.");
                rows.Add((await LoadGenerator.RunAsync(backendUrl, null, scenario.Direct(), concurrency, duration, warmUp, cancellationToken).ConfigureAwait(false),
                    "backend directly", null));
            }

            Console.Error.WriteLine($"Starting the gateway {gatewayFile}.");
            double idleMb, peakMb;
            var gateway = await GatewayProcess.StartAsync(gatewayFile, HttpPort, AdminPort, BackendPort, inspectBody, requestLog, cancellationToken).ConfigureAwait(false);
            await using (gateway.ConfigureAwait(false))
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                idleMb = gateway.WorkingSetMb;
                foreach (var scenario in Scenario.All)
                {
                    Console.Error.WriteLine($"Through the gateway: {scenario.Description}.");
                    gateway.MarkCpu();
                    var result = await LoadGenerator.RunAsync(gateway.PublicUrl, null, scenario, concurrency, duration, warmUp, cancellationToken).ConfigureAwait(false);
                    rows.Add((result, "gateway", gateway.CpuCoresSinceMark()));
                }

                peakMb = gateway.PeakWorkingSetMb;
            }

            var report = Report.Suite(rows, gatewayFile, concurrency, duration, warmUp, requestLog, inspectBody, idleMb, peakMb);
            Console.WriteLine(report);
            if (options.Value("output") is { } output)
            {
                await File.WriteAllTextAsync(output, report, cancellationToken).ConfigureAwait(false);
                Console.Error.WriteLine($"Report written to {output}.");
            }

            return rows.All(r => r.Result.Errors == 0) ? 0 : 1;
        }
    }
}

/// <summary>The Markdown report.</summary>
internal static class Report
{
    public const string Header =
        "| Scenario | Through | Requests/s | p50 ms | p95 ms | p99 ms | Max ms | Errors | Gateway CPU |\n" +
        "|---|---|---:|---:|---:|---:|---:|---:|---:|";

    public static string Row(LoadResult r, string through, double? cpu) => string.Create(
        CultureInfo.InvariantCulture,
        $"| {r.Scenario} | {through} | {r.RequestsPerSecond:N0} | {r.P50:0.00} | {r.P95:0.00} | {r.P99:0.00} | {r.Max:0.0} | {r.Errors} | {(cpu is { } c ? $"{c:0.0} cores" : "–")} |");

    public static void WriteErrors(TextWriter writer, IEnumerable<LoadResult> results)
    {
        foreach (var r in results.Where(r => r.Errors > 0))
        {
            writer.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{r.Scenario}: {r.Errors} of {r.Requests} requests failed; first: {r.FirstError}"));
        }
    }

    public static string Suite(
        IReadOnlyList<(LoadResult Result, string Through, double? Cpu)> rows, string gatewayFile, int concurrency, TimeSpan duration,
        TimeSpan warmUp, bool requestLog, bool inspectBody, double idleMb, double peakMb)
    {
        var text = new StringBuilder();
        var invariant = CultureInfo.InvariantCulture;
        text.AppendLine(invariant, $"### {DateTime.Now:yyyy-MM-dd}, {Machine()}").AppendLine();
        text.AppendLine(invariant, $"Gateway `{Path.GetFileName(gatewayFile)}`; {concurrency} concurrent connections; {duration.TotalSeconds:0} s per scenario after {warmUp.TotalSeconds:0} s warm-up; request log {(requestLog ? "on" : "off")}; body inspection {(inspectBody ? "on" : "off")}. Load generator, backend and gateway on the same machine.").AppendLine();
        text.AppendLine(Header);
        foreach (var (result, through, cpu) in rows)
        {
            text.AppendLine(Row(result, through, cpu));
        }

        text.AppendLine().AppendLine(invariant, $"Gateway memory: {idleMb:0} MB after start, peak {peakMb:0} MB.");
        using var errors = new StringWriter(invariant);
        WriteErrors(errors, rows.Select(r => r.Result));
        if (errors.ToString().Length > 0)
        {
            text.AppendLine().Append(errors);
        }

        return text.ToString();
    }

    private static string Machine()
    {
        var cpu = CpuName();
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{(cpu is null ? string.Empty : cpu + ", ")}{Environment.ProcessorCount} logical cores, {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}), .NET {Environment.Version}");
    }

    private static string? CpuName()
    {
        if (OperatingSystem.IsWindows())
        {
            return Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", null) is string name
                ? name.Trim()
                : null;
        }

        try
        {
            // x64: "model name"; Raspberry Pi: "Model" (the board).
            var lines = File.ReadAllLines("/proc/cpuinfo");
            return lines.Where(l => l.StartsWith("Model", StringComparison.Ordinal) || l.StartsWith("model name", StringComparison.Ordinal))
                .Select(l => l[(l.IndexOf(':', StringComparison.Ordinal) + 1)..].Trim())
                .LastOrDefault();
        }
        catch (IOException)
        {
            return null;
        }
    }
}

/// <summary>--name value and --flag command-line options.</summary>
internal sealed class Options
{
    private readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    public static Options Parse(IEnumerable<string> args)
    {
        var options = new Options();
        var list = args.ToList();
        for (var i = 0; i < list.Count; i++)
        {
            if (!list[i].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument '{list[i]}'.");
            }

            var hasValue = i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal);
            options._values[list[i][2..]] = hasValue ? list[++i] : null;
        }

        return options;
    }

    public bool Flag(string name) => _values.ContainsKey(name);

    public string? Value(string name) => _values.TryGetValue(name, out var value) ? value : null;

    public string Get(string name, string fallback) => Value(name) ?? fallback;

    public string Required(string name) => Value(name) ?? throw new ArgumentException($"--{name} is required.");

    public int Int(string name, int fallback) =>
        Value(name) is { } text
            ? int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0
                ? value
                : throw new ArgumentException($"--{name} must be a positive whole number.")
            : fallback;
}
