using System.Diagnostics;
using System.Globalization;

namespace FASoft.Waf.LoadTests;

/// <summary>
/// A published gateway (WafGateway or WafGateway.exe; a .dll is run with dotnet), started with a temporary data folder,
/// spare ports and one route to the load-test backend. Its settings come from environment variables, as an
/// administrator's appsettings would. Stopped and cleaned up on dispose.
/// </summary>
internal sealed class GatewayProcess : IAsyncDisposable
{
    private readonly Process _process;
    private readonly string _work;
    private TimeSpan _cpuAtMark;
    private long _wallAtMark;

    private GatewayProcess(Process process, string work, int httpPort, int adminPort)
    {
        _process = process;
        _work = work;
        HttpPort = httpPort;
        AdminPort = adminPort;
    }

    public int HttpPort { get; }

    public int AdminPort { get; }

    public Uri PublicUrl => new($"http://127.0.0.1:{HttpPort}/");

    public static async Task<GatewayProcess> StartAsync(
        string program, int httpPort, int adminPort, int backendPort, bool inspectBody, bool requestLog, CancellationToken cancellationToken)
    {
        var work = Path.Combine(Path.GetTempPath(), "waf-loadtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(work, "data"));
        Directory.CreateDirectory(Path.Combine(work, "config"));

        program = Path.GetFullPath(program);
        if (!File.Exists(program))
        {
            throw new ArgumentException($"The gateway program {program} does not exist.");
        }

        var start = program.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? new ProcessStartInfo("dotnet") { ArgumentList = { program } }
            : new ProcessStartInfo(program);
        start.WorkingDirectory = Path.GetDirectoryName(program)!;
        start.UseShellExecute = false;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;

        var environment = start.Environment;
        environment["DOTNET_ENVIRONMENT"] = "Production";
        environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        environment["Gateway__Storage__DataDirectory"] = Path.Combine(work, "data");
        environment["Gateway__Storage__ConfigDirectory"] = Path.Combine(work, "config");
        environment["Gateway__Endpoints__HttpPort"] = Text(httpPort);
        environment["Gateway__Endpoints__HttpsPort"] = Text(httpPort + 1);
        environment["Gateway__Endpoints__AdminPort"] = Text(adminPort);
        environment["Gateway__Endpoints__PublicBindAddress"] = "*";
        environment["Gateway__Routes__0__Name"] = "loadtest";
        environment["Gateway__Routes__0__Destinations__0__Scheme"] = "http";
        environment["Gateway__Routes__0__Destinations__0__Address"] = "127.0.0.1";
        environment["Gateway__Routes__0__Destinations__0__Port"] = Text(backendPort);
        environment["Gateway__Settings__AttackDetection__InspectBody"] = inspectBody ? "true" : "false";
        environment["Gateway__EventLog__Enabled"] = requestLog ? "true" : "false";
        // As in production: warnings and errors only (each blocked request is still logged as a WAF event).
        environment["Logging__LogLevel__Default"] = "Warning";

        var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {program}.");
        process.OutputDataReceived += (_, _) => { };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var gateway = new GatewayProcess(process, work, httpPort, adminPort);
        try
        {
            await gateway.WaitUntilReadyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await gateway.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        return gateway;
    }

    /// <summary>Memory the gateway holds now (resident set / working set), in MB.</summary>
    public double WorkingSetMb
    {
        get
        {
            _process.Refresh();
            return _process.WorkingSet64 / 1024.0 / 1024.0;
        }
    }

    /// <summary>The most memory the gateway held since it started (VmHWM on Linux, peak working set on Windows), in MB.</summary>
    public double PeakWorkingSetMb
    {
        get
        {
            _process.Refresh();
            return _process.PeakWorkingSet64 / 1024.0 / 1024.0;
        }
    }

    /// <summary>Starts a CPU measurement; <see cref="CpuCoresSinceMark"/> reads it.</summary>
    public void MarkCpu()
    {
        _process.Refresh();
        _cpuAtMark = _process.TotalProcessorTime;
        _wallAtMark = Stopwatch.GetTimestamp();
    }

    /// <summary>CPU the gateway used since <see cref="MarkCpu"/>, in cores (1.0 = one core fully busy).</summary>
    public double CpuCoresSinceMark()
    {
        _process.Refresh();
        var wall = Stopwatch.GetElapsedTime(_wallAtMark);
        return (_process.TotalProcessorTime - _cpuAtMark).TotalSeconds / wall.TotalSeconds;
    }

    private async Task WaitUntilReadyAsync(CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var deadline = Stopwatch.GetTimestamp() + 120 * Stopwatch.Frequency;
        while (true)
        {
            if (_process.HasExited)
            {
                throw new InvalidOperationException($"The gateway stopped while starting (exit code {_process.ExitCode}).");
            }

            try
            {
                using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{AdminPort}/healthz"), cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Not listening yet.
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Slow start.
            }

            if (Stopwatch.GetTimestamp() > deadline)
            {
                throw new TimeoutException("The gateway did not become healthy within 120 seconds.");
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_process.HasExited)
        {
            _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync().ConfigureAwait(false);
        }

        _process.Dispose();
        try
        {
            Directory.Delete(_work, recursive: true);
        }
        catch (IOException)
        {
            // A file still held for a moment; it is in the temp folder.
        }
        catch (UnauthorizedAccessException)
        {
            // As above.
        }
    }

    private static string Text(int value) => value.ToString(CultureInfo.InvariantCulture);
}
