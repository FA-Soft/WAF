using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Host.Hosting;

/// <summary>Traffic count settings, bound from <c>Gateway:Metrics</c> (host settings, not part of the configuration versions).</summary>
public sealed class MetricsOptions
{
    public const string SectionName = "Gateway:Metrics";

    /// <summary>Count every public request for the performance dashboard. On by default.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>The database file. Empty: <c>metrics.db</c> in the data folder; a relative path is relative to the data folder.</summary>
    public string? DatabasePath { get; set; }

    /// <summary>
    /// Seconds between writes. Counts are collected in memory and written in one transaction per interval, so an SD
    /// card is not written for every request. A restart or power failure loses at most this interval.
    /// </summary>
    public int FlushIntervalSeconds { get; set; } = 5;

    /// <summary>Most counts waiting in memory (one per second, kind and route). Beyond it, requests are not counted (and that is counted).</summary>
    public int MaxPendingCounts { get; set; } = 100_000;

    /// <summary>Longest <see cref="FlushIntervalSeconds"/>: one minute.</summary>
    public const int MaxFlushIntervalSeconds = 60;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (FlushIntervalSeconds is < 1 or > MaxFlushIntervalSeconds)
        {
            errors.Add($"{SectionName}:FlushIntervalSeconds must be between 1 and {MaxFlushIntervalSeconds} (is {FlushIntervalSeconds}).");
        }

        if (MaxPendingCounts is < 1_000 or > 10_000_000)
        {
            errors.Add($"{SectionName}:MaxPendingCounts must be between 1000 and 10000000 (is {MaxPendingCounts}).");
        }

        if (DatabasePath is { } path && path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            errors.Add($"{SectionName}:DatabasePath is not a valid path.");
        }

        return errors;
    }
}

/// <summary>
/// The traffic counts: requests are counted in memory (<see cref="TrafficCounter"/>), and a background writer stores
/// the completed seconds (and the bad sources per minute) in <c>metrics.db</c> every few seconds.
/// </summary>
/// <remarks>
/// Like the request log, counting is best effort and never slows a request down: when too many counts are waiting
/// (the store cannot keep up) or a write fails, those counts are dropped and counted (<see cref="RequestMetricsStatistics.Dropped"/>),
/// and a warning is logged at most once a minute. On shutdown, everything counted so far is written.
/// </remarks>
public sealed partial class RequestMetricsWriter : BackgroundService, IRequestMetrics, IRequestMetricsMonitor
{
    /// <summary>How long after a minute ends its sources are written (slow requests that started in it are counted by their start).</summary>
    public static readonly TimeSpan SourceGrace = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan WarningInterval = TimeSpan.FromMinutes(1);

    private readonly TrafficCounter _counter;
    private readonly IMetricsStore _store;
    private readonly MetricsOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<RequestMetricsWriter> _logger;
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private long _counted;
    private long _dropped;
    private long _droppedReported;
    private DateTimeOffset _lastDropWarning = DateTimeOffset.MinValue;
    private DateTimeOffset? _lastWrite;
    private string? _lastError;
    private bool _ready;

    public RequestMetricsWriter(IMetricsStore store, MetricsOptions options, TimeProvider time, ILogger<RequestMetricsWriter> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _store = store;
        _options = options;
        _time = time;
        _logger = logger;
        _counter = new TrafficCounter(options.MaxPendingCounts, Math.Max(1, options.MaxPendingCounts / 5));
    }

    public RequestMetricsStatistics? Statistics
    {
        get
        {
            lock (_counter)
            {
                return new(Interlocked.Read(ref _counted), Interlocked.Read(ref _dropped), _counter.Pending, _lastWrite, _lastError);
            }
        }
    }

    /// <summary>Counts <paramref name="entry"/>; never blocks or throws.</summary>
    public void Record(RequestLogEntry entry, bool failed)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var (kind, name) = TrafficClassifier.Classify(entry, failed);
        if (_counter.Add(entry.Timestamp, kind, name, entry.RouteName, entry.ClientIp))
        {
            Interlocked.Increment(ref _counted);
        }
        else
        {
            Interlocked.Increment(ref _dropped);
        }
    }

    /// <summary>Writes the completed buckets now (all of them when <paramref name="all"/>). Used by the loop and by tests.</summary>
    public async Task FlushAsync(bool all, CancellationToken cancellationToken)
    {
        await _flushLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_ready)
            {
                _ready = await InitializeAsync().ConfigureAwait(false);
            }

            var (counts, sources) = _counter.TakeCompleted(_time.GetUtcNow(), SourceGrace, all);
            if (counts.Count == 0 && sources.Count == 0)
            {
                return;
            }

            if (!_ready)
            {
                Interlocked.Add(ref _dropped, counts.Sum(c => c.Count));
                return;
            }

            try
            {
                await _store.WriteAsync(counts, sources, CancellationToken.None).ConfigureAwait(false);
                lock (_counter)
                {
                    _lastWrite = _time.GetUtcNow();
                    _lastError = null;
                }
            }
#pragma warning disable CA1031 // Counting is best effort: drop these counts, keep going.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                Interlocked.Add(ref _dropped, counts.Sum(c => c.Count));
                bool first;
                lock (_counter)
                {
                    first = _lastError is null;
                    _lastError = ex.Message;
                }

                if (first)
                {
                    LogWriteFailed(_logger, ex);
                }
            }
        }
        finally
        {
            ReportDrops(all);
            _flushLock.Release();
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await FlushAsync(all: true, CancellationToken.None).ConfigureAwait(false);
    }

    public override void Dispose()
    {
        _flushLock.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Yield first: the host's start must not wait for the database.
        await Task.Yield();

        var interval = TimeSpan.FromSeconds(_options.FlushIntervalSeconds);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, _time, stoppingToken).ConfigureAwait(false);
                await FlushAsync(all: false, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break; // StopAsync writes the rest
            }
        }
    }

    private async Task<bool> InitializeAsync()
    {
        try
        {
            await _store.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            lock (_counter)
            {
                _lastError = null;
            }

            return true;
        }
#pragma warning disable CA1031 // A broken metrics.db must never stop the gateway.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            bool first;
            lock (_counter)
            {
                first = _lastError is null;
                _lastError = ex.Message;
            }

            if (first)
            {
                LogInitializationFailed(_logger, ex);
            }

            return false;
        }
    }

    private void ReportDrops(bool force)
    {
        var dropped = Interlocked.Read(ref _dropped);
        var now = _time.GetUtcNow();
        if (dropped == _droppedReported || (!force && now - _lastDropWarning < WarningInterval))
        {
            return;
        }

        LogDropped(_logger, dropped - _droppedReported, dropped);
        _droppedReported = dropped;
        _lastDropWarning = now;
    }

    [LoggerMessage(EventId = 420, Level = LogLevel.Warning, Message = "Traffic counts: {Count} requests were not counted ({Total} since start) because too many counts were waiting or storing failed. Requests were not affected.")]
    private static partial void LogDropped(ILogger logger, long count, long total);

    [LoggerMessage(EventId = 421, Level = LogLevel.Error, Message = "Traffic counts could not be written to metrics.db; retrying at the next interval.")]
    private static partial void LogWriteFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 422, Level = LogLevel.Error, Message = "Traffic counts: metrics.db could not be opened or created; counts are dropped until it works.")]
    private static partial void LogInitializationFailed(ILogger logger, Exception exception);
}
