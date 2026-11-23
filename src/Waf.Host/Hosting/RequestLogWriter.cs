using System.Threading.Channels;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Host.Hosting;

/// <summary>Request log settings, bound from <c>Gateway:EventLog</c> (host settings, not part of the configuration versions).</summary>
public sealed class EventLogOptions
{
    public const string SectionName = "Gateway:EventLog";

    /// <summary>Record every public request in <c>events.db</c>. On by default.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Entries that may wait to be written. When the queue is full (the disk cannot keep up or the database is
    /// locked), new entries are dropped and counted; requests are never slowed down.
    /// </summary>
    public int QueueCapacity { get; set; } = 10_000;

    /// <summary>Most entries written in one transaction.</summary>
    public int BatchSize { get; set; } = 500;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (QueueCapacity is < 100 or > 1_000_000)
        {
            errors.Add($"{SectionName}:QueueCapacity must be between 100 and 1000000 (is {QueueCapacity}).");
        }

        if (BatchSize is < 1 or > 10_000)
        {
            errors.Add($"{SectionName}:BatchSize must be between 1 and 10000 (is {BatchSize}).");
        }

        return errors;
    }
}

/// <summary>
/// The request log: a bounded in-memory queue in front of <see cref="IRequestLogStore"/>, emptied by one background
/// writer in batches.
/// </summary>
/// <remarks>
/// Back-pressure: <see cref="Write"/> never waits. When the queue is full, the new entry is dropped and counted
/// (<see cref="RequestLogStatistics.Dropped"/>), and a warning is logged at most once a minute. When a batch cannot
/// be stored (disk full, database damaged or locked for longer than the busy timeout), that batch is dropped and
/// counted too, and the writer retries with the next batch after a short pause. Logging is best effort by design:
/// the WAF's protection never depends on it (unlike configuration problems, which fail closed). On shutdown the
/// queue is drained.
/// </remarks>
public sealed partial class RequestLogWriter : BackgroundService, IRequestLog, IRequestLogMonitor
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan WarningInterval = TimeSpan.FromMinutes(1);

    private readonly Channel<RequestLogEntry> _queue;
    private readonly IRequestLogStore _store;
    private readonly EventLogOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<RequestLogWriter> _logger;
    private long _written;
    private long _dropped;
    private long _droppedReported;
    private DateTimeOffset _lastDropWarning = DateTimeOffset.MinValue;
    private string? _lastError;

    public RequestLogWriter(IRequestLogStore store, EventLogOptions options, TimeProvider time, ILogger<RequestLogWriter> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _store = store;
        _options = options;
        _time = time;
        _logger = logger;
        _queue = Channel.CreateBounded<RequestLogEntry>(
            new BoundedChannelOptions(options.QueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false,
            },
            _ => Interlocked.Increment(ref _dropped));
    }

    public RequestLogStatistics? Statistics => new(
        Interlocked.Read(ref _written), Interlocked.Read(ref _dropped), _queue.Reader.Count, _options.QueueCapacity, Volatile.Read(ref _lastError));

    /// <summary>Queues <paramref name="entry"/>; never blocks. A full queue drops it (counted).</summary>
    public void Write(RequestLogEntry entry)
    {
        if (!_queue.Writer.TryWrite(entry))
        {
            Interlocked.Increment(ref _dropped); // only after shutdown completed the queue
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // Let the writer drain what is queued; base.StopAsync waits for it until the host's shutdown timeout.
        _queue.Writer.TryComplete();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Yield first: the host's start must not wait for the database.
        await Task.Yield();

        var ready = await InitializeAsync(stoppingToken).ConfigureAwait(false);
        var batch = new List<RequestLogEntry>(_options.BatchSize);

        // Not cancelled by stoppingToken: after StopAsync completed the queue, the loop drains it and ends.
        while (await _queue.Reader.WaitToReadAsync(CancellationToken.None).ConfigureAwait(false))
        {
            batch.Clear();
            while (batch.Count < _options.BatchSize && _queue.Reader.TryRead(out var entry))
            {
                batch.Add(entry);
            }

            if (!ready)
            {
                Interlocked.Add(ref _dropped, batch.Count);
                ready = await InitializeAsync(stoppingToken).ConfigureAwait(false);
            }
            else
            {
                await WriteBatchAsync(batch, stoppingToken).ConfigureAwait(false);
            }

            ReportDrops();
        }

        ReportDrops(force: true);
    }

    private async Task<bool> InitializeAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _store.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            Volatile.Write(ref _lastError, null);
            return true;
        }
#pragma warning disable CA1031 // Logging is best effort: a broken events.db must never stop the gateway.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Volatile.Write(ref _lastError, ex.Message);
            LogInitializationFailed(_logger, ex);
            await PauseAsync(stoppingToken).ConfigureAwait(false);
            return false;
        }
    }

    private async Task WriteBatchAsync(List<RequestLogEntry> batch, CancellationToken stoppingToken)
    {
        try
        {
            await _store.WriteAsync(batch, CancellationToken.None).ConfigureAwait(false);
            Interlocked.Add(ref _written, batch.Count);
            Volatile.Write(ref _lastError, null);
        }
#pragma warning disable CA1031 // Logging is best effort: drop the batch, keep going.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Interlocked.Add(ref _dropped, batch.Count);
            if (Volatile.Read(ref _lastError) is null)
            {
                LogWriteFailed(_logger, ex, batch.Count);
            }

            Volatile.Write(ref _lastError, ex.Message);
            await PauseAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task PauseAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(RetryDelay, _time, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutting down: continue draining without pausing.
        }
    }

    private void ReportDrops(bool force = false)
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

    [LoggerMessage(EventId = 400, Level = LogLevel.Warning, Message = "Request log: {Count} entries were dropped ({Total} since start) because the queue was full or storing failed. Requests were not affected.")]
    private static partial void LogDropped(ILogger logger, long count, long total);

    [LoggerMessage(EventId = 401, Level = LogLevel.Error, Message = "Request log: {Count} entries could not be written to events.db; retrying with the next batch.")]
    private static partial void LogWriteFailed(ILogger logger, Exception exception, int count);

    [LoggerMessage(EventId = 402, Level = LogLevel.Error, Message = "Request log: events.db could not be opened or migrated; entries are dropped until it works.")]
    private static partial void LogInitializationFailed(ILogger logger, Exception exception);
}
