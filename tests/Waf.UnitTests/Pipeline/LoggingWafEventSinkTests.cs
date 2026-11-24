using System.Net;
using Microsoft.Extensions.Logging;
using FASoft.Waf.Engine;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Engine;

namespace FASoft.Waf.UnitTests.Pipeline;

/// <summary>
/// WAF events in the application log: written one by one up to a limit per minute, the rest summarized, so an attack
/// flood cannot flood the log (or slow down the gateway with it). The request log keeps every request.
/// </summary>
public sealed class LoggingWafEventSinkTests
{
    private readonly ManualTimeProvider _time = new();
    private readonly CapturingLogger _logger = new();

    private WafEvent Blocked(int i) => new(
        _time.GetUtcNow(), WafEventKind.AttackBlocked, IPAddress.Loopback, "GET", "example.com", $"/item/{i}", "site", "sqli", 403, "SqlInjection");

    [Fact]
    public void Events_are_written_one_by_one_up_to_the_limit_per_minute()
    {
        using var sink = new LoggingWafEventSink(_logger, _time);

        for (var i = 0; i < LoggingWafEventSink.MaxLinesPerMinute; i++)
        {
            sink.Publish(Blocked(i));
        }

        Assert.Equal(LoggingWafEventSink.MaxLinesPerMinute, _logger.Lines.Count);
        Assert.All(_logger.Lines, line => Assert.Equal(200, line.EventId));
        Assert.Contains("AttackBlocked 'sqli': 127.0.0.1 GET example.com/item/0 -> 403", _logger.Lines[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_flood_is_summarized_in_one_line_with_the_next_event_after_the_minute()
    {
        using var sink = new LoggingWafEventSink(_logger, _time);

        for (var i = 0; i < 10_000; i++)
        {
            sink.Publish(Blocked(i));
        }

        Assert.Equal(LoggingWafEventSink.MaxLinesPerMinute, _logger.Lines.Count);

        _time.Advance(TimeSpan.FromMinutes(1));
        sink.Publish(Blocked(10_000));

        var summary = Assert.Single(_logger.Lines, line => line.EventId == 201);
        Assert.Contains($"{10_000 - LoggingWafEventSink.MaxLinesPerMinute} more WAF events since", summary.Message, StringComparison.Ordinal);
        Assert.Contains("every request is in the request log", summary.Message, StringComparison.Ordinal);
        Assert.Equal(200, _logger.Lines[^1].EventId); // a new minute: events are written again
        Assert.Equal(LoggingWafEventSink.MaxLinesPerMinute + 2, _logger.Lines.Count);
    }

    [Fact]
    public void Events_not_written_yet_are_summarized_on_shutdown()
    {
        var sink = new LoggingWafEventSink(_logger, _time);
        for (var i = 0; i <= LoggingWafEventSink.MaxLinesPerMinute + 4; i++)
        {
            sink.Publish(Blocked(i));
        }

        sink.Dispose();

        var summary = Assert.Single(_logger.Lines, line => line.EventId == 201);
        Assert.StartsWith("5 more WAF events since", summary.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_quiet_gateway_writes_no_summary()
    {
        using (var sink = new LoggingWafEventSink(_logger, _time))
        {
            sink.Publish(Blocked(1));
            _time.Advance(TimeSpan.FromMinutes(5));
            sink.Publish(Blocked(2));
        }

        Assert.Equal(2, _logger.Lines.Count);
        Assert.DoesNotContain(_logger.Lines, line => line.EventId == 201);
    }

    private sealed class CapturingLogger : ILogger<LoggingWafEventSink>
    {
        public List<(int EventId, string Message)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Lines)
            {
                Lines.Add((eventId.Id, formatter(state, exception)));
            }
        }
    }
}
