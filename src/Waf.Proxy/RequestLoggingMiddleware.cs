using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using FASoft.Waf.Engine;
using Yarp.ReverseProxy.Model;

namespace FASoft.Waf.Proxy;

/// <summary>
/// Per-request state of the request log: when the request started and the most important WAF event. The WAF
/// reports its events here (<see cref="Record(HttpContext, WafEvent)"/>).
/// </summary>
public sealed class RequestLogFeature(DateTimeOffset startedAt, long startTimestamp)
{
    public DateTimeOffset StartedAt { get; } = startedAt;

    public long StartTimestamp { get; } = startTimestamp;

    public WafEventKind? Event { get; private set; }

    public string? RuleName { get; private set; }

    public string? Detail { get; private set; }

    /// <summary>Why no backend answered, e.g. "Backend timeout"; null when one did.</summary>
    public string? BackendError { get; private set; }

    /// <summary>Records on the request's log feature that no backend answered, if request logging is on.</summary>
    public static void RecordBackendError(HttpContext context, string text)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Features.Get<RequestLogFeature>() is { } feature)
        {
            feature.BackendError = text;
        }
    }

    /// <summary>Keeps <paramref name="wafEvent"/> when it is more important than the event recorded so far.</summary>
    public void Record(WafEvent wafEvent)
    {
        ArgumentNullException.ThrowIfNull(wafEvent);

        if (Event is { } current && Importance(current) >= Importance(wafEvent.Kind))
        {
            return;
        }

        Event = wafEvent.Kind;
        RuleName = string.IsNullOrEmpty(wafEvent.RuleName) ? null : wafEvent.RuleName;
        Detail = wafEvent.Detail;
    }

    /// <summary>Records <paramref name="wafEvent"/> on the request's log feature, if request logging is on.</summary>
    public static void Record(HttpContext context, WafEvent wafEvent)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Features.Get<RequestLogFeature>()?.Record(wafEvent);
    }

    /// <summary>Decisions first, then "would have blocked", then log-only matches.</summary>
    private static int Importance(WafEventKind kind) => kind switch
    {
        WafEventKind.FailClosed or WafEventKind.RuleBlocked or WafEventKind.AttackBlocked or WafEventKind.RateLimited => 3,
        WafEventKind.RuleDetected or WafEventKind.AttackDetected or WafEventKind.RateLimitDetected => 2,
        _ => 1,
    };
}

/// <summary>
/// Records every public request in the request log and the traffic counts when its response is complete. Never
/// delays a request: the entry is handed to <see cref="IRequestLog"/>, which only queues it, and to
/// <see cref="IRequestMetrics"/>, which only increments a counter in memory.
/// </summary>
public sealed class RequestLoggingMiddleware(RequestDelegate next, IRequestLog log, IRequestMetrics metrics, LiveTraffic live, TimeProvider time)
{
    public const int MaxHostLength = 255;
    public const int MaxPathLength = 2048;
    public const int MaxDetailLength = 1000;

    /// <summary>Longest destination stored (the events.db column): the address, with the target label when there is one.</summary>
    public const int MaxDestinationLength = 300;

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var feature = new RequestLogFeature(time.GetUtcNow(), time.GetTimestamp());
        context.Features.Set(feature);
        var failed = false;
        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch
        {
            failed = true;
            throw;
        }
        finally
        {
            var entry = CreateEntry(context, feature, failed, time.GetElapsedTime(feature.StartTimestamp));
            metrics.Record(entry, failed);
            live.Record(entry, failed); // returns at once when no dashboard watches
            log.Write(entry);
        }
    }

    internal static RequestLogEntry CreateEntry(HttpContext context, RequestLogFeature feature, bool failed, TimeSpan elapsed)
    {
        var route = HttpContextWafRequest.GetRouteName(context);
        var proxied = context.Features.Get<IReverseProxyFeature>()?.ProxiedDestination?.Model.Config;
        var destination = proxied is null ? null : YarpConfigMapper.DescribeDestination(proxied);
        var status = failed && !context.Response.HasStarted ? StatusCodes.Status500InternalServerError : context.Response.StatusCode;

        var action = feature.Event switch
        {
            WafEventKind.RuleBlocked or WafEventKind.AttackBlocked => RequestAction.Blocked,
            WafEventKind.RateLimited => RequestAction.RateLimited,
            WafEventKind.FailClosed => RequestAction.FailClosed,
            _ when context.Items.ContainsKey(HttpsEnforcementMiddleware.RedirectedItemKey) => RequestAction.Redirected,
            _ when feature.BackendError is not null => RequestAction.BackendUnavailable,
            _ when destination is not null => RequestAction.Forwarded,
            _ when route is not null => RequestAction.BackendUnavailable,
            _ when status == StatusCodes.Status404NotFound => RequestAction.NoRoute,
            _ => RequestAction.Answered,
        };

        return new RequestLogEntry(
            feature.StartedAt,
            (context.Connection.RemoteIpAddress ?? System.Net.IPAddress.None).ToString(),
            context.Request.Method,
            Truncate(context.Request.Host.Host, MaxHostLength)!,
            Truncate(context.Request.Path.HasValue ? context.Request.Path.Value! : "/", MaxPathLength)!,
            route,
            action,
            feature.Event,
            feature.RuleName,
            Truncate(feature.BackendError is null ? feature.Detail : feature.Detail is null ? feature.BackendError : $"{feature.BackendError} · {feature.Detail}", MaxDetailLength),
            Truncate(destination, MaxDestinationLength),
            status,
            Math.Round(elapsed.TotalMilliseconds, 3));
    }

    private static string? Truncate(string? text, int max) =>
        text is null || text.Length <= max ? text : text[..(max - 1)] + "…";
}

/// <summary>Pipeline registration for request logging.</summary>
public static class RequestLoggingApplicationBuilderExtensions
{
    /// <summary>Logs every request. Place first in the public pipeline, so even fail-closed answers are logged.</summary>
    public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder app) =>
        app.UseMiddleware<RequestLoggingMiddleware>();
}
