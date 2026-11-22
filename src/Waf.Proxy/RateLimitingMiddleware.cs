using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Waf.Engine;
using Waf.Engine.RateLimiting;

namespace Waf.Proxy;

/// <summary>
/// Applies rate limits: requests over a limit get <c>429 Too Many Requests</c> with a <c>Retry-After</c>
/// header; in detection-only mode they pass. Both are reported to the <see cref="IWafEventSink"/>.
/// </summary>
public sealed class RateLimitingMiddleware(RequestDelegate next, RateLimiter limiter, IWafEventSink events, TimeProvider time)
{
    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!limiter.HasLimits)
        {
            return next(context);
        }

        var request = new HttpContextWafRequest(context);
        var decision = limiter.Check(request);

        switch (decision.Outcome)
        {
            case RateLimitOutcome.Limited:
                Publish(request, decision, WafEventKind.RateLimited, StatusCodes.Status429TooManyRequests);
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.Headers.RetryAfter = ((int)decision.RetryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
                context.Response.ContentType = "text/plain; charset=utf-8";
                return context.Response.WriteAsync("Too many requests. Please slow down.", context.RequestAborted);

            case RateLimitOutcome.WouldLimit:
                Publish(request, decision, WafEventKind.RateLimitDetected, StatusCodes.Status200OK);
                return next(context);

            default:
                return next(context);
        }
    }

    private void Publish(HttpContextWafRequest request, RateLimitDecision decision, WafEventKind kind, int status) =>
        events.Publish(new WafEvent(
            time.GetUtcNow(), kind, request.ClientIp, request.Method, request.Host, request.Path, request.RouteName, decision.RuleName!, status));
}

/// <summary>Default event sink: writes security events to the application log.</summary>
public sealed partial class LoggingWafEventSink(ILogger<LoggingWafEventSink> logger) : IWafEventSink
{
    public void Publish(WafEvent wafEvent)
    {
        ArgumentNullException.ThrowIfNull(wafEvent);
        LogEvent(logger, wafEvent.Kind, wafEvent.RuleName, wafEvent.ClientIp, wafEvent.Method, wafEvent.Host, wafEvent.Path, wafEvent.StatusCode);
    }

    [LoggerMessage(EventId = 200, Level = LogLevel.Warning,
        Message = "{Kind} by '{RuleName}': {ClientIp} {Method} {Host}{Path} -> {StatusCode}")]
    private static partial void LogEvent(ILogger logger, WafEventKind kind, string ruleName, System.Net.IPAddress clientIp, string method, string host, string path, int statusCode);
}

/// <summary>Pipeline registration for <see cref="RateLimitingMiddleware"/>.</summary>
public static class RateLimitingApplicationBuilderExtensions
{
    /// <summary>Applies rate limits. Place after client-IP resolution and routing.</summary>
    public static IApplicationBuilder UseWafRateLimiting(this IApplicationBuilder app) =>
        app.UseMiddleware<RateLimitingMiddleware>();
}
