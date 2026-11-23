using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine;
using FASoft.Waf.Engine.Detection;
using FASoft.Waf.Engine.RateLimiting;

namespace FASoft.Waf.Proxy;

/// <summary>
/// Judges every public request with the active <see cref="WafEngine"/>, in this order:
/// <list type="number">
/// <item>Rules: Block → 403; an explicit Allow skips the remaining checks.</item>
/// <item>Rate limits → 429 with Retry-After.</item>
/// <item>Attack detection (path, query, headers, optionally the body) → 403.</item>
/// </list>
/// Fails closed: without an active engine, or when evaluation throws, the request gets 503 and is never
/// forwarded. In detection-only mode blocks are reported but not enforced.
/// </summary>
public sealed partial class WafMiddleware(
    RequestDelegate next, WafEngineHolder engines, IWafEventSink events, TimeProvider time, ILogger<WafMiddleware> logger)
{
    /// <summary>Body of 403 responses. Deliberately generic: no rule names or reasons for attackers.</summary>
    public const string ForbiddenMessage = "Forbidden. The request was blocked by the web application firewall.";

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Judge with the engine of the same configuration as the routes this request was routed by, so a
        // configuration swap can never pair new routes with old rules (or vice versa).
        var engine = engines.Resolve(HttpContextWafRequest.GetConfigTag(context));
        if (engine is null)
        {
            await FailClosedGuardMiddleware.RespondUnavailableAsync(context, events, time, engines.UnavailableReason).ConfigureAwait(false);
            return;
        }

        bool proceed;
        try
        {
            proceed = await JudgeAsync(context, new HttpContextWafRequest(context), engine).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return; // client went away; nothing to answer
        }
#pragma warning disable CA1031 // Fail closed on ANY evaluation error: never forward an unchecked request.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogEvaluationFailed(logger, ex, context.Request.Method, context.Request.Path);
            if (!context.Response.HasStarted)
            {
                await FailClosedGuardMiddleware.RespondUnavailableAsync(context, events, time, "WAF evaluation failed.").ConfigureAwait(false);
            }

            return;
        }

        if (proceed)
        {
            // Outside the try: errors while proxying are backend errors (502), not WAF failures.
            await next(context).ConfigureAwait(false);
        }
    }

    /// <summary>Returns true when the request may be forwarded; otherwise the response has been written.</summary>
    private async Task<bool> JudgeAsync(HttpContext context, HttpContextWafRequest request, WafEngine engine)
    {

        // 1. Rules.
        var decision = engine.Rules.Evaluate(request);
        foreach (var match in decision.Matches)
        {
            if (match.Action == RuleAction.LogOnly)
            {
                Publish(request, WafEventKind.RuleLogged, match.RuleName, StatusCodes.Status200OK);
            }
            else if (match.DetectionOnly)
            {
                Publish(request, WafEventKind.RuleDetected, match.RuleName, StatusCodes.Status200OK);
            }
        }

        if (decision.IsBlocked)
        {
            Publish(request, WafEventKind.RuleBlocked, decision.DecidingRule!.RuleName, StatusCodes.Status403Forbidden);
            await RespondForbiddenAsync(context).ConfigureAwait(false);
            return false;
        }

        if (decision.DecidingRule is not null)
        {
            return true; // explicit Allow rule: trusted, skip rate limits and attack detection
        }

        // 2. Rate limits.
        var rate = engine.RateLimiter.Check(request);
        if (rate.Outcome == RateLimitOutcome.Limited)
        {
            Publish(request, WafEventKind.RateLimited, rate.RuleName!, StatusCodes.Status429TooManyRequests);
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.Headers.RetryAfter = ((int)rate.RetryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("Too many requests. Please slow down.", context.RequestAborted).ConfigureAwait(false);
            return false;
        }

        if (rate.Outcome == RateLimitOutcome.WouldLimit)
        {
            Publish(request, WafEventKind.RateLimitDetected, rate.RuleName!, StatusCodes.Status200OK);
        }

        // 3. Attack detection.
        if (!engine.Detector.IsEnabled)
        {
            return true;
        }

        var body = engine.Detector.Settings.InspectBody && MayHaveBody(context.Request)
            ? await RequestBodyReader.ReadAsync(context.Request, engine.Detector.Settings.MaxBodyBytes, context.RequestAborted).ConfigureAwait(false)
            : null;

        var finding = engine.Detector.Inspect(request, body);
        if (finding is null)
        {
            return true;
        }

        // Cookie values are session secrets: name the cookie, but never record (part of) its value.
        var snippet = finding.Location == RequestLocation.Cookie ? "(cookie value not logged)" : finding.Snippet;
        var detail = $"{finding.Category} in {finding.Location}{(finding.Name is null ? string.Empty : $" '{finding.Name}'")}: {snippet}";
        if (engine.DetectionOnly)
        {
            Publish(request, WafEventKind.AttackDetected, finding.SignatureId, StatusCodes.Status200OK, detail);
            return true;
        }

        Publish(request, WafEventKind.AttackBlocked, finding.SignatureId, StatusCodes.Status403Forbidden, detail);
        await RespondForbiddenAsync(context).ConfigureAwait(false);
        return false;
    }

    private static bool MayHaveBody(HttpRequest request) =>
        !HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method) && !HttpMethods.IsOptions(request.Method)
        && !HttpMethods.IsTrace(request.Method);

    private static Task RespondForbiddenAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync(ForbiddenMessage, context.RequestAborted);
    }

    private void Publish(HttpContextWafRequest request, WafEventKind kind, string ruleName, int status, string? detail = null)
    {
        var wafEvent = new WafEvent(
            time.GetUtcNow(), kind, request.ClientIp, request.Method, request.Host, request.Path, request.RouteName, ruleName, status, detail);
        RequestLogFeature.Record(request.Context, wafEvent);
        events.Publish(wafEvent);
    }

    [LoggerMessage(EventId = 300, Level = LogLevel.Error, Message = "WAF evaluation failed for {Method} {Path}; the request was refused (fail-closed).")]
    private static partial void LogEvaluationFailed(ILogger logger, Exception exception, string method, PathString path);
}

/// <summary>
/// Refuses all public traffic with 503 while no WAF engine is active (fail-closed). The admin listener
/// is handled before this guard and stays reachable.
/// </summary>
public sealed class FailClosedGuardMiddleware(RequestDelegate next, WafEngineHolder engines, IWafEventSink events, TimeProvider time)
{
    /// <summary>Body of 503 responses.</summary>
    public const string UnavailableMessage = "Service unavailable. The web application firewall is not ready.";

    /// <summary>Retry-After for 503 responses, in seconds.</summary>
    public const int RetryAfterSeconds = 30;

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return engines.Current is null
            ? RespondUnavailableAsync(context, events, time, engines.UnavailableReason)
            : next(context);
    }

    internal static Task RespondUnavailableAsync(HttpContext context, IWafEventSink events, TimeProvider time, string? reason)
    {
        var request = new HttpContextWafRequest(context);
        var wafEvent = new WafEvent(
            time.GetUtcNow(), WafEventKind.FailClosed, request.ClientIp, request.Method, request.Host, request.Path,
            RouteName: null, RuleName: string.Empty, StatusCodes.Status503ServiceUnavailable, reason);
        RequestLogFeature.Record(context, wafEvent);
        events.Publish(wafEvent);

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync(UnavailableMessage, context.RequestAborted);
    }
}

/// <summary>Default event sink: writes security events to the application log.</summary>
public sealed partial class LoggingWafEventSink(ILogger<LoggingWafEventSink> logger) : IWafEventSink
{
    public void Publish(WafEvent wafEvent)
    {
        ArgumentNullException.ThrowIfNull(wafEvent);
        LogEvent(logger, wafEvent.Kind, wafEvent.RuleName, wafEvent.ClientIp, wafEvent.Method, wafEvent.Host, wafEvent.Path, wafEvent.StatusCode, wafEvent.Detail ?? string.Empty);
    }

    [LoggerMessage(EventId = 200, Level = LogLevel.Warning,
        Message = "{Kind} '{RuleName}': {ClientIp} {Method} {Host}{Path} -> {StatusCode} {Detail}")]
    private static partial void LogEvent(ILogger logger, WafEventKind kind, string ruleName, System.Net.IPAddress clientIp, string method, string host, string path, int statusCode, string detail);
}

/// <summary>Pipeline registration for the WAF middleware.</summary>
public static class WafApplicationBuilderExtensions
{
    /// <summary>503 for public traffic while no WAF engine is active. Place after client-IP resolution.</summary>
    public static IApplicationBuilder UseFailClosedGuard(this IApplicationBuilder app) =>
        app.UseMiddleware<FailClosedGuardMiddleware>();

    /// <summary>Rules, rate limits and attack detection. Place after client-IP resolution and routing.</summary>
    public static IApplicationBuilder UseWaf(this IApplicationBuilder app) =>
        app.UseMiddleware<WafMiddleware>();
}
