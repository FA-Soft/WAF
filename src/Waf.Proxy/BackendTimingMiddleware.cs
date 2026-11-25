using Microsoft.AspNetCore.Http;

namespace FASoft.Waf.Proxy;

/// <summary>
/// Measures the time spent forwarding to the backend: the last step of the proxy pipeline, around YARP's forwarder
/// (connecting, the backend's answer, and passing the response on). The rest of a request's time is what the gateway
/// itself adds (the WAF, routing, the request log). Recorded on the request log feature, for the response times.
/// </summary>
public sealed class BackendTimingMiddleware(RequestDelegate next, TimeProvider time)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var started = time.GetTimestamp();
        try
        {
            await next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Features.Get<RequestLogFeature>()?.AddBackendTime(time.GetElapsedTime(started));
        }
    }
}
