using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>The live view of the log viewer: new entries as JSON, polled by <c>logs.js</c>.</summary>
public static class LogEndpoints
{
    public const string LivePath = "/logs/live";

    /// <summary>At most this many new entries per poll; the page keeps up because it polls every few seconds.</summary>
    public const int MaxLiveEntries = 200;

    public static IEndpointRouteBuilder MapLogEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Read-only GET: nothing changes, and the response cannot be read by other sites (same-origin policy).
        endpoints.MapGet(LivePath, LiveAsync);
        return endpoints;
    }

    private static async Task<IResult> LiveAsync(HttpContext context, RequestLogReader reader, TimeProvider time, CancellationToken cancellationToken)
    {
        var query = LogQuery.Parse(context.Request.Query);
        if (!long.TryParse(context.Request.Query["after"], out var after) || after < 0)
        {
            return Results.BadRequest("Missing 'after'.");
        }

        // Read up to the newest id known *before* reading, so an entry written meanwhile is picked up by the next poll
        // instead of being skipped.
        var newest = await reader.GetLatestIdAsync(cancellationToken).ConfigureAwait(false);
        var entries = await reader.ReadNewerAsync(query.ToFilter(time.GetUtcNow()), after, MaxLiveEntries, cancellationToken, upTo: newest).ConfigureAwait(false);
        var more = entries.Count == MaxLiveEntries;

        // Continue from the newest entry examined, also when it did not match the filter, so polls stay cheap.
        var latest = Math.Max(after, more ? entries[^1].Id : newest);
        return Results.Json(new { latest, more, items = entries.Select(LogFormat.ToLiveRow) });
    }
}
