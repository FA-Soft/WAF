using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace FASoft.Waf.Web;

/// <summary>The Performance page's CSV export: the shown series, with the same period and filters.</summary>
public static class PerformanceEndpoints
{
    public const string ExportPath = "/performance/export.csv";

    public static IEndpointRouteBuilder MapPerformanceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Read-only GET: nothing changes, and the response cannot be read by other sites (same-origin policy).
        endpoints.MapGet(ExportPath, ExportAsync);
        return endpoints;
    }

    private static async Task<IResult> ExportAsync(HttpContext context, IMetricsHistory history, TimeProvider time, CancellationToken cancellationToken)
    {
        if (history.Store is not { } store)
        {
            return Results.NotFound();
        }

        var query = PerformanceQuery.Parse(context.Request.Query);
        var now = time.GetUtcNow();
        var report = await PerformanceReport.BuildAsync(store, history.Retention, query, now, cancellationToken).ConfigureAwait(false);
        var name = string.Create(CultureInfo.InvariantCulture, $"traffic-{report.From.UtcDateTime:yyyyMMdd-HHmm}-{report.To.UtcDateTime:yyyyMMdd-HHmm}.csv");
        return Results.File(System.Text.Encoding.UTF8.GetBytes(report.ToCsv()), "text/csv; charset=utf-8", name);
    }
}
