using Waf.Core;

namespace Waf.Host.Hosting;

/// <summary>
/// Request pipeline for the localhost admin listener. The Blazor admin UI is added here later.
/// </summary>
internal static class AdminPipeline
{
    public static void Configure(IApplicationBuilder admin)
    {
        admin.UseRouting();
        admin.UseEndpoints(endpoints =>
        {
            endpoints.MapHealthChecks("/healthz");
            endpoints.MapGet("/", () => Results.Text($"{ProductInfo.Name} admin"));
        });
    }
}
