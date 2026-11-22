namespace Waf.Host.Hosting;

/// <summary>
/// Request pipeline for public traffic on the HTTP/HTTPS listeners.
/// The WAF rule engine and reverse proxy are added here in later milestones.
/// </summary>
internal static class PublicPipeline
{
    public static void Configure(IApplicationBuilder app)
    {
        // No routes are configured yet: answer everything with 404.
        app.Run(context =>
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        });
    }
}
