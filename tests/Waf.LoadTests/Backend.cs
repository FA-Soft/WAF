using System.Net;
using System.Text;

namespace FASoft.Waf.LoadTests;

/// <summary>
/// A minimal backend: answers every GET with the same 1 KB of JSON and every POST (after reading the body) with a small
/// JSON confirmation. As cheap as possible, so the measurements show the gateway, not the backend.
/// </summary>
internal static class Backend
{
    private static readonly byte[] Page = Encoding.UTF8.GetBytes(
        "{\"items\":[" + string.Join(",", Enumerable.Range(1, 12).Select(i =>
            $"{{\"id\":{i},\"name\":\"Item {i}\",\"colour\":\"blue\",\"price\":{i * 3}.95,\"stock\":{i * 7}}}")) + "]}");

    private static readonly byte[] Created = Encoding.UTF8.GetBytes("{\"status\":\"created\"}");

    public static async Task<WebApplication> StartAsync(IPAddress address, int port)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Listen(address, port);
        });

        var app = builder.Build();
        app.Run(async context =>
        {
            byte[] answer;
            if (HttpMethods.IsPost(context.Request.Method))
            {
                using var sink = new MemoryStream();
                await context.Request.Body.CopyToAsync(sink, context.RequestAborted).ConfigureAwait(false);
                answer = Created;
            }
            else
            {
                answer = Page;
            }

            context.Response.ContentType = "application/json";
            context.Response.ContentLength = answer.Length;
            await context.Response.Body.WriteAsync(answer, context.RequestAborted).ConfigureAwait(false);
        });

        await app.StartAsync().ConfigureAwait(false);
        return app;
    }
}
