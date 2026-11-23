using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FASoft.Waf.IntegrationTests.Proxy;

/// <summary>
/// Stands in for Anthropic's Messages API on a free loopback port (the gateway's <c>Gateway:Ai:AnthropicBaseUrl</c>):
/// records every request body and answers with <see cref="Answer"/> as the model's text.
/// </summary>
public sealed class FakeAnthropic : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly List<string> _requests = [];

    private FakeAnthropic(WebApplication app) => _app = app;

    public Uri BaseUrl { get; private set; } = null!;

    /// <summary>The model's answer (the structured output text).</summary>
    public string Answer { get; set; } = string.Empty;

    /// <summary>The bodies of the message requests received so far.</summary>
    public IReadOnlyList<string> Requests
    {
        get
        {
            lock (_requests)
            {
                return [.. _requests];
            }
        }
    }

    /// <summary>The answer for <paramref name="summary"/> and <paramref name="configuration"/> (the proposed sections).</summary>
    public static string Proposal(string summary, string configuration) =>
        new JsonObject { ["summary"] = summary, ["configuration"] = configuration }.ToJsonString();

    public static async Task<FakeAnthropic> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        var fake = new FakeAnthropic(app);
        app.MapPost("/v1/messages", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync(context.RequestAborted);
            lock (fake._requests)
            {
                fake._requests.Add(body);
            }

            var model = JsonNode.Parse(body)?["model"]?.GetValue<string>() ?? "claude-opus-5-5";
            var message = new JsonObject
            {
                ["id"] = "msg_fake",
                ["type"] = "message",
                ["role"] = "assistant",
                ["model"] = model,
                ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = fake.Answer }),
                ["stop_reason"] = "end_turn",
                ["stop_sequence"] = null,
                ["usage"] = new JsonObject { ["input_tokens"] = 4200, ["output_tokens"] = 310 },
            };
            return Results.Text(message.ToJsonString(), "application/json");
        });

        await app.StartAsync(TestContext.Current.CancellationToken);
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        fake.BaseUrl = new Uri(address);
        return fake;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
