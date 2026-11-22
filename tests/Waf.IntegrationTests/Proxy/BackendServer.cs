using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Waf.IntegrationTests.Proxy;

/// <summary>What a test backend saw of a proxied request.</summary>
public sealed record BackendEcho(
    string Backend,
    string Method,
    string Path,
    string Host,
    string? XForwardedFor,
    string? XForwardedProto,
    string? XForwardedHost,
    string? Forwarded);

/// <summary>
/// A small real backend on a free loopback port: echoes request details as JSON, serves
/// <c>/health</c> and a WebSocket echo on <c>/ws</c>. Optionally HTTPS with a self-signed certificate.
/// </summary>
public sealed class BackendServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private BackendServer(string id, int port, WebApplication app)
    {
        Id = id;
        Port = port;
        _app = app;
    }

    public string Id { get; }

    public int Port { get; }

    public static async Task<BackendServer> StartAsync(string id, X509Certificate2? certificate = null)
    {
        var port = GatewayFixture.FreePort();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port, listen =>
        {
            if (certificate is not null)
            {
                listen.UseHttps(certificate);
            }
        }));

        var app = builder.Build();
        app.UseWebSockets();
        app.Map("/ws", ws => ws.Run(context => EchoWebSocketAsync(id, context)));
        app.MapGet("/health", () => "ok");
        app.Map("/{**path}", (HttpContext context) =>
        {
            var headers = context.Request.Headers;
            return Results.Json(new BackendEcho(
                id,
                context.Request.Method,
                context.Request.Path.Value ?? string.Empty,
                context.Request.Host.Value ?? string.Empty,
                headers["X-Forwarded-For"].FirstOrDefault(),
                headers["X-Forwarded-Proto"].FirstOrDefault(),
                headers["X-Forwarded-Host"].FirstOrDefault(),
                headers["Forwarded"].FirstOrDefault()));
        });

        await app.StartAsync(TestContext.Current.CancellationToken);
        return new BackendServer(id, port, app);
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync(CancellationToken.None);
        await _app.DisposeAsync();
    }

    /// <summary>Creates a self-signed server certificate for 127.0.0.1/localhost, valid for a day.</summary>
    public static X509Certificate2 CreateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Round-trip through PKCS#12 so the private key is usable by the TLS stack on Windows.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), password: null);
    }

    private static async Task EchoWebSocketAsync(string id, HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync();
        var buffer = new byte[4096];
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, context.RequestAborted);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, context.RequestAborted);
                return;
            }

            var reply = Encoding.UTF8.GetBytes($"{id}:{Encoding.UTF8.GetString(buffer, 0, result.Count)}");
            await socket.SendAsync(reply, WebSocketMessageType.Text, endOfMessage: true, context.RequestAborted);
        }
    }
}
