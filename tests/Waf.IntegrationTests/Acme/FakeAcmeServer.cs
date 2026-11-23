using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FASoft.Waf.UnitTests.Tls;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

namespace FASoft.Waf.IntegrationTests.Acme;

/// <summary>
/// A small ACME server (RFC 8555) for tests, standing in for Let's Encrypt. It checks what a real one checks: every
/// request is a JWS signed with the account key (ES256), nonces are used once, the signed URL matches; HTTP-01 is
/// validated by fetching <c>/.well-known/acme-challenge/{token}</c> from the gateway's HTTP port with the host name
/// in the Host header; the CSR must be for the ordered host name. Certificates are issued by a test CA.
/// </summary>
internal sealed class FakeAcmeServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly Func<int> _gatewayHttpPort;
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _issuer;
    private readonly ConcurrentDictionary<string, byte> _nonces = new();
    private readonly ConcurrentDictionary<string, ECDsa> _accounts = new();
    private readonly ConcurrentDictionary<string, Order> _orders = new();
    private readonly ConcurrentDictionary<string, Authorization> _authorizations = new();
    private readonly ConcurrentDictionary<string, string> _certificates = new();
    private readonly HttpClient _validator = new() { Timeout = TimeSpan.FromSeconds(10) };
    private int _id;

    private sealed class Order
    {
        public required string Id { get; init; }
        public required string Account { get; init; }
        public required string Host { get; init; }
        public required string AuthorizationId { get; init; }
        public string Status { get; set; } = "pending";
        public string? CertificateId { get; set; }
    }

    private sealed class Authorization
    {
        public required string Id { get; init; }
        public required string Host { get; init; }
        public required string Token { get; init; }
        public required string Account { get; init; }
        public string Status { get; set; } = "pending";
        public string? Error { get; set; }
    }

    private FakeAcmeServer(WebApplication app, Func<int> gatewayHttpPort)
    {
        _app = app;
        _gatewayHttpPort = gatewayHttpPort;
        var (root, intermediate, leaf) = TestCertificates.Chain("unused.test");
        leaf.Dispose();
        _root = root;
        _issuer = intermediate;
    }

    public string BaseUrl { get; private set; } = string.Empty;

    public string DirectoryUrl => $"{BaseUrl}/directory";

    /// <summary>Lifetime of the certificates it issues.</summary>
    public TimeSpan CertificateLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>How far in the past issued certificates start (to issue one that is already due for renewal).</summary>
    public TimeSpan Backdate { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>When set, HTTP-01 validation fails (as if the host name pointed elsewhere).</summary>
    public bool FailValidation { get; set; }

    /// <summary>When set, the next signed request is refused with badNonce (clients must retry).</summary>
    public bool RejectNextNonce { get; set; }

    /// <summary>Host names whose HTTP-01 challenge was fetched successfully from the gateway.</summary>
    public ConcurrentQueue<string> Validated { get; } = new();

    /// <summary>Host names a certificate was issued for, in order.</summary>
    public ConcurrentQueue<string> Issued { get; } = new();

    public int BadNoncesSent { get; private set; }

    public static async Task<FakeAcmeServer> StartAsync(Func<int> gatewayHttpPort)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, o => o.Protocols = HttpProtocols.Http1));
        builder.Logging.ClearProviders();
        var app = builder.Build();
        var server = new FakeAcmeServer(app, gatewayHttpPort);
        app.Use(async (context, next) =>
        {
            try
            {
                await next(context);
            }
#pragma warning disable CA1031 // A test server: report any failure to the client.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { type = "urn:test:exception", detail = ex.ToString() });
            }
        });
        server.Map(app);
        await app.StartAsync();
        server.BaseUrl = app.Urls.First().TrimEnd('/');
        return server;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _validator.Dispose();
        _root.Dispose();
        _issuer.Dispose();
        foreach (var key in _accounts.Values)
        {
            key.Dispose();
        }
    }

    private void Map(WebApplication app)
    {
        app.MapGet("/directory", () => Results.Json(new
        {
            newNonce = $"{BaseUrl}/new-nonce",
            newAccount = $"{BaseUrl}/new-account",
            newOrder = $"{BaseUrl}/new-order",
        }));
        app.MapMethods("/new-nonce", ["HEAD", "GET"], (HttpContext context) =>
        {
            AddNonce(context);
            return Results.Ok();
        });
        app.MapPost("/new-account", (HttpContext context, CancellationToken _) => HandleAsync(context, NewAccount, jwkAllowed: true));
        app.MapPost("/new-order", (HttpContext context, CancellationToken _) => HandleAsync(context, NewOrder));
        app.MapPost("/authz/{id}", (HttpContext context, string id) => HandleAsync(context, (_, _, _) => Task.FromResult(AuthorizationResult(id))));
        app.MapPost("/chall/{id}", (HttpContext context, string id) => HandleAsync(context, (account, _, _) => ChallengeAsync(id, account)));
        app.MapPost("/finalize/{id}", (HttpContext context, string id) => HandleAsync(context, (_, payload, _) => Task.FromResult(Finalize(id, payload))));
        app.MapPost("/order/{id}", (HttpContext context, string id) => HandleAsync(context, (_, _, _) => Task.FromResult(OrderResult(id, advance: true))));
        app.MapPost("/cert/{id}", (HttpContext context, string id) => HandleAsync(context, (_, _, _) =>
            Task.FromResult(Results.Text(_certificates[id], "application/pem-certificate-chain"))));
    }

    private void AddNonce(HttpContext context)
    {
        var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        _nonces[nonce] = 0;
        context.Response.Headers["Replay-Nonce"] = nonce;
        context.Response.Headers.CacheControl = "no-store";
    }

    private static IResult Problem(string type, string detail, int status = 400) =>
        Results.Json(new { type = $"urn:ietf:params:acme:error:{type}", detail }, statusCode: status, contentType: "application/problem+json");

    /// <summary>Verifies the JWS (signature, nonce, URL, key) and calls <paramref name="handler"/> with the account and payload.</summary>
    private async Task<IResult> HandleAsync(HttpContext context, Func<string, JsonNode?, JsonObject, Task<IResult>> handler, bool jwkAllowed = false)
    {
        AddNonce(context);
        if (context.Request.ContentType != "application/jose+json")
        {
            return Problem("malformed", "Content-Type must be application/jose+json.");
        }

        var jws = (await JsonNode.ParseAsync(context.Request.Body))!.AsObject();
        var protectedText = jws["protected"]!.GetValue<string>();
        var payloadText = jws["payload"]!.GetValue<string>();
        var header = JsonNode.Parse(Base64Url.DecodeFromChars(protectedText))!.AsObject();

        if (header["alg"]?.GetValue<string>() != "ES256")
        {
            return Problem("badSignatureAlgorithm", "Only ES256 is accepted here.");
        }

        var nonce = header["nonce"]?.GetValue<string>();
        if (RejectNextNonce || nonce is null || !_nonces.TryRemove(nonce, out _))
        {
            RejectNextNonce = false;
            BadNoncesSent++;
            return Problem("badNonce", "The nonce was not issued or was already used.");
        }

        var requestUrl = $"{BaseUrl}{context.Request.Path}";
        if (header["url"]?.GetValue<string>() != requestUrl)
        {
            return Problem("unauthorized", $"The signed URL does not match {requestUrl}.");
        }

        ECDsa key;
        string account;
        if (header["jwk"] is JsonObject jwk)
        {
            if (!jwkAllowed)
            {
                return Problem("malformed", "Use kid, not jwk, after the account was created.");
            }

            key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Base64Url.DecodeFromChars(jwk["x"]!.GetValue<string>()),
                    Y = Base64Url.DecodeFromChars(jwk["y"]!.GetValue<string>()),
                },
            });
            account = $"{BaseUrl}/acct/{Thumbprint(jwk)}";
        }
        else
        {
            account = header["kid"]?.GetValue<string>() ?? string.Empty;
            if (!_accounts.TryGetValue(account, out key!))
            {
                return Problem("accountDoesNotExist", "Unknown account.");
            }
        }

        var signature = Base64Url.DecodeFromChars(jws["signature"]!.GetValue<string>());
        if (!key.VerifyData(Encoding.ASCII.GetBytes($"{protectedText}.{payloadText}"), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return Problem("unauthorized", "The JWS signature is not valid.");
        }

        if (header["jwk"] is JsonObject newKey)
        {
            _accounts.TryAdd(account, key);
            context.Items["jwk"] = newKey;
        }

        var payload = payloadText.Length == 0 ? null : JsonNode.Parse(Base64Url.DecodeFromChars(payloadText));
        return await handler(account, payload, header);
    }

    private static string Thumbprint(JsonObject jwk) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $$"""{"crv":"{{jwk["crv"]}}","kty":"{{jwk["kty"]}}","x":"{{jwk["x"]}}","y":"{{jwk["y"]}}"}""")));

    private Task<IResult> NewAccount(string account, JsonNode? payload, JsonObject header)
    {
        if (payload?["termsOfServiceAgreed"]?.GetValue<bool>() != true)
        {
            return Task.FromResult(Problem("userActionRequired", "The terms of service must be agreed to."));
        }

        return Task.FromResult(Results.Created(account, new { status = "valid" }));
    }

    private Task<IResult> NewOrder(string account, JsonNode? payload, JsonObject header)
    {
        var host = payload!["identifiers"]![0]!["value"]!.GetValue<string>();
        var id = Interlocked.Increment(ref _id).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var authorization = new Authorization
        {
            Id = id, Host = host, Account = account, Token = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24)),
        };
        _authorizations[id] = authorization;
        var order = new Order { Id = id, Account = account, Host = host, AuthorizationId = id };
        _orders[id] = order;
        return Task.FromResult(Results.Created($"{BaseUrl}/order/{id}", OrderJson(order)));
    }

    private object OrderJson(Order order) => new
    {
        status = order.Status,
        identifiers = new[] { new { type = "dns", value = order.Host } },
        authorizations = new[] { $"{BaseUrl}/authz/{order.AuthorizationId}" },
        finalize = $"{BaseUrl}/finalize/{order.Id}",
        certificate = order.CertificateId is null ? null : $"{BaseUrl}/cert/{order.CertificateId}",
    };

    private IResult AuthorizationResult(string id)
    {
        var authorization = _authorizations[id];
        return Results.Json(new
        {
            status = authorization.Status,
            identifier = new { type = "dns", value = authorization.Host },
            challenges = new[]
            {
                new
                {
                    type = "http-01",
                    url = $"{BaseUrl}/chall/{id}",
                    token = authorization.Token,
                    status = authorization.Status,
                    error = authorization.Error is null ? null : new { type = "urn:ietf:params:acme:error:unauthorized", detail = authorization.Error },
                },
            },
        });
    }

    /// <summary>HTTP-01: fetch the key authorization from the gateway, as Let's Encrypt fetches it from the host.</summary>
    private async Task<IResult> ChallengeAsync(string id, string account)
    {
        var authorization = _authorizations[id];
        var key = _accounts[account];
        var point = key.ExportParameters(false).Q;
        var thumbprint = Thumbprint(new JsonObject
        {
            ["crv"] = "P-256", ["kty"] = "EC", ["x"] = Base64Url.EncodeToString(point.X), ["y"] = Base64Url.EncodeToString(point.Y),
        });

        using var request = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{_gatewayHttpPort()}/.well-known/acme-challenge/{authorization.Token}");
        request.Headers.Host = authorization.Host;
        using var response = await _validator.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        var expected = $"{authorization.Token}.{thumbprint}";
        if (!FailValidation && response.StatusCode == HttpStatusCode.OK && body == expected)
        {
            authorization.Status = "valid";
            Validated.Enqueue(authorization.Host);
        }
        else
        {
            authorization.Status = "invalid";
            authorization.Error = $"Invalid response from http://{authorization.Host}/.well-known/acme-challenge/{authorization.Token}: {(int)response.StatusCode}";
        }

        return Results.Json(new { type = "http-01", status = "processing", token = authorization.Token });
    }

    private IResult Finalize(string id, JsonNode? payload)
    {
        var order = _orders[id];
        if (_authorizations[order.AuthorizationId].Status != "valid")
        {
            return Problem("orderNotReady", "The authorization is not valid.", 403);
        }

        var csr = CertificateRequest.LoadSigningRequest(
            Base64Url.DecodeFromChars(payload!["csr"]!.GetValue<string>()), HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var names = csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToList();
        if (names.Count != 1 || names[0] != order.Host)
        {
            return Problem("badCSR", $"The CSR must name exactly {order.Host}.");
        }

        var request = new CertificateRequest(csr.SubjectName, csr.PublicKey, HashAlgorithmName.SHA256);
        foreach (var extension in csr.CertificateExtensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var now = DateTimeOffset.UtcNow;
        using var leaf = request.Create(_issuer, now - Backdate, now - Backdate + CertificateLifetime, RandomNumberGenerator.GetBytes(12));
        order.CertificateId = id;
        _certificates[id] = leaf.ExportCertificatePem() + "\n" + _issuer.ExportCertificatePem() + "\n";
        order.Status = "processing"; // becomes valid on the next poll, as with Let's Encrypt
        Issued.Enqueue(order.Host);
        return Results.Json(OrderJson(order));
    }

    private IResult OrderResult(string id, bool advance)
    {
        var order = _orders[id];
        if (advance && order.Status == "processing")
        {
            order.Status = "valid";
        }

        return Results.Json(OrderJson(order));
    }
}
