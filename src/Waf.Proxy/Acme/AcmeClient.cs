using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FASoft.Waf.Proxy.Acme;

/// <summary>An error reported by the ACME server (or a protocol failure), in the server's words where possible.</summary>
public sealed class AcmeException : Exception
{
    public AcmeException()
    {
    }

    public AcmeException(string message)
        : base(message)
    {
    }

    public AcmeException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public AcmeException(string message, string? problemType)
        : base(message) => ProblemType = problemType;

    /// <summary>The problem type, e.g. <c>urn:ietf:params:acme:error:unauthorized</c>.</summary>
    public string? ProblemType { get; }
}

/// <summary>A certificate obtained from the ACME server: the PEM chain (leaf first) and its new private key.</summary>
public sealed record AcmeCertificate(string ChainPem, string PrivateKeyPem);

/// <summary>
/// Minimal ACME client (RFC 8555) for Let's Encrypt with HTTP-01 validation: account, order for one host name,
/// HTTP-01 challenge, finalize with a CSR, download. Requests are JWS-signed with the account's P-256 key (ES256).
/// </summary>
/// <remarks>
/// Kept small on purpose: one identifier per order, HTTP-01 only, ECDSA P-256 keys for the account and certificates.
/// Uses only .NET's own cryptography; no third-party crypto library.
/// </remarks>
public sealed class AcmeClient
{
    private const string JoseContentType = "application/jose+json";
    private const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    private const int MaxBadNonceRetries = 3;

    private readonly HttpClient _http;
    private readonly Uri _directoryUrl;
    private readonly ECDsa _accountKey;
    private readonly TimeProvider _time;
    private readonly Queue<string> _nonces = new();
    private readonly JsonObject _jwk;
    private JsonElement? _directory;

    /// <param name="http">HTTP client for the ACME server (not disposed here).</param>
    /// <param name="directoryUrl">The server's directory, e.g. Let's Encrypt staging.</param>
    /// <param name="accountKey">The account's P-256 key.</param>
    /// <param name="time">Clock for polling delays.</param>
    public AcmeClient(HttpClient http, Uri directoryUrl, ECDsa accountKey, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(directoryUrl);
        ArgumentNullException.ThrowIfNull(accountKey);
        ArgumentNullException.ThrowIfNull(time);

        if (accountKey.KeySize != 256)
        {
            throw new ArgumentException("The account key must be ECDSA P-256.", nameof(accountKey));
        }

        _http = http;
        _directoryUrl = directoryUrl;
        _accountKey = accountKey;
        _time = time;
        var point = accountKey.ExportParameters(includePrivateParameters: false).Q;
        _jwk = new JsonObject
        {
            ["crv"] = "P-256",
            ["kty"] = "EC",
            ["x"] = Base64Url.EncodeToString(point.X),
            ["y"] = Base64Url.EncodeToString(point.Y),
        };

        // RFC 7638: the members in lexicographic order, no whitespace.
        Thumbprint = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(_jwk.ToJsonString())));
    }

    /// <summary>The account URL ("kid") after <see cref="RegisterAsync"/>, or one stored earlier.</summary>
    public string? AccountUrl { get; set; }

    /// <summary>RFC 7638 thumbprint of the account key, the second half of every key authorization.</summary>
    public string Thumbprint { get; }

    /// <summary>How long to wait between status checks when the server gives no Retry-After.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>How long a validation or issuance may take in total.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(3);

    /// <summary>The key authorization for an HTTP-01 <paramref name="token"/>: what the server must find at the challenge URL.</summary>
    public string KeyAuthorization(string token) => $"{token}.{Thumbprint}";

    /// <summary>Creates the account (or finds the existing one for this key) and accepts the terms of service.</summary>
    public async Task<string> RegisterAsync(string email, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var payload = new JsonObject
        {
            ["termsOfServiceAgreed"] = true,
            ["contact"] = new JsonArray($"mailto:{email}"),
        };
        var response = await PostAsync(await DirectoryUrlAsync("newAccount", cancellationToken).ConfigureAwait(false), payload, useJwk: true, cancellationToken).ConfigureAwait(false);
        AccountUrl = response.Location ?? throw new AcmeException("The ACME server did not return the account URL.");
        return AccountUrl;
    }

    /// <summary>
    /// Orders a certificate for <paramref name="hostName"/>, proves control of it with HTTP-01 and downloads the
    /// certificate. <paramref name="present"/> must make the key authorization reachable at
    /// <c>http://{hostName}/.well-known/acme-challenge/{token}</c> until <paramref name="cleanUp"/> is called.
    /// </summary>
    public async Task<AcmeCertificate> IssueAsync(
        string hostName, Action<string, string> present, Action<string> cleanUp, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentNullException.ThrowIfNull(present);
        ArgumentNullException.ThrowIfNull(cleanUp);
        if (AccountUrl is null)
        {
            throw new InvalidOperationException("Register the account first.");
        }

        // 1. The order.
        var orderPayload = new JsonObject
        {
            ["identifiers"] = new JsonArray(new JsonObject { ["type"] = "dns", ["value"] = hostName }),
        };
        var created = await PostAsync(await DirectoryUrlAsync("newOrder", cancellationToken).ConfigureAwait(false), orderPayload, useJwk: false, cancellationToken).ConfigureAwait(false);
        var orderUrl = created.Location ?? throw new AcmeException("The ACME server did not return the order URL.");
        var order = created.Body;

        // 2. Prove control of the host name for every authorization that is not valid yet.
        foreach (var authorizationUrl in order.GetProperty("authorizations").EnumerateArray().Select(a => a.GetString()!))
        {
            await AuthorizeAsync(authorizationUrl, present, cleanUp, cancellationToken).ConfigureAwait(false);
        }

        // 3. Finalize with a CSR for a new key, wait until the certificate is ready, download it.
        using var certificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={hostName}", certificateKey, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(hostName);
        request.CertificateExtensions.Add(names.Build());
        var finalize = new JsonObject { ["csr"] = Base64Url.EncodeToString(request.CreateSigningRequest()) };
        order = (await PostAsync(order.GetProperty("finalize").GetString()!, finalize, useJwk: false, cancellationToken).ConfigureAwait(false)).Body;

        order = await PollAsync(orderUrl, order, "processing", "pending", "ready", cancellationToken).ConfigureAwait(false);
        if (Status(order) != "valid" || !order.TryGetProperty("certificate", out var certificateUrl))
        {
            throw new AcmeException($"The order for {hostName} ended as '{Status(order)}'{ProblemText(order)}.");
        }

        var chain = await PostAsync(certificateUrl.GetString()!, null, useJwk: false, cancellationToken, accept: "application/pem-certificate-chain").ConfigureAwait(false);
        return new AcmeCertificate(chain.Text, certificateKey.ExportPkcs8PrivateKeyPem());
    }

    private async Task AuthorizeAsync(string authorizationUrl, Action<string, string> present, Action<string> cleanUp, CancellationToken cancellationToken)
    {
        var authorization = (await PostAsync(authorizationUrl, null, useJwk: false, cancellationToken).ConfigureAwait(false)).Body;
        if (Status(authorization) == "valid")
        {
            return;
        }

        var host = authorization.GetProperty("identifier").GetProperty("value").GetString();
        var challenge = authorization.GetProperty("challenges").EnumerateArray()
            .FirstOrDefault(c => c.GetProperty("type").GetString() == "http-01");
        if (challenge.ValueKind != JsonValueKind.Object)
        {
            throw new AcmeException($"The ACME server offers no HTTP-01 challenge for {host}.");
        }

        var token = challenge.GetProperty("token").GetString()!;
        present(token, KeyAuthorization(token));
        try
        {
            await PostAsync(challenge.GetProperty("url").GetString()!, new JsonObject(), useJwk: false, cancellationToken).ConfigureAwait(false);
            authorization = await PollAsync(authorizationUrl, authorization, "pending", null, null, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cleanUp(token);
        }

        if (Status(authorization) != "valid")
        {
            var failed = authorization.GetProperty("challenges").EnumerateArray()
                .FirstOrDefault(c => c.GetProperty("type").GetString() == "http-01");
            throw new AcmeException($"The ACME server could not validate {host} with HTTP-01{ProblemText(failed)}. " +
                $"Check that the host name points to this gateway and that port 80 is reachable from the internet.");
        }
    }

    /// <summary>Re-reads <paramref name="url"/> while its status is one of the waiting states.</summary>
    private async Task<JsonElement> PollAsync(string url, JsonElement current, string waiting, string? waiting2, string? waiting3, CancellationToken cancellationToken)
    {
        var deadline = _time.GetUtcNow() + Timeout;
        var retryAfter = PollInterval;
        while (Status(current) is { } status && (status == waiting || status == waiting2 || status == waiting3))
        {
            if (_time.GetUtcNow() > deadline)
            {
                throw new AcmeException($"The ACME server did not finish within {Timeout.TotalSeconds:0} seconds (status '{status}').");
            }

            await Task.Delay(retryAfter, _time, cancellationToken).ConfigureAwait(false);
            var response = await PostAsync(url, null, useJwk: false, cancellationToken).ConfigureAwait(false);
            current = response.Body;
            retryAfter = response.RetryAfter is { } wait && wait > TimeSpan.Zero ? Min(wait, TimeSpan.FromSeconds(30)) : PollInterval;
        }

        return current;
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static string? Status(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty("status", out var status) ? status.GetString() : null;

    private static string ProblemText(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty("error", out var error) && error.TryGetProperty("detail", out var detail)
            ? $": {detail.GetString()}"
            : string.Empty;

    private async Task<string> DirectoryUrlAsync(string name, CancellationToken cancellationToken)
    {
        if (_directory is null)
        {
            using var response = await _http.GetAsync(_directoryUrl, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new AcmeException($"The ACME directory {_directoryUrl} answered {(int)response.StatusCode}.");
            }

            _directory = JsonElement.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        }

        return _directory.Value.TryGetProperty(name, out var url) ? url.GetString()! : throw new AcmeException($"The ACME directory has no '{name}'.");
    }

    private async Task<string> NonceAsync(CancellationToken cancellationToken)
    {
        if (_nonces.TryDequeue(out var nonce))
        {
            return nonce;
        }

        using var request = new HttpRequestMessage(HttpMethod.Head, await DirectoryUrlAsync("newNonce", cancellationToken).ConfigureAwait(false));
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return ReplayNonce(response) ?? throw new AcmeException("The ACME server sent no nonce.");
    }

    private static string? ReplayNonce(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Replay-Nonce", out var values) ? values.FirstOrDefault() : null;

    private sealed record Response(JsonElement Body, string Text, string? Location, TimeSpan? RetryAfter);

    /// <summary>A signed POST; <paramref name="payload"/> null is a POST-as-GET.</summary>
    private async Task<Response> PostAsync(
        string url, JsonObject? payload, bool useJwk, CancellationToken cancellationToken, string accept = "application/json")
    {
        for (var attempt = 0; ; attempt++)
        {
            var body = Sign(url, payload, useJwk, await NonceAsync(cancellationToken).ConfigureAwait(false));
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(JoseContentType);
            request.Headers.Accept.ParseAdd(accept);
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (ReplayNonce(response) is { } nonce)
            {
                _nonces.Enqueue(nonce);
            }

            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var (type, detail) = Problem(text);
                if (type == BadNonce && attempt < MaxBadNonceRetries)
                {
                    continue;
                }

                throw new AcmeException(
                    $"The ACME server refused the request ({(int)response.StatusCode}): {detail ?? response.ReasonPhrase}", type);
            }

            var json = text.Length > 0 && response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true
                ? JsonElement.Parse(text)
                : default;
            var retryAfter = response.Headers.RetryAfter?.Delta
                ?? (response.Headers.RetryAfter?.Date is { } date ? date - _time.GetUtcNow() : null);
            return new Response(json, text, response.Headers.Location?.ToString(), retryAfter);
        }
    }

    private static (string? Type, string? Detail) Problem(string text)
    {
        try
        {
            var problem = JsonElement.Parse(text);
            return (problem.TryGetProperty("type", out var type) ? type.GetString() : null,
                problem.TryGetProperty("detail", out var detail) ? detail.GetString() : null);
        }
        catch (JsonException)
        {
            return (null, text.Length > 200 ? text[..200] : text);
        }
    }

    /// <summary>RFC 8555 §6.2: flattened JWS, ES256, with the account key (jwk) or the account URL (kid).</summary>
    private string Sign(string url, JsonObject? payload, bool useJwk, string nonce)
    {
        var header = new JsonObject { ["alg"] = "ES256", ["nonce"] = nonce, ["url"] = url };
        if (useJwk)
        {
            header["jwk"] = _jwk.DeepClone();
        }
        else
        {
            header["kid"] = AccountUrl;
        }

        var protectedHeader = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadText = payload is null ? string.Empty : Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signature = _accountKey.SignData(
            Encoding.ASCII.GetBytes($"{protectedHeader}.{payloadText}"), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new JsonObject
        {
            ["protected"] = protectedHeader,
            ["payload"] = payloadText,
            ["signature"] = Base64Url.EncodeToString(signature),
        }.ToJsonString();
    }

    /// <summary>A new account key.</summary>
    public static ECDsa CreateAccountKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
