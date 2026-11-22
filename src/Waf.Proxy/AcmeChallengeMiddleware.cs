using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Waf.Proxy;

/// <summary>Pending ACME HTTP-01 challenge responses (token → key authorization).</summary>
public interface IAcmeChallengeStore
{
    bool TryGetResponse(string token, out string keyAuthorization);
}

/// <summary>In-memory challenge store, filled by the certificate manager while a challenge is pending.</summary>
public sealed class InMemoryAcmeChallengeStore : IAcmeChallengeStore
{
    private readonly ConcurrentDictionary<string, string> _responses = new(StringComparer.Ordinal);

    public void Add(string token, string keyAuthorization) => _responses[token] = keyAuthorization;

    public void Remove(string token) => _responses.TryRemove(token, out _);

    public bool TryGetResponse(string token, out string keyAuthorization) =>
        _responses.TryGetValue(token, out keyAuthorization!);
}

/// <summary>
/// Pipeline step 1: answers ACME HTTP-01 challenges (<c>GET /.well-known/acme-challenge/{token}</c>) for
/// pending tokens. Runs before the WAF so certificate validation also works while the WAF is unavailable;
/// it only ever returns stored tokens. Other requests continue down the pipeline.
/// </summary>
public sealed class AcmeChallengeMiddleware(RequestDelegate next, IAcmeChallengeStore store)
{
    /// <summary>Path prefix of HTTP-01 challenges.</summary>
    public const string PathPrefix = "/.well-known/acme-challenge/";

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var path = context.Request.Path.Value;
        if ((HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method))
            && path is not null
            && path.StartsWith(PathPrefix, StringComparison.Ordinal)
            && IsToken(path.AsSpan(PathPrefix.Length))
            && store.TryGetResponse(path[PathPrefix.Length..], out var keyAuthorization))
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/octet-stream";
            return context.Response.WriteAsync(keyAuthorization, context.RequestAborted);
        }

        return next(context);
    }

    /// <summary>ACME tokens are base64url: letters, digits, '-' and '_'.</summary>
    private static bool IsToken(ReadOnlySpan<char> token)
    {
        if (token.IsEmpty || token.Length > 256)
        {
            return false;
        }

        foreach (var c in token)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_')
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>Pipeline registration for <see cref="AcmeChallengeMiddleware"/>.</summary>
public static class AcmeApplicationBuilderExtensions
{
    public static IApplicationBuilder UseAcmeChallenges(this IApplicationBuilder app) =>
        app.UseMiddleware<AcmeChallengeMiddleware>();
}
