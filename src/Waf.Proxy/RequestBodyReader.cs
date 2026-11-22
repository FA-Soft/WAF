using System.Buffers;
using Microsoft.AspNetCore.Http;
using Waf.Engine.Detection;

namespace Waf.Proxy;

/// <summary>
/// Reads at most a fixed number of bytes of a request body for inspection, without consuming it: the
/// body is buffered and rewound, so the proxy still forwards it in full.
/// </summary>
public static class RequestBodyReader
{
    /// <summary>
    /// Returns the first <paramref name="maxBytes"/> bytes of the body, or null when there is no body.
    /// Bodies larger than <paramref name="maxBytes"/> are inspected only up to that size.
    /// </summary>
    public static async Task<RequestBody?> ReadAsync(HttpRequest request, int maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);

        if (request.ContentLength == 0 || (request.ContentLength is null && !request.Headers.ContainsKey("Transfer-Encoding")))
        {
            return null;
        }

        // Keep up to maxBytes in memory; larger bodies spill to a temporary file while the proxy forwards them.
        request.EnableBuffering(bufferThreshold: Math.Min(maxBytes, 1024 * 1024));

        var buffer = ArrayPool<byte>.Shared.Rent(maxBytes);
        try
        {
            var total = 0;
            while (total < maxBytes)
            {
                var read = await request.Body.ReadAsync(buffer.AsMemory(total, maxBytes - total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            request.Body.Position = 0;
            return total == 0 ? null : new RequestBody(request.ContentType, buffer.AsSpan(0, total).ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
