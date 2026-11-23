using Microsoft.AspNetCore.Http;

namespace FASoft.Waf.Web;

/// <summary>Marks and recognizes requests that reach the admin UI over remote access (not the localhost listener).</summary>
public static class RemoteAdminRequest
{
    /// <summary><see cref="HttpContext.Items"/> key set by the host for remote admin requests.</summary>
    public const string ItemKey = "WafRemoteAdmin";

    public static bool IsRemote(HttpContext? context) => context?.Items.ContainsKey(ItemKey) == true;

    public static void MarkRemote(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Items[ItemKey] = true;
    }
}

/// <summary>What the host knows about remote admin access right now (implemented by the host).</summary>
public interface IRemoteAdminAccess
{
    /// <summary>The gateway's HTTPS port (remote access without its own port uses it).</summary>
    int HttpsPort { get; }

    /// <summary>The ports the gateway listens on for HTTP and the localhost admin UI (not usable as a dedicated port).</summary>
    IReadOnlyCollection<int> ReservedPorts { get; }

    /// <summary>True when the gateway already listens for HTTPS on <paramref name="port"/> (else a restart opens it).</summary>
    bool IsListening(int port);

    /// <summary>Reads the stored settings again, so a change applies at once.</summary>
    Task RefreshAsync(CancellationToken cancellationToken);
}
