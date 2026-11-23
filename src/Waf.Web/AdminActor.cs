using Microsoft.AspNetCore.Http;
using Waf.Data;

namespace Waf.Web;

/// <summary>The signed-in admin as recorded in configuration versions and the audit log.</summary>
public static class AdminActor
{
    /// <summary>Where changes made in the admin UI come from.</summary>
    public const string AdminUi = "admin UI";

    private const string Unknown = "unknown";

    /// <summary>The admin making this request: user name and client address.</summary>
    public static AuditActor From(HttpContext? context, string source = AdminUi)
    {
        if (context is null)
        {
            return new AuditActor(Unknown, null, source);
        }

        var name = context.User.Identity?.IsAuthenticated == true ? context.User.Identity.Name : null;
        return new AuditActor(string.IsNullOrWhiteSpace(name) ? Unknown : name, SignInHistory.ClientIp(context), source);
    }

    /// <summary>Like <see cref="From(HttpContext?, string)"/>, with the user name given (before the sign-in cookie exists).</summary>
    public static AuditActor From(HttpContext context, string? userName, string source)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new AuditActor(string.IsNullOrWhiteSpace(userName) ? Unknown : userName, SignInHistory.ClientIp(context), source);
    }
}
