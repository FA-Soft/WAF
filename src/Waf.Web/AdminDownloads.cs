using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Waf.Core.Configuration;
using Waf.Data;

namespace Waf.Web;

/// <summary>
/// File downloads of the admin UI: the configuration as JSON and the full backup. Both are POST forms with an
/// antiforgery token (they can include secrets), and leave secrets out unless the form asks for them.
/// </summary>
public static class AdminDownloads
{
    public const string ConfigurationPath = "/export/configuration";
    public const string BackupPath = "/export/backup";

    public static IEndpointRouteBuilder MapAdminDownloads(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // [FromForm] parameters make these endpoints require a valid antiforgery token.
        endpoints.MapPost(ConfigurationPath, ExportConfigurationAsync);
        endpoints.MapPost(BackupPath, ExportBackupAsync);
        return endpoints;
    }

    /// <summary>The active configuration, or <paramref name="version"/>, as a JSON file.</summary>
    private static async Task<IResult> ExportConfigurationAsync(
        [FromForm(Name = "version")] long? version,
        [FromForm(Name = "includeSecrets")] bool? includeSecrets,
        ConfigurationStore store,
        AuditLogStore audit,
        HttpContext context,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var stored = version is null
            ? await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false)
            : await store.GetAsync(version.Value, cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return Results.NotFound("That configuration version does not exist.");
        }

        var json = ConfigurationExport.ToJson(stored.Configuration, includeSecrets == true);
        await audit.RecordAsync(
            AuditCategory.Maintenance,
            AuditActions.ConfigDownloaded,
            AdminActor.From(context),
            $"Configuration version {stored.Version} downloaded{(includeSecrets == true ? " with secrets" : " without secrets")}.",
            null,
            cancellationToken).ConfigureAwait(false);
        var name = string.Create(CultureInfo.InvariantCulture, $"waf-config-v{stored.Version}-{time.GetUtcNow():yyyyMMdd}.json");
        return Results.File(Encoding.UTF8.GetBytes(json), "application/json", name);
    }

    /// <summary>Every configuration version as a backup zip.</summary>
    private static async Task<IResult> ExportBackupAsync(
        [FromForm(Name = "includeSecrets")] bool? includeSecrets,
        ConfigurationStore store,
        AuditLogStore audit,
        HttpContext context,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        GatewayBackup backup;
        try
        {
            backup = await store.CreateBackupAsync(includeSecrets == true, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(ex.Message);
        }

        await audit.RecordAsync(
            AuditCategory.Maintenance,
            AuditActions.BackupDownloaded,
            AdminActor.From(context),
            $"Backup downloaded: {backup.Versions.Count} version(s){(backup.IncludesSecrets ? " with secrets" : " without secrets")}.",
            null,
            cancellationToken).ConfigureAwait(false);

        using var buffer = new MemoryStream();
        BackupArchive.Write(buffer, backup);
        var name = string.Create(CultureInfo.InvariantCulture, $"waf-backup-{time.GetUtcNow():yyyyMMdd-HHmmss}.zip");
        return Results.File(buffer.ToArray(), "application/zip", name);
    }
}

/// <summary>Exported configuration files.</summary>
public static class ConfigurationExport
{
    /// <summary>The configuration as JSON, with secret values replaced unless <paramref name="includeSecrets"/>.</summary>
    public static string ToJson(GatewayConfiguration configuration, bool includeSecrets)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var copy = GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration)).Configuration
            ?? throw new InvalidOperationException("The configuration could not be copied.");
        copy.Schema = null;
        if (!includeSecrets)
        {
            ConfigurationSecrets.Redact(copy);
        }

        return GatewayConfigurationJson.Serialize(copy);
    }
}
