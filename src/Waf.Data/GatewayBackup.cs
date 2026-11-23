using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Data;

/// <summary>One configuration version in a backup.</summary>
public sealed record BackupVersion(long Version, DateTime CreatedAtUtc, string Author, string? Comment, GatewayConfiguration Configuration);

/// <summary>A full backup: every configuration version and which one is active.</summary>
/// <param name="CreatedAtUtc">When the backup was made.</param>
/// <param name="ProductVersion">Version of the gateway that made it.</param>
/// <param name="ActiveVersion">The version that was active.</param>
/// <param name="IncludesSecrets">False when secret values were replaced by <see cref="ConfigurationSecrets.Placeholder"/>.</param>
/// <param name="Versions">All versions, oldest first.</param>
public sealed record GatewayBackup(
    DateTime CreatedAtUtc, string ProductVersion, long ActiveVersion, bool IncludesSecrets, IReadOnlyList<BackupVersion> Versions)
{
    /// <summary>Uploaded certificates with their private keys; only in a backup that includes secrets.</summary>
    public IReadOnlyList<BackupCertificate> Certificates { get; init; } = [];

    /// <summary>The active version's entry.</summary>
    public BackupVersion Active => Versions.First(v => v.Version == ActiveVersion);
}

/// <summary>Outcome of reading a backup file.</summary>
public sealed record BackupReadResult(GatewayBackup? Backup, IReadOnlyList<string> Errors);

/// <summary>
/// Reads and writes backup files: a zip with <c>manifest.json</c> (format, versions, secrets flag) and
/// <c>versions.json</c> (every configuration version with its metadata), and <c>certificates.json</c> (uploaded
/// certificates with their private keys as PFX) only when secrets are included.
/// </summary>
public static class BackupArchive
{
    /// <summary>Identifies the file format in the manifest.</summary>
    public const string Format = "waf-gateway-backup";

    /// <summary>The format version this code writes and reads.</summary>
    public const int FormatVersion = 1;

    /// <summary>Largest entry that is read (uncompressed), against zip bombs.</summary>
    public const int MaxEntryBytes = 64 * 1024 * 1024;

    private const string ManifestEntry = "manifest.json";
    private const string VersionsEntry = "versions.json";
    private const string CertificatesEntry = "certificates.json";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public static void Write(Stream destination, GatewayBackup backup)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(backup);

        var manifest = new JsonObject
        {
            ["Format"] = Format,
            ["FormatVersion"] = FormatVersion,
            ["ProductVersion"] = backup.ProductVersion,
            ["CreatedAtUtc"] = backup.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture),
            ["ActiveVersion"] = backup.ActiveVersion,
            ["IncludesSecrets"] = backup.IncludesSecrets,
            ["VersionCount"] = backup.Versions.Count,
        };

        var versions = new JsonArray();
        foreach (var version in backup.Versions)
        {
            versions.Add(new JsonObject
            {
                ["Version"] = version.Version,
                ["CreatedAtUtc"] = version.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["Author"] = version.Author,
                ["Comment"] = version.Comment,
                ["Configuration"] = JsonNode.Parse(GatewayConfigurationJson.Serialize(version.Configuration)),
            });
        }

        using var zip = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true);
        WriteEntry(zip, ManifestEntry, manifest.ToJsonString(Indented));
        WriteEntry(zip, VersionsEntry, versions.ToJsonString(Indented));

        // Private keys never go into a backup without secrets, whatever the caller passed.
        if (backup.IncludesSecrets && backup.Certificates.Count > 0)
        {
            var certificates = new JsonArray();
            foreach (var certificate in backup.Certificates)
            {
                certificates.Add(new JsonObject
                {
                    ["Thumbprint"] = certificate.Thumbprint,
                    ["Pfx"] = Convert.ToBase64String(certificate.Pfx),
                });
            }

            WriteEntry(zip, CertificatesEntry, certificates.ToJsonString(Indented));
        }
    }

    /// <summary>Reads a backup. Configurations are parsed but not validated: a backup without secrets still has placeholders.</summary>
    public static BackupReadResult Read(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);

        try
        {
            using var zip = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true);
            var manifestText = ReadEntry(zip, ManifestEntry);
            var versionsText = ReadEntry(zip, VersionsEntry);
            if (manifestText is null || versionsText is null)
            {
                return Failed("This is not a WAF Gateway backup: manifest.json or versions.json is missing.");
            }

            var manifest = JsonNode.Parse(manifestText)?.AsObject();
            if (manifest?["Format"]?.GetValue<string>() != Format)
            {
                return Failed("This is not a WAF Gateway backup (unknown format).");
            }

            var formatVersion = manifest["FormatVersion"]?.GetValue<int>() ?? 0;
            if (formatVersion != FormatVersion)
            {
                return Failed($"This backup has format version {formatVersion}; this gateway reads version {FormatVersion}. Use a matching gateway version.");
            }

            var errors = new List<string>();
            var versions = new List<BackupVersion>();
            foreach (var node in JsonNode.Parse(versionsText)?.AsArray() ?? [])
            {
                var number = node?["Version"]?.GetValue<long>() ?? 0;
                var parsed = GatewayConfigurationJson.Parse(node?["Configuration"]?.ToJsonString() ?? "null");
                if (parsed.Configuration is null)
                {
                    errors.AddRange(parsed.Errors.Select(e => $"Version {number}: {e}"));
                    continue;
                }

                versions.Add(new BackupVersion(
                    number,
                    Utc(Required(node, "CreatedAtUtc")),
                    node?["Author"]?.GetValue<string>() ?? "unknown",
                    node?["Comment"]?.GetValue<string>(),
                    parsed.Configuration));
            }

            var active = manifest["ActiveVersion"]?.GetValue<long>() ?? 0;
            if (versions.Count == 0 && errors.Count == 0)
            {
                errors.Add("The backup contains no configuration versions.");
            }

            if (versions.Select(v => v.Version).Distinct().Count() != versions.Count || versions.Any(v => v.Version < 1))
            {
                errors.Add("The backup's version numbers are invalid (duplicate or below 1).");
            }

            if (errors.Count == 0 && versions.All(v => v.Version != active))
            {
                errors.Add($"The backup's active version {active} is not in the backup.");
            }

            if (errors.Count > 0)
            {
                return new BackupReadResult(null, errors);
            }

            var certificates = new List<BackupCertificate>();
            foreach (var node in ReadEntry(zip, CertificatesEntry) is { } certificatesText ? JsonNode.Parse(certificatesText)?.AsArray() ?? [] : [])
            {
                certificates.Add(new BackupCertificate(Required(node, "Thumbprint"), Convert.FromBase64String(Required(node, "Pfx"))));
            }

            return new BackupReadResult(
                new GatewayBackup(
                    Utc(Required(manifest, "CreatedAtUtc")),
                    manifest["ProductVersion"]?.GetValue<string>() ?? "unknown",
                    active,
                    manifest["IncludesSecrets"]?.GetValue<bool>() ?? false,
                    [.. versions.OrderBy(v => v.Version)])
                {
                    Certificates = certificates,
                },
                []);
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidOperationException or FormatException)
        {
            return Failed($"The backup file is damaged or not a WAF Gateway backup ({ex.Message}).");
        }
    }

    private static BackupReadResult Failed(string error) => new(null, [error]);

    private static string Required(JsonNode? node, string property) =>
        node?[property]?.GetValue<string>() ?? throw new FormatException($"'{property}' is missing");

    private static DateTime Utc(string text) =>
        DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

    private static void WriteEntry(ZipArchive zip, string name, string text)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        var bytes = Encoding.UTF8.GetBytes(text);
        stream.Write(bytes);
    }

    private static string? ReadEntry(ZipArchive zip, string name)
    {
        var entry = zip.GetEntry(name);
        if (entry is null)
        {
            return null;
        }

        if (entry.Length > MaxEntryBytes)
        {
            throw new InvalidDataException($"{name} is larger than {MaxEntryBytes / (1024 * 1024)} MB");
        }

        using var stream = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk)) > 0)
        {
            if (buffer.Length + read > MaxEntryBytes)
            {
                throw new InvalidDataException($"{name} is larger than {MaxEntryBytes / (1024 * 1024)} MB");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }
}
