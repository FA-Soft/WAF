using System.IO.Compression;
using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.UnitTests.Configuration;

namespace FASoft.Waf.UnitTests.Data;

public class BackupArchiveTests
{
    private static GatewayBackup Sample(bool includeSecrets = true)
    {
        var first = ConfigurationSecretsTests.WithSecrets();
        var second = ConfigurationSecretsTests.WithSecrets();
        second.Settings.DetectionOnly = true;
        if (!includeSecrets)
        {
            ConfigurationSecrets.Redact(first);
            ConfigurationSecrets.Redact(second);
        }

        return new GatewayBackup(
            new DateTime(2026, 11, 22, 10, 0, 0, DateTimeKind.Utc), "1.2.3", 1, includeSecrets,
            [
                new BackupVersion(1, new DateTime(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc), "first-run", null, first),
                new BackupVersion(2, new DateTime(2026, 11, 2, 9, 30, 0, DateTimeKind.Utc), "admin UI", "Detection only on.", second),
            ]);
    }

    private static byte[] Write(GatewayBackup backup)
    {
        using var buffer = new MemoryStream();
        BackupArchive.Write(buffer, backup);
        return buffer.ToArray();
    }

    private static BackupReadResult Read(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes);
        return BackupArchive.Read(stream);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Backup_round_trips(bool includeSecrets)
    {
        var original = Sample(includeSecrets);

        var result = Read(Write(original));

        Assert.Empty(result.Errors);
        var backup = result.Backup!;
        Assert.Equal((original.CreatedAtUtc, "1.2.3", 1L, includeSecrets), (backup.CreatedAtUtc, backup.ProductVersion, backup.ActiveVersion, backup.IncludesSecrets));
        Assert.Equal(DateTimeKind.Utc, backup.CreatedAtUtc.Kind);
        Assert.Equal(
            original.Versions.Select(v => (v.Version, v.CreatedAtUtc, v.Author, v.Comment, GatewayConfigurationJson.Serialize(v.Configuration))),
            backup.Versions.Select(v => (v.Version, v.CreatedAtUtc, v.Author, v.Comment, GatewayConfigurationJson.Serialize(v.Configuration))));
        Assert.Equal(1, backup.Active.Version);
    }

    [Fact]
    public void Other_files_are_rejected()
    {
        Assert.StartsWith("The backup file is damaged", Read(Encoding.UTF8.GetBytes("{\"Routes\": []}")).Errors.Single(), StringComparison.Ordinal);

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            zip.CreateEntry("readme.txt");
        }

        Assert.Contains("manifest.json or versions.json is missing", Read(buffer.ToArray()).Errors.Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void Inconsistent_backups_are_rejected()
    {
        var backup = Sample() with { ActiveVersion = 7 };

        Assert.Equal("The backup's active version 7 is not in the backup.", Read(Write(backup)).Errors.Single());
    }

    [Fact]
    public void Unknown_format_versions_are_rejected()
    {
        using var buffer = new MemoryStream(Write(Sample()).ToArray());
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Update, leaveOpen: true))
        {
            zip.GetEntry("manifest.json")!.Delete();
            using var writer = new StreamWriter(zip.CreateEntry("manifest.json").Open());
            writer.Write("{\"Format\": \"waf-gateway-backup\", \"FormatVersion\": 99}");
        }

        Assert.Contains("format version 99", Read(buffer.ToArray()).Errors.Single(), StringComparison.Ordinal);
    }
}
