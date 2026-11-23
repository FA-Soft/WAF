using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.UnitTests.Tls;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FASoft.Waf.UnitTests.Data;

/// <summary>The encrypted certificate store in config.db, and certificates in backups.</summary>
public sealed class CertificateStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly StoragePaths _paths;
    private readonly ManualTimeProvider _time = new();

    public CertificateStoreTests()
    {
        _paths = new StoragePaths(_directory, _directory);
        _paths.EnsureDataDirectory();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>Stands in for Data Protection: a reversible scramble, so stored bytes differ from the PFX.</summary>
    private sealed class ScramblingProtector : ICertificateProtector
    {
        public int Unprotected { get; private set; }

        public byte[] Protect(byte[] plaintext) => [0xEE, .. plaintext.Select(b => (byte)(b ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData)
        {
            Unprotected++;
            Assert.Equal(0xEE, protectedData[0]);
            return [.. protectedData.Skip(1).Select(b => (byte)(b ^ 0x5A))];
        }
    }

    private async Task<(CertificateStore Store, ScramblingProtector Protector)> CreateAsync()
    {
        await ConfigurationStore.Create(_paths, _time).InitializeAsync(Ct);
        var protector = new ScramblingProtector();
        return (CertificateStore.Create(_paths, protector, _time), protector);
    }

    private static ServerCertificate Read(params string[] names) =>
        CertificateFiles.Read(TestCertificates.Pfx(TestCertificates.SelfSigned(names))).Certificate!;

    [Fact]
    public async Task Certificates_are_stored_encrypted_and_loaded_with_their_key()
    {
        var (store, protector) = await CreateAsync();
        using var certificate = Read("www.example.com", "example.com");
        var pfx = certificate.ExportPfx();

        var (stored, added) = await store.AddAsync(certificate, "admin", Ct);

        Assert.True(added);
        Assert.Equal((certificate.Thumbprint, "www.example.com\nexample.com", "admin"), (stored.Thumbprint, stored.DnsNames, stored.UploadedBy));
        Assert.Equal(certificate.Leaf.NotAfter.ToUniversalTime(), stored.NotAfterUtc);

        // What is in config.db is the protector's output, never the plain PFX.
        await using (var connection = new SqliteConnection(DataServiceCollectionExtensions.ConnectionString(_paths)))
        {
            await connection.OpenAsync(Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT ProtectedPfx FROM StoredCertificates";
            var raw = (byte[])(await command.ExecuteScalarAsync(Ct))!;
            Assert.Equal(0xEE, raw[0]);
            Assert.False(raw.AsSpan().IndexOf(pfx.AsSpan(0, 64)) >= 0);
        }

        using var loaded = await store.LoadAsync(certificate.Thumbprint.ToLowerInvariant(), Ct);
        Assert.NotNull(loaded);
        Assert.True(loaded.Leaf.HasPrivateKey);
        Assert.Equal(1, protector.Unprotected);
        Assert.Null(await store.LoadAsync(new string('0', 64), Ct));
    }

    [Fact]
    public async Task The_same_certificate_is_stored_once_and_can_be_deleted()
    {
        var (store, _) = await CreateAsync();
        using var certificate = Read("www.example.com");

        await store.AddAsync(certificate, "admin", Ct);
        var (_, again) = await store.AddAsync(certificate, "someone else", Ct);

        Assert.False(again);
        Assert.Single(await store.GetAllAsync(Ct));
        Assert.True(await store.DeleteAsync(certificate.Thumbprint, Ct));
        Assert.False(await store.DeleteAsync(certificate.Thumbprint, Ct));
        Assert.Empty(await store.GetAllAsync(Ct));
    }

    [Fact]
    public async Task Backups_carry_certificates_only_with_secrets()
    {
        var (store, _) = await CreateAsync();
        using var certificate = Read("www.example.com");
        await store.AddAsync(certificate, "admin", Ct);
        var exported = await store.ExportAllAsync(Ct);
        Assert.Equal(certificate.Thumbprint, Assert.Single(exported).Thumbprint);

        static GatewayBackup Backup(bool secrets, IReadOnlyList<BackupCertificate> certificates) =>
            new(DateTime.UtcNow, "1.0.0", 1, secrets, [new BackupVersion(1, DateTime.UtcNow, "a", null, RuleBuilder.Config())]) { Certificates = certificates };

        static GatewayBackup RoundTrip(GatewayBackup backup)
        {
            using var buffer = new MemoryStream();
            BackupArchive.Write(buffer, backup);
            buffer.Position = 0;
            return BackupArchive.Read(buffer).Backup!;
        }

        var withSecrets = RoundTrip(Backup(true, exported));
        var restored = Assert.Single(withSecrets.Certificates);
        using (var fromBackup = CertificateFiles.LoadPfx(restored.Pfx))
        {
            Assert.Equal(certificate.Thumbprint, fromBackup.Thumbprint);
            Assert.True(fromBackup.Leaf.HasPrivateKey);
        }

        // Even when a caller passes certificates, a backup without secrets never contains private keys.
        Assert.Empty(RoundTrip(Backup(false, exported)).Certificates);
    }

    [Fact]
    public async Task Migration_creates_the_table()
    {
        await CreateAsync();
        var options = new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite(DataServiceCollectionExtensions.ConnectionString(_paths)).Options;
        await using var db = new ConfigDbContext(options);

        Assert.Empty(await db.StoredCertificates.ToListAsync(Ct));
        Assert.Contains(CertificateSource.Uploaded, Enum.GetValues<CertificateSource>());
    }
}
