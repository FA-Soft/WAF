using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Outcome of uploading a certificate.</summary>
/// <param name="Certificate">The stored certificate; null on failure.</param>
/// <param name="Added">False when the same certificate was already stored.</param>
/// <param name="Errors">Why it was refused, in plain language.</param>
public sealed record CertificateUploadResult(StoredCertificate? Certificate, bool Added, IReadOnlyList<string> Errors)
{
    public static CertificateUploadResult Failed(string error) => new(null, false, [error]);
}

/// <summary>
/// TLS certificates for the admin UI. Implemented by the host. Which certificate a host name uses is part of the
/// configuration (and changed through <see cref="IGatewayConfigurationService"/>); the uploaded certificates
/// themselves live in an encrypted store next to it.
/// </summary>
public interface ICertificateManager
{
    /// <summary>The certificate state of every host name of the running configuration.</summary>
    IReadOnlyList<CertificateStatus> Statuses { get; }

    /// <summary>Uploaded certificates (metadata only), newest first.</summary>
    Task<IReadOnlyList<StoredCertificate>> GetStoredAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Checks and stores a certificate: a PFX (with its password, if any), or a PEM certificate with its PEM key. The
    /// private key is encrypted before it is stored.
    /// </summary>
    Task<CertificateUploadResult> UploadAsync(byte[] certificateFile, string? password, byte[]? keyFile, AuditActor actor, CancellationToken cancellationToken);

    /// <summary>Deletes an uploaded certificate that no host name uses; returns why not otherwise.</summary>
    Task<IReadOnlyList<string>> DeleteAsync(string thumbprint, AuditActor actor, CancellationToken cancellationToken);

    /// <summary>Reloads the certificates (after an upload or a configuration change).</summary>
    Task ReloadAsync(CancellationToken cancellationToken);
}
