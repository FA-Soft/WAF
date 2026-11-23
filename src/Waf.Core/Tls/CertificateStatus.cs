using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Core.Tls;

/// <summary>How a host name's certificate is doing.</summary>
public enum CertificateState
{
    /// <summary>Valid, and valid for at least <see cref="CertificateStatus.WarningPeriod"/>.</summary>
    Ok,

    /// <summary>Valid, but expires within <see cref="CertificateStatus.WarningPeriod"/>.</summary>
    ExpiresSoon,

    /// <summary>Past its end date: still served, but browsers refuse it.</summary>
    Expired,

    /// <summary>Its start date is in the future.</summary>
    NotYetValid,

    /// <summary>Does not cover the host name: served, but browsers refuse it.</summary>
    WrongHost,

    /// <summary>No certificate could be loaded (missing upload, unreadable file); TLS handshakes for the host fail.</summary>
    Missing,

    /// <summary>Let's Encrypt has not issued it yet.</summary>
    Pending,
}

/// <summary>The certificate state of one host name of the active configuration.</summary>
public sealed record CertificateStatus(
    string HostName,
    CertificateSource Source,
    CertificateState State,
    string? Subject,
    string? Thumbprint,
    DateTime? NotAfterUtc,
    string? Problem)
{
    /// <summary>Certificates expiring within this period are reported.</summary>
    public static readonly TimeSpan WarningPeriod = TimeSpan.FromDays(30);

    /// <summary>True when the state needs the administrator's attention.</summary>
    public bool NeedsAttention => State is not (CertificateState.Ok or CertificateState.Pending);

    /// <summary>Whole days until the end date (negative when expired); null without a certificate.</summary>
    public int? DaysLeft(DateTime nowUtc) => NotAfterUtc is { } end ? (int)Math.Floor((end - nowUtc).TotalDays) : null;
}
