using System.Text;
using QRCoder;

namespace Waf.Web;

/// <summary>What the 2FA setup page shows to add the account to an authenticator app.</summary>
public static class Authenticator
{
    /// <summary>The key in groups of four, lower case, easier to type.</summary>
    public static string FormatKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var result = new StringBuilder();
        for (var i = 0; i < key.Length; i += 4)
        {
            if (i > 0)
            {
                result.Append(' ');
            }

            result.Append(key.AsSpan(i, Math.Min(4, key.Length - i)));
        }

        return result.ToString().ToLowerInvariant();
    }

    /// <summary>The <c>otpauth://</c> link that authenticator apps read from the QR code (TOTP, SHA-1, 6 digits, 30 s).</summary>
    public static Uri SetupUri(string userName, string key)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(key);

        var issuer = Uri.EscapeDataString(AdminIdentity.AuthenticatorIssuer);
        return new Uri($"otpauth://totp/{issuer}:{Uri.EscapeDataString(userName)}?secret={key}&issuer={issuer}&digits=6");
    }

    /// <summary>The link as a QR code, as a <c>data:</c> PNG (allowed by the admin UI's Content-Security-Policy).</summary>
    public static string QrCodeDataUri(Uri setupUri)
    {
        ArgumentNullException.ThrowIfNull(setupUri);

        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(setupUri.AbsoluteUri, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(5);
        return "data:image/png;base64," + Convert.ToBase64String(png);
    }
}
