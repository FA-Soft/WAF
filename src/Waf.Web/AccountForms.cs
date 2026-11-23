using System.ComponentModel.DataAnnotations;

namespace FASoft.Waf.Web;

/// <summary>Form model of the sign-in page.</summary>
internal sealed class LoginFormModel
{
    [Required(ErrorMessage = "Enter your user name.")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Enter your password.")]
    public string Password { get; set; } = string.Empty;

    /// <summary>The page to open after signing in.</summary>
    public string? ReturnUrl { get; set; }
}

/// <summary>Form model of the first-run page that creates the admin account.</summary>
internal sealed class SetupFormModel
{
    [Required(ErrorMessage = "Choose a user name.")]
    [StringLength(64, ErrorMessage = "Use at most 64 characters.")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Choose a password.")]
    [StringLength(256, MinimumLength = AdminIdentity.MinPasswordLength, ErrorMessage = "Use at least 12 characters.")]
    public string Password { get; set; } = string.Empty;

    [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>The one-time token from the service log; only needed from another machine.</summary>
    public string? SetupToken { get; set; }
}

/// <summary>Form model of "change password".</summary>
internal sealed class ChangePasswordFormModel
{
    [Required(ErrorMessage = "Enter your current password.")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Choose a new password.")]
    [StringLength(256, MinimumLength = AdminIdentity.MinPasswordLength, ErrorMessage = "Use at least 12 characters.")]
    public string NewPassword { get; set; } = string.Empty;

    [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

/// <summary>Form model of the 2FA code and recovery-code sign-in pages.</summary>
internal sealed class CodeFormModel
{
    [Required(ErrorMessage = "Enter the code.")]
    [StringLength(32, ErrorMessage = "That is too long for a code.")]
    public string Code { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

/// <summary>Form model of "turn on two-factor sign-in": the first code from the authenticator app.</summary>
internal sealed class EnableTwoFactorFormModel
{
    [Required(ErrorMessage = "Enter the code your authenticator app shows.")]
    [StringLength(9, ErrorMessage = "Enter the 6-digit code.")]
    public string Code { get; set; } = string.Empty;
}

/// <summary>Form model of the 2FA changes that need the password (new recovery codes, turning 2FA off).</summary>
internal sealed class ConfirmPasswordFormModel
{
    [Required(ErrorMessage = "Enter your password.")]
    public string Password { get; set; } = string.Empty;
}
