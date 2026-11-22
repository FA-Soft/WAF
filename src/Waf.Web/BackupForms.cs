using System.ComponentModel.DataAnnotations;
using Waf.Core.Configuration;

namespace Waf.Web;

/// <summary>Form model of the backup restore form (the file itself is read from the request).</summary>
internal sealed class RestoreFormModel
{
    // Checkbox: an unticked box is not posted, so the default must be false.
    public bool Confirm { get; set; }
}

/// <summary>Form model of the import page (an uploaded file is read from the request into <see cref="Json"/>).</summary>
internal sealed class ImportFormModel
{
    /// <summary>"preview" or "apply"; set by the button that was pressed.</summary>
    public string? Command { get; set; }

    /// <summary>The <see cref="ImportPreview.Tag"/> the user saw; importing only works when it is still the same.</summary>
    public string? PreviewTag { get; set; }

    public string? Json { get; set; }
}

/// <summary>Form model of the "restore this version" button.</summary>
internal sealed class RestoreVersionFormModel
{
    /// <summary>The version that was active when the page was shown.</summary>
    public long BaseVersion { get; set; }
}

/// <summary>Form model of the log retention settings.</summary>
internal sealed class LogRetentionFormModel
{
    public long BaseVersion { get; set; }

    [Range(0, LogRetentionSettings.MaxMaxAgeDays, ErrorMessage = "Use 0 (no age limit) up to 3650 days.")]
    public int MaxAgeDays { get; set; }

    [Range(LogRetentionSettings.MinDatabaseSizeMb, LogRetentionSettings.MaxDatabaseSizeLimitMb, ErrorMessage = "Use at least 10 MB.")]
    public int MaxDatabaseSizeMb { get; set; }
}
