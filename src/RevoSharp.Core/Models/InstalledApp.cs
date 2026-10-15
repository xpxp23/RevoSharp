namespace RevoSharp.Core.Models;

public class InstalledApp
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string DisplayVersion { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public string InstallLocation { get; init; } = string.Empty;
    public string UninstallString { get; init; } = string.Empty;
    public string QuietUninstallString { get; init; } = string.Empty;
    public string DisplayIcon { get; init; } = string.Empty;
    public string InstallDate { get; init; } = string.Empty;
    public long EstimatedSizeInBytes { get; init; }
    public string Architecture { get; init; } = "x64";
    public bool Is64Bit { get; init; } = true;
    public bool HasTraceLog { get; set; }
    public string? TraceLogPath { get; set; }

    public string FormattedSize
    {
        get
        {
            if (EstimatedSizeInBytes <= 0) return "--";
            double mb = EstimatedSizeInBytes / (1024.0 * 1024.0);
            if (mb > 1024.0)
            {
                return $"{mb / 1024.0:F2} GB";
            }
            return $"{mb:F1} MB";
        }
    }
}
