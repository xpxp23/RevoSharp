namespace RevoSharp.Core.Models;

public class HunterTargetInfo
{
    public IntPtr WindowHandle { get; set; }
    public string WindowTitle { get; set; } = string.Empty;
    public string WindowClassName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string DirectoryPath { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string ProductVersion { get; set; } = string.Empty;
    public string Architecture { get; set; } = "x64";
    public bool Is64Bit { get; set; } = true;
    public bool IsSystemCritical { get; set; }
    public string SystemProtectionReason { get; set; } = string.Empty;

    public bool IsRegisteredApp { get; set; }
    public InstalledApp? MatchedApp { get; set; }

    public bool HasAutostartEntry { get; set; }
    public List<string> AutostartDescriptions { get; set; } = new();

    public InstalledApp EffectiveApp { get; set; } = null!;
}
