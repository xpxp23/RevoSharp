using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class AppSettings
{
    public string ThemeMode { get; set; } = "Dark";
    public ScanMode DefaultScanMode { get; set; } = ScanMode.Moderate;
    public bool IncludeWindowsApps { get; set; }
    public bool IsInspectorOpen { get; set; } = true;
    public bool BlockUninstallSurveyWebpages { get; set; } = true;
    public bool EnableNtfsMftDeepScan { get; set; } = true;
    public bool EnableAuthenticodeGuard { get; set; } = true;
    public bool CreateRestorePointByDefault { get; set; }
    public bool ScheduleLockedOnReboot { get; set; } = true;
    public double WindowWidth { get; set; } = 1280;
    public double WindowHeight { get; set; } = 800;

    public List<string> WhitelistedPaths { get; set; } = [];

    public List<string> WhitelistedPublishers { get; set; } =
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "NVIDIA Corporation",
        "Intel Corporation",
        "Advanced Micro Devices, Inc.",
        "Realtek Semiconductor Corp.",
        "Apple Inc."
    ];
}
