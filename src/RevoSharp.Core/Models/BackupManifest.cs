using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace RevoSharp.Core.Models;

public class BackupManifest : INotifyPropertyChanged
{
    private bool _isRestored;

    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public required string AppName { get; set; }
    public string BackupCategory { get; set; } = "卸载残留清理";
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public string ManifestPath { get; set; } = string.Empty;
    public List<string> RegBackupFiles { get; set; } = [];
    public List<string> RecycledFilePaths { get; set; } = [];
    public List<string> RebootScheduledPaths { get; set; } = [];
    public List<string> TaskXmlBackupFiles { get; set; } = [];

    /// <summary>
    /// Maps each backed-up .reg file path to whether it belongs to the 64-bit registry view (true) or 32-bit view (false).
    /// Ensures reg.exe import uses the exact /reg:64 or /reg:32 flag during restoration.
    /// </summary>
    public Dictionary<string, bool> RegBackupViewMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps each backed-up Scheduled Task XML file path to its original Task Scheduler path (e.g. "\Vendor\TaskName").
    /// </summary>
    public Dictionary<string, string> TaskScheduleMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps original file path (e.g. Startup .lnk shortcut) to a direct backup copy inside BackupDir for 1-click restoration.
    /// </summary>
    public Dictionary<string, string> FileBackupCopyMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps "Machine::Path" or "User::Path" to the full original PATH environment variable value prior to dead-link removal.
    /// </summary>
    public Dictionary<string, string> EnvironmentPathBackupMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Human-readable list of backed-up targets (registry paths, file paths, task names, environment paths) for inspection in the Backup Manager UI.
    /// </summary>
    public List<string> BackedUpTargetDescriptions { get; set; } = [];

    public bool SystemRestorePointCreated { get; set; }

    public bool IsRestored
    {
        get => _isRestored;
        set
        {
            if (_isRestored != value)
            {
                _isRestored = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SummaryText));
            }
        }
    }

    public int TotalFileCount =>
        RecycledFilePaths
            .Concat(FileBackupCopyMap.Keys)
            .Concat(RebootScheduledPaths)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

    public int TotalBackedUpItems =>
        RegBackupFiles.Count +
        TotalFileCount +
        TaskXmlBackupFiles.Count +
        EnvironmentPathBackupMap.Count;

    public string CreatedTimeDisplay => CreatedTime.ToString("yyyy-MM-dd HH:mm:ss");

    public string SummaryText =>
        (IsRestored ? "[已还原] " : string.Empty) +
        $"[{BackupCategory}] 注册表备份: {RegBackupFiles.Count} 份 | 文件/目录: {TotalFileCount} 项" +
        (TaskXmlBackupFiles.Count > 0 ? $" | 计划任务: {TaskXmlBackupFiles.Count} 项" : "") +
        (EnvironmentPathBackupMap.Count > 0 ? $" | 环境变量: {EnvironmentPathBackupMap.Count} 项" : "") +
        (RebootScheduledPaths.Count > 0 ? $" | 重启延迟删除: {RebootScheduledPaths.Count} 项" : "") +
        (SystemRestorePointCreated ? " | 已建系统还原点" : "");

    public string DetailsTooltipText => BackedUpTargetDescriptions.Count > 0
        ? string.Join(Environment.NewLine, BackedUpTargetDescriptions.Take(30)) +
          (BackedUpTargetDescriptions.Count > 30 ? $"{Environment.NewLine}... 共 {BackedUpTargetDescriptions.Count} 项" : "")
        : SummaryText;

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
