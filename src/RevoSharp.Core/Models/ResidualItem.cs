using System.ComponentModel;
using System.Runtime.CompilerServices;
using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

/// <summary>
/// Coordinates batch tree node check-state cascades so checking/unchecking a parent folder or registry key
/// with hundreds of children only triggers a single ViewModel selection recalculation instead of an O(N^2) event storm.
/// </summary>
public static class TreeSelectionSyncScope
{
    [ThreadStatic]
    private static int _suppressDepth;

    public static bool IsBatchUpdating => _suppressDepth > 0;

    public static event Action? BatchUpdateCompleted;

    public static IDisposable BeginBatch()
    {
        _suppressDepth++;
        return new ScopeToken();
    }

    private sealed class ScopeToken : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (--_suppressDepth <= 0)
            {
                _suppressDepth = 0;
                BatchUpdateCompleted?.Invoke();
            }
        }
    }
}

public class ResidualItem : INotifyPropertyChanged
{
    private bool _isSelected;
    private bool _isLocked;
    private string _lockedBySummary = string.Empty;

    public required ResidualType Type { get; init; }
    public ResidualCategory Category { get; set; } = ResidualCategory.File;
    public required string Path { get; init; }
    public string? ValueName { get; set; }
    public string? ValuePreview { get; set; }
    public string? ServiceName { get; set; }
    public string? TaskSchedulerName { get; set; }
    public bool? Is64BitRegistryView { get; set; }
    public string? EnvironmentVariableName { get; set; }
    public bool IsSystemEnvironmentVariable { get; set; }
    public string? PathSegmentToRemove { get; set; }
    public string? DriverPublishedInfName { get; set; }
    public string? DigitalSignatureInfo { get; set; }
    public ConfidenceLevel Confidence { get; set; }
    public string Reason { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public string SourceAppName { get; set; } = string.Empty;
    public List<LockingProcessInfo> LockingProcesses { get; set; } = [];

    /// <summary>
    /// True ONLY when this parent Directory/RegistryKey was automatically deselected because a child item under it
    /// was unchecked while other children remain checked. Prevents whole-folder deletion when the user explicitly
    /// unchecked the parent directory itself!
    /// </summary>
    public bool IsDemotedByChildUncheck { get; set; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                if (value)
                {
                    IsDemotedByChildUncheck = false;
                }
                OnPropertyChanged();
            }
        }
    }

    public bool IsLocked
    {
        get => _isLocked;
        set
        {
            if (_isLocked != value)
            {
                _isLocked = value;
                OnPropertyChanged();
            }
        }
    }

    public string LockedBySummary
    {
        get => _lockedBySummary;
        set
        {
            if (_lockedBySummary != value)
            {
                _lockedBySummary = value;
                OnPropertyChanged();
            }
        }
    }

    public void UpdateLockingProcesses(IReadOnlyList<LockingProcessInfo> processes)
    {
        LockingProcesses = [.. processes];
        IsLocked = processes.Count > 0;
        LockedBySummary = processes.Count > 0
            ? $"占用: {string.Join(", ", processes.Select(p => $"{p.ProcessName}({p.ProcessId})").Take(2))}" +
              (processes.Count > 2 ? $" 等{processes.Count}个" : string.Empty)
            : string.Empty;
    }

    public bool HasSourceAppName => !string.IsNullOrWhiteSpace(SourceAppName);
    public bool HasValueName => !string.IsNullOrEmpty(ValueName);
    public bool HasValuePreview => !string.IsNullOrEmpty(ValuePreview);
    public bool HasDigitalSignature => !string.IsNullOrWhiteSpace(DigitalSignatureInfo);

    /// <summary>
    /// Parent directory or registry key prefix (with trailing slash) for muted secondary syntax highlighting.
    /// </summary>
    public string PathPrefixDisplay
    {
        get
        {
            int lastSlash = Path.LastIndexOf('\\');
            return lastSlash >= 0 && lastSlash < Path.Length - 1
                ? Path.Substring(0, lastSlash + 1)
                : string.Empty;
        }
    }

    /// <summary>
    /// Leaf folder, file, or registry key name for primary bold syntax highlighting.
    /// </summary>
    public string PathLeafDisplay
    {
        get
        {
            int lastSlash = Path.LastIndexOf('\\');
            return lastSlash >= 0 && lastSlash < Path.Length - 1
                ? Path.Substring(lastSlash + 1)
                : Path;
        }
    }

    public string ValueBadgeText => string.IsNullOrEmpty(ValueName) ? string.Empty : $"[{ValueName}]";

    public string ValuePreviewText => string.IsNullOrEmpty(ValuePreview) ? string.Empty : $"= {ValuePreview}";

    public string FullDisplayPath
    {
        get
        {
            if (string.IsNullOrEmpty(ValueName))
                return Path;
            return string.IsNullOrEmpty(ValuePreview)
                ? $"{Path}  ➔  [{ValueName}]"
                : $"{Path}  ➔  [{ValueName}] = {ValuePreview}";
        }
    }

    public string DisplayIcon => Category switch
    {
        ResidualCategory.Shortcut => "Link24",
        ResidualCategory.Service => "Settings24",
        ResidualCategory.FirewallRule => "Shield24",
        ResidualCategory.ScheduledTask => "Clock24",
        ResidualCategory.MsiMetadata => "Box24",
        ResidualCategory.ShellExtension => "Apps24",
        ResidualCategory.EnvironmentPath => "Code24",
        ResidualCategory.BrowserExtension => "GlobeSearch24",
        ResidualCategory.UrlProtocol => "Link24",
        ResidualCategory.DriverPackage => "Wrench24",
        ResidualCategory.NtfsMftMatch => "HardDrive24",
        _ => Type switch
        {
            ResidualType.Directory => "Folder24",
            ResidualType.File => "Document24",
            ResidualType.RegistryKey => "Code24",
            ResidualType.RegistryValue => "Tag24",
            _ => "QuestionCircle24"
        }
    };

    public string TypeDisplay => Category switch
    {
        ResidualCategory.Shortcut => "快捷方式",
        ResidualCategory.Service => "系统服务",
        ResidualCategory.FirewallRule => "防火墙规则",
        ResidualCategory.ScheduledTask => "计划任务",
        ResidualCategory.MsiMetadata => "MSI 组件",
        ResidualCategory.ShellExtension => "外壳扩展",
        ResidualCategory.EnvironmentPath => "环境变量",
        ResidualCategory.BrowserExtension => "浏览器扩展",
        ResidualCategory.UrlProtocol => "协议处理器",
        ResidualCategory.DriverPackage => "驱动组件",
        ResidualCategory.NtfsMftMatch => "MFT 全盘检出",
        _ => Type switch
        {
            ResidualType.Directory => "文件夹",
            ResidualType.File => "文件",
            ResidualType.RegistryKey => "注册表项",
            ResidualType.RegistryValue => "注册表值",
            _ => "未知"
        }
    };

    public string ConfidenceDisplay => Confidence switch
    {
        ConfidenceLevel.High => "高 (推荐清除)",
        ConfidenceLevel.Medium => "中 (建议核对)",
        ConfidenceLevel.Low => "低 (谨慎清除)",
        _ => "未知"
    };

    public bool IsHighConfidence => Confidence == ConfidenceLevel.High;
    public bool IsMediumConfidence => Confidence == ConfidenceLevel.Medium;
    public bool IsLowConfidence => Confidence == ConfidenceLevel.Low;

    public string FormattedSize
    {
        get
        {
            if (Type is ResidualType.RegistryKey or ResidualType.RegistryValue || SizeInBytes <= 0)
                return "--";
            if (SizeInBytes >= 1024L * 1024 * 1024)
                return $"{SizeInBytes / (1024.0 * 1024 * 1024):F2} GB";
            if (SizeInBytes >= 1024L * 1024)
                return $"{SizeInBytes / (1024.0 * 1024):F1} MB";
            if (SizeInBytes >= 1024L)
                return $"{SizeInBytes / 1024.0:F1} KB";
            return $"{SizeInBytes} B";
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
