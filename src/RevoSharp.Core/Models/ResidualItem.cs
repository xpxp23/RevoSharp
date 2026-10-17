using System.ComponentModel;
using System.Runtime.CompilerServices;
using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class ResidualItem : INotifyPropertyChanged
{
    private bool _isSelected;
    private bool _isLocked;
    private string _lockedBySummary = string.Empty;

    public required ResidualType Type { get; init; }
    public ResidualCategory Category { get; init; } = ResidualCategory.File;
    public required string Path { get; init; }
    public string? ValueName { get; init; }
    public string? ValuePreview { get; init; }
    public string? TaskSchedulerName { get; init; }
    public bool? Is64BitRegistryView { get; init; }
    public string? EnvironmentVariableName { get; init; }
    public bool IsSystemEnvironmentVariable { get; init; }
    public string? PathSegmentToRemove { get; init; }
    public string? DriverPublishedInfName { get; init; }
    public required ConfidenceLevel Confidence { get; init; }
    public required string Reason { get; init; }
    public long SizeInBytes { get; init; }
    public string SourceAppName { get; set; } = string.Empty;
    public List<LockingProcessInfo> LockingProcesses { get; set; } = [];

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
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
        ResidualCategory.DriverPackage => "Wrench24",
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
        ResidualCategory.DriverPackage => "驱动组件",
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
