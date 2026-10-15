using System.ComponentModel;
using System.Runtime.CompilerServices;
using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class ResidualItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public required ResidualType Type { get; init; }
    public ResidualCategory Category { get; init; } = ResidualCategory.File;
    public required string Path { get; init; }
    public string? ValueName { get; init; }
    public required ConfidenceLevel Confidence { get; init; }
    public required string Reason { get; init; }
    public long SizeInBytes { get; init; }

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

    public string FullDisplayPath => string.IsNullOrEmpty(ValueName)
        ? Path
        : $"{Path}  ➔  [{ValueName}]";

    public string DisplayIcon => Category switch
    {
        ResidualCategory.Shortcut => "Link24",
        ResidualCategory.Service => "Settings24",
        ResidualCategory.FirewallRule => "Shield24",
        ResidualCategory.ScheduledTask => "Clock24",
        ResidualCategory.MsiMetadata => "Box24",
        ResidualCategory.ShellExtension => "Apps24",
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
        ResidualCategory.MsiMetadata => "MSI 元数据",
        ResidualCategory.ShellExtension => "外壳扩展",
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
