using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace RevoSharp.Core.Models;

public class InstalledApp : INotifyPropertyChanged
{
    private long _estimatedSizeInBytes;
    private bool _hasTraceLog;
    private string? _traceLogPath;
    private bool _isSizeCalculating;

    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string DisplayVersion { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public string InstallLocation { get; init; } = string.Empty;
    public string UninstallString { get; init; } = string.Empty;
    public string QuietUninstallString { get; init; } = string.Empty;
    public string DisplayIcon { get; init; } = string.Empty;
    public string InstallDate { get; init; } = string.Empty;
    public string Architecture { get; init; } = "64 位";
    public bool Is64Bit { get; init; } = true;
    public string RegistryKeyPath { get; init; } = string.Empty;
    public string UninstallKeyName { get; init; } = string.Empty;
    public bool IsWindowsApp { get; init; }
    public bool IsProtectedSingleFile { get; init; }
    public bool IsRecentlyInstalled { get; init; }

    public long EstimatedSizeInBytes
    {
        get => _estimatedSizeInBytes;
        set
        {
            if (_estimatedSizeInBytes != value)
            {
                _estimatedSizeInBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedSize));
            }
        }
    }

    public bool IsSizeCalculating
    {
        get => _isSizeCalculating;
        set
        {
            if (_isSizeCalculating != value)
            {
                _isSizeCalculating = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedSize));
            }
        }
    }

    public bool HasTraceLog
    {
        get => _hasTraceLog;
        set
        {
            if (_hasTraceLog != value)
            {
                _hasTraceLog = value;
                OnPropertyChanged();
            }
        }
    }

    public string? TraceLogPath
    {
        get => _traceLogPath;
        set
        {
            if (_traceLogPath != value)
            {
                _traceLogPath = value;
                OnPropertyChanged();
            }
        }
    }

    public string PublisherDisplay => string.IsNullOrWhiteSpace(Publisher) ? "未知发行商" : Publisher;
    public string VersionDisplay => string.IsNullOrWhiteSpace(DisplayVersion) ? "--" : DisplayVersion;
    public string InstallDateDisplay => string.IsNullOrWhiteSpace(InstallDate) ? "--" : InstallDate;
    public string InstallLocationDisplay => string.IsNullOrWhiteSpace(InstallLocation) ? "未记录独立目录 (系统路径或注册表项)" : InstallLocation;

    public string FormattedSize
    {
        get
        {
            if (_estimatedSizeInBytes <= 0)
            {
                return _isSizeCalculating ? "计算中..." : "--";
            }
            double mb = _estimatedSizeInBytes / (1024.0 * 1024.0);
            if (mb >= 1024.0)
            {
                return $"{mb / 1024.0:F2} GB";
            }
            if (mb >= 1.0)
            {
                return $"{mb:F1} MB";
            }
            double kb = _estimatedSizeInBytes / 1024.0;
            return $"{kb:F0} KB";
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
