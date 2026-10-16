using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace RevoSharp.Core.Models;

public class AutostartEntry : INotifyPropertyChanged
{
    private bool _isEnabled = true;

    public required string Name { get; init; }
    public required string Command { get; init; }
    public required string ExecutablePath { get; init; }
    public required string LocationType { get; init; }
    public required string FullLocation { get; init; }
    public string RegistryHiveName { get; init; } = string.Empty;
    public string RegistrySubKey { get; init; } = string.Empty;
    public bool Is64BitRegistryView { get; init; } = true;
    public bool IsStartupShortcut { get; init; }
    public bool IsScheduledTask { get; init; }
    public string ScheduledTaskPath { get; init; } = string.Empty;
    public bool FileExists { get; init; }
    public string Publisher { get; init; } = string.Empty;

    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (_isEnabled != value)
            {
                _isEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
                OnPropertyChanged(nameof(ToggleActionText));
            }
        }
    }

    public string StatusDisplay => IsEnabled ? "已启用" : "已禁用";
    public string ToggleActionText => IsEnabled ? "禁用自启" : "恢复启用";

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
