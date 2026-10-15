using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly AppLocator _appLocator = new();
    private readonly UninstallerRunner _uninstallerRunner = new();
    private readonly ResidualScanner _residualScanner = new();

    private List<InstalledApp> _allApps = [];

    [ObservableProperty]
    private ObservableCollection<InstalledApp> _apps = [];

    [ObservableProperty]
    private InstalledApp? _selectedApp;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private bool _includeWindowsApps;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _statusText = "就绪";

    public MainViewModel()
    {
        _ = LoadAppsAsync();
    }

    partial void OnSearchTextChanged(string value)
    {
        ApplyFilter();
    }

    partial void OnIncludeWindowsAppsChanged(bool value)
    {
        _ = LoadAppsAsync();
    }

    [RelayCommand]
    public async Task LoadAppsAsync()
    {
        IsLoading = true;
        StatusText = "正在扫描系统已安装软件与关联监控日志...";
        try
        {
            string? previousSelectedId = SelectedApp?.Id;
            _allApps = await _appLocator.GetInstalledAppsAsync(IncludeWindowsApps);
            ApplyFilter();

            if (previousSelectedId != null)
            {
                SelectedApp = Apps.FirstOrDefault(a => a.Id == previousSelectedId);
            }

            int tracedCount = _allApps.Count(a => a.HasTraceLog);
            StatusText = tracedCount > 0
                ? $"共发现 {_allApps.Count} 款程序（其中 {tracedCount} 款已关联 ETW 安装监控日志）"
                : $"共发现 {_allApps.Count} 款已安装程序";
        }
        catch (Exception ex)
        {
            StatusText = $"加载失败: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void ApplyFilter()
    {
        if (string.IsNullOrWhiteSpace(SearchText))
        {
            Apps = new ObservableCollection<InstalledApp>(_allApps);
        }
        else
        {
            string query = SearchText.Trim();
            var filtered = _allApps.Where(a =>
                a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                a.DisplayVersion.Contains(query, StringComparison.OrdinalIgnoreCase));
            Apps = new ObservableCollection<InstalledApp>(filtered);
        }
    }

    [RelayCommand]
    public void OpenLocation()
    {
        if (SelectedApp == null) return;

        string targetDir = AppLocator.DeduceInstallLocation(
            SelectedApp.InstallLocation,
            SelectedApp.DisplayIcon,
            SelectedApp.UninstallString,
            SelectedApp.QuietUninstallString);

        if (!string.IsNullOrWhiteSpace(targetDir) && Directory.Exists(targetDir))
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{targetDir}\"",
                    UseShellExecute = true
                });
                StatusText = $"已打开目录: {targetDir}";
            }
            catch (Exception ex)
            {
                StatusText = $"打开目录失败: {ex.Message}";
            }
        }
        else
        {
            StatusText = $"未检测到【{SelectedApp.DisplayName}】的独立物理安装目录";
        }
    }

    [RelayCommand]
    public void OpenRegistryKey()
    {
        if (SelectedApp == null || string.IsNullOrWhiteSpace(SelectedApp.RegistryKeyPath)) return;

        try
        {
            int slash = SelectedApp.RegistryKeyPath.IndexOf('\\');
            if (slash <= 0) return;

            string hiveFull = SelectedApp.RegistryKeyPath.Substring(0, slash).ToUpperInvariant() switch
            {
                "HKLM" => "HKEY_LOCAL_MACHINE",
                "HKCU" => "HKEY_CURRENT_USER",
                _ => SelectedApp.RegistryKeyPath.Substring(0, slash)
            };

            string fullRegPath = $@"Computer\{hiveFull}{SelectedApp.RegistryKeyPath.Substring(slash)}";
            using var regeditKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
            regeditKey?.SetValue("LastKey", fullRegPath);

            Process.Start(new ProcessStartInfo
            {
                FileName = "regedit.exe",
                Arguments = "-m",
                UseShellExecute = true
            });
            StatusText = $"已在注册表编辑器中定位: {SelectedApp.RegistryKeyPath}";
        }
        catch (Exception ex)
        {
            StatusText = $"打开注册表失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void CopyUninstallString()
    {
        if (SelectedApp == null || string.IsNullOrWhiteSpace(SelectedApp.UninstallString)) return;
        try
        {
            Clipboard.SetText(SelectedApp.UninstallString);
            StatusText = $"已复制卸载命令: {SelectedApp.UninstallString}";
        }
        catch { }
    }

    public UninstallerRunner UninstallerRunner => _uninstallerRunner;
    public ResidualScanner ResidualScanner => _residualScanner;
}
