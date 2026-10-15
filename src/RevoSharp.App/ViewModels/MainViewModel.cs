using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

    [RelayCommand]
    public async Task LoadAppsAsync()
    {
        IsLoading = true;
        StatusText = "正在扫描系统已安装软件...";
        try
        {
            _allApps = await _appLocator.GetInstalledAppsAsync();
            ApplyFilter();
            StatusText = $"共发现 {_allApps.Count} 款已安装程序";
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
                a.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase));
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
            StatusText = $"未检测到 {SelectedApp.DisplayName} 的物理安装目录（可能为免安装工具或注册表未记录有效路径）";
        }
    }

    public UninstallerRunner UninstallerRunner => _uninstallerRunner;
    public ResidualScanner ResidualScanner => _residualScanner;

    public async Task<List<ResidualItem>> ScanResidualsAsync(InstalledApp app)
    {
        StatusText = $"正在深度扫描 {app.DisplayName} 注册表与文件残留...";
        var residuals = await _residualScanner.ScanResidualsAsync(app);
        StatusText = $"残留扫描完成，发现 {residuals.Count} 项残留";
        return residuals;
    }
}
