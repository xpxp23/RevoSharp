using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly AppLocator _appLocator = new();
    private readonly UninstallerRunner _uninstallerRunner = new();
    private readonly ResidualScanner _residualScanner = new();
    private CancellationTokenSource? _sizeCalculationCts;

    private List<InstalledApp> _allApps = [];

    /// <summary>
    /// Full unfiltered list of installed applications, used by Hunter Mode so search text never blinds target matching.
    /// </summary>
    public IReadOnlyList<InstalledApp> AllApps => _allApps;

    [ObservableProperty]
    private ObservableCollection<InstalledApp> _apps = [];

    [ObservableProperty]
    private InstalledApp? _selectedApp;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string _selectedCategoryFilter = "全部";

    [ObservableProperty]
    private bool _includeWindowsApps;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _statusText = "就绪";

    public int TotalAppCount => _allApps.Count;
    public int RecentAppCount => _allApps.Count(a => a.IsRecentlyInstalled);
    public int TracedAppCount => _allApps.Count(a => a.HasTraceLog);
    public int StoreAppCount => _allApps.Count(a => a.IsWindowsApp);

    public MainViewModel()
    {
        _ = LoadAppsAsync();
    }

    partial void OnSearchTextChanged(string value)
    {
        ApplyFilter();
    }

    partial void OnSelectedCategoryFilterChanged(string value)
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
        _sizeCalculationCts?.Cancel();
        _sizeCalculationCts?.Dispose();
        _sizeCalculationCts = new CancellationTokenSource();
        var token = _sizeCalculationCts.Token;

        IsLoading = true;
        StatusText = "正在扫描系统已安装软件与关联监控日志...";
        try
        {
            string? previousSelectedId = SelectedApp?.Id;
            _allApps = await _appLocator.GetInstalledAppsAsync(IncludeWindowsApps);
            NotifyCategoryCounts();
            ApplyFilter();

            if (previousSelectedId != null)
            {
                SelectedApp = Apps.FirstOrDefault(a => a.Id == previousSelectedId);
            }

            int tracedCount = _allApps.Count(a => a.HasTraceLog);
            int recentCount = _allApps.Count(a => a.IsRecentlyInstalled);
            StatusText = $"共发现 {_allApps.Count} 款程序（近期新装 {recentCount} 款 | 已关联监控日志 {tracedCount} 款）";

            // Asynchronously populate missing folder sizes in the background without blocking the UI
            _ = _appLocator.PopulateMissingSizesAsync(_allApps, token);
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

    private void NotifyCategoryCounts()
    {
        OnPropertyChanged(nameof(TotalAppCount));
        OnPropertyChanged(nameof(RecentAppCount));
        OnPropertyChanged(nameof(TracedAppCount));
        OnPropertyChanged(nameof(StoreAppCount));
    }

    private void ApplyFilter()
    {
        IEnumerable<InstalledApp> query = _allApps;

        if (SelectedCategoryFilter == "近期新装")
        {
            query = query.Where(a => a.IsRecentlyInstalled);
        }
        else if (SelectedCategoryFilter == "已追踪")
        {
            query = query.Where(a => a.HasTraceLog);
        }
        else if (SelectedCategoryFilter == "商店应用")
        {
            query = query.Where(a => a.IsWindowsApp);
        }
        else if (SelectedCategoryFilter == "桌面软件")
        {
            query = query.Where(a => !a.IsWindowsApp);
        }

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string keyword = SearchText.Trim();
            query = query.Where(a =>
                a.DisplayName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                a.DisplayVersion.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                a.InstallLocation.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        Apps = new ObservableCollection<InstalledApp>(query);
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
            RegistryBackup.OpenInRegEdit(SelectedApp.RegistryKeyPath);
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

    [RelayCommand]
    public void SearchOnlineInfo()
    {
        if (SelectedApp == null) return;
        try
        {
            string q = Uri.EscapeDataString($"{SelectedApp.DisplayName} {SelectedApp.Publisher} software uninstall info");
            Process.Start(new ProcessStartInfo
            {
                FileName = $"https://www.bing.com/search?q={q}",
                UseShellExecute = true
            });
            StatusText = $"已在浏览器中搜索【{SelectedApp.DisplayName}】相关信息";
        }
        catch { }
    }

    public UninstallerRunner UninstallerRunner => _uninstallerRunner;
    public ResidualScanner ResidualScanner => _residualScanner;
}
