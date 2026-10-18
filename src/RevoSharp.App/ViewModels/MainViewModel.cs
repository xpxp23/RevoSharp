using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RevoSharp.App.Converters;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
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
    private readonly DispatcherTimer _searchDebounceTimer;
    private CancellationTokenSource? _sizeCalculationCts;

    private List<InstalledApp> _allApps = [];

    /// <summary>
    /// Full unfiltered list of installed applications, used by Hunter Mode and Sibling Protection so search text never blinds target matching.
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
    private bool _blockUninstallSurveyWebpages = true;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private bool _isInspectorOpen = true;

    [ObservableProperty]
    private string _statusText = "就绪";

    [ObservableProperty]
    private int _multiSelectedCount;

    [ObservableProperty]
    private string _multiSelectionSummaryText = string.Empty;

    [ObservableProperty]
    private string _currentThemeButtonText = $"主题: {App.CurrentThemeDisplay}";

    public bool IsMultiSelectionActive => MultiSelectedCount >= 2;

    public int TotalAppCount => _allApps.Count;
    public int RecentAppCount => _allApps.Count(a => a.IsRecentlyInstalled);
    public int TracedAppCount => _allApps.Count(a => a.HasTraceLog);
    public int DesktopAppCount => _allApps.Count(a => !a.IsWindowsApp);
    public int StoreAppCount => _allApps.Count(a => a.IsWindowsApp);

    public MainViewModel()
    {
        var cfg = SettingsSerializer.Current;
        _includeWindowsApps = cfg.IncludeWindowsApps;
        _isInspectorOpen = cfg.IsInspectorOpen;
        _blockUninstallSurveyWebpages = cfg.BlockUninstallSurveyWebpages;
        _currentThemeButtonText = $"主题: {App.CurrentThemeDisplay}";

        _searchDebounceTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(120)
        };
        _searchDebounceTimer.Tick += (_, _) =>
        {
            _searchDebounceTimer.Stop();
            ApplyFilter();
        };

        _ = LoadAppsAsync();
    }

    partial void OnSearchTextChanged(string value)
    {
        _searchDebounceTimer.Stop();
        _searchDebounceTimer.Start();
    }

    partial void OnSelectedCategoryFilterChanged(string value)
    {
        _searchDebounceTimer.Stop();
        ApplyFilter();
    }

    partial void OnIncludeWindowsAppsChanged(bool value)
    {
        SettingsSerializer.Current.IncludeWindowsApps = value;
        SettingsSerializer.Save();
        _ = LoadAppsAsync();
    }

    partial void OnBlockUninstallSurveyWebpagesChanged(bool value)
    {
        SettingsSerializer.Current.BlockUninstallSurveyWebpages = value;
        SettingsSerializer.Save();
        StatusText = value
            ? "已开启：卸载期间将自动拦截原厂卸载程序拉起的浏览器调查问卷弹窗"
            : "已关闭卸载调查问卷网页拦截";
    }

    partial void OnIsInspectorOpenChanged(bool value)
    {
        SettingsSerializer.Current.IsInspectorOpen = value;
        SettingsSerializer.Save();
    }

    partial void OnMultiSelectedCountChanged(int value)
    {
        OnPropertyChanged(nameof(IsMultiSelectionActive));
    }

    public void SyncSettingsState()
    {
        var cfg = SettingsSerializer.Current;
        if (BlockUninstallSurveyWebpages != cfg.BlockUninstallSurveyWebpages)
        {
            BlockUninstallSurveyWebpages = cfg.BlockUninstallSurveyWebpages;
        }
        CurrentThemeButtonText = $"主题: {App.CurrentThemeDisplay}";
    }

    public void UpdateMultiSelection(IReadOnlyCollection<InstalledApp> selectedApps)
    {
        MultiSelectedCount = selectedApps.Count;
        if (selectedApps.Count >= 2)
        {
            long totalBytes = selectedApps.Sum(a => Math.Max(0, a.EstimatedSizeInBytes));
            string sizeStr = totalBytes > 0 ? $" · 预计占用 {FormatBytes(totalBytes)}" : string.Empty;
            MultiSelectionSummaryText = $"已批量选中 {selectedApps.Count} 款软件{sizeStr}";
        }
        else
        {
            MultiSelectionSummaryText = string.Empty;
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        if (bytes >= 1024L * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        if (bytes >= 1024L) return $"{bytes / 1024.0:F0} KB";
        return $"{bytes} B";
    }

    [RelayCommand]
    public void CycleTheme()
    {
        string modeName = App.CycleThemeMode();
        CurrentThemeButtonText = $"主题: {modeName}";
        StatusText = $"已切换界面主题模式为：{modeName}（已保存至本地配置）";
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

            // Hydrate already-cached icons synchronously (<1ms) so refreshing never causes icon flicker!
            AppIconConverter.HydrateCachedIconsImmediate(_allApps);

            NotifyCategoryCounts();
            ApplyFilter();

            if (previousSelectedId != null)
            {
                SelectedApp = Apps.FirstOrDefault(a => a.Id == previousSelectedId);
            }
            SelectedApp ??= Apps.FirstOrDefault();

            int tracedCount = _allApps.Count(a => a.HasTraceLog);
            int recentCount = _allApps.Count(a => a.IsRecentlyInstalled);
            StatusText = $"共发现 {_allApps.Count} 款程序（近期新装 {recentCount} 款 · 已关联监控日志 {tracedCount} 款）";

            // Preload remaining app icons and missing folder sizes in background workers with batched UI thread dispatching
            AppIconConverter.PreloadIconsInBackground(
                _allApps,
                token,
                update => Application.Current?.Dispatcher.InvokeAsync(update));

            _ = _appLocator.PopulateMissingSizesAsync(
                _allApps,
                token,
                update => Application.Current?.Dispatcher.InvokeAsync(update));
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
        OnPropertyChanged(nameof(DesktopAppCount));
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
    public void ToggleInspector()
    {
        IsInspectorOpen = !IsInspectorOpen;
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
    public void CopyInstallLocation()
    {
        if (SelectedApp == null || string.IsNullOrWhiteSpace(SelectedApp.InstallLocation)) return;
        try
        {
            Clipboard.SetText(SelectedApp.InstallLocation);
            StatusText = $"已复制安装路径: {SelectedApp.InstallLocation}";
        }
        catch { }
    }

    [RelayCommand]
    public void CopyRegistryKeyPath()
    {
        if (SelectedApp == null || string.IsNullOrWhiteSpace(SelectedApp.RegistryKeyPath)) return;
        try
        {
            Clipboard.SetText(SelectedApp.RegistryKeyPath);
            StatusText = $"已复制注册表路径: {SelectedApp.RegistryKeyPath}";
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
