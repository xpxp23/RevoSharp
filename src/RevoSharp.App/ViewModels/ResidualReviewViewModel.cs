using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.ViewModels;

public partial class ResidualReviewViewModel : ObservableObject
{
    private readonly ResidualScanner _scanner = new();

    public InstalledApp TargetApp { get; }

    private List<ResidualItem> _allResiduals = [];

    [ObservableProperty]
    private ObservableCollection<ResidualItem> _displayedResiduals = [];

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusMessage = "就绪";

    [ObservableProperty]
    private string _pathFilterText = string.Empty;

    [ObservableProperty]
    private string _selectedCategory = "全部";

    [ObservableProperty]
    private ScanMode _currentScanMode = ScanMode.Moderate;

    public int TotalCount => _allResiduals.Count;
    public int RegCount => _allResiduals.Count(r => r.Type == ResidualType.RegistryKey || r.Type == ResidualType.RegistryValue);
    public int FileCount => _allResiduals.Count(r => r.Type == ResidualType.Directory || r.Type == ResidualType.File && !r.Reason.Contains("快捷方式"));
    public int ShortcutCount => _allResiduals.Count(r => r.Reason.Contains("快捷方式"));

    public ResidualReviewViewModel(InstalledApp app, List<ResidualItem>? initialResiduals = null)
    {
        TargetApp = app;
        if (initialResiduals != null && initialResiduals.Count > 0)
        {
            _allResiduals = [.. initialResiduals];
        }
    }

    public async Task InitializeScanAsync()
    {
        if (_allResiduals.Count > 0)
        {
            ApplyFilter();
            StatusMessage = $"扫描完成，共检出 {_allResiduals.Count} 项残留";
            OnPropertyChanged(nameof(TotalCount));
            OnPropertyChanged(nameof(RegCount));
            OnPropertyChanged(nameof(FileCount));
            OnPropertyChanged(nameof(ShortcutCount));
            return;
        }

        await ExecuteScanAsync();
    }

    partial void OnPathFilterTextChanged(string value) => ApplyFilter();
    partial void OnSelectedCategoryChanged(string value) => ApplyFilter();

    [RelayCommand]
    public async Task ExecuteScanAsync()
    {
        IsBusy = true;
        StatusMessage = $"正在深度扫描 {TargetApp.DisplayName} 的多维残留项目...";

        try
        {
            _allResiduals = await _scanner.ScanResidualsAsync(TargetApp, CurrentScanMode);
            ApplyFilter();
            NotifyCounts();
            StatusMessage = $"扫描完成：共发现 {_allResiduals.Count} 项残留（注册表 {RegCount} 项，文件 {FileCount} 项，快捷方式 {ShortcutCount} 项）";
        }
        catch (Exception ex)
        {
            StatusMessage = $"扫描发生异常: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyFilter()
    {
        IEnumerable<ResidualItem> query = _allResiduals;

        // 1. Category Filter
        if (SelectedCategory == "注册表")
        {
            query = query.Where(r => r.Type == ResidualType.RegistryKey || r.Type == ResidualType.RegistryValue);
        }
        else if (SelectedCategory == "文件与目录")
        {
            query = query.Where(r => (r.Type == ResidualType.Directory || r.Type == ResidualType.File) && !r.Reason.Contains("快捷方式"));
        }
        else if (SelectedCategory == "快捷方式")
        {
            query = query.Where(r => r.Reason.Contains("快捷方式"));
        }

        // 2. Keyword Filter
        if (!string.IsNullOrWhiteSpace(PathFilterText))
        {
            string keyword = PathFilterText.Trim();
            query = query.Where(r => r.Path.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                     r.Reason.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        DisplayedResiduals = new ObservableCollection<ResidualItem>(query);
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void SelectAll()
    {
        foreach (var item in DisplayedResiduals) item.IsSelected = true;
        OnPropertyChanged(nameof(DisplayedResiduals));
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void DeselectAll()
    {
        foreach (var item in DisplayedResiduals) item.IsSelected = false;
        OnPropertyChanged(nameof(DisplayedResiduals));
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void SelectHighOnly()
    {
        foreach (var item in DisplayedResiduals)
        {
            item.IsSelected = item.Confidence == ConfidenceLevel.High;
        }
        OnPropertyChanged(nameof(DisplayedResiduals));
        UpdateSelectionStatus();
    }

    private void UpdateSelectionStatus()
    {
        int selected = _allResiduals.Count(r => r.IsSelected);
        StatusMessage = $"已选中 {selected} / {_allResiduals.Count} 项残留 (将自动执行 .reg 备份与移入回收站)";
    }

    [RelayCommand]
    public async Task CleanAllSelectedSilentAsync(Action onFinished)
    {
        var itemsToClean = _allResiduals.Where(r => r.IsSelected).ToList();
        if (itemsToClean.Count == 0)
        {
            onFinished?.Invoke();
            return;
        }

        IsBusy = true;
        StatusMessage = $"正在静默清除 {itemsToClean.Count} 项残留...";

        int cleanedCount = 0;
        await Task.Run(async () =>
        {
            foreach (var item in itemsToClean)
            {
                try
                {
                    switch (item.Type)
                    {
                        case ResidualType.File:
                        case ResidualType.Directory:
                            if (FileBackup.SendToRecycleBin(item.Path))
                            {
                                cleanedCount++;
                            }
                            break;

                        case ResidualType.RegistryKey:
                            await RegistryBackup.ExportKeyAsync(item.Path, TargetApp.DisplayName);
                            int slash = item.Path.IndexOf('\\');
                            if (slash > 0)
                            {
                                string hive = item.Path.Substring(0, slash);
                                string sub = item.Path.Substring(slash + 1);
                                if (RegistryBackup.DeleteKey(hive, sub))
                                {
                                    cleanedCount++;
                                }
                            }
                            break;

                        case ResidualType.RegistryValue:
                            if (!string.IsNullOrEmpty(item.ValueName))
                            {
                                int valSlash = item.Path.IndexOf('\\');
                                if (valSlash > 0)
                                {
                                    string hive = item.Path.Substring(0, valSlash);
                                    string sub = item.Path.Substring(valSlash + 1);
                                    if (RegistryBackup.DeleteValue(hive, sub, item.ValueName))
                                    {
                                        cleanedCount++;
                                    }
                                }
                            }
                            break;
                    }
                }
                catch { }
            }
        });

        IsBusy = false;
        StatusMessage = $"清理完毕！成功清除 {cleanedCount} 项残留。";

        // Auto-close immediately without lingering
        onFinished?.Invoke();
    }

    private void NotifyCounts()
    {
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(RegCount));
        OnPropertyChanged(nameof(FileCount));
        OnPropertyChanged(nameof(ShortcutCount));
    }
}
