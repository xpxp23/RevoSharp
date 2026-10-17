using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
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
    private bool _suppressTreeSync;

    public InstalledApp TargetApp { get; }

    private List<ResidualItem> _allResiduals = [];

    [ObservableProperty]
    private ObservableCollection<ResidualItem> _displayedResiduals = [];

    [ObservableProperty]
    private ObservableCollection<RegistryTreeNode> _registryTreeNodes = [];

    [ObservableProperty]
    private ObservableCollection<FileSystemTreeNode> _fileSystemTreeNodes = [];

    [ObservableProperty]
    private ResidualItem? _selectedResidual;

    [ObservableProperty]
    private bool _isTreeViewMode;

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

    [ObservableProperty]
    private bool _createRestorePoint;

    [ObservableProperty]
    private bool _scheduleLockedOnReboot = true;

    public int TotalCount => _allResiduals.Count;
    public int RegCount => _allResiduals.Count(r =>
        (r.Type == ResidualType.RegistryKey || r.Type == ResidualType.RegistryValue) &&
        r.Category != ResidualCategory.Service);
    public int FileCount => _allResiduals.Count(r =>
        (r.Type == ResidualType.Directory || r.Type == ResidualType.File) &&
        r.Category != ResidualCategory.Shortcut &&
        r.Category != ResidualCategory.ScheduledTask);
    public int ShortcutCount => _allResiduals.Count(r => r.Category == ResidualCategory.Shortcut);
    public int ServiceAndTaskCount => _allResiduals.Count(r =>
        r.Category == ResidualCategory.Service || r.Category == ResidualCategory.ScheduledTask);

    public ResidualReviewViewModel(InstalledApp app, List<ResidualItem>? initialResiduals = null)
    {
        TargetApp = app;
        if (initialResiduals != null && initialResiduals.Count > 0)
        {
            AttachResiduals(initialResiduals);
        }
    }

    /// <summary>
    /// Returns the total count of selected Low-Confidence residual items across the entire unfiltered list
    /// so category/search filters never bypass the safety confirmation dialog.
    /// </summary>
    public int GetSelectedLowConfidenceCount() =>
        _allResiduals.Count(r => r.IsSelected && r.Confidence == ConfidenceLevel.Low);

    public int GetTotalSelectedCount() =>
        _allResiduals.Count(r => r.IsSelected);

    private void AttachResiduals(List<ResidualItem> items)
    {
        foreach (var old in _allResiduals)
        {
            old.PropertyChanged -= OnResidualItemPropertyChanged;
        }

        _allResiduals = [.. items];

        foreach (var item in _allResiduals)
        {
            item.PropertyChanged += OnResidualItemPropertyChanged;
        }
    }

    private void RebuildTrees(IEnumerable<ResidualItem> filteredItems)
    {
        _suppressTreeSync = true;
        try
        {
            var list = filteredItems as IReadOnlyCollection<ResidualItem> ?? filteredItems.ToList();
            RegistryTreeNodes = TreeBuilder.BuildRegistryTree(list);
            FileSystemTreeNodes = TreeBuilder.BuildFileSystemTree(list);
        }
        finally
        {
            _suppressTreeSync = false;
        }
    }

    private void SyncTreesFromItems()
    {
        if (_suppressTreeSync) return;
        _suppressTreeSync = true;
        try
        {
            foreach (var root in RegistryTreeNodes)
            {
                root.SyncFromItemSelection();
            }
            foreach (var root in FileSystemTreeNodes)
            {
                root.SyncFromItemSelection();
            }
        }
        finally
        {
            _suppressTreeSync = false;
        }
    }

    partial void OnIsTreeViewModeChanged(bool value)
    {
        if (value)
        {
            SyncTreesFromItems();
        }
    }

    private void OnResidualItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ResidualItem.IsSelected))
        {
            if (!IsTreeViewMode && !_suppressTreeSync)
            {
                SyncTreesFromItems();
            }
            UpdateSelectionStatus();
        }
    }

    public async Task InitializeScanAsync()
    {
        if (_allResiduals.Count > 0)
        {
            ApplyFilter();
            NotifyCounts();
            UpdateSelectionStatus();
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
        StatusMessage = $"正在按【{CurrentScanMode}】级别深度扫描 {TargetApp.DisplayName} 的残留项...";

        try
        {
            var scanned = await _scanner.ScanResidualsAsync(TargetApp, CurrentScanMode);
            AttachResiduals(scanned);
            ApplyFilter();
            NotifyCounts();
            UpdateSelectionStatus();
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

        if (SelectedCategory == "注册表")
        {
            query = query.Where(r =>
                (r.Type == ResidualType.RegistryKey || r.Type == ResidualType.RegistryValue) &&
                r.Category != ResidualCategory.Service);
        }
        else if (SelectedCategory == "文件与目录")
        {
            query = query.Where(r =>
                (r.Type == ResidualType.Directory || r.Type == ResidualType.File) &&
                r.Category != ResidualCategory.Shortcut &&
                r.Category != ResidualCategory.ScheduledTask);
        }
        else if (SelectedCategory == "快捷方式")
        {
            query = query.Where(r => r.Category == ResidualCategory.Shortcut);
        }
        else if (SelectedCategory == "服务与任务")
        {
            query = query.Where(r => r.Category == ResidualCategory.Service || r.Category == ResidualCategory.ScheduledTask);
        }

        if (!string.IsNullOrWhiteSpace(PathFilterText))
        {
            string keyword = PathFilterText.Trim();
            query = query.Where(r =>
                r.FullDisplayPath.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.Reason.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.TypeDisplay.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.SourceAppName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        var filteredList = query.ToList();
        DisplayedResiduals = new ObservableCollection<ResidualItem>(filteredList);
        RebuildTrees(filteredList);
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void SelectAll()
    {
        _suppressTreeSync = true;
        try
        {
            foreach (var item in DisplayedResiduals) item.IsSelected = true;
        }
        finally
        {
            _suppressTreeSync = false;
        }
        SyncTreesFromItems();
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void DeselectAll()
    {
        _suppressTreeSync = true;
        try
        {
            foreach (var item in DisplayedResiduals) item.IsSelected = false;
        }
        finally
        {
            _suppressTreeSync = false;
        }
        SyncTreesFromItems();
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void SelectHighOnly()
    {
        _suppressTreeSync = true;
        try
        {
            foreach (var item in DisplayedResiduals)
            {
                item.IsSelected = item.Confidence == ConfidenceLevel.High;
            }
        }
        finally
        {
            _suppressTreeSync = false;
        }
        SyncTreesFromItems();
        UpdateSelectionStatus();
    }

    [RelayCommand]
    public void ExpandAllTrees()
    {
        SetTreeExpandedRecursive(RegistryTreeNodes, true);
        SetTreeExpandedRecursive(FileSystemTreeNodes, true);
    }

    [RelayCommand]
    public void CollapseAllTrees()
    {
        SetTreeExpandedRecursive(RegistryTreeNodes, false);
        SetTreeExpandedRecursive(FileSystemTreeNodes, false);
    }

    private static void SetTreeExpandedRecursive(IEnumerable<RegistryTreeNode> nodes, bool expanded)
    {
        foreach (var n in nodes)
        {
            n.IsExpanded = expanded;
            SetTreeExpandedRecursive(n.Children, expanded);
        }
    }

    private static void SetTreeExpandedRecursive(IEnumerable<FileSystemTreeNode> nodes, bool expanded)
    {
        foreach (var n in nodes)
        {
            n.IsExpanded = expanded;
            SetTreeExpandedRecursive(n.Children, expanded);
        }
    }

    [RelayCommand]
    public void OpenItemLocation(ResidualItem? item)
    {
        var target = item ?? SelectedResidual;
        if (target == null) return;

        if (target.Type is ResidualType.RegistryKey or ResidualType.RegistryValue)
        {
            OpenInRegEdit(target);
            return;
        }

        try
        {
            if (File.Exists(target.Path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{target.Path}\"",
                    UseShellExecute = true
                });
            }
            else if (Directory.Exists(target.Path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{target.Path}\"",
                    UseShellExecute = true
                });
            }
            else
            {
                string? parent = Path.GetDirectoryName(target.Path);
                if (!string.IsNullOrEmpty(parent) && Directory.Exists(parent))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"\"{parent}\"",
                        UseShellExecute = true
                    });
                }
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"打开目录失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void OpenInRegEdit(ResidualItem? item)
    {
        var target = item ?? SelectedResidual;
        if (target == null || (target.Type != ResidualType.RegistryKey && target.Type != ResidualType.RegistryValue))
        {
            StatusMessage = "当前选中项不是注册表项";
            return;
        }

        try
        {
            RegistryBackup.OpenInRegEdit(target.Path);
            StatusMessage = $"已在注册表编辑器中定位: {target.Path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"打开注册表编辑器失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void CopyPath(ResidualItem? item)
    {
        var target = item ?? SelectedResidual;
        if (target == null) return;
        try
        {
            Clipboard.SetText(target.FullDisplayPath);
            StatusMessage = $"已复制路径: {target.FullDisplayPath}";
        }
        catch { }
    }

    private void UpdateSelectionStatus()
    {
        var selectedItems = _allResiduals.Where(r => r.IsSelected).ToList();
        long totalBytes = selectedItems.Sum(r => r.SizeInBytes);
        string sizeStr = totalBytes > 0 ? $"，预计释放 {FormatBytes(totalBytes)}" : string.Empty;
        StatusMessage = $"已选中 {selectedItems.Count} / {_allResiduals.Count} 项残留{sizeStr}（自动生成注册表/文件备份与回收站保护）";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        if (bytes >= 1024L * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        if (bytes >= 1024L) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
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
        var manifest = new BackupManifest
        {
            AppName = TargetApp.DisplayName,
            BackupCategory = "卸载残留清理",
            CreatedTime = DateTime.Now
        };

        if (CreateRestorePoint)
        {
            StatusMessage = "正在创建 Windows 系统还原点...";
            manifest.SystemRestorePointCreated = await RegistryBackup.CreateSystemRestorePointAsync($"RevoSharp Uninstall {TargetApp.DisplayName}");
        }

        StatusMessage = $"正在安全备份并清理 {itemsToClean.Count} 项残留...";

        int cleanedCount = 0;
        int rebootScheduledCount = 0;
        int skippedUnbackedCount = 0;

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
                            if (item.Category == ResidualCategory.ScheduledTask)
                            {
                                var (taskBak, resolvedTn) = await RegistryBackup.BackupAndDeleteScheduledTaskWithNameAsync(
                                    item.Path,
                                    item.TaskSchedulerName,
                                    TargetApp.DisplayName);
                                if (!string.IsNullOrEmpty(taskBak))
                                {
                                    manifest.TaskXmlBackupFiles.Add(taskBak);
                                    if (!string.IsNullOrEmpty(resolvedTn))
                                    {
                                        manifest.TaskScheduleMap[taskBak] = resolvedTn;
                                    }
                                    manifest.BackedUpTargetDescriptions.Add($"[计划任务] {resolvedTn}");
                                }
                                cleanedCount++;
                                break;
                            }

                            string? fileSnapshot = item.Type == ResidualType.File
                                ? FileBackup.TryCreateFileBackupCopy(item.Path, TargetApp.DisplayName)
                                : null;

                            if (FileBackup.SendToRecycleBin(item.Path))
                            {
                                manifest.RecycledFilePaths.Add(item.Path);
                                if (!string.IsNullOrEmpty(fileSnapshot))
                                {
                                    manifest.FileBackupCopyMap[item.Path] = fileSnapshot;
                                }
                                manifest.BackedUpTargetDescriptions.Add($"[{item.TypeDisplay}] {item.Path}");
                                cleanedCount++;
                            }
                            else if (ScheduleLockedOnReboot && FileBackup.ScheduleDeleteOnReboot(item.Path))
                            {
                                manifest.RebootScheduledPaths.Add(item.Path);
                                if (!string.IsNullOrEmpty(fileSnapshot))
                                {
                                    manifest.FileBackupCopyMap[item.Path] = fileSnapshot;
                                }
                                manifest.BackedUpTargetDescriptions.Add($"[重启删除] {item.Path}");
                                rebootScheduledCount++;
                                cleanedCount++;
                            }
                            break;

                        case ResidualType.RegistryKey:
                            // Critical fix: Export the registry key backup BEFORE stopping/deleting the Windows Service,
                            // because "sc delete" immediately deletes the service registry key!
                            string? regBak = await RegistryBackup.ExportKeyAsync(item.Path, TargetApp.DisplayName, item.Is64BitRegistryView);
                            if (!string.IsNullOrEmpty(regBak))
                            {
                                manifest.RegBackupFiles.Add(regBak);
                                manifest.RegBackupViewMap[regBak] = item.Is64BitRegistryView ?? true;
                                manifest.BackedUpTargetDescriptions.Add($"[注册表项] {item.Path}");
                            }

                            if (item.Category == ResidualCategory.Service && !string.IsNullOrEmpty(item.ValueName))
                            {
                                await RegistryBackup.StopAndDeleteServiceAsync(item.ValueName);
                            }

                            if (!string.IsNullOrEmpty(regBak))
                            {
                                int slash = item.Path.IndexOf('\\');
                                if (slash > 0)
                                {
                                    string hive = item.Path.Substring(0, slash);
                                    string sub = item.Path.Substring(slash + 1);
                                    if (RegistryBackup.DeleteKey(hive, sub, item.Is64BitRegistryView) ||
                                        item.Category == ResidualCategory.Service)
                                    {
                                        cleanedCount++;
                                    }
                                }
                            }
                            else
                            {
                                skippedUnbackedCount++;
                            }
                            break;

                        case ResidualType.RegistryValue:
                            if (!string.IsNullOrEmpty(item.ValueName))
                            {
                                string? valBak = await RegistryBackup.ExportValueAsync(
                                    item.Path,
                                    item.ValueName,
                                    item.ValuePreview,
                                    TargetApp.DisplayName,
                                    item.Is64BitRegistryView);

                                if (!string.IsNullOrEmpty(valBak))
                                {
                                    manifest.RegBackupFiles.Add(valBak);
                                    manifest.RegBackupViewMap[valBak] = item.Is64BitRegistryView ?? true;
                                    manifest.BackedUpTargetDescriptions.Add($"[注册表值] {item.Path} [{item.ValueName}]");

                                    int valSlash = item.Path.IndexOf('\\');
                                    if (valSlash > 0)
                                    {
                                        string hive = item.Path.Substring(0, valSlash);
                                        string sub = item.Path.Substring(valSlash + 1);
                                        if (RegistryBackup.DeleteValue(hive, sub, item.ValueName, item.Is64BitRegistryView))
                                        {
                                            cleanedCount++;
                                        }
                                    }
                                }
                                else
                                {
                                    skippedUnbackedCount++;
                                }
                            }
                            break;
                    }
                }
                catch { }
            }

            if (manifest.TotalBackedUpItems > 0 || manifest.RebootScheduledPaths.Count > 0 || manifest.SystemRestorePointCreated)
            {
                await RegistryBackup.SaveBackupManifestAsync(manifest);
            }
        });

        IsBusy = false;
        string skipNote = skippedUnbackedCount > 0 ? $"（另有 {skippedUnbackedCount} 项因导出备份失败已安全跳过）" : string.Empty;
        StatusMessage = rebootScheduledCount > 0
            ? $"清理完成：已清除 {cleanedCount} 项（其中 {rebootScheduledCount} 个占用项已安排重启后移除）{skipNote}。"
            : $"清理完毕：已安全清除 {cleanedCount} 项残留并生成备份档案{skipNote}。";

        onFinished?.Invoke();
    }

    private void NotifyCounts()
    {
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(RegCount));
        OnPropertyChanged(nameof(FileCount));
        OnPropertyChanged(nameof(ShortcutCount));
        OnPropertyChanged(nameof(ServiceAndTaskCount));
    }
}
