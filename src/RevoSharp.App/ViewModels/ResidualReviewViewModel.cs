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
    private readonly IReadOnlyList<InstalledApp>? _otherInstalledApps;
    private bool _suppressTreeSync;
    private bool _isTreeDirty = true;

    public InstalledApp TargetApp { get; }

    private List<ResidualItem> _allResiduals = [];
    private List<ResidualItem> _currentFilteredResiduals = [];

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
    private bool _isCleaningProgressVisible;

    [ObservableProperty]
    private double _cleanProgressPercent;

    [ObservableProperty]
    private string _cleanProgressDetail = string.Empty;

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
        r.Category is not (ResidualCategory.Service or ResidualCategory.DriverPackage or ResidualCategory.EnvironmentPath or ResidualCategory.BrowserExtension));
    public int FileCount => _allResiduals.Count(r =>
        (r.Type == ResidualType.Directory || r.Type == ResidualType.File) &&
        r.Category != ResidualCategory.Shortcut &&
        r.Category != ResidualCategory.ScheduledTask);
    public int ShortcutCount => _allResiduals.Count(r => r.Category == ResidualCategory.Shortcut);
    public int ServiceAndTaskCount => _allResiduals.Count(r =>
        r.Category is ResidualCategory.Service or ResidualCategory.DriverPackage or ResidualCategory.ScheduledTask);
    public int ExtensionAndEnvCount => _allResiduals.Count(r =>
        r.Category is ResidualCategory.EnvironmentPath or ResidualCategory.BrowserExtension or ResidualCategory.ShellExtension or ResidualCategory.MsiMetadata);
    public int LockedItemCount => _allResiduals.Count(r => r.IsLocked);
    public bool HasLockedItems => LockedItemCount > 0;

    public ResidualReviewViewModel(
        InstalledApp app,
        List<ResidualItem>? initialResiduals = null,
        IReadOnlyList<InstalledApp>? otherInstalledApps = null)
    {
        TargetApp = app;
        _otherInstalledApps = otherInstalledApps;
        if (initialResiduals != null && initialResiduals.Count > 0)
        {
            AttachResiduals(initialResiduals);
        }
    }

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
        _isTreeDirty = true;
    }

    private void RebuildTreesIfNeeded()
    {
        if (!_isTreeDirty) return;
        _suppressTreeSync = true;
        try
        {
            RegistryTreeNodes = TreeBuilder.BuildRegistryTree(_currentFilteredResiduals);
            FileSystemTreeNodes = TreeBuilder.BuildFileSystemTree(_currentFilteredResiduals);
            _isTreeDirty = false;
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
            if (_isTreeDirty)
            {
                RebuildTreesIfNeeded();
            }
            else
            {
                SyncTreesFromItems();
            }
        }
    }

    private void OnResidualItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ResidualItem.IsSelected) && sender is ResidualItem changedItem)
        {
            if (!_suppressTreeSync)
            {
                // Critical safety fix: When a user unchecks a child item in Flat mode, automatically uncheck any
                // ancestor Directory or RegistryKey item so whole-folder or whole-key deletion cannot wipe out the unchecked child!
                if (!changedItem.IsSelected)
                {
                    DeselectAncestorItemsContaining(changedItem);
                }

                if (IsTreeViewMode)
                {
                    SyncTreesFromItems();
                }
                else
                {
                    _isTreeDirty = true;
                }
            }
            UpdateSelectionStatus();
        }
    }

    private void DeselectAncestorItemsContaining(ResidualItem unselectedChild)
    {
        _suppressTreeSync = true;
        try
        {
            foreach (var candidateParent in _allResiduals)
            {
                if (!candidateParent.IsSelected || ReferenceEquals(candidateParent, unselectedChild))
                    continue;

                if (candidateParent.Type is ResidualType.Directory or ResidualType.RegistryKey)
                {
                    string prefix = candidateParent.Path.TrimEnd('\\') + "\\";
                    bool isAncestorPath = unselectedChild.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
                    bool isKeyContainingValue = candidateParent.Type == ResidualType.RegistryKey &&
                                                unselectedChild.Type == ResidualType.RegistryValue &&
                                                unselectedChild.Path.Equals(candidateParent.Path, StringComparison.OrdinalIgnoreCase);

                    if (isAncestorPath || isKeyContainingValue)
                    {
                        candidateParent.IsSelected = false;
                    }
                }
            }
        }
        finally
        {
            _suppressTreeSync = false;
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
        IsCleaningProgressVisible = false;
        StatusMessage = $"正在按【{CurrentScanMode}】级别深度扫描 {TargetApp.DisplayName} 的残留项与文件句柄占用...";

        try
        {
            var scanned = await _scanner.ScanResidualsAsync(TargetApp, CurrentScanMode, _otherInstalledApps);
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

    [RelayCommand]
    public async Task UnlockAllLockedItemsAsync()
    {
        var lockedItems = _allResiduals.Where(r => r.IsLocked).Select(r => r.Path).ToList();
        if (lockedItems.Count == 0)
        {
            StatusMessage = "当前未检测到任何被后台进程占用的残留文件或外壳扩展 DLL。";
            return;
        }

        IsBusy = true;
        IsCleaningProgressVisible = false;
        StatusMessage = "正在通过 Windows Restart Manager 解除残留文件与外壳扩展 DLL 的进程句柄占用...";

        try
        {
            var (killed, explorerRestarted) = await FileLockUnlocker.UnlockFilesAsync(lockedItems, allowExplorerRestart: true);
            int remainingLocks = await FileLockUnlocker.ScanAndAttachLocksToResidualsAsync(_allResiduals);
            NotifyCounts();

            string expNote = explorerRestarted ? "（已平滑重启 Explorer 释放外壳扩展 DLL）" : string.Empty;
            StatusMessage = $"占用解除完成：已终止 {killed} 个关联占用进程{expNote}，剩余占用项: {remainingLocks}。";
        }
        catch (Exception ex)
        {
            StatusMessage = $"解除占用异常: {ex.Message}";
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
                r.Category is not (ResidualCategory.Service or ResidualCategory.DriverPackage or ResidualCategory.EnvironmentPath or ResidualCategory.BrowserExtension));
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
            query = query.Where(r => r.Category is ResidualCategory.Service or ResidualCategory.DriverPackage or ResidualCategory.ScheduledTask);
        }
        else if (SelectedCategory == "扩展与环境")
        {
            query = query.Where(r => r.Category is ResidualCategory.EnvironmentPath or ResidualCategory.BrowserExtension or ResidualCategory.ShellExtension or ResidualCategory.MsiMetadata);
        }
        else if (SelectedCategory == "占用锁定")
        {
            query = query.Where(r => r.IsLocked);
        }

        if (!string.IsNullOrWhiteSpace(PathFilterText))
        {
            string keyword = PathFilterText.Trim();
            query = query.Where(r =>
                r.FullDisplayPath.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.Reason.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.TypeDisplay.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.LockedBySummary.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.SourceAppName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        _currentFilteredResiduals = query.ToList();
        DisplayedResiduals = new ObservableCollection<ResidualItem>(_currentFilteredResiduals);
        _isTreeDirty = true;

        if (IsTreeViewMode)
        {
            RebuildTreesIfNeeded();
        }

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
        if (IsTreeViewMode) SyncTreesFromItems();
        else _isTreeDirty = true;
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
        if (IsTreeViewMode) SyncTreesFromItems();
        else _isTreeDirty = true;
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
        if (IsTreeViewMode) SyncTreesFromItems();
        else _isTreeDirty = true;
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
    public void OpenTreeNodeLocation(object? nodeObj)
    {
        if (nodeObj is RegistryTreeNode regNode)
        {
            string regPath = regNode.AssociatedItem?.Path ?? regNode.FullPath;
            int bracketIdx = regPath.IndexOf(" [", StringComparison.Ordinal);
            if (bracketIdx > 0) regPath = regPath.Substring(0, bracketIdx);
            try
            {
                RegistryBackup.OpenInRegEdit(regPath);
                StatusMessage = $"已在注册表编辑器中定位: {regPath}";
            }
            catch (Exception ex)
            {
                StatusMessage = $"打开注册表失败: {ex.Message}";
            }
        }
        else if (nodeObj is FileSystemTreeNode fileNode)
        {
            string path = fileNode.AssociatedItem?.Path ?? fileNode.FullPath;
            OpenFileSystemPathInExplorer(path);
        }
    }

    [RelayCommand]
    public void CopyTreeNodePath(object? nodeObj)
    {
        string? text = nodeObj switch
        {
            RegistryTreeNode rn => rn.AssociatedItem?.FullDisplayPath ?? rn.FullPath,
            FileSystemTreeNode fn => fn.AssociatedItem?.FullDisplayPath ?? fn.FullPath,
            _ => null
        };

        if (!string.IsNullOrWhiteSpace(text))
        {
            try
            {
                Clipboard.SetText(text);
                StatusMessage = $"已复制节点路径: {text}";
            }
            catch { }
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

        OpenFileSystemPathInExplorer(target.Path);
    }

    private void OpenFileSystemPathInExplorer(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{path}\"",
                    UseShellExecute = true
                });
                StatusMessage = $"已在资源管理器中定位文件: {path}";
            }
            else if (Directory.Exists(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{path}\"",
                    UseShellExecute = true
                });
                StatusMessage = $"已打开目录: {path}";
            }
            else
            {
                string? parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(parent) && Directory.Exists(parent))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"\"{parent}\"",
                        UseShellExecute = true
                    });
                    StatusMessage = $"已打开上级目录: {parent}";
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
        int lockedCount = selectedItems.Count(r => r.IsLocked);
        string sizeStr = totalBytes > 0 ? $"，预计释放 {FormatBytes(totalBytes)}" : string.Empty;
        string lockStr = lockedCount > 0 ? $"（含 {lockedCount} 个占用锁定项，清理时将自动通过 Restart Manager 解锁）" : "（自动生成合并注册表备份与回收站保护）";
        StatusMessage = $"已选中 {selectedItems.Count} / {_allResiduals.Count} 项残留{sizeStr} {lockStr}";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        if (bytes >= 1024L * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        if (bytes >= 1024L) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }

    private void ReportProgress(double percent, string statusText, string detailText)
    {
        Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            CleanProgressPercent = Math.Clamp(percent, 0, 100);
            StatusMessage = statusText;
            CleanProgressDetail = detailText;
        });
    }

    /// <summary>
    /// Surgically expands a partially-selected directory (where the user unchecked one or more specific child files/subfolders
    /// to keep them) into the remaining sibling files/subfolders that CAN be safely deleted without touching the kept child!
    /// </summary>
    private static void ExpandPartialDirectorySiblingTargets(
        string currentDir,
        IReadOnlyList<string> keptPaths,
        List<ResidualItem> outputItems)
    {
        if (!Directory.Exists(currentDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(currentDir))
            {
                bool isKept = keptPaths.Any(k => k.Equals(file, StringComparison.OrdinalIgnoreCase));
                if (!isKept)
                {
                    outputItems.Add(new ResidualItem
                    {
                        Type = ResidualType.File,
                        Category = ResidualCategory.File,
                        Path = file,
                        Confidence = ConfidenceLevel.High,
                        Reason = "部分保留目录下可清理同级文件",
                        IsSelected = true
                    });
                }
            }

            foreach (var subDir in Directory.GetDirectories(currentDir))
            {
                bool isExactKept = keptPaths.Any(k => k.Equals(subDir, StringComparison.OrdinalIgnoreCase));
                if (isExactKept) continue;

                string prefix = subDir.TrimEnd('\\') + "\\";
                bool containsKeptChild = keptPaths.Any(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
                if (containsKeptChild)
                {
                    ExpandPartialDirectorySiblingTargets(subDir, keptPaths, outputItems);
                }
                else
                {
                    outputItems.Add(new ResidualItem
                    {
                        Type = ResidualType.Directory,
                        Category = ResidualCategory.Directory,
                        Path = subDir,
                        Confidence = ConfidenceLevel.High,
                        Reason = "部分保留目录下可清理同级子目录",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    [RelayCommand]
    public async Task CleanAllSelectedSilentAsync(Action onFinished)
    {
        var itemsToClean = _allResiduals.Where(r => r.IsSelected).ToList();
        var unselectedItems = _allResiduals.Where(r => !r.IsSelected).ToList();
        if (itemsToClean.Count == 0)
        {
            onFinished?.Invoke();
            return;
        }

        IsBusy = true;
        IsCleaningProgressVisible = true;
        CleanProgressPercent = 2;
        CleanProgressDetail = "正在初始化多级备份清单...";

        var manifest = new BackupManifest
        {
            AppName = TargetApp.DisplayName,
            BackupCategory = "卸载残留清理",
            CreatedTime = DateTime.Now
        };

        if (CreateRestorePoint)
        {
            ReportProgress(6, "正在创建 Windows 系统还原点...", "调用 WMI SystemRestore.CreateRestorePoint");
            manifest.SystemRestorePointCreated = await RegistryBackup.CreateSystemRestorePointAsync($"RevoSharp Uninstall {TargetApp.DisplayName}");
        }

        int cleanedCount = 0;
        int rebootScheduledCount = 0;

        await Task.Run(async () =>
        {
            bool HasUnselectedDescendant(ResidualItem parentItem)
            {
                string prefix = parentItem.Path.TrimEnd('\\') + "\\";
                return unselectedItems.Any(u =>
                    u.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    (parentItem.Type == ResidualType.RegistryKey &&
                     u.Type == ResidualType.RegistryValue &&
                     u.Path.Equals(parentItem.Path, StringComparison.OrdinalIgnoreCase)));
            }

            // Step 1: In-process merged .reg backup synthesis (< 200ms for hundreds of registry keys & values!)
            var regItems = itemsToClean
                .Where(i => i.Type is ResidualType.RegistryKey or ResidualType.RegistryValue &&
                            i.Category != ResidualCategory.EnvironmentPath)
                .ToList();

            if (regItems.Count > 0)
            {
                ReportProgress(15, $"正在原位合成 {regItems.Count} 项注册表备份 (.reg)...", "内存递归子树合成引擎 (零子进程开销)");
                var mergedFiles = await RegistryBackup.SynthesizeMergedRegBackupAsync(regItems, TargetApp.DisplayName);
                foreach (var (regFile, is64) in mergedFiles)
                {
                    manifest.RegBackupFiles.Add(regFile);
                    manifest.RegBackupViewMap[regFile] = is64;
                }
            }

            // Step 2: Clean Registry Keys, Values, Services, Driver Packages, and Environment PATH dead-links
            var allRegAndEnvItems = itemsToClean
                .Where(i => i.Type is ResidualType.RegistryKey or ResidualType.RegistryValue)
                .ToList();

            int totalSteps = itemsToClean.Count;
            int completedSteps = 0;

            foreach (var item in allRegAndEnvItems)
            {
                completedSteps++;
                double pct = 20.0 + (40.0 * completedSteps / Math.Max(1, totalSteps));
                ReportProgress(pct, $"正在清理注册表与系统配置 ({completedSteps}/{totalSteps})...", item.FullDisplayPath);

                try
                {
                    if (item.Category == ResidualCategory.EnvironmentPath && !string.IsNullOrEmpty(item.PathSegmentToRemove))
                    {
                        if (RegistryBackup.BackupAndCleanEnvironmentPathSegment(item.IsSystemEnvironmentVariable, item.PathSegmentToRemove, manifest))
                        {
                            manifest.BackedUpTargetDescriptions.Add($"[环境变量 PATH] 移除死链: {item.PathSegmentToRemove}");
                            cleanedCount++;
                        }
                        continue;
                    }

                    if (item.Type == ResidualType.RegistryKey)
                    {
                        if (HasUnselectedDescendant(item))
                        {
                            continue;
                        }

                        if ((item.Category is ResidualCategory.Service or ResidualCategory.DriverPackage) &&
                            !string.IsNullOrEmpty(item.ValueName))
                        {
                            await RegistryBackup.StopAndDeleteServiceAsync(item.ValueName);
                            if (!string.IsNullOrEmpty(item.DriverPublishedInfName))
                            {
                                await RegistryBackup.UninstallDriverPackageAsync(item.DriverPublishedInfName);
                            }
                        }

                        int slash = item.Path.IndexOf('\\');
                        if (slash > 0)
                        {
                            string hive = item.Path.Substring(0, slash);
                            string sub = item.Path.Substring(slash + 1);
                            if (RegistryBackup.DeleteKey(hive, sub, item.Is64BitRegistryView) ||
                                item.Category is ResidualCategory.Service or ResidualCategory.DriverPackage)
                            {
                                manifest.BackedUpTargetDescriptions.Add($"[{item.TypeDisplay}] {item.Path}");
                                cleanedCount++;
                            }
                        }
                    }
                    else if (item.Type == ResidualType.RegistryValue && !string.IsNullOrEmpty(item.ValueName))
                    {
                        int valSlash = item.Path.IndexOf('\\');
                        if (valSlash > 0)
                        {
                            string hive = item.Path.Substring(0, valSlash);
                            string sub = item.Path.Substring(valSlash + 1);
                            if (RegistryBackup.DeleteValue(hive, sub, item.ValueName, item.Is64BitRegistryView))
                            {
                                manifest.BackedUpTargetDescriptions.Add($"[{item.TypeDisplay}] {item.Path} [{item.ValueName}]");
                                cleanedCount++;
                            }
                        }
                    }
                }
                catch { }
            }

            // Step 3: Clean Scheduled Tasks
            var taskItems = itemsToClean
                .Where(i => i.Category == ResidualCategory.ScheduledTask)
                .ToList();

            foreach (var taskItem in taskItems)
            {
                completedSteps++;
                double pct = 20.0 + (45.0 * completedSteps / Math.Max(1, totalSteps));
                ReportProgress(pct, $"正在注销并备份计划任务 ({completedSteps}/{totalSteps})...", taskItem.Path);

                var (taskBak, resolvedTn) = await RegistryBackup.BackupAndDeleteScheduledTaskWithNameAsync(
                    taskItem.Path,
                    taskItem.TaskSchedulerName,
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
            }

            // Step 4: Prepare file & directory items, surgically expanding any directory that has both selected and unselected children
            var fileAndDirItems = new List<ResidualItem>();
            var keptFilePaths = unselectedItems
                .Where(u => u.Type is ResidualType.File or ResidualType.Directory)
                .Select(u => u.Path.TrimEnd('\\'))
                .ToList();

            foreach (var item in itemsToClean.Where(i => i.Type is ResidualType.File or ResidualType.Directory && i.Category != ResidualCategory.ScheduledTask))
            {
                if (item.Type == ResidualType.Directory && HasUnselectedDescendant(item))
                {
                    ExpandPartialDirectorySiblingTargets(item.Path, keptFilePaths, fileAndDirItems);
                }
                else
                {
                    fileAndDirItems.Add(item);
                }
            }

            // Also check if an unselected parent directory in _allResiduals was auto-deselected ONLY because a child was unchecked,
            // while still having other checked children under it!
            foreach (var unselectedDir in unselectedItems.Where(u => u.Type == ResidualType.Directory))
            {
                string prefix = unselectedDir.Path.TrimEnd('\\') + "\\";
                bool hasCheckedChild = itemsToClean.Any(c => c.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
                if (hasCheckedChild)
                {
                    ExpandPartialDirectorySiblingTargets(unselectedDir.Path, keptFilePaths, fileAndDirItems);
                }
            }

            fileAndDirItems = fileAndDirItems
                .DistinctBy(f => f.Path.TrimEnd('\\'), StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (fileAndDirItems.Count > 0)
            {
                var targetPaths = fileAndDirItems.Select(f => f.Path).ToList();
                var activeLocks = FileLockUnlocker.FindLockingProcesses(targetPaths);
                if (activeLocks.Count > 0)
                {
                    ReportProgress(70, $"检测到 {activeLocks.Count} 个后台进程占用残留文件，正在自动解锁...", string.Join(", ", activeLocks.Select(l => l.DisplaySummary)));
                    await FileLockUnlocker.UnlockFilesAsync(targetPaths, allowExplorerRestart: true);
                }

                foreach (var fi in fileAndDirItems.Where(f => f.Type == ResidualType.File))
                {
                    string? snap = FileBackup.TryCreateFileBackupCopy(fi.Path, TargetApp.DisplayName);
                    if (!string.IsNullOrEmpty(snap))
                    {
                        manifest.FileBackupCopyMap[fi.Path] = snap;
                    }
                }

                ReportProgress(82, $"正在批量移入系统回收站 ({fileAndDirItems.Count} 项文件与目录)...", fileAndDirItems[0].Path);
                var recycledSet = FileBackup.SendToRecycleBinBatch(targetPaths);

                foreach (var item in fileAndDirItems)
                {
                    if (recycledSet.Contains(item.Path))
                    {
                        manifest.RecycledFilePaths.Add(item.Path);
                        manifest.BackedUpTargetDescriptions.Add($"[{item.TypeDisplay}] {item.Path}");
                        cleanedCount++;
                    }
                    else if (ScheduleLockedOnReboot && FileBackup.ScheduleDeleteOnReboot(item.Path))
                    {
                        manifest.RebootScheduledPaths.Add(item.Path);
                        manifest.BackedUpTargetDescriptions.Add($"[重启删除] {item.Path}");
                        rebootScheduledCount++;
                        cleanedCount++;
                    }
                }
            }

            ReportProgress(96, "正在写入多级还原档案索引...", manifest.AppName);
            if (manifest.TotalBackedUpItems > 0 || manifest.RebootScheduledPaths.Count > 0 || manifest.SystemRestorePointCreated)
            {
                await RegistryBackup.SaveBackupManifestAsync(manifest);
            }
            ReportProgress(100, "清理完成！", string.Empty);
        });

        IsCleaningProgressVisible = false;
        IsBusy = false;
        StatusMessage = rebootScheduledCount > 0
            ? $"清理完成：已清除 {cleanedCount} 项（其中 {rebootScheduledCount} 个占用项已安排重启后移除）。"
            : $"清理完毕：已安全清除 {cleanedCount} 项残留并生成合并备份档案。";

        onFinished?.Invoke();
    }

    private void NotifyCounts()
    {
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(RegCount));
        OnPropertyChanged(nameof(FileCount));
        OnPropertyChanged(nameof(ShortcutCount));
        OnPropertyChanged(nameof(ServiceAndTaskCount));
        OnPropertyChanged(nameof(ExtensionAndEnvCount));
        OnPropertyChanged(nameof(LockedItemCount));
        OnPropertyChanged(nameof(HasLockedItems));
    }
}
