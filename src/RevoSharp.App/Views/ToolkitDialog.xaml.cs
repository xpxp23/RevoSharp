using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Hunter;
using RevoSharp.Engine.Safety;

namespace RevoSharp.App.Views;

public partial class ToolkitDialog
{
    private readonly HunterService _hunterService = new();
    private readonly AppLocator _appLocator = new();
    private List<AutostartEntry> _allAutostarts = [];

    public InstalledApp? AppToCleanFromLog { get; private set; }

    public ToolkitDialog()
    {
        InitializeComponent();
        Loaded += OnWindowLoadedOnce;
    }

    private async void OnWindowLoadedOnce(object sender, RoutedEventArgs e)
    {
        Loaded -= OnWindowLoadedOnce;
        await LoadAllTabsAsync();
    }

    private async Task LoadAllTabsAsync()
    {
        ToolkitLoadingRing.Visibility = Visibility.Visible;
        StatusTextBlock.Text = "正在扫描系统开机自启动项、历史备份档案与安装监控日志...";
        try
        {
            _allAutostarts = await Task.Run(() => _hunterService.GetAllAutostartEntries());
            ApplyAutostartFilter();

            var backups = await RegistryBackup.GetBackupManifestsAsync();
            BackupGrid.ItemsSource = backups;
            BackupEmptyOverlay.Visibility = backups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (backups.Count > 0)
            {
                BackupGrid.SelectedIndex = 0;
            }

            var logs = await _appLocator.GetAllTraceLogsAsync();
            TraceLogGrid.ItemsSource = logs;
            TraceLogEmptyOverlay.Visibility = logs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            StatusTextBlock.Text = $"已加载 {_allAutostarts.Count} 项开机自启条目、{backups.Count} 份备份档案与 {logs.Count} 份安装监控日志。";
        }
        finally
        {
            ToolkitLoadingRing.Visibility = Visibility.Collapsed;
        }
    }

    private void OnAutostartSearchChanged(object sender, TextChangedEventArgs e)
    {
        ApplyAutostartFilter();
    }

    private void ApplyAutostartFilter()
    {
        string kw = AutostartSearchBox?.Text?.Trim() ?? string.Empty;
        var filtered = string.IsNullOrEmpty(kw)
            ? _allAutostarts
            : _allAutostarts
                .Where(a =>
                    a.Name.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                    a.Command.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                    a.Publisher.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                    a.LocationType.Contains(kw, StringComparison.OrdinalIgnoreCase))
                .ToList();

        AutostartGrid.ItemsSource = filtered;
        if (AutostartEmptyOverlay != null)
        {
            AutostartEmptyOverlay.Visibility = filtered.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private async void OnRefreshAutostartClick(object sender, RoutedEventArgs e)
    {
        ToolkitLoadingRing.Visibility = Visibility.Visible;
        try
        {
            _allAutostarts = await Task.Run(() => _hunterService.GetAllAutostartEntries());
            ApplyAutostartFilter();
            StatusTextBlock.Text = $"自启动项列表已刷新（共 {_allAutostarts.Count} 项）。";
        }
        finally
        {
            ToolkitLoadingRing.Visibility = Visibility.Collapsed;
        }
    }

    private async void OnToggleAutostartClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;

        bool ok = await _hunterService.ToggleAutostartEntryStateAsync(entry);
        StatusTextBlock.Text = ok
            ? $"已将自启动项【{entry.Name}】切换为：{entry.StatusDisplay}"
            : $"无法切换【{entry.Name}】的启用状态（RunOnce 一次性项不支持禁用，可直接备份移除）";
    }

    private void OnOpenAutostartLocationClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;

        if (!entry.IsStartupShortcut && !entry.IsScheduledTask && !string.IsNullOrEmpty(entry.RegistrySubKey))
        {
            if (!string.IsNullOrEmpty(entry.ExecutablePath) && File.Exists(entry.ExecutablePath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{entry.ExecutablePath}\"",
                    UseShellExecute = true
                });
            }
            else
            {
                RegistryBackup.OpenInRegEdit($@"{entry.RegistryHiveName}\{entry.RegistrySubKey}");
            }
            return;
        }

        string target = (entry.IsStartupShortcut || entry.IsScheduledTask) ? entry.FullLocation : entry.ExecutablePath;
        if (!string.IsNullOrEmpty(target) && File.Exists(target))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{target}\"",
                UseShellExecute = true
            });
        }
    }

    private async void OnRemoveAutostartClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;

        bool confirmed = FluentMessageDialog.ShowConfirm(
            this,
            "移除自启动项确认",
            $"确定要安全备份并从系统中移除自启动项【{entry.Name}】吗？\n（移除后会自动在“多级备份还原中心”生成完整备份记录，支持一键原位还原）",
            confirmText: "备份并移除",
            cancelText: "取消",
            isWarningOrDanger: true);

        if (!confirmed) return;

        bool ok = await _hunterService.RemoveAutostartEntryAsync(entry);
        StatusTextBlock.Text = ok
            ? $"已安全备份并移除自启动项：{entry.Name}（已同步记入多级备份还原中心）"
            : $"移除自启动项失败（可能需要管理员权限）：{entry.Name}";

        _allAutostarts = await Task.Run(() => _hunterService.GetAllAutostartEntries());
        ApplyAutostartFilter();
        var backups = await RegistryBackup.GetBackupManifestsAsync();
        BackupGrid.ItemsSource = backups;
        BackupEmptyOverlay.Visibility = backups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnBackupSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (BackupGrid.SelectedItem is BackupManifest manifest)
        {
            BackupPreviewTextBlock.Text = $"【{manifest.AppName}】备份条目明细 (共 {manifest.BackedUpTargetDescriptions.Count} 项)：";
            BackupDetailsListBox.ItemsSource = manifest.BackedUpTargetDescriptions.Count > 0
                ? manifest.BackedUpTargetDescriptions
                : new List<string> { manifest.SummaryText };
        }
        else
        {
            BackupPreviewTextBlock.Text = "选中任意备份记录可在此滚动检视其包含的注册表路径、计划任务、环境变量与文件快照详情：";
            BackupDetailsListBox.ItemsSource = null;
        }
    }

    private void OnOpenBackupFolderClick(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(RegistryBackup.BackupDir))
        {
            Directory.CreateDirectory(RegistryBackup.BackupDir);
        }
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{RegistryBackup.BackupDir}\"",
            UseShellExecute = true
        });
    }

    private async void OnRestoreBackupClick(object sender, RoutedEventArgs e)
    {
        if (BackupGrid.SelectedItem is not BackupManifest manifest) return;
        StatusTextBlock.Text = $"正在还原【{manifest.AppName}】的注册表、计划任务、环境变量与文件快照备份...";
        int count = await RegistryBackup.RestoreBackupManifestAsync(manifest);
        StatusTextBlock.Text = count > 0
            ? $"已成功原位还原 {count} 份备份项（大型目录可在系统回收站中直接还原）。"
            : "该档案未包含可直接导入的注册表/文件快照，请前往系统回收站还原对应目录。";
        _allAutostarts = await Task.Run(() => _hunterService.GetAllAutostartEntries());
        ApplyAutostartFilter();
    }

    private async void OnDeleteBackupClick(object sender, RoutedEventArgs e)
    {
        if (BackupGrid.SelectedItem is not BackupManifest manifest) return;

        bool confirmed = FluentMessageDialog.ShowConfirm(
            this,
            "删除备份记录确认",
            $"确定要永久删除【{manifest.AppName}】({manifest.CreatedTimeDisplay}) 的备份档案吗？",
            confirmText: "永久删除",
            cancelText: "取消",
            isWarningOrDanger: true);

        if (!confirmed) return;

        try
        {
            foreach (var reg in manifest.RegBackupFiles)
            {
                if (File.Exists(reg)) File.Delete(reg);
            }
            foreach (var xml in manifest.TaskXmlBackupFiles)
            {
                if (File.Exists(xml)) File.Delete(xml);
            }
            if (manifest.FileBackupCopyMap != null)
            {
                foreach (var bakCopy in manifest.FileBackupCopyMap.Values)
                {
                    if (File.Exists(bakCopy)) File.Delete(bakCopy);
                }
            }
            if (File.Exists(manifest.ManifestPath)) File.Delete(manifest.ManifestPath);
            var backups = await RegistryBackup.GetBackupManifestsAsync();
            BackupGrid.ItemsSource = backups;
            BackupEmptyOverlay.Visibility = backups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            StatusTextBlock.Text = $"已删除【{manifest.AppName}】的备份记录。";
        }
        catch { }
    }

    private async void OnImportTraceLogClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "导入安装监控追踪日志 (.revolog.json.gz)",
            Filter = "RevoSharp 追踪日志 (*.revolog.json.gz)|*.revolog.json.gz|所有文件 (*.*)|*.*"
        };

        if (dlg.ShowDialog() == true && File.Exists(dlg.FileName))
        {
            try
            {
                if (!Directory.Exists(AppLocator.LogDirectory))
                {
                    Directory.CreateDirectory(AppLocator.LogDirectory);
                }

                var log = await TraceLogSerializer.LoadAsync(dlg.FileName);
                if (log == null)
                {
                    StatusTextBlock.Text = "无法解析所选日志文件，格式可能已损坏。";
                    return;
                }

                string destPath = Path.Combine(AppLocator.LogDirectory, Path.GetFileName(dlg.FileName));
                await TraceLogSerializer.SaveAsync(log, destPath);
                var logs = await _appLocator.GetAllTraceLogsAsync();
                TraceLogGrid.ItemsSource = logs;
                TraceLogEmptyOverlay.Visibility = logs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                StatusTextBlock.Text = $"已成功导入【{log.AppName}】的安装监控日志。";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"导入失败: {ex.Message}";
            }
        }
    }

    private async void OnExportTraceLogReportClick(object sender, RoutedEventArgs e)
    {
        if (TraceLogGrid.SelectedItem is not TraceLog log) return;

        var dlg = new SaveFileDialog
        {
            Title = "导出安装监控可读报告",
            FileName = $"{AppLocator.SanitizeFileName(log.AppName)}_TraceReport.txt",
            Filter = "文本报告 (*.txt)|*.txt"
        };

        if (dlg.ShowDialog() == true)
        {
            try
            {
                await TraceLogSerializer.ExportReadableReportAsync(log, dlg.FileName);
                StatusTextBlock.Text = $"已导出可读报告: {dlg.FileName}";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"导出失败: {ex.Message}";
            }
        }
    }

    private void OnOpenLogFolderClick(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(AppLocator.LogDirectory))
        {
            Directory.CreateDirectory(AppLocator.LogDirectory);
        }
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{AppLocator.LogDirectory}\"",
            UseShellExecute = true
        });
    }

    private void OnCleanByTraceLogClick(object sender, RoutedEventArgs e)
    {
        if (TraceLogGrid.SelectedItem is not TraceLog log) return;
        string regPath = !string.IsNullOrWhiteSpace(log.UninstallKeyId)
            ? $@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{log.UninstallKeyId}"
            : string.Empty;

        AppToCleanFromLog = new InstalledApp
        {
            Id = $"TraceLog_{log.AppName}",
            DisplayName = !string.IsNullOrWhiteSpace(log.DetectedDisplayName) ? log.DetectedDisplayName : log.AppName,
            InstallLocation = log.DetectedInstallLocation,
            UninstallKeyName = log.UninstallKeyId,
            RegistryKeyPath = regPath,
            HasTraceLog = true,
            TraceLogPath = log.FilePath
        };
        DialogResult = true;
        Close();
    }

    private async void OnDeleteTraceLogClick(object sender, RoutedEventArgs e)
    {
        if (TraceLogGrid.SelectedItem is not TraceLog log) return;

        bool confirmed = FluentMessageDialog.ShowConfirm(
            this,
            "删除监控日志确认",
            $"确定要删除【{log.AppName}】的安装监控追踪日志吗？",
            confirmText: "确定删除",
            cancelText: "取消",
            isWarningOrDanger: true);

        if (!confirmed) return;

        try
        {
            if (File.Exists(log.FilePath)) File.Delete(log.FilePath);
            await TraceLogSerializer.LoadOrSyncIndexAsync(AppLocator.LogDirectory);
            var logs = await _appLocator.GetAllTraceLogsAsync();
            TraceLogGrid.ItemsSource = logs;
            TraceLogEmptyOverlay.Visibility = logs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            StatusTextBlock.Text = $"已删除【{log.AppName}】的安装监控日志。";
        }
        catch { }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
