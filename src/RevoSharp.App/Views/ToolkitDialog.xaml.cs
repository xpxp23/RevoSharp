using System.Diagnostics;
using System.IO;
using System.Windows;
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
        AutostartGrid.ItemsSource = await Task.Run(() => _hunterService.GetAllAutostartEntries());
        BackupGrid.ItemsSource = await RegistryBackup.GetBackupManifestsAsync();
        TraceLogGrid.ItemsSource = await _appLocator.GetAllTraceLogsAsync();
        StatusTextBlock.Text = "已加载系统自启动项、历史备份档案与安装监控日志。";
    }

    private async void OnRefreshAutostartClick(object sender, RoutedEventArgs e)
    {
        AutostartGrid.ItemsSource = await Task.Run(() => _hunterService.GetAllAutostartEntries());
        StatusTextBlock.Text = "自启动项列表已刷新。";
    }

    private async void OnToggleAutostartClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;

        bool ok = await _hunterService.ToggleAutostartEntryStateAsync(entry);
        StatusTextBlock.Text = ok
            ? $"✅ 已将自启动项【{entry.Name}】切换为：{entry.StatusDisplay}"
            : $"⚠️ 无法切换【{entry.Name}】的启用状态（RunOnce 一次性项不支持禁用，可直接备份移除）";
    }

    private void OnOpenAutostartLocationClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;
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
            $"确定要安全备份并从系统中移除自启动项【{entry.Name}】吗？\n（移除后会自动在“多级备份还原中心”生成备份记录，可随时一键还原）",
            confirmText: "备份并移除",
            cancelText: "取消",
            isWarningOrDanger: true);

        if (!confirmed) return;

        bool ok = await _hunterService.RemoveAutostartEntryAsync(entry);
        StatusTextBlock.Text = ok
            ? $"✅ 已安全备份并移除自启动项：{entry.Name}（已同步记入多级备份还原中心）"
            : $"⚠️ 移除自启动项失败（可能需要更高权限）：{entry.Name}";

        AutostartGrid.ItemsSource = await Task.Run(() => _hunterService.GetAllAutostartEntries());
        BackupGrid.ItemsSource = await RegistryBackup.GetBackupManifestsAsync();
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
        StatusTextBlock.Text = $"正在还原【{manifest.AppName}】的注册表与计划任务备份...";
        int count = await RegistryBackup.RestoreBackupManifestAsync(manifest);
        StatusTextBlock.Text = $"✅ 已成功导入还原 {count} 份备份项（回收站文件可在系统回收站中直接还原）。";
        AutostartGrid.ItemsSource = await Task.Run(() => _hunterService.GetAllAutostartEntries());
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
            if (File.Exists(manifest.ManifestPath)) File.Delete(manifest.ManifestPath);
            BackupGrid.ItemsSource = await RegistryBackup.GetBackupManifestsAsync();
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
                    StatusTextBlock.Text = "⚠️ 无法解析所选日志文件，格式可能已损坏。";
                    return;
                }

                string destPath = Path.Combine(AppLocator.LogDirectory, Path.GetFileName(dlg.FileName));
                await TraceLogSerializer.SaveAsync(log, destPath);
                TraceLogGrid.ItemsSource = await _appLocator.GetAllTraceLogsAsync();
                StatusTextBlock.Text = $"✅ 已成功导入【{log.AppName}】的安装监控日志。";
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
                StatusTextBlock.Text = $"✅ 已导出可读报告: {dlg.FileName}";
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
        AppToCleanFromLog = new InstalledApp
        {
            Id = $"TraceLog_{log.AppName}",
            DisplayName = log.AppName,
            InstallLocation = log.DetectedInstallLocation,
            UninstallKeyName = log.UninstallKeyId,
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
            TraceLogGrid.ItemsSource = await _appLocator.GetAllTraceLogsAsync();
            StatusTextBlock.Text = $"已删除【{log.AppName}】的安装监控日志。";
        }
        catch { }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
