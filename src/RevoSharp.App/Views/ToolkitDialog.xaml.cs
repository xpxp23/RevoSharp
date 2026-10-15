using System.Diagnostics;
using System.IO;
using System.Windows;
using RevoSharp.Core.Models;
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
        Loaded += async (s, e) => await LoadAllTabsAsync();
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

    private void OnOpenAutostartLocationClick(object sender, RoutedEventArgs e)
    {
        if (AutostartGrid.SelectedItem is not AutostartEntry entry) return;
        string target = entry.IsStartupShortcut ? entry.FullLocation : entry.ExecutablePath;
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
        bool ok = _hunterService.RemoveAutostartEntry(entry);
        StatusTextBlock.Text = ok
            ? $"✅ 已安全备份并移除自启动项：{entry.Name}"
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
        StatusTextBlock.Text = $"正在还原【{manifest.AppName}】的注册表备份...";
        int count = await RegistryBackup.RestoreBackupManifestAsync(manifest);
        StatusTextBlock.Text = $"✅ 已成功导入还原 {count} 份 .reg 注册表备份文件（回收站文件可在系统回收站中直接还原）。";
    }

    private async void OnDeleteBackupClick(object sender, RoutedEventArgs e)
    {
        if (BackupGrid.SelectedItem is not BackupManifest manifest) return;
        try
        {
            foreach (var reg in manifest.RegBackupFiles)
            {
                if (File.Exists(reg)) File.Delete(reg);
            }
            if (File.Exists(manifest.ManifestPath)) File.Delete(manifest.ManifestPath);
            BackupGrid.ItemsSource = await RegistryBackup.GetBackupManifestsAsync();
            StatusTextBlock.Text = $"已删除【{manifest.AppName}】的备份记录。";
        }
        catch { }
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
        try
        {
            if (File.Exists(log.FilePath)) File.Delete(log.FilePath);
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
