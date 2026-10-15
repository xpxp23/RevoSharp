using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using RevoSharp.Engine.Monitoring;

namespace RevoSharp.App.ViewModels;

public partial class MonitorViewModel : ObservableObject
{
    private EtwInstallMonitor? _monitor;

    [ObservableProperty]
    private string _installerPath = string.Empty;

    [ObservableProperty]
    private string _appName = string.Empty;

    [ObservableProperty]
    private bool _isMonitoring;

    [ObservableProperty]
    private int _capturedFiles;

    [ObservableProperty]
    private int _capturedRegistry;

    [ObservableProperty]
    private string _statusText = "请选择安装包并填写软件名称";

    [ObservableProperty]
    private ObservableCollection<string> _recentEvents = [];

    [RelayCommand]
    public void BrowseInstaller()
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择要监视的安装程序",
            Filter = "安装程序 (*.exe;*.msi)|*.exe;*.msi|所有文件 (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            InstallerPath = dialog.FileName;
            if (string.IsNullOrWhiteSpace(AppName))
            {
                AppName = Path.GetFileNameWithoutExtension(dialog.FileName);
            }
            StatusText = "已准备就绪，点击“开始监视安装”启动安装程序。";
        }
    }

    [RelayCommand]
    public async Task StartMonitoringAsync()
    {
        if (string.IsNullOrWhiteSpace(InstallerPath) || !File.Exists(InstallerPath))
        {
            MessageBox.Show("请先选择有效的安装文件", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(AppName))
        {
            AppName = Path.GetFileNameWithoutExtension(InstallerPath);
        }

        IsMonitoring = true;
        StatusText = "正在监听安装过程中的底层文件与注册表变动...";
        RecentEvents.Clear();

        _monitor = new EtwInstallMonitor();
        _monitor.OnItemCaptured += item =>
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                CapturedFiles = _monitor.CapturedFileCount;
                CapturedRegistry = _monitor.CapturedRegCount;

                RecentEvents.Insert(0, item);
                if (RecentEvents.Count > 100)
                {
                    RecentEvents.RemoveAt(RecentEvents.Count - 1);
                }
            });
        };

        try
        {
            await _monitor.StartAsync(InstallerPath, AppName);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"启动监视失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            IsMonitoring = false;
            StatusText = "监视启动失败";
        }
    }

    [RelayCommand]
    public async Task StopAndSaveAsync(Action onSaved)
    {
        if (_monitor == null) return;

        StatusText = "正在整合与压缩保存安装日志...";
        var log = await _monitor.StopAsync();
        _monitor.Dispose();
        _monitor = null;
        IsMonitoring = false;

        StatusText = $"监视完成！共捕获 {log.CreatedFiles.Count} 个文件，{log.CreatedRegistryKeys.Count} 项注册表变更。";
        MessageBox.Show($"安装日志已成功保存！\n捕获文件: {log.CreatedFiles.Count}\n捕获注册表: {log.CreatedRegistryKeys.Count}\n后续卸载此软件时将自动使用此日志进行 100% 完整反向回退！",
            "安装监视完成", MessageBoxButton.OK, MessageBoxImage.Information);

        onSaved?.Invoke();
    }
}
