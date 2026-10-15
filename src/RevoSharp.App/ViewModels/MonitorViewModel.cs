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
    private string _statusText = "请选择安装包（安装完成后将自动识别新增注册表软件名称）";

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
            StatusText = "已就绪，点击“开始监视安装”将先建立 ETW 内核会话再启动安装程序。";
        }
    }

    [RelayCommand]
    public async Task StartMonitoringAsync()
    {
        if (string.IsNullOrWhiteSpace(InstallerPath) || !File.Exists(InstallerPath))
        {
            StatusText = "⚠️ 请先选择有效的安装文件 (.exe / .msi)";
            return;
        }

        if (string.IsNullOrWhiteSpace(AppName))
        {
            AppName = Path.GetFileNameWithoutExtension(InstallerPath);
        }

        IsMonitoring = true;
        StatusText = "正在初始化 ETW 内核追踪会话并启动安装程序...";
        RecentEvents.Clear();

        _monitor = new EtwInstallMonitor();
        _monitor.OnItemCaptured += item =>
        {
            Application.Current?.Dispatcher.InvokeAsync(() =>
            {
                if (_monitor == null) return;
                CapturedFiles = _monitor.CapturedFileCount;
                CapturedRegistry = _monitor.CapturedRegCount;

                RecentEvents.Insert(0, item);
                if (RecentEvents.Count > 150)
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
            StatusText = $"❌ 启动监视失败: {ex.Message}";
            CancelAndDispose();
        }
    }

    [RelayCommand]
    public async Task StopAndSaveAsync(Action onSaved)
    {
        if (_monitor == null) return;

        StatusText = "正在对比注册表快照并保存安装追踪日志...";
        var log = await _monitor.StopAsync();
        _monitor.Dispose();
        _monitor = null;
        IsMonitoring = false;

        string targetTitle = !string.IsNullOrWhiteSpace(log.DetectedDisplayName)
            ? $"{log.DetectedDisplayName} (自动关联注册表)"
            : log.AppName;

        StatusText = $"✅ 监视完成！已关联【{targetTitle}】，记录 {log.CreatedFiles.Count} 个文件与 {log.CreatedRegistryKeys.Count} 项注册表。";
        onSaved?.Invoke();
    }

    public void CancelAndDispose()
    {
        IsMonitoring = false;
        try
        {
            _monitor?.Dispose();
            _monitor = null;
        }
        catch { }
    }
}
