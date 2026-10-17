using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using RevoSharp.Engine.Monitoring;

namespace RevoSharp.App.ViewModels;

public partial class MonitorViewModel : ObservableObject
{
    private EtwInstallMonitor? _monitor;
    private readonly ConcurrentQueue<string> _eventQueue = new();
    private readonly Queue<string> _allCapturedHistory = new(1600);
    private readonly DispatcherTimer _flushTimer;
    private readonly Stopwatch _elapsedStopwatch = new();

    [ObservableProperty]
    private string _installerPath = string.Empty;

    [ObservableProperty]
    private string _appName = string.Empty;

    [ObservableProperty]
    private bool _isMonitoring;

    [ObservableProperty]
    private bool _isStreamPaused;

    [ObservableProperty]
    private string _eventFilterText = string.Empty;

    [ObservableProperty]
    private int _capturedFiles;

    [ObservableProperty]
    private int _capturedRegistry;

    [ObservableProperty]
    private int _trackedProcesses;

    [ObservableProperty]
    private string _elapsedTimeDisplay = "00:00";

    [ObservableProperty]
    private string _statusText = "请选择安装包（安装完成后可点击“试运行新软件”一并捕获首次启动配置）";

    [ObservableProperty]
    private ObservableCollection<string> _recentEvents = [];

    public string PauseStreamButtonText => IsStreamPaused ? "恢复滚动" : "暂停滚动";

    public MonitorViewModel()
    {
        _flushTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(180)
        };
        _flushTimer.Tick += OnFlushTimerTick;
    }

    partial void OnIsStreamPausedChanged(bool value)
    {
        OnPropertyChanged(nameof(PauseStreamButtonText));
    }

    partial void OnEventFilterTextChanged(string value)
    {
        RebuildFilteredEvents();
    }

    private void OnFlushTimerTick(object? sender, EventArgs e)
    {
        if (_monitor == null) return;

        CapturedFiles = _monitor.CapturedFileCount;
        CapturedRegistry = _monitor.CapturedRegCount;
        TrackedProcesses = _monitor.TrackedProcessCount;
        ElapsedTimeDisplay = _elapsedStopwatch.Elapsed.ToString(@"mm\:ss");

        if (IsStreamPaused) return;

        bool anyAdded = false;
        int dequeuedCount = 0;
        while (_eventQueue.TryDequeue(out string? item))
        {
            // Use Queue.Dequeue() O(1) instead of List.RemoveAt(0) O(N) array shift
            _allCapturedHistory.Enqueue(item);
            while (_allCapturedHistory.Count > 1500)
            {
                _allCapturedHistory.Dequeue();
            }

            if (MatchesFilter(item))
            {
                RecentEvents.Insert(0, item);
                if (RecentEvents.Count > 180)
                {
                    RecentEvents.RemoveAt(RecentEvents.Count - 1);
                }
                anyAdded = true;
            }

            if (++dequeuedCount >= 40)
                break;
        }

        if (!anyAdded && _eventQueue.Count > 500)
        {
            while (_eventQueue.Count > 200 && _eventQueue.TryDequeue(out _)) { }
        }
    }

    private bool MatchesFilter(string item)
    {
        if (string.IsNullOrWhiteSpace(EventFilterText)) return true;
        return item.Contains(EventFilterText.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private void RebuildFilteredEvents()
    {
        var filtered = _allCapturedHistory
            .Where(MatchesFilter)
            .Reverse()
            .Take(180)
            .ToList();
        RecentEvents = new ObservableCollection<string>(filtered);
    }

    [RelayCommand]
    public void TogglePauseStream()
    {
        IsStreamPaused = !IsStreamPaused;
    }

    [RelayCommand]
    public void ClearEvents()
    {
        while (_eventQueue.TryDequeue(out _)) { }
        _allCapturedHistory.Clear();
        RecentEvents.Clear();
    }

    [RelayCommand]
    public void BrowseInstaller()
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择要监视的安装程序",
            Filter = "安装程序 (*.exe;*.msi;*.msp)|*.exe;*.msi;*.msp|所有文件 (*.*)|*.*"
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
            StatusText = "请先选择有效的安装文件 (.exe / .msi)";
            return;
        }

        if (string.IsNullOrWhiteSpace(AppName))
        {
            AppName = Path.GetFileNameWithoutExtension(InstallerPath);
        }

        IsMonitoring = true;
        IsStreamPaused = false;
        StatusText = "正在初始化 ETW 内核追踪会话并启动安装程序...";
        ClearEvents();

        _elapsedStopwatch.Restart();
        _flushTimer.Start();

        _monitor = new EtwInstallMonitor();
        _monitor.OnItemCaptured += item =>
        {
            _eventQueue.Enqueue(item);
        };

        try
        {
            await _monitor.StartAsync(InstallerPath, AppName);
        }
        catch (Exception ex)
        {
            StatusText = $"启动监视失败: {ex.Message}";
            CancelAndDispose();
        }
    }

    [RelayCommand]
    public void LaunchDetectedApp()
    {
        if (_monitor == null || !IsMonitoring) return;

        if (_monitor.TryLaunchDetectedInstalledApp(out string launchedExe))
        {
            StatusText = $"已拉起新安装的软件 ({Path.GetFileName(launchedExe)})，待其初始化后关闭该软件再点击“完成安装并保存日志”即可完整捕获首次运行配置。";
        }
        else
        {
            StatusText = "暂未检测到已完成的安装目录，请等待安装向导完成后再试，或手动启动一次该软件。";
        }
    }

    [RelayCommand]
    public async Task StopAndSaveAsync(Action onSaved)
    {
        if (_monitor == null) return;

        _flushTimer.Stop();
        _elapsedStopwatch.Stop();
        StatusText = "正在对比注册表快照并保存安装追踪日志...";
        var log = await _monitor.StopAsync();
        _monitor.Dispose();
        _monitor = null;
        IsMonitoring = false;

        string targetTitle = !string.IsNullOrWhiteSpace(log.DetectedDisplayName)
            ? $"{log.DetectedDisplayName} (自动关联注册表)"
            : log.AppName;

        StatusText = $"监视完成：已关联【{targetTitle}】，记录 {log.CreatedFiles.Count} 个文件、{log.CreatedRegistryKeys.Count} 项注册表键与 {log.ModifiedRegistryValues.Count} 项注册表值。";
        onSaved?.Invoke();
    }

    public void CancelAndDispose()
    {
        _flushTimer.Stop();
        _elapsedStopwatch.Stop();
        IsMonitoring = false;
        try
        {
            _monitor?.Dispose();
            _monitor = null;
        }
        catch { }
    }
}
