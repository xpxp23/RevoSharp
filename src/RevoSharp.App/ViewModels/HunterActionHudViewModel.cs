using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Hunter;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.ViewModels;

public partial class HunterActionHudViewModel : ObservableObject
{
    private readonly HunterService _hunterService;
    private readonly ResidualScanner _residualScanner;
    private readonly UninstallerRunner _uninstallerRunner;
    private readonly IReadOnlyList<InstalledApp>? _installedApps;

    [ObservableProperty]
    private HunterTargetInfo _targetInfo;

    [ObservableProperty]
    private ImageSource? _appIcon;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _hasAutostartEntry;

    [ObservableProperty]
    private int _autostartCount;

    public Action? RequestCloseAction { get; set; }
    public Action<InstalledApp, List<ResidualItem>>? RequestOpenReviewAction { get; set; }
    public Action? RequestRestoreMainWindowAction { get; set; }

    public bool CanUninstall => !TargetInfo.IsSystemCritical &&
        (!string.IsNullOrEmpty(TargetInfo.EffectiveApp.UninstallString) || TargetInfo.IsRegisteredApp);

    public bool CanForceClean => !TargetInfo.IsSystemCritical;

    public bool CanKillProcess => !TargetInfo.IsSystemCritical && TargetInfo.ProcessId > 4;

    public bool CanDisableAutostart => HasAutostartEntry && !TargetInfo.IsSystemCritical;

    public HunterActionHudViewModel(
        HunterTargetInfo targetInfo,
        HunterService hunterService,
        ResidualScanner residualScanner,
        UninstallerRunner uninstallerRunner,
        IReadOnlyList<InstalledApp>? installedApps = null)
    {
        _targetInfo = targetInfo;
        _hunterService = hunterService;
        _residualScanner = residualScanner;
        _uninstallerRunner = uninstallerRunner;
        _installedApps = installedApps;

        HasAutostartEntry = targetInfo.HasAutostartEntry;
        AutostartCount = targetInfo.AutostartDescriptions.Count;

        LoadIcon();
        UpdateStatusSummary();

        // Run deep autostart persistence scan asynchronously in the background if not yet scanned,
        // so mouse-up HUD popup is 100% instantaneous with zero UI thread lag!
        if (!targetInfo.IsSystemCritical && !targetInfo.HasAutostartEntry)
        {
            _ = ScanAutostartInBackgroundAsync();
        }
    }

    private async Task ScanAutostartInBackgroundAsync()
    {
        await Task.Run(() => _hunterService.ScanAutostartPersistence(TargetInfo));
        Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            HasAutostartEntry = TargetInfo.HasAutostartEntry;
            AutostartCount = TargetInfo.AutostartDescriptions.Count;
            OnPropertyChanged(nameof(CanDisableAutostart));
            UpdateStatusSummary();
        });
    }

    private void UpdateStatusSummary()
    {
        if (TargetInfo.IsSystemCritical)
        {
            StatusMessage = TargetInfo.SystemProtectionReason;
        }
        else if (TargetInfo.HasAutostartEntry)
        {
            StatusMessage = $"已检测到 {TargetInfo.AutostartDescriptions.Count} 处系统自启动驻留项（含注册表/启动目录/计划任务）";
        }
        else
        {
            StatusMessage = TargetInfo.IsRegisteredApp
                ? "已精准匹配系统已安装软件档案"
                : (TargetInfo.EffectiveApp.IsProtectedSingleFile
                    ? "独立单文件程序（已启用所在共享文件夹保护）"
                    : "未在注册表安装列表登记（已生成便携程序专属猎犬档案）");
        }
    }

    private void LoadIcon()
    {
        if (string.IsNullOrEmpty(TargetInfo.ExecutablePath) || !File.Exists(TargetInfo.ExecutablePath))
            return;

        IntPtr[] large = new IntPtr[1];
        IntPtr[] small = new IntPtr[1];
        try
        {
            if (ExtractIconEx(TargetInfo.ExecutablePath, 0, large, small, 1) > 0)
            {
                IntPtr chosen = large[0] != IntPtr.Zero ? large[0] : small[0];
                if (chosen != IntPtr.Zero)
                {
                    var bs = Imaging.CreateBitmapSourceFromHIcon(
                        chosen,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    bs.Freeze();
                    AppIcon = bs;
                }
            }
        }
        catch { }
        finally
        {
            if (large[0] != IntPtr.Zero) DestroyIcon(large[0]);
            if (small[0] != IntPtr.Zero) DestroyIcon(small[0]);
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    private static extern uint ExtractIconEx(string szFileName, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [RelayCommand]
    public async Task UninstallAsync()
    {
        if (!CanUninstall) return;
        IsBusy = true;
        StatusMessage = "正在唤起原厂卸载程序并监控进程树...";

        try
        {
            var app = TargetInfo.EffectiveApp;
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            await _uninstallerRunner.RunAndTrackUninstallerAsync(
                app,
                forceInteractive: true,
                status => Application.Current?.Dispatcher.InvokeAsync(() => StatusMessage = status),
                cts.Token);

            StatusMessage = "原厂卸载已结束，正在进行深度逆向残留扫描...";
            var residuals = await _residualScanner.ScanResidualsAsync(app, otherInstalledApps: _installedApps);

            RequestCloseAction?.Invoke();
            RequestOpenReviewAction?.Invoke(app, residuals);
        }
        catch (Exception ex)
        {
            StatusMessage = $"卸载流程异常: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task ForceCleanAsync()
    {
        if (!CanForceClean) return;
        IsBusy = true;
        StatusMessage = "正在强力终止进程树并执行深度逆向残留扫描...";

        try
        {
            if (TargetInfo.ProcessId > 4)
            {
                await Task.Run(() => _hunterService.KillProcessTree(TargetInfo.ProcessId));
            }

            var app = TargetInfo.EffectiveApp;
            StatusMessage = "正在逆向索引 CLSID、服务、驱动、计划任务与目录残留...";
            var residuals = await _residualScanner.ScanResidualsAsync(app, otherInstalledApps: _installedApps);

            RequestCloseAction?.Invoke();
            RequestOpenReviewAction?.Invoke(app, residuals);
        }
        catch (Exception ex)
        {
            StatusMessage = $"强力清理异常: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task KillProcessAsync()
    {
        if (!CanKillProcess) return;
        IsBusy = true;
        try
        {
            int targetPid = TargetInfo.ProcessId;
            bool ok = await Task.Run(() => _hunterService.KillProcessTree(targetPid));
            if (ok)
            {
                TargetInfo.ProcessId = 0;
                OnPropertyChanged(nameof(CanKillProcess));
            }
            StatusMessage = ok
                ? $"已成功终止目标进程树 (PID: {targetPid})"
                : "终止进程失败（目标进程可能已退出）";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task DisableAutostartAsync()
    {
        if (!CanDisableAutostart) return;
        IsBusy = true;
        try
        {
            bool killed = TargetInfo.ProcessId > 4 && await Task.Run(() => _hunterService.KillProcessTree(TargetInfo.ProcessId));
            if (killed)
            {
                TargetInfo.ProcessId = 0;
                OnPropertyChanged(nameof(CanKillProcess));
            }
            bool removed = await _hunterService.DisableAutostartAsync(TargetInfo);

            HasAutostartEntry = TargetInfo.HasAutostartEntry;
            AutostartCount = TargetInfo.AutostartDescriptions.Count;
            OnPropertyChanged(nameof(CanDisableAutostart));

            StatusMessage = removed
                ? (killed ? "已终止目标进程并安全备份清除所有自启动项（可在备份中心一键还原）" : "已安全备份并清除所有开机自启动项（可在备份中心一键还原）")
                : "未发现或无法移除自启项";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    public void OpenLocation()
    {
        if (string.IsNullOrEmpty(TargetInfo.ExecutablePath)) return;
        try
        {
            if (File.Exists(TargetInfo.ExecutablePath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{TargetInfo.ExecutablePath}\"",
                    UseShellExecute = true
                });
                StatusMessage = "已在资源管理器中定位主文件";
            }
            else if (Directory.Exists(TargetInfo.DirectoryPath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{TargetInfo.DirectoryPath}\"",
                    UseShellExecute = true
                });
                StatusMessage = "已打开程序所在目录";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"打开目录失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void SearchWeb()
    {
        try
        {
            string query = Uri.EscapeDataString($"{TargetInfo.ProcessName} {TargetInfo.Publisher} 进程安全性分析");
            string url = $"https://www.bing.com/search?q={query}";
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            StatusMessage = "已在浏览器中发起进程安全情报检索";
        }
        catch (Exception ex)
        {
            StatusMessage = $"唤起浏览器失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void RestoreMainWindow()
    {
        RequestCloseAction?.Invoke();
        RequestRestoreMainWindowAction?.Invoke();
    }
}
