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

    [ObservableProperty]
    private HunterTargetInfo _targetInfo;

    [ObservableProperty]
    private ImageSource? _appIcon;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    public Action? RequestCloseAction { get; set; }
    public Action<InstalledApp, List<ResidualItem>>? RequestOpenReviewAction { get; set; }
    public Action? RequestRestoreMainWindowAction { get; set; }

    public bool CanUninstall => !TargetInfo.IsSystemCritical &&
        (!string.IsNullOrEmpty(TargetInfo.EffectiveApp.UninstallString) || TargetInfo.IsRegisteredApp);

    public bool CanForceClean => !TargetInfo.IsSystemCritical;

    public bool CanKillProcess => !TargetInfo.IsSystemCritical;

    public bool CanDisableAutostart => TargetInfo.HasAutostartEntry && !TargetInfo.IsSystemCritical;

    public HunterActionHudViewModel(
        HunterTargetInfo targetInfo,
        HunterService hunterService,
        ResidualScanner residualScanner,
        UninstallerRunner uninstallerRunner)
    {
        _targetInfo = targetInfo;
        _hunterService = hunterService;
        _residualScanner = residualScanner;
        _uninstallerRunner = uninstallerRunner;

        LoadIcon();

        if (targetInfo.IsSystemCritical)
        {
            StatusMessage = $"🛡️ {targetInfo.SystemProtectionReason}";
        }
        else if (targetInfo.HasAutostartEntry)
        {
            StatusMessage = $"已检测到 {targetInfo.AutostartDescriptions.Count} 处系统自启动驻留项";
        }
        else
        {
            StatusMessage = targetInfo.IsRegisteredApp
                ? "已精准匹配系统已安装软件档案"
                : (targetInfo.EffectiveApp.IsProtectedSingleFile
                    ? "独立单文件程序（已启用所在共享文件夹保护）"
                    : "未在注册表安装列表登记（已生成便携程序专属猎犬档案）");
        }
    }

    private void LoadIcon()
    {
        if (string.IsNullOrEmpty(TargetInfo.ExecutablePath) || !File.Exists(TargetInfo.ExecutablePath))
            return;

        try
        {
            IntPtr[] large = new IntPtr[1];
            IntPtr[] small = new IntPtr[1];
            if (ExtractIconEx(TargetInfo.ExecutablePath, 0, large, small, 1) > 0 && large[0] != IntPtr.Zero)
            {
                try
                {
                    var bs = Imaging.CreateBitmapSourceFromHIcon(
                        large[0],
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    bs.Freeze();
                    AppIcon = bs;
                }
                finally
                {
                    DestroyIcon(large[0]);
                    if (small[0] != IntPtr.Zero) DestroyIcon(small[0]);
                }
            }
        }
        catch { }
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
                status => StatusMessage = status,
                cts.Token);

            StatusMessage = "原厂卸载已结束，正在进行深度逆向残留扫描...";
            var residuals = await _residualScanner.ScanResidualsAsync(app);

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
            _hunterService.KillProcessTree(TargetInfo.ProcessId);

            var app = TargetInfo.EffectiveApp;
            StatusMessage = "正在逆向索引 CLSID、服务、计划任务与目录残留...";
            var residuals = await _residualScanner.ScanResidualsAsync(app);

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
    public void KillProcess()
    {
        if (!CanKillProcess) return;
        bool ok = _hunterService.KillProcessTree(TargetInfo.ProcessId);
        StatusMessage = ok
            ? $"✅ 已成功终止目标进程树 (PID: {TargetInfo.ProcessId})"
            : "终止进程失败（目标进程可能已退出）";
    }

    [RelayCommand]
    public void DisableAutostart()
    {
        if (!CanDisableAutostart) return;

        // First terminate the active process tree, then backup & remove autostart entries
        bool killed = _hunterService.KillProcessTree(TargetInfo.ProcessId);
        bool removed = _hunterService.DisableAutostart(TargetInfo);

        StatusMessage = removed
            ? (killed ? "✅ 已终止目标进程并安全备份清除所有自启动项" : "✅ 已安全备份并清除该目标的所有开机自启动项")
            : "未发现或无法移除自启项";
        OnPropertyChanged(nameof(CanDisableAutostart));
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
