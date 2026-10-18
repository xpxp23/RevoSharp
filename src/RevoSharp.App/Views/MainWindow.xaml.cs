using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using RevoSharp.App.Views.Hunter;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Hunter;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.Views;

public partial class MainWindow
{
    private HunterTargetWindow? _hunterTargetWindow;
    private bool _startupHuntProcessed;

    public MainWindow()
    {
        InitializeComponent();

        var cfg = SettingsSerializer.Current;
        if (cfg.WindowWidth >= MinWidth && cfg.WindowWidth <= SystemParameters.WorkArea.Width)
        {
            Width = cfg.WindowWidth;
        }
        if (cfg.WindowHeight >= MinHeight && cfg.WindowHeight <= SystemParameters.WorkArea.Height)
        {
            Height = cfg.WindowHeight;
        }

        Loaded += OnMainWindowLoaded;

        Closing += (_, _) =>
        {
            if (WindowState == WindowState.Normal)
            {
                SettingsSerializer.Current.WindowWidth = Width;
                SettingsSerializer.Current.WindowHeight = Height;
                SettingsSerializer.Save();
            }
        };

        Closed += (_, _) =>
        {
            try
            {
                _hunterTargetWindow?.CloseHunterMode();
            }
            catch { }
            Application.Current?.Shutdown();
        };
    }

    private async void OnMainWindowLoaded(object sender, RoutedEventArgs e)
    {
        if (_startupHuntProcessed || string.IsNullOrWhiteSpace(App.StartupHuntTargetPath))
            return;

        _startupHuntProcessed = true;
        string targetPath = App.StartupHuntTargetPath;
        if (!File.Exists(targetPath) && !Directory.Exists(targetPath))
            return;

        // Wait briefly for the initial installed apps scan to finish so target matching has full context
        while (ViewModel.IsLoading)
        {
            await Task.Delay(60);
        }

        var hunterService = new HunterService();
        var targetInfo = await Task.Run(() => hunterService.InspectFileOrShortcut(targetPath, ViewModel.AllApps.ToList()));
        if (targetInfo == null) return;

        if (targetInfo.IsSystemCritical)
        {
            FluentMessageDialog.ShowInfo(this, "系统核心保护", targetInfo.SystemProtectionReason);
            return;
        }

        if (!string.IsNullOrWhiteSpace(targetInfo.EffectiveApp.UninstallString))
        {
            bool runOfficialFirst = FluentMessageDialog.ShowConfirm(
                this,
                "右键强力卸载目标确认",
                $"已定位目标程序：【{targetInfo.EffectiveApp.DisplayName}】\n路径：{targetInfo.ExecutablePath}\n\n检测到该程序包含原厂卸载引导器，推荐先执行原厂卸载再深度清扫残留（也可选择直接强制扫描残留）：",
                confirmText: "先卸载再扫残留 (推荐)",
                cancelText: "跳过卸载，直接扫残留",
                isWarningOrDanger: false);

            if (runOfficialFirst)
            {
                await RunUninstallQueueAsync([targetInfo.EffectiveApp], forceInteractive: true);
                return;
            }
        }

        if (targetInfo.ProcessId > 4)
        {
            await Task.Run(() => hunterService.KillProcessTree(targetInfo.ProcessId));
        }

        var reviewWindow = new ResidualReviewWindow(
            targetInfo.EffectiveApp,
            initialResiduals: null,
            initialScanMode: SettingsSerializer.Current.DefaultScanMode,
            otherInstalledApps: ViewModel.AllApps)
        {
            Owner = this
        };
        reviewWindow.ShowDialog();
        await ViewModel.LoadAppsAsync();
    }

    private void OnAppCategoryFilterChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string cat && ViewModel != null)
        {
            ViewModel.SelectedCategoryFilter = cat;
        }
    }

    private void OnAppsDataGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ViewModel == null || AppsDataGrid == null) return;
        var selected = AppsDataGrid.SelectedItems.Cast<InstalledApp>().ToList();
        ViewModel.UpdateMultiSelection(selected);
    }

    private void OnClearMultiSelectionClick(object sender, RoutedEventArgs e)
    {
        if (AppsDataGrid == null || ViewModel == null) return;
        var primary = ViewModel.SelectedApp;
        AppsDataGrid.SelectedItems.Clear();
        if (primary != null)
        {
            AppsDataGrid.SelectedItem = primary;
        }
    }

    private List<InstalledApp> GetTargetSelectedApps()
    {
        var selected = AppsDataGrid.SelectedItems.Cast<InstalledApp>().ToList();
        if (selected.Count == 0 && ViewModel.SelectedApp != null)
        {
            selected.Add(ViewModel.SelectedApp);
        }
        return selected;
    }

    private void OnHunterModeClick(object sender, RoutedEventArgs e)
    {
        Hide();
        var hunterService = new HunterService();
        var installedApps = ViewModel.AllApps.ToList();

        _hunterTargetWindow = new HunterTargetWindow(
            this,
            hunterService,
            ViewModel.ResidualScanner,
            ViewModel.UninstallerRunner,
            installedApps,
            (app, residuals) =>
            {
                ShowResidualWindowWithResiduals(app, residuals);
            });

        _hunterTargetWindow.Show();
    }

    private void ShowResidualWindowWithResiduals(InstalledApp app, List<ResidualItem> residuals)
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();

        var window = new ResidualReviewWindow(
            app,
            residuals,
            initialScanMode: SettingsSerializer.Current.DefaultScanMode,
            otherInstalledApps: ViewModel.AllApps)
        {
            Owner = this
        };

        window.ShowDialog();
        _ = ViewModel.LoadAppsAsync();
    }

    private void OnDataGridDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source) return;
        var row = ItemsControl.ContainerFromElement(AppsDataGrid, source) as DataGridRow;
        if (row == null || ViewModel.SelectedApp == null) return;

        if (!ViewModel.IsInspectorOpen)
        {
            ViewModel.IsInspectorOpen = true;
        }
        else
        {
            ViewModel.OpenLocation();
        }
    }

    private async void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        var targets = GetTargetSelectedApps();
        if (targets.Count == 0) return;

        string titlePrompt = targets.Count == 1
            ? $"确定要卸载程序【{targets[0].DisplayName}】吗？\n\n原厂卸载向导运行完毕后，系统将自动进行深度逆向残留扫描。"
            : $"已选中 {targets.Count} 款程序，将按顺序执行批量队列卸载，并在队列完成后汇总审查清理所有残留。\n（在卸载等待窗口中可随时中止后续队列）";

        bool confirmed = FluentMessageDialog.ShowConfirm(
            this,
            "卸载确认",
            titlePrompt,
            confirmText: "开始卸载",
            cancelText: "取消",
            isWarningOrDanger: true);

        if (!confirmed) return;

        await RunUninstallQueueAsync(targets, forceInteractive: true);
    }

    private async void OnQuickUninstallClick(object sender, RoutedEventArgs e)
    {
        var targets = GetTargetSelectedApps();
        if (targets.Count == 0) return;

        string titlePrompt = targets.Count == 1
            ? $"将尝试以静默参数极速卸载【{targets[0].DisplayName}】（自动适配 MSI / Inno / NSIS / Burn 静默参数）。\n\n是否继续？"
            : $"已选中 {targets.Count} 款程序，将以静默队列模式依次快速卸载，并在队列完成后集中审查清理所有残留。\n\n是否继续？";

        bool confirmed = FluentMessageDialog.ShowConfirm(
            this,
            "静默快速卸载确认",
            titlePrompt,
            confirmText: "启动静默快卸",
            cancelText: "取消",
            isWarningOrDanger: false);

        if (!confirmed) return;

        await RunUninstallQueueAsync(targets, forceInteractive: false);
    }

    private async Task RunUninstallQueueAsync(List<InstalledApp> queue, bool forceInteractive)
    {
        bool isMultiQueue = queue.Count > 1;
        var aggregatedBatchResiduals = new List<ResidualItem>();
        var remainingInstalled = ViewModel.AllApps.Where(a => !queue.Any(q => q.Id == a.Id)).ToList();
        var processedAppNames = new List<string>();

        if (isMultiQueue)
        {
            ViewModel.StatusText = $"正在为批量卸载队列 ({queue.Count} 款软件) 创建系统还原点...";
            bool rpCreated = await RegistryBackup.CreateSystemRestorePointAsync($"RevoSharp Batch Uninstall ({queue.Count} apps)");
            if (!rpCreated)
            {
                ViewModel.StatusText = "系统还原点未创建（系统保护可能未开启或处于 24 小时冷却期），将继续执行合并注册表与回收站备份保护...";
            }
        }

        for (int index = 0; index < queue.Count; index++)
        {
            var app = queue[index];
            var waitingDialog = new UninstallWaitingDialog(
                app,
                ViewModel.UninstallerRunner,
                forceInteractive,
                currentQueueIndex: index + 1,
                totalQueueCount: queue.Count)
            {
                Owner = this
            };

            waitingDialog.ShowDialog();

            if (waitingDialog.AbortEntireQueue)
            {
                ViewModel.StatusText = $"已中止批量卸载队列（已完成 {index} / {queue.Count} 款）。";
                break;
            }

            if (!waitingDialog.ShouldProceedToScan)
                continue;

            if (!waitingDialog.ForcedByUser && UninstallerRunner.IsAppRegistryEntryStillPresent(app))
            {
                bool confirmStillInstalled = FluentMessageDialog.ShowConfirm(
                    this,
                    "检测到程序仍未卸载",
                    $"检测到【{app.DisplayName}】的注册表安装项仍然存在，原厂卸载可能已被取消或未完成。\n\n是否仍要强制进入残留扫描（注意：强制清理将移除程序主目录）？",
                    confirmText: "强制扫描残留",
                    cancelText: "跳过此软件",
                    isWarningOrDanger: true);

                if (!confirmStillInstalled)
                {
                    continue;
                }
            }

            processedAppNames.Add(app.DisplayName);

            if (isMultiQueue)
            {
                ViewModel.StatusText = $"正在后台扫描【{app.DisplayName}】({index + 1}/{queue.Count}) 的残留项...";
                var appResiduals = await ViewModel.ResidualScanner.ScanResidualsAsync(
                    app,
                    SettingsSerializer.Current.DefaultScanMode,
                    otherInstalledApps: remainingInstalled);
                foreach (var item in appResiduals)
                {
                    item.SourceAppName = app.DisplayName;
                    ResidualScanner.AddResidualIfUnique(aggregatedBatchResiduals, item);
                }
            }
            else
            {
                var reviewWindow = new ResidualReviewWindow(
                    app,
                    initialResiduals: null,
                    initialScanMode: SettingsSerializer.Current.DefaultScanMode,
                    otherInstalledApps: ViewModel.AllApps)
                {
                    Owner = this
                };
                reviewWindow.ShowDialog();
            }
        }

        if (isMultiQueue && processedAppNames.Count > 0)
        {
            if (aggregatedBatchResiduals.Count > 0)
            {
                string joinedNames = string.Join("、", processedAppNames.Take(3)) +
                                     (processedAppNames.Count > 3 ? $" 等 {processedAppNames.Count} 款" : string.Empty);
                var combinedApp = new InstalledApp
                {
                    Id = "Batch_Combined",
                    DisplayName = $"批量卸载 ({joinedNames})"
                };
                var batchReviewWindow = new ResidualReviewWindow(
                    combinedApp,
                    aggregatedBatchResiduals,
                    initialScanMode: SettingsSerializer.Current.DefaultScanMode,
                    otherInstalledApps: remainingInstalled)
                {
                    Owner = this
                };
                batchReviewWindow.ShowDialog();
            }
            else
            {
                FluentMessageDialog.ShowInfo(
                    this,
                    "批量卸载完成",
                    $"已完成 {processedAppNames.Count} 款程序的队列卸载，原厂卸载程序均已清理干净，未检测到遗留文件或注册表残余！");
            }
        }

        await ViewModel.LoadAppsAsync();
    }

    private void OnDirectScanResidualsClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedApp == null) return;
        var window = new ResidualReviewWindow(
            ViewModel.SelectedApp,
            initialResiduals: null,
            initialScanMode: SettingsSerializer.Current.DefaultScanMode,
            otherInstalledApps: ViewModel.AllApps)
        {
            Owner = this
        };
        window.ShowDialog();
        _ = ViewModel.LoadAppsAsync();
    }

    private void OnForcedUninstallClick(object sender, RoutedEventArgs e)
    {
        var forcedDialog = new ForcedUninstallDialog
        {
            Owner = this
        };

        if (forcedDialog.ShowDialog() == true && forcedDialog.ConstructedApp != null)
        {
            var reviewWindow = new ResidualReviewWindow(
                forcedDialog.ConstructedApp,
                initialResiduals: null,
                initialScanMode: forcedDialog.SelectedScanMode,
                otherInstalledApps: ViewModel.AllApps)
            {
                Owner = this
            };
            reviewWindow.ShowDialog();
            _ = ViewModel.LoadAppsAsync();
        }
    }

    private void OnToolkitClick(object sender, RoutedEventArgs e)
    {
        var toolkit = new ToolkitDialog
        {
            Owner = this
        };

        if (toolkit.ShowDialog() == true && toolkit.AppToCleanFromLog != null)
        {
            var reviewWindow = new ResidualReviewWindow(
                toolkit.AppToCleanFromLog,
                initialResiduals: null,
                initialScanMode: SettingsSerializer.Current.DefaultScanMode,
                otherInstalledApps: ViewModel.AllApps)
            {
                Owner = this
            };
            reviewWindow.ShowDialog();
        }

        ViewModel.SyncSettingsState();
        _ = ViewModel.LoadAppsAsync();
    }

    private void OnMonitorInstallClick(object sender, RoutedEventArgs e)
    {
        var dialog = new MonitorDialog
        {
            Owner = this
        };

        dialog.ShowDialog();
        _ = ViewModel.LoadAppsAsync();
    }
}
