using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using RevoSharp.App.Views.Hunter;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Hunter;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.Views;

public partial class MainWindow
{
    private HunterTargetWindow? _hunterTargetWindow;

    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnAppCategoryFilterChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string cat && ViewModel != null)
        {
            ViewModel.SelectedCategoryFilter = cat;
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
        // Always pass the full unfiltered list (AllApps) so active search filters never blind Hunter Mode matching
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

        var window = new ResidualReviewWindow(app, residuals)
        {
            Owner = this
        };

        window.ShowDialog();
        _ = ViewModel.LoadAppsAsync();
    }

    private void OnDataGridDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ViewModel.SelectedApp != null)
        {
            OnUninstallClick(sender, e);
        }
    }

    private async void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        var targets = GetTargetSelectedApps();
        if (targets.Count == 0) return;

        string titlePrompt = targets.Count == 1
            ? $"确定要卸载程序【{targets[0].DisplayName}】吗？\n\n原厂卸载向导运行完毕后，系统将自动进行深度逆向残留扫描。"
            : $"已选中 {targets.Count} 款程序，是否按顺序执行批量队列卸载并清理残留？\n（在卸载等待窗口中可随时中止后续队列）";

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
            ? $"将尝试以静默参数极速卸载【{targets[0].DisplayName}】（MSI 自动切换 /X /qn）。\n\n是否继续？"
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
        bool isBatchSilent = !forceInteractive && queue.Count > 1;
        var aggregatedBatchResiduals = new List<ResidualItem>();

        if (isBatchSilent)
        {
            ViewModel.StatusText = $"正在为批量静默卸载队列 ({queue.Count} 款软件) 创建系统还原点...";
            await RegistryBackup.CreateSystemRestorePointAsync($"RevoSharp Batch Uninstall ({queue.Count} apps)");
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

            // Check if the app's registry Uninstall key is still present (e.g. user clicked Cancel in native wizard)
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

            if (isBatchSilent)
            {
                ViewModel.StatusText = $"正在后台扫描【{app.DisplayName}】({index + 1}/{queue.Count}) 的残留项...";
                var appResiduals = await ViewModel.ResidualScanner.ScanResidualsAsync(app);
                foreach (var item in appResiduals)
                {
                    ResidualScanner.AddResidualIfUnique(aggregatedBatchResiduals, item);
                }
            }
            else
            {
                var reviewWindow = new ResidualReviewWindow(app)
                {
                    Owner = this
                };
                reviewWindow.ShowDialog();
            }
        }

        if (isBatchSilent && aggregatedBatchResiduals.Count > 0)
        {
            var combinedApp = new InstalledApp
            {
                Id = "Batch_Combined",
                DisplayName = $"批量卸载汇总 ({queue.Count} 款程序)"
            };
            var batchReviewWindow = new ResidualReviewWindow(combinedApp, aggregatedBatchResiduals)
            {
                Owner = this
            };
            batchReviewWindow.ShowDialog();
        }

        await ViewModel.LoadAppsAsync();
    }

    private void OnDirectScanResidualsClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedApp == null) return;
        var window = new ResidualReviewWindow(ViewModel.SelectedApp)
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
                initialScanMode: forcedDialog.SelectedScanMode)
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
            var reviewWindow = new ResidualReviewWindow(toolkit.AppToCleanFromLog)
            {
                Owner = this
            };
            reviewWindow.ShowDialog();
        }

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
