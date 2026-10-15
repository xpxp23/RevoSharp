using System.Windows;
using System.Windows.Input;
using RevoSharp.App.Views.Hunter;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Hunter;

namespace RevoSharp.App.Views;

public partial class MainWindow
{
    private HunterTargetWindow? _hunterTargetWindow;

    public MainWindow()
    {
        InitializeComponent();
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
        var installedApps = ViewModel.Apps.ToList();

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

    private void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        var targets = GetTargetSelectedApps();
        if (targets.Count == 0) return;

        string titlePrompt = targets.Count == 1
            ? $"确定要卸载程序【{targets[0].DisplayName}】吗？\n\n原厂卸载向导运行完毕后，系统将自动进行深度逆向残留扫描。"
            : $"已选中 {targets.Count} 款程序，是否按顺序执行批量队列卸载并清理残留？";

        var result = MessageBox.Show(
            titlePrompt,
            "卸载确认",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        RunUninstallQueue(targets, forceInteractive: true);
    }

    private void OnQuickUninstallClick(object sender, RoutedEventArgs e)
    {
        var targets = GetTargetSelectedApps();
        if (targets.Count == 0) return;

        string titlePrompt = targets.Count == 1
            ? $"将尝试以静默参数极速卸载【{targets[0].DisplayName}】（MSI 自动切换 /X /qn）。\n\n是否继续？"
            : $"已选中 {targets.Count} 款程序，将以静默队列模式依次快速卸载并扫描残留。\n\n是否继续？";

        var result = MessageBox.Show(
            titlePrompt,
            "静默快速卸载确认",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        RunUninstallQueue(targets, forceInteractive: false);
    }

    private void RunUninstallQueue(List<InstalledApp> queue, bool forceInteractive)
    {
        foreach (var app in queue)
        {
            var waitingDialog = new UninstallWaitingDialog(app, ViewModel.UninstallerRunner, forceInteractive)
            {
                Owner = this
            };

            waitingDialog.ShowDialog();

            if (!waitingDialog.ShouldProceedToScan)
                continue;

            // Check if the app's registry Uninstall key is still present (e.g. user clicked Cancel in native wizard)
            if (!waitingDialog.ForcedByUser && UninstallerRunner.IsAppRegistryEntryStillPresent(app))
            {
                var confirmStillInstalled = MessageBox.Show(
                    $"检测到【{app.DisplayName}】的注册表安装项仍然存在，原厂卸载可能已被取消或未完成。\n\n是否仍要强制进入残留扫描（注意：强制清理将移除程序主目录）？",
                    "检测到程序仍未卸载",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (confirmStillInstalled != MessageBoxResult.Yes)
                {
                    continue;
                }
            }

            var reviewWindow = new ResidualReviewWindow(app)
            {
                Owner = this
            };
            reviewWindow.ShowDialog();
        }

        _ = ViewModel.LoadAppsAsync();
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
