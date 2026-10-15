using System.Windows;
using RevoSharp.App.ViewModels;
using RevoSharp.App.Views.Hunter;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Hunter;

namespace RevoSharp.App.Views;

public partial class MainWindow
{
    private HunterTargetWindow? _hunterTargetWindow;

    public MainWindow()
    {
        InitializeComponent();
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

    private void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedApp == null) return;
        var app = ViewModel.SelectedApp;

        var result = MessageBox.Show(
            $"确定要卸载程序【{app.DisplayName}】吗？\n\n卸载向导运行完毕后，系统将自动进行深度残留文件与注册表扫描。",
            "卸载确认",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        // 1. Show waiting dialog that tracks the process tree until all uninstaller processes terminate
        var waitingDialog = new UninstallWaitingDialog(app, ViewModel.UninstallerRunner, forceInteractive: true)
        {
            Owner = this
        };

        waitingDialog.ShowDialog();

        // 2. Only proceed if user or natural process completion triggered progression
        if (waitingDialog.ShouldProceedToScan)
        {
            ShowResidualWindow(app);
        }
    }

    private void OnQuickUninstallClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedApp == null) return;
        var app = ViewModel.SelectedApp;

        var result = MessageBox.Show(
            $"将尝试以静默模式极速卸载【{app.DisplayName}】。\n若目标不支持静默模式将自动弹出常规向导。\n\n是否继续？",
            "静默快速卸载确认",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        var waitingDialog = new UninstallWaitingDialog(app, ViewModel.UninstallerRunner, forceInteractive: false)
        {
            Owner = this
        };

        waitingDialog.ShowDialog();

        if (waitingDialog.ShouldProceedToScan)
        {
            ShowResidualWindow(app);
        }
    }

    private void ShowResidualWindow(Core.Models.InstalledApp app)
    {
        var window = new ResidualReviewWindow(app)
        {
            Owner = this
        };

        window.ShowDialog();
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
