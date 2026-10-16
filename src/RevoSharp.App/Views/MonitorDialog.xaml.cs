using System.ComponentModel;
using System.Windows;

namespace RevoSharp.App.Views;

public partial class MonitorDialog
{
    private bool _isSavedAndClosing;

    public MonitorDialog()
    {
        InitializeComponent();
        Closing += OnWindowClosing;
    }

    private void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (!_isSavedAndClosing && ViewModel.IsMonitoring)
        {
            bool confirmed = FluentMessageDialog.ShowConfirm(
                this,
                "中止安装监控确认",
                "当前正在监听安装过程，确定要中止监听并丢弃本次记录吗？",
                confirmText: "确定中止",
                cancelText: "继续监听",
                isWarningOrDanger: true);

            if (!confirmed)
            {
                e.Cancel = true;
                return;
            }

            ViewModel.CancelAndDispose();
        }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private async void OnSaveClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.StopAndSaveAsync(() =>
        {
            _isSavedAndClosing = true;
            Close();
        });
    }
}
