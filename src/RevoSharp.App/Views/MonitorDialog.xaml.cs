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

    private void OnDialogDragOver(object sender, DragEventArgs e)
    {
        e.Effects = (!ViewModel.IsMonitoring && e.Data.GetDataPresent(DataFormats.FileDrop))
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDialogFileDrop(object sender, DragEventArgs e)
    {
        if (ViewModel.IsMonitoring || !e.Data.GetDataPresent(DataFormats.FileDrop))
            return;

        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            ViewModel.ApplyDroppedInstallerPath(files[0]);
        }
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
