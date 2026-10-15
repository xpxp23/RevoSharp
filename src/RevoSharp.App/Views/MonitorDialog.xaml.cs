using System.Windows;

namespace RevoSharp.App.Views;

public partial class MonitorDialog
{
    public MonitorDialog()
    {
        InitializeComponent();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.IsMonitoring)
        {
            var res = MessageBox.Show("当前正在监视安装过程，确定要取消并放弃本次记录吗？", "警告", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res != MessageBoxResult.Yes) return;
        }
        Close();
    }

    private async void OnSaveClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.StopAndSaveAsync(() =>
        {
            Close();
        });
    }
}
