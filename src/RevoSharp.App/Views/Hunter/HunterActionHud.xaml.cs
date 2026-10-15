using System.Windows;
using RevoSharp.App.ViewModels;

namespace RevoSharp.App.Views.Hunter;

public partial class HunterActionHud : Window
{
    public HunterActionHud(HunterActionHudViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.RequestCloseAction = Close;
    }

    public void PositionNear(Point screenPoint)
    {
        var source = PresentationSource.FromVisual(this);
        double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
        double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;

        double targetX = screenPoint.X / dpiX + 20;
        double targetY = screenPoint.Y / dpiY + 20;

        // Ensure inside screen bounds
        double screenW = SystemParameters.PrimaryScreenWidth;
        double screenH = SystemParameters.PrimaryScreenHeight;

        if (targetX + 520 > screenW)
        {
            targetX = screenPoint.X / dpiX - 520;
        }
        if (targetY + 380 > screenH)
        {
            targetY = screenPoint.Y / dpiY - 380;
        }

        Left = Math.Max(10, targetX);
        Top = Math.Max(10, targetY);
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
