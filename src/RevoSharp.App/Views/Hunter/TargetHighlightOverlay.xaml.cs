using System.Windows;
using System.Windows.Media;

namespace RevoSharp.App.Views.Hunter;

public partial class TargetHighlightOverlay : Window
{
    public TargetHighlightOverlay()
    {
        InitializeComponent();
    }

    public void ShowAt(int physicalLeft, int physicalTop, int physicalWidth, int physicalHeight, bool isWarning = false)
    {
        if (physicalWidth <= 0 || physicalHeight <= 0)
        {
            Hide();
            return;
        }

        var source = PresentationSource.FromVisual(this);
        double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
        double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;

        Left = physicalLeft / dpiX;
        Top = physicalTop / dpiY;
        Width = Math.Max(10, physicalWidth / dpiX);
        Height = Math.Max(10, physicalHeight / dpiY);

        if (isWarning)
        {
            HighlightBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x44, 0x44));
            HighlightBorder.Background = new SolidColorBrush(Color.FromArgb(0x20, 0xFF, 0x44, 0x44));
        }
        else
        {
            HighlightBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(0x00, 0x80, 0xFF));
            HighlightBorder.Background = new SolidColorBrush(Color.FromArgb(0x18, 0x00, 0x80, 0xFF));
        }

        if (!IsVisible)
        {
            Show();
        }
    }
}
