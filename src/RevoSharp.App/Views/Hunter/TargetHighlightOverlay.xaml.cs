using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace RevoSharp.App.Views.Hunter;

public partial class TargetHighlightOverlay : Window
{
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int WS_EX_TRANSPARENT = 0x00000020;
    private const int WS_EX_LAYERED = 0x00080000;

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    public TargetHighlightOverlay()
    {
        InitializeComponent();
        SourceInitialized += (s, e) =>
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            SetWindowLong(hwnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
        };
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
