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

    private static readonly IntPtr HWND_TOPMOST = new(-1);
    private const uint SWP_NOACTIVATE = 0x0010;
    private const uint SWP_SHOWWINDOW = 0x0040;

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

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

        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd != IntPtr.Zero)
        {
            // Position directly in Win32 physical screen coordinates so mixed-DPI multi-monitor setups align 100% accurately
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                physicalLeft,
                physicalTop,
                Math.Max(10, physicalWidth),
                Math.Max(10, physicalHeight),
                SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
        else
        {
            var source = PresentationSource.FromVisual(this);
            Matrix transform = source?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;
            var topLeft = transform.Transform(new Point(physicalLeft, physicalTop));
            var size = transform.Transform(new Vector(physicalWidth, physicalHeight));

            Left = topLeft.X;
            Top = topLeft.Y;
            Width = Math.Max(10, size.X);
            Height = Math.Max(10, size.Y);
        }
    }
}
