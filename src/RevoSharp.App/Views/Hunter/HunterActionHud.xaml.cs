using System.Runtime.InteropServices;
using System.Windows;
using RevoSharp.App.ViewModels;

namespace RevoSharp.App.Views.Hunter;

public partial class HunterActionHud : Window
{
    private const uint MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(POINT pt, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    public HunterActionHud(HunterActionHudViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.RequestCloseAction = Close;
        MouseLeftButtonDown += (s, e) => { if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) DragMove(); };
    }

    public void PositionNear(Point screenPoint)
    {
        var source = PresentationSource.FromVisual(this);
        double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
        double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;

        double workLeft = 0;
        double workTop = 0;
        double workRight = SystemParameters.WorkArea.Width;
        double workBottom = SystemParameters.WorkArea.Height;

        var pt = new POINT { X = (int)screenPoint.X, Y = (int)screenPoint.Y };
        IntPtr hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        if (hMon != IntPtr.Zero)
        {
            var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(hMon, ref mi))
            {
                workLeft = mi.rcWork.Left / dpiX;
                workTop = mi.rcWork.Top / dpiY;
                workRight = mi.rcWork.Right / dpiX;
                workBottom = mi.rcWork.Bottom / dpiY;
            }
        }

        const double hudWidth = 560;
        const double hudHeight = 400;

        double targetX = screenPoint.X / dpiX + 16;
        double targetY = screenPoint.Y / dpiY + 16;

        if (targetX + hudWidth > workRight)
        {
            targetX = screenPoint.X / dpiX - hudWidth;
        }
        if (targetY + hudHeight > workBottom)
        {
            targetY = screenPoint.Y / dpiY - hudHeight;
        }

        Left = Math.Clamp(targetX, workLeft + 8, Math.Max(workLeft + 8, workRight - hudWidth));
        Top = Math.Clamp(targetY, workTop + 8, Math.Max(workTop + 8, workBottom - hudHeight));
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
