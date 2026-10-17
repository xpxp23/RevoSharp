using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
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
        MouseLeftButtonDown += (s, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };
        PreviewKeyDown += (s, e) =>
        {
            if (e.Key == Key.Escape)
            {
                Close();
                e.Handled = true;
            }
        };
    }

    public void PositionNear(Point screenPoint)
    {
        Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        double hudWidth = DesiredSize.Width > 100 ? DesiredSize.Width : 568;
        double hudHeight = DesiredSize.Height > 100 ? DesiredSize.Height : 395;

        var source = PresentationSource.FromVisual(this);
        Matrix transform = source?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;

        double workLeft = SystemParameters.WorkArea.Left;
        double workTop = SystemParameters.WorkArea.Top;
        double workRight = SystemParameters.WorkArea.Right;
        double workBottom = SystemParameters.WorkArea.Bottom;

        var pt = new POINT { X = (int)screenPoint.X, Y = (int)screenPoint.Y };
        IntPtr hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        if (hMon != IntPtr.Zero)
        {
            var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(hMon, ref mi))
            {
                var topLeft = transform.Transform(new Point(mi.rcWork.Left, mi.rcWork.Top));
                var bottomRight = transform.Transform(new Point(mi.rcWork.Right, mi.rcWork.Bottom));
                workLeft = topLeft.X;
                workTop = topLeft.Y;
                workRight = bottomRight.X;
                workBottom = bottomRight.Y;
            }
        }

        var logicalCursor = transform.Transform(screenPoint);
        double targetX = logicalCursor.X + 16;
        double targetY = logicalCursor.Y + 16;

        if (targetX + hudWidth > workRight)
        {
            targetX = logicalCursor.X - hudWidth;
        }
        if (targetY + hudHeight > workBottom)
        {
            targetY = logicalCursor.Y - hudHeight;
        }

        Left = Math.Clamp(targetX, workLeft + 8, Math.Max(workLeft + 8, workRight - hudWidth));
        Top = Math.Clamp(targetY, workTop + 8, Math.Max(workTop + 8, workBottom - hudHeight));
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
