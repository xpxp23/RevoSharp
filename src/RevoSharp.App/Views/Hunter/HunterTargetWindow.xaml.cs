using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using RevoSharp.App.ViewModels;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Hunter;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.App.Views.Hunter;

public partial class HunterTargetWindow : Window
{
    private readonly Window _mainWindow;
    private readonly HunterService _hunterService;
    private readonly ResidualScanner _residualScanner;
    private readonly UninstallerRunner _uninstallerRunner;
    private readonly List<InstalledApp> _installedApps;
    private readonly Action<InstalledApp, List<ResidualItem>> _openReviewCallback;

    private readonly TargetHighlightOverlay _overlay;
    private bool _isAiming;
    private Point _dragStartPoint;
    private HunterTargetInfo? _currentTarget;
    private HunterActionHud? _currentHud;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    public HunterTargetWindow(
        Window mainWindow,
        HunterService hunterService,
        ResidualScanner residualScanner,
        UninstallerRunner uninstallerRunner,
        List<InstalledApp> installedApps,
        Action<InstalledApp, List<ResidualItem>> openReviewCallback)
    {
        InitializeComponent();
        _mainWindow = mainWindow;
        _hunterService = hunterService;
        _residualScanner = residualScanner;
        _uninstallerRunner = uninstallerRunner;
        _installedApps = installedApps;
        _openReviewCallback = openReviewCallback;

        _overlay = new TargetHighlightOverlay();

        // Position at top-right of primary screen by default
        double screenW = SystemParameters.PrimaryScreenWidth;
        Left = screenW - 120;
        Top = 80;

        Loaded += (s, e) =>
        {
            // Set ToolWindow style so it doesn't show in Alt-Tab
            var helper = new System.Windows.Interop.WindowInteropHelper(this);
            SetWindowToolWindow(helper.Handle);
        };
    }

    private static void SetWindowToolWindow(IntPtr hWnd)
    {
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;
        [DllImport("user32.dll")]
        static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")]
        static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        int exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
        SetWindowLong(hWnd, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
    }

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonDown(e);
        _isAiming = true;
        _currentTarget = null;
        _dragStartPoint = e.GetPosition(this);
        CaptureMouse();
        Cursor = Cursors.Cross;
    }

    protected override void OnPreviewMouseMove(MouseEventArgs e)
    {
        base.OnPreviewMouseMove(e);

        if (!_isAiming) return;

        GetCursorPos(out POINT pt);

        // Check if mouse is still inside the target window (allow repositioning the widget)
        var posInWindow = e.GetPosition(this);
        double dist = Math.Sqrt(Math.Pow(posInWindow.X - _dragStartPoint.X, 2) + Math.Pow(posInWindow.Y - _dragStartPoint.Y, 2));

        if (e.LeftButton == MouseButtonState.Pressed && dist > 5)
        {
            // Inspect window under cursor
            var target = _hunterService.InspectPoint(pt.X, pt.Y, _installedApps);
            var thisHwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            var overlayHwnd = new System.Windows.Interop.WindowInteropHelper(_overlay).Handle;

            if (target != null && target.WindowHandle != thisHwnd && target.WindowHandle != overlayHwnd)
            {
                _currentTarget = target;
                var rect = _hunterService.GetWindowBoundingRect(target.WindowHandle);
                _overlay.ShowAt(rect.Left, rect.Top, rect.Width, rect.Height, target.IsSystemCritical);
            }
            else
            {
                _overlay.Hide();
            }

            // Follow cursor slightly or move widget
            var source = PresentationSource.FromVisual(this);
            double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
            double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;
            Left = (pt.X / dpiX) - 34;
            Top = (pt.Y / dpiY) - 34;
        }
    }

    protected override void OnPreviewMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonUp(e);

        if (!_isAiming) return;
        _isAiming = false;
        ReleaseMouseCapture();
        Cursor = Cursors.Hand;
        _overlay.Hide();

        if (_currentTarget != null)
        {
            GetCursorPos(out POINT pt);
            ShowActionHud(_currentTarget, new Point(pt.X, pt.Y));
        }
    }

    protected override void OnPreviewMouseDoubleClick(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseDoubleClick(e);
        RestoreMainWindow();
    }

    private void ShowActionHud(HunterTargetInfo target, Point screenPoint)
    {
        _currentHud?.Close();

        var vm = new HunterActionHudViewModel(
            target,
            _hunterService,
            _residualScanner,
            _uninstallerRunner);

        vm.RequestRestoreMainWindowAction = RestoreMainWindow;
        vm.RequestOpenReviewAction = (app, residuals) =>
        {
            _currentHud?.Close();
            CloseHunterMode();
            _openReviewCallback(app, residuals);
        };

        _currentHud = new HunterActionHud(vm);
        _currentHud.PositionNear(screenPoint);
        _currentHud.Show();
    }

    public void RestoreMainWindow()
    {
        CloseHunterMode();
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    public void CloseHunterMode()
    {
        _overlay.Close();
        _currentHud?.Close();
        Close();
    }

    private void OnRestoreMainClick(object sender, RoutedEventArgs e)
    {
        RestoreMainWindow();
    }

    private void OnExitHunterClick(object sender, RoutedEventArgs e)
    {
        RestoreMainWindow();
    }

    private void OnOpacity100Click(object sender, RoutedEventArgs e) => Opacity = 1.0;
    private void OnOpacity75Click(object sender, RoutedEventArgs e) => Opacity = 0.75;
    private void OnOpacity50Click(object sender, RoutedEventArgs e) => Opacity = 0.5;
}
