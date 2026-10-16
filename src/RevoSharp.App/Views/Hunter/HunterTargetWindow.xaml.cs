using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using Microsoft.Win32;
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
    private bool _isRightButtonDown;
    private bool _isRightDragging;
    private bool _isClickThroughApplied;
    private Point _dragStartPoint;
    private POINT _rightDragStartScreenPt;
    private double _rightDragStartLeft;
    private double _rightDragStartTop;
    private IntPtr _lastInspectedHwnd = IntPtr.Zero;
    private HunterTargetInfo? _currentTarget;
    private HunterActionHud? _currentHud;

    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int WS_EX_TRANSPARENT = 0x00000020;
    private const int WS_EX_LAYERED = 0x00080000;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

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

        double screenW = SystemParameters.WorkArea.Width;
        Left = screenW - 130;
        Top = 60;

        Loaded += (s, e) =>
        {
            var helper = new WindowInteropHelper(this);
            int exStyle = GetWindowLong(helper.Handle, GWL_EXSTYLE);
            SetWindowLong(helper.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
        };
    }

    private void SetClickThrough(bool enable)
    {
        if (_isClickThroughApplied == enable) return;
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;

        int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        if (enable)
        {
            SetWindowLong(hwnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
        }
        else
        {
            SetWindowLong(hwnd, GWL_EXSTYLE, (exStyle & ~WS_EX_TRANSPARENT) | WS_EX_TOOLWINDOW);
        }
        _isClickThroughApplied = enable;
    }

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonDown(e);

        // Allow Shift + Left Drag to simply reposition the reticle without aiming
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
        {
            DragMove();
            e.Handled = true;
            return;
        }

        _isAiming = true;
        _currentTarget = null;
        _lastInspectedHwnd = IntPtr.Zero;
        _dragStartPoint = e.GetPosition(this);
        CaptureMouse();
        Cursor = Cursors.Cross;
    }

    protected override void OnPreviewMouseRightButtonDown(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseRightButtonDown(e);
        _isRightButtonDown = true;
        _isRightDragging = false;
        GetCursorPos(out _rightDragStartScreenPt);
        _rightDragStartLeft = Left;
        _rightDragStartTop = Top;
        CaptureMouse();
        e.Handled = true;
    }

    protected override void OnPreviewMouseMove(MouseEventArgs e)
    {
        base.OnPreviewMouseMove(e);

        // 1. Handle Right-Button Drag to reposition reticle smoothly (matching ToolTip!)
        if (_isRightButtonDown && e.RightButton == MouseButtonState.Pressed)
        {
            GetCursorPos(out POINT rPt);
            double dxPhysical = rPt.X - _rightDragStartScreenPt.X;
            double dyPhysical = rPt.Y - _rightDragStartScreenPt.Y;

            if (_isRightDragging || Math.Sqrt(dxPhysical * dxPhysical + dyPhysical * dyPhysical) > 5)
            {
                _isRightDragging = true;
                var source = PresentationSource.FromVisual(this);
                double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
                double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;
                Left = _rightDragStartLeft + (dxPhysical / dpiX);
                Top = _rightDragStartTop + (dyPhysical / dpiY);
            }
            return;
        }

        // 2. Handle Left-Button Aiming Drag with HWND Caching (120+ FPS zero-lag aiming)
        if (!_isAiming) return;

        GetCursorPos(out POINT pt);
        var posInWindow = e.GetPosition(this);
        double dist = Math.Sqrt(Math.Pow(posInWindow.X - _dragStartPoint.X, 2) + Math.Pow(posInWindow.Y - _dragStartPoint.Y, 2));

        if (e.LeftButton == MouseButtonState.Pressed && dist > 5)
        {
            SetClickThrough(true);

            var thisHwnd = new WindowInteropHelper(this).Handle;
            var overlayHwnd = new WindowInteropHelper(_overlay).Handle;
            IntPtr candidateHwnd = _hunterService.GetRootWindowAtPoint(pt.X, pt.Y);

            if (candidateHwnd != IntPtr.Zero && candidateHwnd != thisHwnd && candidateHwnd != overlayHwnd)
            {
                // Only run process/version inspection when the cursor crosses into a DIFFERENT window handle!
                // Defer expensive COM/Registry autostart scan until MouseLeftButtonUp!
                if (candidateHwnd != _lastInspectedHwnd)
                {
                    _lastInspectedHwnd = candidateHwnd;
                    _currentTarget = _hunterService.InspectWindowHandle(candidateHwnd, _installedApps, includeDeepAutostartScan: false);
                }

                if (_currentTarget != null)
                {
                    var rect = _hunterService.GetWindowBoundingRect(_currentTarget.WindowHandle);
                    _overlay.ShowAt(rect.Left, rect.Top, rect.Width, rect.Height, _currentTarget.IsSystemCritical);
                }
            }
            else
            {
                _lastInspectedHwnd = IntPtr.Zero;
                _currentTarget = null;
                _overlay.Hide();
            }

            var source = PresentationSource.FromVisual(this);
            double dpiX = source?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
            double dpiY = source?.CompositionTarget?.TransformToDevice.M22 ?? 1.0;
            Left = (pt.X / dpiX) - 48;
            Top = (pt.Y / dpiY) - 48;
        }
    }

    protected override void OnPreviewMouseRightButtonUp(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseRightButtonUp(e);
        if (!_isRightButtonDown) return;

        bool wasDragging = _isRightDragging;
        _isRightButtonDown = false;
        _isRightDragging = false;
        ReleaseMouseCapture();

        if (!wasDragging && ReticleContextMenu != null)
        {
            ReticleContextMenu.PlacementTarget = this;
            ReticleContextMenu.IsOpen = true;
        }
        e.Handled = true;
    }

    protected override void OnPreviewMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonUp(e);

        if (!_isAiming) return;
        _isAiming = false;
        _lastInspectedHwnd = IntPtr.Zero;
        SetClickThrough(false);
        ReleaseMouseCapture();
        Cursor = Cursors.Hand;
        _overlay.Hide();

        if (_currentTarget != null)
        {
            // Perform deep autostart persistence scan once upon target lock-on
            if (!_currentTarget.IsSystemCritical)
            {
                _hunterService.ScanAutostartPersistence(_currentTarget);
            }

            GetCursorPos(out POINT pt);
            ShowActionHud(_currentTarget, new Point(pt.X, pt.Y));
        }
    }

    protected override void OnPreviewMouseDoubleClick(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseDoubleClick(e);
        RestoreMainWindow();
    }

    private void OnReticleDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Link;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void OnReticleFileDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            InspectFileAndOpenHud(files[0]);
        }
    }

    private void OnSelectFileTargetClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择桌面快捷方式 (.lnk) 或目标程序文件 (.exe)",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Filter = "快捷方式或程序 (*.lnk;*.exe)|*.lnk;*.exe|所有文件 (*.*)|*.*"
        };

        if (dlg.ShowDialog() == true && File.Exists(dlg.FileName))
        {
            InspectFileAndOpenHud(dlg.FileName);
        }
    }

    private void InspectFileAndOpenHud(string filePath)
    {
        var info = _hunterService.InspectFileOrShortcut(filePath, _installedApps);
        if (info != null)
        {
            GetCursorPos(out POINT pt);
            ShowActionHud(info, new Point(pt.X, pt.Y));
        }
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
        SetClickThrough(false);
        _overlay.Close();
        _currentHud?.Close();
        Close();
    }

    private void OnRestoreMainClick(object sender, RoutedEventArgs e) => RestoreMainWindow();
    private void OnExitHunterClick(object sender, RoutedEventArgs e) => RestoreMainWindow();
    private void OnOpacity100Click(object sender, RoutedEventArgs e) => Opacity = 1.0;
    private void OnOpacity75Click(object sender, RoutedEventArgs e) => Opacity = 0.75;
    private void OnOpacity50Click(object sender, RoutedEventArgs e) => Opacity = 0.5;
}
