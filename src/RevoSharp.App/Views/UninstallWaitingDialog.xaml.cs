using System.Windows;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Execution;

namespace RevoSharp.App.Views;

public partial class UninstallWaitingDialog
{
    private readonly InstalledApp _app;
    private readonly UninstallerRunner _runner;
    private readonly bool _forceInteractive;
    private readonly CancellationTokenSource _cts = new();

    public bool ShouldProceedToScan { get; private set; }
    public bool ForcedByUser { get; private set; }

    public UninstallWaitingDialog(InstalledApp app, UninstallerRunner runner, bool forceInteractive)
    {
        InitializeComponent();
        _app = app;
        _runner = runner;
        _forceInteractive = forceInteractive;

        AppNameTextBlock.Text = $"正在卸载【{app.DisplayName}】";
        Loaded += OnLoaded;
        Closed += (s, e) => _cts.Cancel();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            bool success = await _runner.RunAndTrackUninstallerAsync(
                _app,
                _forceInteractive,
                status => Dispatcher.InvokeAsync(() => StatusTextBlock.Text = status),
                _cts.Token);

            if (!_cts.IsCancellationRequested && success)
            {
                ShouldProceedToScan = true;
                DialogResult = true;
                Close();
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = $"执行异常: {ex.Message}";
        }
    }

    private void OnForceProceedClick(object sender, RoutedEventArgs e)
    {
        ForcedByUser = true;
        ShouldProceedToScan = true;
        _cts.Cancel();
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        ShouldProceedToScan = false;
        _cts.Cancel();
        DialogResult = false;
        Close();
    }
}
