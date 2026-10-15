using System.Windows;
using System.Windows.Controls;
using RevoSharp.App.ViewModels;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.App.Views;

public partial class ResidualReviewWindow
{
    public ResidualReviewViewModel ViewModel { get; }

    public ResidualReviewWindow(
        InstalledApp app,
        List<ResidualItem>? initialResiduals = null,
        ScanMode initialScanMode = ScanMode.Moderate)
    {
        InitializeComponent();
        ViewModel = new ResidualReviewViewModel(app, initialResiduals)
        {
            CurrentScanMode = initialScanMode
        };
        DataContext = ViewModel;

        ScanModeComboBox.SelectedIndex = initialScanMode switch
        {
            ScanMode.Safe => 0,
            ScanMode.Advanced => 2,
            _ => 1
        };

        AppNameTextBlock.Text = $"【{app.DisplayName}】深度残留清单";
        Loaded += async (s, e) => await ViewModel.InitializeScanAsync();
    }

    private void OnCategoryFilterChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string cat && ViewModel != null)
        {
            ViewModel.SelectedCategory = cat;
        }
    }

    private void OnScanModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded && ScanModeComboBox != null && ViewModel != null)
        {
            ViewModel.CurrentScanMode = ScanModeComboBox.SelectedIndex switch
            {
                0 => ScanMode.Safe,
                2 => ScanMode.Advanced,
                _ => ScanMode.Moderate
            };
            _ = ViewModel.ExecuteScanAsync();
        }
    }

    private async void OnCleanAllClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.CleanAllSelectedSilentAsync(() =>
        {
            Close();
        });
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
