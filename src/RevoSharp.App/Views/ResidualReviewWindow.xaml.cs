using System.Windows;
using System.Windows.Controls;
using RevoSharp.App.ViewModels;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.App.Views;

public partial class ResidualReviewWindow
{
    public ResidualReviewViewModel ViewModel { get; }

    public ResidualReviewWindow(InstalledApp app, List<ResidualItem>? initialResiduals = null)
    {
        InitializeComponent();
        ViewModel = new ResidualReviewViewModel(app, initialResiduals);
        DataContext = ViewModel;

        AppNameTextBlock.Text = $"【{app.DisplayName}】深度残留清单";
        Loaded += async (s, e) => await ViewModel.InitializeScanAsync();
    }

    private void OnCategoryFilterChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string cat)
        {
            ViewModel.SelectedCategory = cat;
        }
    }

    private void OnScanModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded && ScanModeComboBox != null)
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
        // Zero modal popup! Directly execute silent backup + delete and auto-close!
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
