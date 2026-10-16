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
        Loaded += OnWindowLoadedOnce;
    }

    private async void OnWindowLoadedOnce(object sender, RoutedEventArgs e)
    {
        Loaded -= OnWindowLoadedOnce;
        await ViewModel.InitializeScanAsync();
    }

    private void OnCategoryFilterChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string cat && ViewModel != null)
        {
            ViewModel.SelectedCategory = cat;
        }
    }

    private void OnViewModeChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string mode && ViewModel != null)
        {
            ViewModel.IsTreeViewMode = string.Equals(mode, "Tree", StringComparison.OrdinalIgnoreCase);
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
        int lowConfCount = ViewModel.DisplayedResiduals.Count(r => r.IsSelected && r.Confidence == ConfidenceLevel.Low);
        if (lowConfCount > 0)
        {
            bool confirmed = FluentMessageDialog.ShowConfirm(
                this,
                "包含低置信度残留项确认",
                $"您当前勾选的待清理列表中包含 {lowConfCount} 项【低置信度】条目（可能为深度特征词模糊匹配或同系列其他版本目录）。\n\n确定已核对无误并继续备份清除吗？",
                confirmText: "确认备份并清除",
                cancelText: "返回核对",
                isWarningOrDanger: true);

            if (!confirmed) return;
        }

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
