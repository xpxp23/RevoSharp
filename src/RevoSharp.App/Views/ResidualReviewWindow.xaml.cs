using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
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
        ScanMode initialScanMode = ScanMode.Moderate,
        IReadOnlyList<InstalledApp>? otherInstalledApps = null)
    {
        InitializeComponent();
        ViewModel = new ResidualReviewViewModel(app, initialResiduals, otherInstalledApps)
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

        // Ensure right-clicking any TreeViewItem immediately selects it before ContextMenu opens
        RegTreeView.PreviewMouseRightButtonDown += OnTreeViewPreviewMouseRightButtonDown;
        FileTreeView.PreviewMouseRightButtonDown += OnTreeViewPreviewMouseRightButtonDown;
    }

    private static void OnTreeViewPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source) return;
        DependencyObject? current = source;
        while (current != null && current is not TreeViewItem)
        {
            current = VisualTreeHelper.GetParent(current);
        }

        if (current is TreeViewItem item)
        {
            item.IsSelected = true;
            item.Focus();
        }
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

    private void OnRegTreeOpenLocationClick(object sender, RoutedEventArgs e)
    {
        if (RegTreeView?.SelectedItem != null)
        {
            ViewModel.OpenTreeNodeLocation(RegTreeView.SelectedItem);
        }
    }

    private void OnRegTreeCopyPathClick(object sender, RoutedEventArgs e)
    {
        if (RegTreeView?.SelectedItem != null)
        {
            ViewModel.CopyTreeNodePath(RegTreeView.SelectedItem);
        }
    }

    private void OnFileTreeOpenLocationClick(object sender, RoutedEventArgs e)
    {
        if (FileTreeView?.SelectedItem != null)
        {
            ViewModel.OpenTreeNodeLocation(FileTreeView.SelectedItem);
        }
    }

    private void OnFileTreeCopyPathClick(object sender, RoutedEventArgs e)
    {
        if (FileTreeView?.SelectedItem != null)
        {
            ViewModel.CopyTreeNodePath(FileTreeView.SelectedItem);
        }
    }

    private async void OnCleanAllClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.GetTotalSelectedCount() == 0)
        {
            ViewModel.StatusMessage = "请先勾选至少一项需要清理的残留条目，或点击“放弃并关闭”。";
            return;
        }

        int lowConfCount = ViewModel.GetSelectedLowConfidenceCount();
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
