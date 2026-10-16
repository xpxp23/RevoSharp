using System.Windows;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace RevoSharp.App.Views;

public partial class FluentMessageDialog
{
    public FluentMessageDialog(
        string title,
        string message,
        string confirmText = "确定继续",
        string cancelText = "取消",
        bool isWarningOrDanger = false)
    {
        InitializeComponent();
        Title = title;
        DialogTitleBar.Title = title;
        MessageTextBlock.Text = message;
        ConfirmButton.Content = confirmText;
        CancelButton.Content = cancelText;

        if (isWarningOrDanger)
        {
            ConfirmButton.Appearance = ControlAppearance.Danger;
            PromptSymbolIcon.Symbol = SymbolRegular.Warning24;
            PromptSymbolIcon.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x99, 0x66));
            IconBadgeBorder.Background = new SolidColorBrush(Color.FromArgb(0x28, 0xFF, 0x66, 0x44));
        }
    }

    public static bool ShowConfirm(
        Window? owner,
        string title,
        string message,
        string confirmText = "确定继续",
        string cancelText = "取消",
        bool isWarningOrDanger = false)
    {
        var dlg = new FluentMessageDialog(title, message, confirmText, cancelText, isWarningOrDanger);
        if (owner != null && owner.IsLoaded)
        {
            dlg.Owner = owner;
        }
        return dlg.ShowDialog() == true;
    }

    private void OnConfirmClick(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
