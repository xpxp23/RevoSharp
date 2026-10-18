using System.Windows;
using Wpf.Ui.Controls;

namespace RevoSharp.App.Views;

public partial class FluentMessageDialog
{
    public FluentMessageDialog(
        string title,
        string message,
        string confirmText = "确定继续",
        string cancelText = "取消",
        bool isWarningOrDanger = false,
        bool isInfoOnly = false)
    {
        InitializeComponent();
        Title = title;
        DialogTitleBar.Title = title;
        MessageTextBlock.Text = message;
        ConfirmButton.Content = confirmText;
        CancelButton.Content = cancelText;

        if (isInfoOnly)
        {
            CancelButton.Visibility = Visibility.Collapsed;
            ConfirmButton.Appearance = ControlAppearance.Primary;
            PromptSymbolIcon.Symbol = SymbolRegular.CheckmarkCircle24;
            PromptSymbolIcon.SetResourceReference(ForegroundProperty, "RevoAccentGreenBrush");
            IconBadgeBorder.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "RevoTagGreenBgBrush");
        }
        else if (isWarningOrDanger)
        {
            ConfirmButton.Appearance = ControlAppearance.Danger;
            PromptSymbolIcon.Symbol = SymbolRegular.Warning24;
            PromptSymbolIcon.SetResourceReference(ForegroundProperty, "RevoWarningIconBrush");
            IconBadgeBorder.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "RevoWarningBadgeBgBrush");
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
        var dlg = new FluentMessageDialog(title, message, confirmText, cancelText, isWarningOrDanger, isInfoOnly: false);
        if (owner != null && owner.IsLoaded)
        {
            dlg.Owner = owner;
        }
        return dlg.ShowDialog() == true;
    }

    public static void ShowInfo(
        Window? owner,
        string title,
        string message,
        string okText = "知道了")
    {
        var dlg = new FluentMessageDialog(title, message, okText, string.Empty, isWarningOrDanger: false, isInfoOnly: true);
        if (owner != null && owner.IsLoaded)
        {
            dlg.Owner = owner;
        }
        dlg.ShowDialog();
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
