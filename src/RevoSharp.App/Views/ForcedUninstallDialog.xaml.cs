using System.IO;
using System.Windows;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.App.Views;

public partial class ForcedUninstallDialog
{
    public InstalledApp? ConstructedApp { get; private set; }
    public ScanMode SelectedScanMode { get; private set; } = ScanMode.Advanced;

    public ForcedUninstallDialog()
    {
        InitializeComponent();
    }

    private void OnBrowseFileClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择残留可执行文件或快捷方式",
            Filter = "可执行程序或快捷方式 (*.exe;*.dll;*.lnk)|*.exe;*.dll;*.lnk|所有文件 (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            TargetPathTextBox.Text = dlg.FileName;
            if (string.IsNullOrWhiteSpace(AppNameTextBox.Text))
            {
                AppNameTextBox.Text = Path.GetFileNameWithoutExtension(dlg.FileName);
            }
        }
    }

    private void OnBrowseFolderClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "选择残留安装文件夹"
        };
        if (dlg.ShowDialog() == true)
        {
            TargetPathTextBox.Text = dlg.FolderName;
            if (string.IsNullOrWhiteSpace(AppNameTextBox.Text))
            {
                AppNameTextBox.Text = Path.GetFileName(dlg.FolderName.TrimEnd('\\', '/'));
            }
        }
    }

    private void OnStartScanClick(object sender, RoutedEventArgs e)
    {
        string name = AppNameTextBox.Text.Trim();
        string path = TargetPathTextBox.Text.Trim().Trim('"');

        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(path))
        {
            HintTextBlock.Text = "⚠️ 请至少输入目标软件名称或指定一个残留路径！";
            return;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = Path.GetFileNameWithoutExtension(path);
        }

        string installDir = string.Empty;
        string displayIcon = string.Empty;
        bool isProtectedSingle = false;

        if (!string.IsNullOrEmpty(path))
        {
            if (File.Exists(path))
            {
                displayIcon = path;
                string? dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !AppLocator.IsProtectedSharedDirectory(dir))
                {
                    installDir = dir;
                }
                else
                {
                    isProtectedSingle = true;
                }
            }
            else if (Directory.Exists(path))
            {
                if (!AppLocator.IsProtectedSharedDirectory(path))
                {
                    installDir = path;
                }
                else
                {
                    HintTextBlock.Text = "⚠️ 所选目录为系统或用户共享根目录，已仅按名称执行安全扫描。";
                }
            }
        }

        SelectedScanMode = ScanModeCombo.SelectedIndex switch
        {
            0 => ScanMode.Safe,
            1 => ScanMode.Moderate,
            _ => ScanMode.Advanced
        };

        ConstructedApp = new InstalledApp
        {
            Id = $"Forced_{Guid.NewGuid():N}",
            DisplayName = name,
            Publisher = "强制卸载目标",
            InstallLocation = installDir,
            DisplayIcon = displayIcon,
            IsProtectedSingleFile = isProtectedSingle
        };

        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
