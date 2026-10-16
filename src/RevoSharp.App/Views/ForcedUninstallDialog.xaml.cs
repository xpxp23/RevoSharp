using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Hunter;

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
            string selectedFile = dlg.FileName;
            // Automatically resolve .lnk shortcut target so Forced Uninstall locates the real installation directory!
            if (selectedFile.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                string? resolved = HunterService.ResolveShortcutTarget(selectedFile);
                if (!string.IsNullOrEmpty(resolved) && (File.Exists(resolved) || Directory.Exists(resolved)))
                {
                    selectedFile = resolved;
                    HintTextBlock.Text = $"🔗 已自动解析快捷方式指向的真实路径: {selectedFile}";
                }
            }

            TargetPathTextBox.Text = selectedFile;
            if (string.IsNullOrWhiteSpace(AppNameTextBox.Text))
            {
                AppNameTextBox.Text = TryExtractProductName(selectedFile);
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

    private static string TryExtractProductName(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);
                if (!string.IsNullOrWhiteSpace(vi.ProductName))
                    return vi.ProductName.Trim();
                if (!string.IsNullOrWhiteSpace(vi.FileDescription))
                    return vi.FileDescription.Trim();
            }
        }
        catch { }

        return Path.GetFileNameWithoutExtension(filePath);
    }

    private void OnStartScanClick(object sender, RoutedEventArgs e)
    {
        string name = AppNameTextBox.Text.Trim();
        string path = TargetPathTextBox.Text.Trim().Trim('"');

        if (!string.IsNullOrEmpty(path) && path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            string? resolved = HunterService.ResolveShortcutTarget(path);
            if (!string.IsNullOrEmpty(resolved))
            {
                path = resolved;
            }
        }

        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(path))
        {
            HintTextBlock.Text = "⚠️ 请至少输入目标软件名称或指定一个残留路径！";
            return;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = TryExtractProductName(path);
        }

        string installDir = string.Empty;
        string displayIcon = string.Empty;
        string publisher = "强制卸载目标";
        bool isProtectedSingle = false;

        if (!string.IsNullOrEmpty(path))
        {
            if (File.Exists(path))
            {
                displayIcon = path;
                try
                {
                    string? comp = FileVersionInfo.GetVersionInfo(path).CompanyName;
                    if (!string.IsNullOrWhiteSpace(comp)) publisher = comp.Trim();
                }
                catch { }

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
            Publisher = publisher,
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
