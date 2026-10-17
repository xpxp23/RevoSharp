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

    private void OnDialogDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Link
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDialogFileDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            ApplySelectedTargetPath(paths[0]);
        }
    }

    private void ApplySelectedTargetPath(string selectedPath)
    {
        if (string.IsNullOrWhiteSpace(selectedPath)) return;

        if (selectedPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            string? resolved = HunterService.ResolveShortcutTarget(selectedPath);
            if (!string.IsNullOrEmpty(resolved) && (File.Exists(resolved) || Directory.Exists(resolved)))
            {
                selectedPath = resolved;
                HintTextBlock.Text = $"已自动解析快捷方式指向的真实路径: {selectedPath}";
            }
        }

        TargetPathTextBox.Text = selectedPath;
        if (string.IsNullOrWhiteSpace(AppNameTextBox.Text))
        {
            if (Directory.Exists(selectedPath))
            {
                AppNameTextBox.Text = Path.GetFileName(selectedPath.TrimEnd('\\', '/'));
            }
            else
            {
                AppNameTextBox.Text = TryExtractProductName(selectedPath);
            }
        }
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
            ApplySelectedTargetPath(dlg.FileName);
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
            ApplySelectedTargetPath(dlg.FolderName);
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
            HintTextBlock.Text = "请至少输入目标软件名称或指定一个残留路径。";
            return;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = Directory.Exists(path)
                ? Path.GetFileName(path.TrimEnd('\\', '/'))
                : TryExtractProductName(path);
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
                    HintTextBlock.Text = "所选目录为系统或用户共享根目录，已仅按名称执行安全扫描。";
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
