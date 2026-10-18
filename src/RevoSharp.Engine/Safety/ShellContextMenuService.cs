using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace RevoSharp.Engine.Safety;

/// <summary>
/// Manages Windows Explorer Shell Context Menu integration ("使用 RevoSharp 强力卸载") for .lnk shortcuts,
/// .exe applications, and Directories under HKCU\Software\Classes (compatible with Windows 10 & Windows 11).
/// </summary>
public static class ShellContextMenuService
{
    private const string VerbKeyName = "RevoSharpUninstall";
    private const string MenuDisplayText = "使用 RevoSharp 强力卸载";

    private const uint SHCNE_ASSOCCHANGED = 0x08000000;
    private const uint SHCNF_IDLIST = 0x0000;

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

    private static readonly string[] TargetClasses =
    [
        @"Software\Classes\lnkfile\shell\" + VerbKeyName,
        @"Software\Classes\exefile\shell\" + VerbKeyName,
        @"Software\Classes\Directory\shell\" + VerbKeyName
    ];

    public static bool IsContextMenuRegistered()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(TargetClasses[0] + @"\command");
            string? cmd = key?.GetValue(string.Empty) as string;
            return !string.IsNullOrWhiteSpace(cmd) && cmd.Contains("--hunt", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static bool RegisterContextMenu(string? customExecutablePath = null)
    {
        try
        {
            string exePath = customExecutablePath ?? Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                return false;

            string commandValue = $"\"{exePath}\" --hunt \"%1\"";
            string iconValue = $"\"{exePath}\",0";

            foreach (var classPath in TargetClasses)
            {
                using var shellKey = Registry.CurrentUser.CreateSubKey(classPath, writable: true);
                if (shellKey == null) continue;

                shellKey.SetValue(string.Empty, MenuDisplayText, RegistryValueKind.String);
                shellKey.SetValue("MUIVerb", MenuDisplayText, RegistryValueKind.String);
                shellKey.SetValue("Icon", iconValue, RegistryValueKind.String);

                using var cmdKey = shellKey.CreateSubKey("command", writable: true);
                cmdKey?.SetValue(string.Empty, commandValue, RegistryValueKind.String);
            }

            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool UnregisterContextMenu()
    {
        try
        {
            foreach (var classPath in TargetClasses)
            {
                Registry.CurrentUser.DeleteSubKeyTree(classPath, throwOnMissingSubKey: false);
            }

            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
