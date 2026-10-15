using System.Diagnostics;
using Microsoft.Win32;

namespace RevoSharp.Engine.Safety;

public static class RegistryBackup
{
    private static readonly string BackupDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp",
        "Backups"
    );

    /// <summary>
    /// Exports the target registry key to a .reg file in the Backups folder before deletion.
    /// </summary>
    public static async Task<string?> ExportKeyAsync(string fullRegistryPath, string appName)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (!Directory.Exists(BackupDir))
                {
                    Directory.CreateDirectory(BackupDir);
                }

                string safeAppName = string.Join("_", appName.Split(Path.GetInvalidFileNameChars()));
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string backupPath = Path.Combine(BackupDir, $"{safeAppName}_{timestamp}.reg");

                var psi = new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export \"{fullRegistryPath}\" \"{backupPath}\" /y",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);

                return File.Exists(backupPath) ? backupPath : null;
            }
            catch
            {
                return null;
            }
        });
    }

    /// <summary>
    /// Deletes a registry key safely.
    /// </summary>
    public static bool DeleteKey(string hiveName, string subKeyPath)
    {
        try
        {
            var hive = ParseHive(hiveName);
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            baseKey.DeleteSubKeyTree(subKeyPath, false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Deletes a registry value safely.
    /// </summary>
    public static bool DeleteValue(string hiveName, string subKeyPath, string valueName)
    {
        try
        {
            var hive = ParseHive(hiveName);
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(subKeyPath, true);
            if (key != null)
            {
                key.DeleteValue(valueName, false);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static RegistryHive ParseHive(string name)
    {
        return name.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            _ => RegistryHive.CurrentUser
        };
    }
}
