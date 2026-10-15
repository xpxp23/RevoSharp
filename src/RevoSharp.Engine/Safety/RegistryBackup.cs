using System.Diagnostics;
using System.Management;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Safety;

public static class RegistryBackup
{
    public static readonly string BackupDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp",
        "Backups"
    );

    private static int _exportCounter;

    /// <summary>
    /// Exports the target registry key to a uniquely named .reg file before deletion (fixing same-second overwrite bug).
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

                string safeAppName = AppLocator.SanitizeFileName(appName);
                int seq = Interlocked.Increment(ref _exportCounter);
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                string backupPath = Path.Combine(BackupDir, $"{safeAppName}_{timestamp}_{seq:D3}.reg");

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
    /// Exports a single registry value into a standard .reg file before deleting that value.
    /// </summary>
    public static async Task<string?> ExportValueAsync(string fullKeyPath, string valueName, string? valueData, string appName)
    {
        return await Task.Run(async () =>
        {
            try
            {
                if (!Directory.Exists(BackupDir))
                {
                    Directory.CreateDirectory(BackupDir);
                }

                string safeAppName = AppLocator.SanitizeFileName(appName);
                int seq = Interlocked.Increment(ref _exportCounter);
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                string backupPath = Path.Combine(BackupDir, $"{safeAppName}_val_{timestamp}_{seq:D3}.reg");

                string fullHeaderKey = ExpandHivePrefix(fullKeyPath);
                string escapedName = valueName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                string escapedVal = (valueData ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");

                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine($"[{fullHeaderKey}]");
                sb.AppendLine($"\"{escapedName}\"=\"{escapedVal}\"");

                await File.WriteAllTextAsync(backupPath, sb.ToString(), Encoding.Unicode);
                return backupPath;
            }
            catch
            {
                return null;
            }
        });
    }

    public static async Task StopAndDeleteServiceAsync(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName)) return;
        await Task.Run(() =>
        {
            try
            {
                foreach (var cmd in new[] { $"stop \"{serviceName}\"", $"delete \"{serviceName}\"" })
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = cmd,
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(3000);
                }
            }
            catch { }
        });
    }

    /// <summary>
    /// Creates a Windows System Restore Point via WMI (Multi-level safety net like Revo Uninstaller Pro).
    /// </summary>
    public static async Task<bool> CreateSystemRestorePointAsync(string description)
    {
        return await Task.Run(() =>
        {
            try
            {
                var scope = new ManagementScope(@"\\localhost\root\default");
                var path = new ManagementPath("SystemRestore");
                using var restoreClass = new ManagementClass(scope, path, new ObjectGetOptions());
                using var inParams = restoreClass.GetMethodParameters("CreateRestorePoint");
                inParams["Description"] = description;
                inParams["RestorePointType"] = 12; // MODIFY_SETTINGS / APPLICATION_UNINSTALL
                inParams["EventType"] = 100;       // BEGIN_SYSTEM_CHANGE

                using var outParams = restoreClass.InvokeMethod("CreateRestorePoint", inParams, null);
                uint ret = Convert.ToUInt32(outParams?["ReturnValue"] ?? 1);
                return ret == 0;
            }
            catch
            {
                return false;
            }
        });
    }

    /// <summary>
    /// Deletes a registry key across 64-bit and 32-bit registry views safely.
    /// </summary>
    public static bool DeleteKey(string hiveName, string subKeyPath)
    {
        var hive = ParseHive(hiveName);
        bool deleted = false;

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var testKey = baseKey.OpenSubKey(subKeyPath);
                if (testKey != null)
                {
                    baseKey.DeleteSubKeyTree(subKeyPath, false);
                    deleted = true;
                }
            }
            catch { }
        }

        return deleted;
    }

    /// <summary>
    /// Deletes a registry value across 64-bit and 32-bit registry views safely.
    /// </summary>
    public static bool DeleteValue(string hiveName, string subKeyPath, string valueName)
    {
        var hive = ParseHive(hiveName);
        bool deleted = false;

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKeyPath, true);
                if (key != null && key.GetValue(valueName) != null)
                {
                    key.DeleteValue(valueName, false);
                    deleted = true;
                }
            }
            catch { }
        }

        return deleted;
    }

    public static async Task SaveBackupManifestAsync(BackupManifest manifest)
    {
        try
        {
            if (!Directory.Exists(BackupDir))
            {
                Directory.CreateDirectory(BackupDir);
            }

            string safeApp = AppLocator.SanitizeFileName(manifest.AppName);
            string file = Path.Combine(BackupDir, $"{safeApp}_{manifest.CreatedTime:yyyyMMdd_HHmmss}_{manifest.Id[..6]}.backup.json");
            manifest.ManifestPath = file;

            var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(file, json, Encoding.UTF8);
        }
        catch { }
    }

    public static async Task<List<BackupManifest>> GetBackupManifestsAsync()
    {
        return await Task.Run(async () =>
        {
            var list = new List<BackupManifest>();
            if (!Directory.Exists(BackupDir)) return list;

            foreach (var file in Directory.GetFiles(BackupDir, "*.backup.json"))
            {
                try
                {
                    string json = await File.ReadAllTextAsync(file, Encoding.UTF8);
                    var m = JsonSerializer.Deserialize<BackupManifest>(json);
                    if (m != null)
                    {
                        m.ManifestPath = file;
                        list.Add(m);
                    }
                }
                catch { }
            }

            return list.OrderByDescending(x => x.CreatedTime).ToList();
        });
    }

    public static async Task<int> RestoreBackupManifestAsync(BackupManifest manifest)
    {
        return await Task.Run(() =>
        {
            int restored = 0;
            foreach (var regFile in manifest.RegBackupFiles)
            {
                if (!File.Exists(regFile)) continue;
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"import \"{regFile}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);
                    if (proc?.ExitCode == 0) restored++;
                }
                catch { }
            }
            return restored;
        });
    }

    private static string ExpandHivePrefix(string fullKeyPath)
    {
        int slash = fullKeyPath.IndexOf('\\');
        if (slash <= 0) return fullKeyPath;
        string prefix = fullKeyPath.Substring(0, slash).ToUpperInvariant() switch
        {
            "HKLM" => "HKEY_LOCAL_MACHINE",
            "HKCU" => "HKEY_CURRENT_USER",
            "HKCR" => "HKEY_CLASSES_ROOT",
            _ => fullKeyPath.Substring(0, slash)
        };
        return prefix + fullKeyPath.Substring(slash);
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
