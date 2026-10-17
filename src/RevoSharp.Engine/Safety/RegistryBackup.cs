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
    /// Exports the target registry key to a uniquely named .reg file before deletion,
    /// honoring 64-bit / 32-bit registry views accurately without double-redirecting WOW6432Node paths.
    /// </summary>
    public static async Task<string?> ExportKeyAsync(string fullRegistryPath, string appName, bool? is64BitView = null)
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

                // Critical fix: If the path already explicitly contains \WOW6432Node\, passing /reg:32 causes reg.exe
                // to double-redirect to WOW6432Node\WOW6432Node and fail. Always use /reg:64 when WOW6432Node is explicit!
                bool hasExplicitWow64 = fullRegistryPath.Contains(@"\WOW6432Node\", StringComparison.OrdinalIgnoreCase);
                string regViewArg = hasExplicitWow64
                    ? " /reg:64"
                    : (is64BitView == false ? " /reg:32" : " /reg:64");

                var psi = new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export \"{fullRegistryPath}\" \"{backupPath}\" /y{regViewArg}",
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
    /// Exports a single registry value into a valid Windows Registry Editor Version 5.00 .reg file
    /// by reading the ACTUAL live value and RegistryValueKind (REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY,
    /// REG_EXPAND_SZ, REG_MULTI_SZ) from the registry before deletion.
    /// </summary>
    public static async Task<string?> ExportValueAsync(
        string fullKeyPath,
        string valueName,
        string? fallbackValueData,
        string appName,
        bool? is64BitView = null)
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

                string fullHeaderKey = ExpandHivePrefixForExport(fullKeyPath, is64BitView);
                string formattedValueLine = ReadAndFormatRegistryValueLine(fullKeyPath, valueName, fallbackValueData, is64BitView);

                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine($"[{fullHeaderKey}]");
                sb.AppendLine(formattedValueLine);

                await File.WriteAllTextAsync(backupPath, sb.ToString(), Encoding.Unicode);
                return backupPath;
            }
            catch
            {
                return null;
            }
        });
    }

    /// <summary>
    /// Expands short hive names (HKLM/HKCU/HKCR) and injects WOW6432Node if a 32-bit view is specified
    /// on an HKLM\SOFTWARE key that does not already include WOW6432Node.
    /// </summary>
    private static string ExpandHivePrefixForExport(string fullKeyPath, bool? is64BitView)
    {
        string expanded = ExpandHivePrefix(fullKeyPath);
        if (is64BitView == false &&
            Environment.Is64BitOperatingSystem &&
            !expanded.Contains(@"\WOW6432Node\", StringComparison.OrdinalIgnoreCase))
        {
            const string hklmSoft = @"HKEY_LOCAL_MACHINE\SOFTWARE\";
            if (expanded.StartsWith(hklmSoft, StringComparison.OrdinalIgnoreCase))
            {
                expanded = @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\" + expanded.Substring(hklmSoft.Length);
            }
        }
        return expanded;
    }

    private static string ReadAndFormatRegistryValueLine(
        string fullKeyPath,
        string valueName,
        string? fallbackValueData,
        bool? is64BitView)
    {
        string escapedNameHeader = string.IsNullOrEmpty(valueName)
            ? "@"
            : $"\"{EscapeRegString(valueName)}\"";

        int slash = fullKeyPath.IndexOf('\\');
        if (slash > 0)
        {
            string hiveName = fullKeyPath.Substring(0, slash);
            string subKeyPath = fullKeyPath.Substring(slash + 1);
            var hive = ParseHive(hiveName);

            foreach (var view in GetTargetViews(subKeyPath, is64BitView))
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKeyPath, false);
                    if (key == null) continue;

                    object? rawVal = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (rawVal == null) continue;

                    RegistryValueKind kind = key.GetValueKind(valueName);
                    return FormatRegistryValueByKind(escapedNameHeader, rawVal, kind);
                }
                catch { }
            }
        }

        string safeFallback = EscapeRegString(fallbackValueData ?? string.Empty);
        return $"{escapedNameHeader}=\"{safeFallback}\"";
    }

    private static string FormatRegistryValueByKind(string escapedNameHeader, object rawVal, RegistryValueKind kind)
    {
        switch (kind)
        {
            case RegistryValueKind.DWord:
                uint dwordVal = unchecked((uint)Convert.ToInt32(rawVal));
                return $"{escapedNameHeader}=dword:{dwordVal:x8}";

            case RegistryValueKind.QWord:
                ulong qwordVal = unchecked((ulong)Convert.ToInt64(rawVal));
                byte[] qwordBytes = BitConverter.GetBytes(qwordVal);
                return $"{escapedNameHeader}=hex(b):{FormatHexBytes(qwordBytes)}";

            case RegistryValueKind.Binary when rawVal is byte[] binBytes:
                return $"{escapedNameHeader}=hex:{FormatHexBytes(binBytes)}";

            case RegistryValueKind.ExpandString:
                string expandStr = rawVal.ToString() ?? string.Empty;
                byte[] expandBytes = Encoding.Unicode.GetBytes(expandStr + "\0");
                return $"{escapedNameHeader}=hex(2):{FormatHexBytes(expandBytes)}";

            case RegistryValueKind.MultiString when rawVal is string[] multiStrings:
                string joined = string.Join("\0", multiStrings) + "\0\0";
                byte[] multiBytes = Encoding.Unicode.GetBytes(joined);
                return $"{escapedNameHeader}=hex(7):{FormatHexBytes(multiBytes)}";

            default:
                string strVal = rawVal.ToString() ?? string.Empty;
                return $"{escapedNameHeader}=\"{EscapeRegString(strVal)}\"";
        }
    }

    private static string FormatHexBytes(byte[] bytes)
    {
        if (bytes.Length == 0) return string.Empty;
        return string.Join(",", bytes.Select(b => b.ToString("x2")));
    }

    private static string EscapeRegString(string input)
    {
        return input.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    /// <summary>
    /// Reads a short human-readable preview of a registry value for display in the review table.
    /// </summary>
    public static string? TryGetRegistryValuePreview(RegistryKey key, string valueName)
    {
        try
        {
            object? val = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (val == null) return null;

            string text = val switch
            {
                byte[] bytes => $"[二进制 {bytes.Length} B]",
                string[] arr => string.Join("; ", arr),
                _ => val.ToString() ?? string.Empty
            };

            return text.Length > 90 ? text.Substring(0, 87) + "..." : text;
        }
        catch
        {
            return null;
        }
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
    /// Backs up a Windows Scheduled Task XML file and cleanly unregisters it from Task Scheduler (schtasks.exe)
    /// so no orphaned TaskCache entries remain in the registry.
    /// </summary>
    public static async Task<(string? BackupXmlPath, string ResolvedTaskName)> BackupAndDeleteScheduledTaskWithNameAsync(
        string taskFilePath,
        string? taskSchedulerName,
        string appName)
    {
        return await Task.Run(() =>
        {
            string? backupXmlPath = null;
            string tn = taskSchedulerName ?? string.Empty;
            try
            {
                if (!Directory.Exists(BackupDir))
                {
                    Directory.CreateDirectory(BackupDir);
                }

                if (string.IsNullOrWhiteSpace(tn))
                {
                    string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                    if (taskFilePath.StartsWith(tasksDir, StringComparison.OrdinalIgnoreCase))
                    {
                        tn = "\\" + taskFilePath.Substring(tasksDir.Length).TrimStart('\\');
                    }
                }

                if (File.Exists(taskFilePath))
                {
                    string safeAppName = AppLocator.SanitizeFileName(appName);
                    string taskLeaf = AppLocator.SanitizeFileName(Path.GetFileName(taskFilePath));
                    int seq = Interlocked.Increment(ref _exportCounter);
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                    backupXmlPath = Path.Combine(BackupDir, $"{safeAppName}_task_{taskLeaf}_{timestamp}_{seq:D3}.xml");
                    File.Copy(taskFilePath, backupXmlPath, overwrite: true);
                }

                // Only delete the scheduled task if we successfully backed up its XML (or if XML was already gone)
                if (!string.IsNullOrEmpty(backupXmlPath) || !File.Exists(taskFilePath))
                {
                    if (!string.IsNullOrWhiteSpace(tn))
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "schtasks.exe",
                            Arguments = $"/Delete /TN \"{tn}\" /F",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        using var proc = Process.Start(psi);
                        proc?.WaitForExit(4000);
                    }

                    if (File.Exists(taskFilePath))
                    {
                        FileBackup.SendToRecycleBin(taskFilePath);
                    }
                }
            }
            catch { }

            return (backupXmlPath, tn);
        });
    }

    public static async Task<string?> BackupAndDeleteScheduledTaskAsync(string taskFilePath, string? taskSchedulerName, string appName)
    {
        var (backupXmlPath, _) = await BackupAndDeleteScheduledTaskWithNameAsync(taskFilePath, taskSchedulerName, appName);
        return backupXmlPath;
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
    /// Deletes a registry key honoring the target architecture view so 32-bit and 64-bit sibling keys are not cross-deleted.
    /// </summary>
    public static bool DeleteKey(string hiveName, string subKeyPath, bool? is64BitView = null)
    {
        var hive = ParseHive(hiveName);
        bool deleted = false;

        foreach (var view in GetTargetViews(subKeyPath, is64BitView))
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
    /// Deletes a registry value honoring the target architecture view safely.
    /// </summary>
    public static bool DeleteValue(string hiveName, string subKeyPath, string valueName, bool? is64BitView = null)
    {
        var hive = ParseHive(hiveName);
        bool deleted = false;

        foreach (var view in GetTargetViews(subKeyPath, is64BitView))
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKeyPath, true);
                if (key != null && key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) != null)
                {
                    key.DeleteValue(valueName, false);
                    deleted = true;
                }
            }
            catch { }
        }

        return deleted;
    }

    private static IEnumerable<RegistryView> GetTargetViews(string subKeyPath, bool? is64BitView)
    {
        // If path explicitly includes WOW6432Node, opening under Registry64 directly accesses that exact node.
        if (subKeyPath.Contains(@"WOW6432Node\", StringComparison.OrdinalIgnoreCase))
        {
            return [RegistryView.Registry64];
        }

        if (is64BitView.HasValue)
        {
            return [is64BitView.Value ? RegistryView.Registry64 : RegistryView.Registry32];
        }

        return [RegistryView.Registry64, RegistryView.Registry32];
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

            // 1. Restore Registry (.reg) backups with accurate /reg:64 or /reg:32 view flag
            foreach (var regFile in manifest.RegBackupFiles)
            {
                if (!File.Exists(regFile)) continue;
                try
                {
                    string viewFlag = " /reg:64";
                    if (manifest.RegBackupViewMap != null &&
                        manifest.RegBackupViewMap.TryGetValue(regFile, out bool is64) &&
                        !is64)
                    {
                        viewFlag = " /reg:32";
                    }

                    var psi = new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"import \"{regFile}\"{viewFlag}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);
                    if (proc?.ExitCode == 0) restored++;
                }
                catch { }
            }

            // 2. Restore Scheduled Tasks to their exact original Task Scheduler path
            foreach (var xmlFile in manifest.TaskXmlBackupFiles)
            {
                if (!File.Exists(xmlFile)) continue;
                try
                {
                    string taskName;
                    if (manifest.TaskScheduleMap != null &&
                        manifest.TaskScheduleMap.TryGetValue(xmlFile, out string? origName) &&
                        !string.IsNullOrWhiteSpace(origName))
                    {
                        taskName = origName.StartsWith('\\') ? origName : "\\" + origName;
                    }
                    else
                    {
                        string fileName = Path.GetFileNameWithoutExtension(xmlFile);
                        taskName = "\\RevoSharp_Restored_" + fileName;
                    }

                    var psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Create /TN \"{taskName}\" /XML \"{xmlFile}\" /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);
                    if (proc?.ExitCode == 0) restored++;
                }
                catch { }
            }

            // 3. Restore backed-up file copies (e.g. Startup folder .lnk shortcuts and config files)
            if (manifest.FileBackupCopyMap != null)
            {
                foreach (var (originalPath, backupCopyPath) in manifest.FileBackupCopyMap)
                {
                    if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(backupCopyPath))
                        continue;

                    try
                    {
                        string? parentDir = Path.GetDirectoryName(originalPath);
                        if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                        {
                            Directory.CreateDirectory(parentDir);
                        }

                        File.Copy(backupCopyPath, originalPath, overwrite: true);
                        restored++;
                    }
                    catch { }
                }
            }

            return restored;
        });
    }

    /// <summary>
    /// Opens RegEdit jumped to the specified registry path, automatically adapting to localized Windows root names
    /// (e.g. "计算机" on Simplified Chinese Windows, "Computer" on English Windows) by reading localized resources or existing LastKey prefix.
    /// </summary>
    public static void OpenInRegEdit(string registryPath)
    {
        if (string.IsNullOrWhiteSpace(registryPath)) return;

        int slash = registryPath.IndexOf('\\');
        if (slash <= 0) return;

        string hiveFull = ExpandHivePrefix(registryPath);
        string rootPrefix = DetectRegEditRootName();
        string fullRegPath = $@"{rootPrefix}\{hiveFull}";

        using (var regeditKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"))
        {
            regeditKey?.SetValue("LastKey", fullRegPath);
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = "regedit.exe",
            Arguments = "-m",
            UseShellExecute = true
        });
    }

    private static string DetectRegEditRootName()
    {
        try
        {
            using var regeditKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
            if (regeditKey?.GetValue("LastKey") is string existingLastKey && !string.IsNullOrWhiteSpace(existingLastKey))
            {
                int firstSlash = existingLastKey.IndexOf('\\');
                if (firstSlash > 0)
                {
                    return existingLastKey.Substring(0, firstSlash);
                }
            }
        }
        catch { }

        string lang = System.Globalization.CultureInfo.InstalledUICulture.Name;
        if (lang.StartsWith("zh-CN", StringComparison.OrdinalIgnoreCase) || lang.StartsWith("zh-Hans", StringComparison.OrdinalIgnoreCase))
            return "计算机";
        if (lang.StartsWith("zh-TW", StringComparison.OrdinalIgnoreCase) || lang.StartsWith("zh-HK", StringComparison.OrdinalIgnoreCase))
            return "電腦";

        return "Computer";
    }

    public static string ExpandHivePrefix(string fullKeyPath)
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
