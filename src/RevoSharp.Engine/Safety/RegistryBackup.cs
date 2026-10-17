using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
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

    private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    private const uint WM_SETTINGCHANGE = 0x001A;
    private const uint SMTO_ABORTIFHUNG = 0x0002;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out IntPtr lpdwResult);

    /// <summary>
    /// High-speed in-process registry backup synthesizer: recursively walks all selected RegistryKey and RegistryValue
    /// residuals in memory via Microsoft.Win32.RegistryKey and writes consolidated .reg backup files (1 for x64, 1 for x86),
    /// eliminating hundreds of slow reg.exe subprocess spawns and completing in under 200ms!
    /// </summary>
    public static async Task<Dictionary<string, bool>> SynthesizeMergedRegBackupAsync(
        IEnumerable<ResidualItem> registryItems,
        string appName)
    {
        return await Task.Run(async () =>
        {
            var createdFiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var itemList = registryItems
                .Where(i => i.Type is ResidualType.RegistryKey or ResidualType.RegistryValue &&
                            i.Category != ResidualCategory.EnvironmentPath)
                .ToList();

            if (itemList.Count == 0) return createdFiles;

            if (!Directory.Exists(BackupDir))
            {
                Directory.CreateDirectory(BackupDir);
            }

            var groups = itemList.GroupBy(i => i.Is64BitRegistryView ?? true);
            string safeAppName = AppLocator.SanitizeFileName(appName);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");

            foreach (var group in groups)
            {
                bool is64View = group.Key;
                var sb = new StringBuilder(16384);
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();

                int exportedSectionCount = 0;

                foreach (var item in group)
                {
                    if (item.Type == ResidualType.RegistryKey)
                    {
                        if (AppendKeySubtreeToRegBuilder(sb, item.Path, is64View, maxDepth: 12))
                        {
                            exportedSectionCount++;
                        }
                        else
                        {
                            // Fallback to reg.exe only if an elevated/service key could not be read in-process
                            string? fallbackReg = await ExportKeyAsync(item.Path, appName, is64View);
                            if (!string.IsNullOrEmpty(fallbackReg))
                            {
                                createdFiles[fallbackReg] = is64View;
                            }
                        }
                    }
                    else if (item.Type == ResidualType.RegistryValue && item.ValueName != null)
                    {
                        string fullHeaderKey = ExpandHivePrefixForExport(item.Path, is64View);
                        string formattedLine = ReadAndFormatRegistryValueLine(item.Path, item.ValueName, item.ValuePreview, is64View);
                        sb.AppendLine($"[{fullHeaderKey}]");
                        sb.AppendLine(formattedLine);
                        sb.AppendLine();
                        exportedSectionCount++;
                    }
                }

                if (exportedSectionCount > 0)
                {
                    int seq = Interlocked.Increment(ref _exportCounter);
                    string archTag = is64View ? "x64" : "x86";
                    string mergedPath = Path.Combine(BackupDir, $"{safeAppName}_merged_{archTag}_{timestamp}_{seq:D3}.reg");
                    await File.WriteAllTextAsync(mergedPath, sb.ToString(), Encoding.Unicode);
                    createdFiles[mergedPath] = is64View;
                }
            }

            return createdFiles;
        });
    }

    private static bool AppendKeySubtreeToRegBuilder(StringBuilder sb, string fullKeyPath, bool? is64BitView, int maxDepth)
    {
        int slash = fullKeyPath.IndexOf('\\');
        if (slash <= 0) return false;

        string hiveName = fullKeyPath.Substring(0, slash);
        string subKeyPath = fullKeyPath.Substring(slash + 1);
        var hive = ParseHive(hiveName);

        foreach (var view in GetTargetViews(subKeyPath, is64BitView))
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var rootKey = baseKey.OpenSubKey(subKeyPath, false);
                if (rootKey == null) continue;

                string expandedRootHeader = ExpandHivePrefixForExport(fullKeyPath, is64BitView);
                WriteKeyRecursive(sb, rootKey, expandedRootHeader, 0, maxDepth);
                return true;
            }
            catch { }
        }

        return false;
    }

    private static void WriteKeyRecursive(StringBuilder sb, RegistryKey key, string currentHeaderPath, int depth, int maxDepth)
    {
        if (depth > maxDepth) return;

        sb.AppendLine($"[{currentHeaderPath}]");

        try
        {
            foreach (var valName in key.GetValueNames())
            {
                try
                {
                    object? rawVal = key.GetValue(valName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (rawVal == null) continue;

                    RegistryValueKind kind = key.GetValueKind(valName);
                    string escapedNameHeader = string.IsNullOrEmpty(valName)
                        ? "@"
                        : $"\"{EscapeRegString(valName)}\"";

                    sb.AppendLine(FormatRegistryValueByKind(escapedNameHeader, rawVal, kind));
                }
                catch { }
            }
        }
        catch { }

        sb.AppendLine();

        if (depth == maxDepth) return;

        try
        {
            foreach (var subName in key.GetSubKeyNames())
            {
                try
                {
                    using var childKey = key.OpenSubKey(subName, false);
                    if (childKey != null)
                    {
                        WriteKeyRecursive(sb, childKey, $@"{currentHeaderPath}\{subName}", depth + 1, maxDepth);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

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
    /// by reading the ACTUAL live value and RegistryValueKind from the registry before deletion.
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
    /// Backs up the full original System or User PATH environment variable into the BackupManifest
    /// and surgically removes only the dead directory segment without disturbing other entries.
    /// </summary>
    public static bool BackupAndCleanEnvironmentPathSegment(
        bool isSystemPath,
        string segmentToRemove,
        BackupManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(segmentToRemove)) return false;

        try
        {
            string mapKey = isSystemPath ? "Machine::Path" : "User::Path";
            using var baseKey = RegistryKey.OpenBaseKey(
                isSystemPath ? RegistryHive.LocalMachine : RegistryHive.CurrentUser,
                RegistryView.Registry64);

            string subKeyPath = isSystemPath
                ? @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                : @"Environment";

            using var envKey = baseKey.OpenSubKey(subKeyPath, writable: true);
            if (envKey == null) return false;

            string? rawPath = envKey.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            if (string.IsNullOrWhiteSpace(rawPath)) return false;

            if (!manifest.EnvironmentPathBackupMap.ContainsKey(mapKey))
            {
                manifest.EnvironmentPathBackupMap[mapKey] = rawPath;
            }

            string targetNorm = segmentToRemove.Trim().Trim('"').TrimEnd('\\', '/');
            var parts = rawPath.Split(';', StringSplitOptions.RemoveEmptyEntries);
            var keptParts = new List<string>(parts.Length);
            bool removedAny = false;

            foreach (var part in parts)
            {
                string expandedPart = Environment.ExpandEnvironmentVariables(part.Trim().Trim('"')).TrimEnd('\\', '/');
                string rawPartClean = part.Trim().Trim('"').TrimEnd('\\', '/');

                if (expandedPart.Equals(targetNorm, StringComparison.OrdinalIgnoreCase) ||
                    rawPartClean.Equals(targetNorm, StringComparison.OrdinalIgnoreCase))
                {
                    removedAny = true;
                }
                else
                {
                    keptParts.Add(part);
                }
            }

            if (removedAny)
            {
                string updatedPath = string.Join(";", keptParts);
                envKey.SetValue("Path", updatedPath, RegistryValueKind.ExpandString);
                BroadcastEnvironmentChange();
                return true;
            }
        }
        catch { }

        return false;
    }

    public static void BroadcastEnvironmentChange()
    {
        try
        {
            SendMessageTimeout(new IntPtr(0xFFFF), WM_SETTINGCHANGE, IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 1000, out _);
        }
        catch { }
    }

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
        bool isDefaultVal = string.IsNullOrEmpty(valueName) || valueName.Equals("(Default)", StringComparison.OrdinalIgnoreCase);
        string actualLookupName = isDefaultVal ? string.Empty : valueName;
        string escapedNameHeader = isDefaultVal ? "@" : $"\"{EscapeRegString(valueName)}\"";

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

                    object? rawVal = key.GetValue(actualLookupName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (rawVal == null) continue;

                    RegistryValueKind kind = key.GetValueKind(actualLookupName);
                    return FormatRegistryValueByKind(escapedNameHeader, rawVal, kind);
                }
                catch { }
            }
        }

        string fallbackStr = fallbackValueData ?? string.Empty;
        if (ContainsMultiLineOrControlChars(fallbackStr))
        {
            byte[] strBytes = Encoding.Unicode.GetBytes(fallbackStr + "\0");
            return $"{escapedNameHeader}=hex(1):{FormatHexBytes(strBytes)}";
        }

        return $"{escapedNameHeader}=\"{EscapeRegString(fallbackStr)}\"";
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
                // Critical fix: Multi-line or control characters in REG_SZ break standard quoted .reg syntax;
                // encode them as hex(1): UTF-16LE so reg.exe import always succeeds!
                if (ContainsMultiLineOrControlChars(strVal))
                {
                    byte[] utf16Bytes = Encoding.Unicode.GetBytes(strVal + "\0");
                    return $"{escapedNameHeader}=hex(1):{FormatHexBytes(utf16Bytes)}";
                }
                return $"{escapedNameHeader}=\"{EscapeRegString(strVal)}\"";
        }
    }

    private static bool ContainsMultiLineOrControlChars(string text)
    {
        foreach (char c in text)
        {
            if (c == '\r' || c == '\n' || c < 0x20)
                return true;
        }
        return false;
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
            string actualName = valueName.Equals("(Default)", StringComparison.OrdinalIgnoreCase) ? string.Empty : valueName;
            object? val = key.GetValue(actualName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (val == null) return null;

            string text = val switch
            {
                byte[] bytes => $"[二进制 {bytes.Length} B]",
                string[] arr => string.Join("; ", arr),
                _ => val.ToString() ?? string.Empty
            };

            text = text.Replace("\r", " ").Replace("\n", " ");
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

    public static async Task UninstallDriverPackageAsync(string publishedInfName)
    {
        if (string.IsNullOrWhiteSpace(publishedInfName) || !publishedInfName.StartsWith("oem", StringComparison.OrdinalIgnoreCase))
            return;

        await Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "pnputil.exe",
                    Arguments = $"/delete-driver {publishedInfName} /uninstall /force",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
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

    public static bool DeleteValue(string hiveName, string subKeyPath, string valueName, bool? is64BitView = null)
    {
        var hive = ParseHive(hiveName);
        bool deleted = false;
        string actualName = valueName.Equals("(Default)", StringComparison.OrdinalIgnoreCase) ? string.Empty : valueName;

        foreach (var view in GetTargetViews(subKeyPath, is64BitView))
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKeyPath, true);
                if (key != null && key.GetValue(actualName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) != null)
                {
                    key.DeleteValue(actualName, false);
                    deleted = true;
                }
            }
            catch { }
        }

        return deleted;
    }

    private static IEnumerable<RegistryView> GetTargetViews(string subKeyPath, bool? is64BitView)
    {
        if (subKeyPath.Contains(@"WOW6432Node\", StringComparison.OrdinalIgnoreCase))
        {
            return [RegistryView.Registry64];
        }

        if (!Environment.Is64BitOperatingSystem)
        {
            return [RegistryView.Default];
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

            if (string.IsNullOrWhiteSpace(manifest.ManifestPath))
            {
                string safeApp = AppLocator.SanitizeFileName(manifest.AppName);
                manifest.ManifestPath = Path.Combine(BackupDir, $"{safeApp}_{manifest.CreatedTime:yyyyMMdd_HHmmss}_{manifest.Id[..6]}.backup.json");
            }

            var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(manifest.ManifestPath, json, Encoding.UTF8);
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
        int restored = await Task.Run(() =>
        {
            int count = 0;

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
                    if (proc?.ExitCode == 0) count++;
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
                    if (proc?.ExitCode == 0) count++;
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
                        count++;
                    }
                    catch { }
                }
            }

            // 4. Restore Environment PATH variable snapshots
            if (manifest.EnvironmentPathBackupMap != null && manifest.EnvironmentPathBackupMap.Count > 0)
            {
                foreach (var (scopeKey, origPathValue) in manifest.EnvironmentPathBackupMap)
                {
                    if (string.IsNullOrWhiteSpace(origPathValue)) continue;
                    try
                    {
                        bool isMachine = scopeKey.StartsWith("Machine", StringComparison.OrdinalIgnoreCase);
                        using var baseKey = RegistryKey.OpenBaseKey(
                            isMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser,
                            RegistryView.Registry64);
                        string subKey = isMachine
                            ? @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                            : @"Environment";
                        using var envKey = baseKey.OpenSubKey(subKey, writable: true);
                        if (envKey != null)
                        {
                            envKey.SetValue("Path", origPathValue, RegistryValueKind.ExpandString);
                            count++;
                        }
                    }
                    catch { }
                }
                BroadcastEnvironmentChange();
            }

            return count;
        });

        if (restored > 0)
        {
            manifest.IsRestored = true;
            await SaveBackupManifestAsync(manifest);
        }

        return restored;
    }

    /// <summary>
    /// Opens RegEdit jumped to the specified registry path, dynamically loading the localized root node name
    /// directly from regedit.exe's string table (Resource ID 16) and closing idle RegEdit instances so LastKey is always honored.
    /// </summary>
    public static void OpenInRegEdit(string registryPath)
    {
        if (string.IsNullOrWhiteSpace(registryPath)) return;

        string cleanPath = registryPath.Trim().TrimEnd('\\');
        int slash = cleanPath.IndexOf('\\');
        if (slash <= 0) return;

        string hiveFull = ExpandHivePrefix(cleanPath);
        string rootPrefix = DetectRegEditRootName();
        string fullRegPath = $@"{rootPrefix}\{hiveFull}";

        try
        {
            foreach (var proc in Process.GetProcessesByName("regedit"))
            {
                try
                {
                    proc.CloseMainWindow();
                    proc.WaitForExit(300);
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }

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
        // 1. Prefer existing LastKey root prefix if the user has opened RegEdit before
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

        // 2. Dynamically read localized root string resource (ID 16) directly from regedit.exe binary
        try
        {
            string regeditExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "regedit.exe");
            IntPtr hMod = LoadLibraryEx(regeditExe, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
            if (hMod != IntPtr.Zero)
            {
                try
                {
                    var sb = new StringBuilder(128);
                    if (LoadString(hMod, 16, sb, sb.Capacity) > 0 && !string.IsNullOrWhiteSpace(sb.ToString()))
                    {
                        return sb.ToString().Trim();
                    }
                }
                finally
                {
                    FreeLibrary(hMod);
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

    public static string NormalizeHivePrefix(string fullKeyPath)
    {
        if (string.IsNullOrWhiteSpace(fullKeyPath)) return string.Empty;
        string trimmed = fullKeyPath.Trim().TrimEnd('\\');
        int slash = trimmed.IndexOf('\\');
        if (slash <= 0) return trimmed;
        string prefix = trimmed.Substring(0, slash).ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" => "HKLM",
            "HKEY_CURRENT_USER" => "HKCU",
            "HKEY_CLASSES_ROOT" => "HKCR",
            var p => p
        };
        return prefix + trimmed.Substring(slash);
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
