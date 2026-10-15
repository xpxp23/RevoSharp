using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;

namespace RevoSharp.Engine.Discovery;

public class AppLocator
{
    public static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp",
        "Logs"
    );

    private static readonly HashSet<string> SystemHostBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "msiexec.exe", "rundll32.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "regsvr32.exe", "explorer.exe", "conhost.exe"
    };

    public async Task<List<InstalledApp>> GetInstalledAppsAsync(bool includeWindowsApps = false)
    {
        return await Task.Run(async () =>
        {
            var apps = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);

            // 1. HKLM 64-bit
            ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM", apps, true);

            // 2. HKLM 32-bit (WOW6432Node)
            if (Environment.Is64BitOperatingSystem)
            {
                ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\WOW6432Node", apps, false);
            }

            // 3. HKCU (Current User)
            ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU", apps, Environment.Is64BitOperatingSystem);

            // 4. Optional: Windows Store / UWP Apps
            if (includeWindowsApps)
            {
                ScanWindowsStoreApps(apps);
            }

            // 5. Match with saved trace logs (by DisplayName, DetectedDisplayName, UninstallKeyId, or file name)
            await AttachTraceLogsAsync(apps.Values);

            return apps.Values
                .OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        });
    }

    private static async Task AttachTraceLogsAsync(IEnumerable<InstalledApp> apps)
    {
        if (!Directory.Exists(LogDirectory)) return;

        var loadedLogs = new List<TraceLog>();
        try
        {
            foreach (var file in Directory.GetFiles(LogDirectory, "*.revolog.json.gz"))
            {
                try
                {
                    var log = await TraceLogSerializer.LoadAsync(file);
                    if (log != null)
                    {
                        log.FilePath = file;
                        loadedLogs.Add(log);
                    }
                }
                catch { }
            }
        }
        catch { }

        foreach (var app in apps)
        {
            string safeName = SanitizeFileName(app.DisplayName);
            string directFile = Path.Combine(LogDirectory, $"{safeName}.revolog.json.gz");
            if (File.Exists(directFile))
            {
                app.HasTraceLog = true;
                app.TraceLogPath = directFile;
                continue;
            }

            var matchedLog = loadedLogs.FirstOrDefault(l =>
                (!string.IsNullOrEmpty(l.DetectedDisplayName) && l.DetectedDisplayName.Equals(app.DisplayName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.AppName) && l.AppName.Equals(app.DisplayName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.UninstallKeyId) && !string.IsNullOrEmpty(app.UninstallKeyName) && l.UninstallKeyId.Equals(app.UninstallKeyName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.DetectedInstallLocation) && !string.IsNullOrEmpty(app.InstallLocation) &&
                 l.DetectedInstallLocation.TrimEnd('\\').Equals(app.InstallLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)));

            if (matchedLog != null && File.Exists(matchedLog.FilePath))
            {
                app.HasTraceLog = true;
                app.TraceLogPath = matchedLog.FilePath;
            }
        }
    }

    public async Task<List<TraceLog>> GetAllTraceLogsAsync()
    {
        return await Task.Run(async () =>
        {
            var list = new List<TraceLog>();
            if (!Directory.Exists(LogDirectory)) return list;

            foreach (var file in Directory.GetFiles(LogDirectory, "*.revolog.json.gz"))
            {
                try
                {
                    var log = await TraceLogSerializer.LoadAsync(file);
                    if (log != null)
                    {
                        log.FilePath = file;
                        list.Add(log);
                    }
                }
                catch { }
            }

            return list.OrderByDescending(l => l.CreatedTime).ToList();
        });
    }

    private static void ScanRegistryKey(
        RegistryHive hive,
        RegistryView view,
        string subKeyPath,
        string hivePrefix,
        Dictionary<string, InstalledApp> apps,
        bool is64Bit)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var uninstallKey = baseKey.OpenSubKey(subKeyPath);
            if (uninstallKey == null) return;

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                try
                {
                    using var appKey = uninstallKey.OpenSubKey(subKeyName);
                    if (appKey == null) continue;

                    string? displayName = appKey.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(displayName)) continue;

                    // Filter out system components and updates
                    if (appKey.GetValue("SystemComponent") is int sysComp && sysComp == 1) continue;
                    if (appKey.GetValue("ParentKeyName") != null) continue;
                    if (displayName.StartsWith("KB", StringComparison.OrdinalIgnoreCase) && displayName.Length > 2 && char.IsDigit(displayName[2])) continue;

                    string uninstallString = appKey.GetValue("UninstallString") as string ?? string.Empty;
                    string quietUninstallString = appKey.GetValue("QuietUninstallString") as string ?? string.Empty;

                    if (string.IsNullOrEmpty(uninstallString) && string.IsNullOrEmpty(quietUninstallString)) continue;

                    string cleanDisplayName = displayName.Trim();
                    string publisher = appKey.GetValue("Publisher") as string ?? string.Empty;
                    string version = appKey.GetValue("DisplayVersion") as string ?? string.Empty;
                    string installLocation = appKey.GetValue("InstallLocation") as string ?? string.Empty;
                    string displayIcon = appKey.GetValue("DisplayIcon") as string ?? string.Empty;
                    string installDate = appKey.GetValue("InstallDate") as string ?? string.Empty;

                    long estimatedSize = 0;
                    if (appKey.GetValue("EstimatedSize") is int sizeInKb && sizeInKb > 0)
                    {
                        estimatedSize = (long)sizeInKb * 1024L;
                    }

                    string resolvedLocation = DeduceInstallLocation(installLocation, displayIcon, uninstallString, quietUninstallString);
                    string archLabel = is64Bit ? "64 位" : "32 位";

                    string regFullPath = hivePrefix == @"HKLM\WOW6432Node"
                        ? $@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}"
                        : $@"{hivePrefix}\{subKeyPath}\{subKeyName}";

                    string dictKey = cleanDisplayName;
                    if (apps.TryGetValue(dictKey, out var existing))
                    {
                        // If exact same uninstall string or location, skip duplicate mirror entry
                        if (existing.UninstallString.Equals(uninstallString.Trim(), StringComparison.OrdinalIgnoreCase))
                            continue;
                        dictKey = $"{cleanDisplayName} ({archLabel} {version})".Trim();
                    }

                    var app = new InstalledApp
                    {
                        Id = $"{hive}_{view}_{subKeyName}",
                        UninstallKeyName = subKeyName,
                        RegistryKeyPath = regFullPath,
                        DisplayName = cleanDisplayName,
                        DisplayVersion = version.Trim(),
                        Publisher = publisher.Trim(),
                        InstallLocation = resolvedLocation,
                        UninstallString = uninstallString.Trim(),
                        QuietUninstallString = quietUninstallString.Trim(),
                        DisplayIcon = displayIcon.Trim().Trim('"'),
                        InstallDate = FormatInstallDate(installDate),
                        EstimatedSizeInBytes = estimatedSize,
                        Architecture = archLabel,
                        Is64Bit = is64Bit
                    };

                    apps[dictKey] = app;
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanWindowsStoreApps(Dictionary<string, InstalledApp> apps)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var pkgRoot = baseKey.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (pkgRoot == null) return;

            foreach (var pkgFullName in pkgRoot.GetSubKeyNames())
            {
                try
                {
                    if (pkgFullName.StartsWith("Microsoft.Windows.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.NET.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.VCLibs.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.UI.Xaml.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("windows.immersivecontrolpanel", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    using var pkgKey = pkgRoot.OpenSubKey(pkgFullName);
                    if (pkgKey == null) continue;

                    string displayName = pkgKey.GetValue("DisplayName") as string ?? string.Empty;
                    string pkgRootFolder = pkgKey.GetValue("PackageRootFolder") as string ?? string.Empty;

                    // Extract readable name from PackageFullName (Name_Version_Arch__PublisherId)
                    string[] parts = pkgFullName.Split('_');
                    string shortName = parts.Length > 0 ? parts[0] : pkgFullName;
                    string version = parts.Length > 1 ? parts[1] : string.Empty;
                    string arch = parts.Length > 2 ? parts[2] : "UWP";

                    if (string.IsNullOrWhiteSpace(displayName) || displayName.StartsWith("@{"))
                    {
                        displayName = shortName;
                    }

                    string dictKey = $"[UWP] {displayName}";
                    if (apps.ContainsKey(dictKey)) continue;

                    string psUninstall = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{pkgFullName}'\"";

                    apps[dictKey] = new InstalledApp
                    {
                        Id = $"UWP_{pkgFullName}",
                        UninstallKeyName = pkgFullName,
                        RegistryKeyPath = $@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\{pkgFullName}",
                        DisplayName = $"{displayName} (商店应用)",
                        DisplayVersion = version,
                        Publisher = "Microsoft Store / UWP",
                        InstallLocation = !IsProtectedSharedDirectory(pkgRootFolder) ? pkgRootFolder : string.Empty,
                        UninstallString = psUninstall,
                        QuietUninstallString = psUninstall,
                        Architecture = arch.ToUpperInvariant(),
                        Is64Bit = !arch.Contains("86"),
                        IsWindowsApp = true
                    };
                }
                catch { }
            }
        }
        catch { }
    }

    public static bool IsProtectedSharedDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;

        try
        {
            string clean = Path.GetFullPath(path.Trim().Trim('"', '\'')).TrimEnd('\\', '/');
            if (clean.Length <= 3) return true; // Drive root e.g. C:

            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            if (clean.Equals(winDir, StringComparison.OrdinalIgnoreCase) ||
                clean.StartsWith(winDir + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var protectedExactDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (var p in protectedExactDirs)
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                string normP = p.TrimEnd('\\', '/');
                if (clean.Equals(normP, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Also protect C:\Users root
            string? usersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (!string.IsNullOrEmpty(usersRoot) && clean.Equals(usersRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        catch
        {
            return true;
        }

        return false;
    }

    public static string DeduceInstallLocation(string? rawLocation, string? displayIcon, string? uninstallString, string? quietUninstallString)
    {
        if (!string.IsNullOrWhiteSpace(rawLocation))
        {
            string clean = rawLocation.Trim().Trim('"', '\'').TrimEnd('\\', '/');
            if (Directory.Exists(clean) && !IsProtectedSharedDirectory(clean))
                return clean;
            if (File.Exists(clean))
            {
                var dir = Path.GetDirectoryName(clean);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !IsProtectedSharedDirectory(dir))
                    return dir;
            }
        }

        // Try DisplayIcon
        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            string icon = displayIcon.Trim().Trim('"', '\'');
            int comma = icon.IndexOf(',');
            if (comma > 0) icon = icon.Substring(0, comma).Trim().Trim('"', '\'');
            string exeName = Path.GetFileName(icon);
            if (!SystemHostBinaries.Contains(exeName) && File.Exists(icon))
            {
                var dir = Path.GetDirectoryName(icon);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !IsProtectedSharedDirectory(dir))
                    return dir;
            }
        }

        // Try UninstallString & QuietUninstallString
        foreach (var cmd in new[] { uninstallString, quietUninstallString })
        {
            if (string.IsNullOrWhiteSpace(cmd)) continue;
            string exe = ExtractExeFromCommand(cmd);
            string exeName = Path.GetFileName(exe);
            if (!string.IsNullOrEmpty(exe) && !SystemHostBinaries.Contains(exeName) && File.Exists(exe))
            {
                var dir = Path.GetDirectoryName(exe);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !IsProtectedSharedDirectory(dir))
                    return dir;
            }
        }

        return string.Empty;
    }

    public static string ExtractExeFromCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;
        string trimmed = command.Trim();
        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return trimmed.Substring(1, endQuote - 1);
            }
        }

        int exeIndex = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex > 0)
        {
            return trimmed.Substring(0, exeIndex + 4).Trim('"', '\'');
        }

        return string.Empty;
    }

    private static string FormatInstallDate(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length != 8) return raw;
        if (int.TryParse(raw, out _))
        {
            return $"{raw.Substring(0, 4)}-{raw.Substring(4, 2)}-{raw.Substring(6, 2)}";
        }
        return raw;
    }

    public static string SanitizeFileName(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }
        return name.Trim();
    }
}
