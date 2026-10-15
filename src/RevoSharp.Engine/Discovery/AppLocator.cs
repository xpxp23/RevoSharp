using Microsoft.Win32;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Discovery;

public class AppLocator
{
    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp",
        "Logs"
    );

    public async Task<List<InstalledApp>> GetInstalledAppsAsync()
    {
        return await Task.Run(() =>
        {
            var apps = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);

            // 1. HKLM 64-bit
            ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", apps, true);

            // 2. HKLM 32-bit (WOW6432Node)
            if (Environment.Is64BitOperatingSystem)
            {
                ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", apps, false);
            }

            // 3. HKCU (Current User)
            ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", apps, Environment.Is64BitOperatingSystem);

            // Check if any has a saved trace log
            if (Directory.Exists(LogDirectory))
            {
                foreach (var app in apps.Values)
                {
                    string safeName = SanitizeFileName(app.DisplayName);
                    string logFile = Path.Combine(LogDirectory, $"{safeName}.revolog.json.gz");
                    if (File.Exists(logFile))
                    {
                        app.HasTraceLog = true;
                        app.TraceLogPath = logFile;
                    }
                }
            }

            return apps.Values
                .OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        });
    }

    private static void ScanRegistryKey(
        RegistryHive hive,
        RegistryView view,
        string subKeyPath,
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

                    // If neither uninstall string is present, it's usually not uninstallable
                    if (string.IsNullOrEmpty(uninstallString) && string.IsNullOrEmpty(quietUninstallString)) continue;

                    string id = $"{hive}_{subKeyName}";
                    if (apps.ContainsKey(displayName)) continue;

                    string publisher = appKey.GetValue("Publisher") as string ?? string.Empty;
                    string version = appKey.GetValue("DisplayVersion") as string ?? string.Empty;
                    string installLocation = appKey.GetValue("InstallLocation") as string ?? string.Empty;
                    string displayIcon = appKey.GetValue("DisplayIcon") as string ?? string.Empty;
                    string installDate = appKey.GetValue("InstallDate") as string ?? string.Empty;

                    long estimatedSize = 0;
                    if (appKey.GetValue("EstimatedSize") is int sizeInKb)
                    {
                        estimatedSize = sizeInKb * 1024L;
                    }

                    string resolvedLocation = DeduceInstallLocation(installLocation, displayIcon, uninstallString, quietUninstallString);

                    var app = new InstalledApp
                    {
                        Id = id,
                        DisplayName = displayName.Trim(),
                        DisplayVersion = version.Trim(),
                        Publisher = publisher.Trim(),
                        InstallLocation = resolvedLocation,
                        UninstallString = uninstallString.Trim(),
                        QuietUninstallString = quietUninstallString.Trim(),
                        DisplayIcon = displayIcon.Trim().Trim('"'),
                        InstallDate = FormatInstallDate(installDate),
                        EstimatedSizeInBytes = estimatedSize,
                        Architecture = is64Bit ? "64 位" : "32 位",
                        Is64Bit = is64Bit
                    };

                    apps[displayName] = app;
                }
                catch
                {
                    // Skip inaccessible entries
                }
            }
        }
        catch
        {
            // Skip inaccessible hives
        }
    }

    public static string DeduceInstallLocation(string? rawLocation, string? displayIcon, string? uninstallString, string? quietUninstallString)
    {
        if (!string.IsNullOrWhiteSpace(rawLocation))
        {
            string clean = rawLocation.Trim().Trim('"', '\'').TrimEnd('\\', '/');
            if (Directory.Exists(clean)) return clean;
            if (File.Exists(clean))
            {
                var dir = Path.GetDirectoryName(clean);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) return dir;
            }
        }

        // Try DisplayIcon
        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            string icon = displayIcon.Trim().Trim('"', '\'');
            int comma = icon.IndexOf(',');
            if (comma > 0) icon = icon.Substring(0, comma).Trim().Trim('"', '\'');
            if (File.Exists(icon))
            {
                var dir = Path.GetDirectoryName(icon);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) return dir;
            }
            if (Directory.Exists(icon)) return icon;
        }

        // Try UninstallString & QuietUninstallString
        foreach (var cmd in new[] { uninstallString, quietUninstallString })
        {
            if (string.IsNullOrWhiteSpace(cmd)) continue;
            string exe = ExtractExeFromCommand(cmd);
            if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
            {
                var dir = Path.GetDirectoryName(exe);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) return dir;
            }
        }

        return !string.IsNullOrWhiteSpace(rawLocation) ? rawLocation.Trim().Trim('"', '\'') : string.Empty;
    }

    private static string ExtractExeFromCommand(string command)
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
        // YYYYMMDD -> YYYY-MM-DD
        if (int.TryParse(raw, out _))
        {
            return $"{raw.Substring(0, 4)}-{raw.Substring(4, 2)}-{raw.Substring(6, 2)}";
        }
        return raw;
    }

    private static string SanitizeFileName(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }
        return name;
    }
}
