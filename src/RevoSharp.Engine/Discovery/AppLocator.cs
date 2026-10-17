using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Scanning;

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

    private static readonly Regex ExeTokenRegex = new(
        @"(?i)\.exe(?=\s|$|[""',;/])",
        RegexOptions.Compiled);

    private static readonly string[] SupportedInstallDateFormats =
    [
        "yyyyMMdd",
        "yyyy-MM-dd",
        "yyyy/MM/dd",
        "MM/dd/yyyy",
        "dd/MM/yyyy",
        "yyyy.MM.dd"
    ];

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

            // 5. Fast match with saved trace logs using lightweight index cache
            await AttachTraceLogsFastAsync(apps.Values);

            return apps.Values
                .OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        });
    }

    /// <summary>
    /// Asynchronously computes real disk directory sizes for installed apps whose registry entry lacked EstimatedSize,
    /// updating UI rows safely without prematurely disposing the concurrency semaphore on cancellation.
    /// </summary>
    public async Task PopulateMissingSizesAsync(
        IEnumerable<InstalledApp> apps,
        CancellationToken cancellationToken = default,
        Action<Action>? uiDispatcher = null)
    {
        var missingApps = apps
            .Where(a => a.EstimatedSizeInBytes <= 0 &&
                        !string.IsNullOrWhiteSpace(a.InstallLocation) &&
                        !IsProtectedSharedDirectory(a.InstallLocation) &&
                        Directory.Exists(a.InstallLocation))
            .ToList();

        if (missingApps.Count == 0) return;

        void DispatchUpdate(Action updateAction)
        {
            if (uiDispatcher != null)
            {
                uiDispatcher(updateAction);
            }
            else
            {
                updateAction();
            }
        }

        var semaphore = new SemaphoreSlim(4);
        var tasks = missingApps.Select(async app =>
        {
            if (cancellationToken.IsCancellationRequested) return;
            bool acquired = false;
            try
            {
                await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;

                DispatchUpdate(() => app.IsSizeCalculating = true);
                long size = await Task.Run(
                    () => ResidualScanner.CalculatePathSize(app.InstallLocation, isDirectory: true),
                    cancellationToken).ConfigureAwait(false);

                if (size > 0 && !cancellationToken.IsCancellationRequested)
                {
                    DispatchUpdate(() => app.EstimatedSizeInBytes = size);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
            finally
            {
                DispatchUpdate(() => app.IsSizeCalculating = false);
                if (acquired)
                {
                    try { semaphore.Release(); } catch { }
                }
            }
        }).ToArray();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch { }
        finally
        {
            semaphore.Dispose();
        }
    }

    private static async Task AttachTraceLogsFastAsync(IEnumerable<InstalledApp> apps)
    {
        if (!Directory.Exists(LogDirectory)) return;

        var indexEntries = await TraceLogSerializer.LoadOrSyncIndexAsync(LogDirectory);
        if (indexEntries.Count == 0) return;

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

            var matchedEntry = indexEntries.FirstOrDefault(l =>
                (!string.IsNullOrEmpty(l.DetectedDisplayName) && l.DetectedDisplayName.Equals(app.DisplayName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.AppName) && l.AppName.Equals(app.DisplayName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.UninstallKeyId) && !string.IsNullOrEmpty(app.UninstallKeyName) && l.UninstallKeyId.Equals(app.UninstallKeyName, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(l.DetectedInstallLocation) && !string.IsNullOrEmpty(app.InstallLocation) &&
                 l.DetectedInstallLocation.TrimEnd('\\').Equals(app.InstallLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)));

            if (matchedEntry != null && File.Exists(matchedEntry.FilePath))
            {
                app.HasTraceLog = true;
                app.TraceLogPath = matchedEntry.FilePath;
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
                    string installDateRaw = appKey.GetValue("InstallDate") as string ?? string.Empty;

                    long estimatedSize = 0;
                    if (appKey.GetValue("EstimatedSize") is int sizeInKb && sizeInKb > 0)
                    {
                        estimatedSize = (long)sizeInKb * 1024L;
                    }

                    string resolvedLocation = DeduceInstallLocation(installLocation, displayIcon, uninstallString, quietUninstallString);
                    var (formattedDate, isRecent) = ParseAndEvaluateInstallDate(installDateRaw, resolvedLocation, displayIcon);
                    string archLabel = is64Bit ? "64 位" : "32 位";

                    string regFullPath = hivePrefix == @"HKLM\WOW6432Node"
                        ? $@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}"
                        : $@"{hivePrefix}\{subKeyPath}\{subKeyName}";

                    string dictKey = cleanDisplayName;
                    if (apps.TryGetValue(dictKey, out var existing))
                    {
                        if (existing.UninstallString.Equals(uninstallString.Trim(), StringComparison.OrdinalIgnoreCase))
                            continue;
                        dictKey = $"{cleanDisplayName} ({archLabel} {version})".Trim();
                        if (apps.ContainsKey(dictKey))
                        {
                            dictKey = $"{cleanDisplayName} ({hivePrefix} {subKeyName})";
                        }
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
                        InstallDate = formattedDate,
                        IsRecentlyInstalled = isRecent,
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

                    string safeLoc = !IsProtectedSharedDirectory(pkgRootFolder) ? pkgRootFolder : string.Empty;
                    var (formattedDate, isRecent) = ParseAndEvaluateInstallDate(string.Empty, safeLoc, null);

                    string psUninstall = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{pkgFullName}'\"";

                    apps[dictKey] = new InstalledApp
                    {
                        Id = $"UWP_{pkgFullName}",
                        UninstallKeyName = pkgFullName,
                        RegistryKeyPath = $@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\{pkgFullName}",
                        DisplayName = $"{displayName} (商店应用)",
                        DisplayVersion = version,
                        Publisher = "Microsoft Store / UWP",
                        InstallLocation = safeLoc,
                        InstallDate = formattedDate,
                        IsRecentlyInstalled = isRecent,
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
            string clean = Environment.ExpandEnvironmentVariables(rawLocation.Trim().Trim('"', '\'')).TrimEnd('\\', '/');
            if (Directory.Exists(clean) && !IsProtectedSharedDirectory(clean))
                return clean;
            if (File.Exists(clean))
            {
                var dir = Path.GetDirectoryName(clean);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !IsProtectedSharedDirectory(dir))
                    return dir;
            }
        }

        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            string icon = Environment.ExpandEnvironmentVariables(displayIcon.Trim().Trim('"', '\''));
            int comma = icon.LastIndexOf(',');
            if (comma > 0) icon = icon.Substring(0, comma).Trim().Trim('"', '\'');
            string exeName = Path.GetFileName(icon);
            if (!SystemHostBinaries.Contains(exeName) && File.Exists(icon))
            {
                var dir = Path.GetDirectoryName(icon);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !IsProtectedSharedDirectory(dir))
                    return dir;
            }
        }

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

    /// <summary>
    /// Accurately extracts the executable path from a raw command line string, supporting environment variables,
    /// quoted paths, unquoted paths with spaces, and folders containing ".exe" substrings.
    /// </summary>
    public static string ExtractExeFromCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;
        string trimmed = Environment.ExpandEnvironmentVariables(command.Trim());

        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return trimmed.Substring(1, endQuote - 1).Trim();
            }
        }

        // Iterate over all ".exe" boundary occurrences (preferring the one that actually exists on disk if multiple)
        string? firstCandidate = null;
        foreach (Match match in ExeTokenRegex.Matches(trimmed))
        {
            string candidate = trimmed.Substring(0, match.Index + 4).Trim('"', '\'', ' ');
            firstCandidate ??= candidate;
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return firstCandidate ?? string.Empty;
    }

    private static (string FormattedDate, bool IsRecent) ParseAndEvaluateInstallDate(
        string rawDate,
        string resolvedLocation,
        string? displayIcon)
    {
        if (!string.IsNullOrWhiteSpace(rawDate))
        {
            string cleanRaw = rawDate.Trim();
            if (DateTime.TryParseExact(
                    cleanRaw,
                    SupportedInstallDateFormats,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out DateTime parsed) ||
                DateTime.TryParse(cleanRaw, CultureInfo.CurrentCulture, DateTimeStyles.None, out parsed))
            {
                if (parsed.Year >= 1995 && parsed <= DateTime.Now.AddDays(1))
                {
                    bool recent = (DateTime.Now - parsed).TotalDays <= 14;
                    return (parsed.ToString("yyyy-MM-dd"), recent);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(resolvedLocation) && Directory.Exists(resolvedLocation))
        {
            try
            {
                DateTime created = Directory.GetCreationTime(resolvedLocation);
                if (created.Year >= 2000 && created <= DateTime.Now.AddDays(1))
                {
                    bool recent = (DateTime.Now - created).TotalDays <= 14;
                    // Verify against icon/main executable creation time if available to prevent false recent flags
                    if (recent && !string.IsNullOrWhiteSpace(displayIcon))
                    {
                        string iconPath = ExtractExeFromCommand(displayIcon);
                        if (!string.IsNullOrEmpty(iconPath) && File.Exists(iconPath))
                        {
                            DateTime exeWrite = File.GetLastWriteTime(iconPath);
                            DateTime exeCreate = File.GetCreationTime(iconPath);
                            DateTime latest = exeCreate > exeWrite ? exeCreate : exeWrite;
                            recent = (DateTime.Now - latest).TotalDays <= 14;
                        }
                    }
                    return (created.ToString("yyyy-MM-dd"), recent);
                }
            }
            catch { }
        }

        return (string.Empty, false);
    }

    public static string SanitizeFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "Unknown";
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }
        return name.Trim();
    }
}
