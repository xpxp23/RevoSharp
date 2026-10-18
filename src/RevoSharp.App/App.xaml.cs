using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using RevoSharp.App.Views;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;
using Wpf.Ui.Appearance;

namespace RevoSharp.App;

public enum AppThemeMode
{
    Dark,
    Light,
    System
}

public partial class App : Application
{
    private const int ATTACH_PARENT_PROCESS = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    public static AppThemeMode CurrentThemeMode { get; private set; } = AppThemeMode.Dark;

    public static string? StartupHuntTargetPath { get; private set; }

    public static string CurrentThemeDisplay => CurrentThemeMode switch
    {
        AppThemeMode.Dark => "深色",
        AppThemeMode.Light => "浅色",
        AppThemeMode.System => "跟随系统",
        _ => "深色"
    };

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 1. Load persisted settings and apply theme before creating any window
        var settings = SettingsSerializer.Load();
        if (Enum.TryParse<AppThemeMode>(settings.ThemeMode, ignoreCase: true, out var savedTheme))
        {
            ApplyThemeMode(savedTheme, persistToSettings: false);
        }
        else
        {
            ApplyThemeMode(AppThemeMode.Dark, persistToSettings: false);
        }

        // 2. Check for CLI headless mode (--cli) or Context Menu hunt target (--hunt "<path>")
        if (e.Args.Length > 0)
        {
            if (e.Args.Any(a => a.Equals("--cli", StringComparison.OrdinalIgnoreCase) ||
                                a.Equals("/cli", StringComparison.OrdinalIgnoreCase)))
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                int exitCode = await RunHeadlessCliAsync(e.Args);
                Shutdown(exitCode);
                return;
            }

            for (int i = 0; i < e.Args.Length; i++)
            {
                if ((e.Args[i].Equals("--hunt", StringComparison.OrdinalIgnoreCase) ||
                     e.Args[i].Equals("--target", StringComparison.OrdinalIgnoreCase)) &&
                    i + 1 < e.Args.Length)
                {
                    StartupHuntTargetPath = e.Args[i + 1].Trim().Trim('"');
                    break;
                }
                else if (File.Exists(e.Args[i]) || Directory.Exists(e.Args[i]))
                {
                    StartupHuntTargetPath = e.Args[i].Trim().Trim('"');
                }
            }
        }

        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    private static async Task<int> RunHeadlessCliAsync(string[] args)
    {
        if (!AttachConsole(ATTACH_PARENT_PROCESS))
        {
            AllocConsole();
        }

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("==================================================================");
        Console.WriteLine("  RevoSharp v2.4 Pro - Headless CLI Automation Engine");
        Console.WriteLine("==================================================================");

        try
        {
            var locator = new AppLocator();
            var scanner = new ResidualScanner();
            var runner = new UninstallerRunner();

            bool isList = args.Any(a => a.Equals("--list", StringComparison.OrdinalIgnoreCase));
            bool isSilent = args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase));
            bool autoClean = args.Any(a => a.Equals("--clean", StringComparison.OrdinalIgnoreCase) ||
                                           a.Equals("--clean-residuals", StringComparison.OrdinalIgnoreCase));

            ScanMode scanMode = SettingsSerializer.Current.DefaultScanMode;
            string? targetQuery = null;
            string? jsonOutPath = null;
            bool isUninstall = false;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if ((arg.Equals("--uninstall", StringComparison.OrdinalIgnoreCase) ||
                     arg.Equals("--scan", StringComparison.OrdinalIgnoreCase)) &&
                    i + 1 < args.Length)
                {
                    isUninstall = arg.Equals("--uninstall", StringComparison.OrdinalIgnoreCase);
                    targetQuery = args[++i].Trim().Trim('"');
                }
                else if (arg.Equals("--mode", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    if (Enum.TryParse<ScanMode>(args[++i], ignoreCase: true, out var parsedMode))
                    {
                        scanMode = parsedMode;
                    }
                }
                else if (arg.Equals("--json-out", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    jsonOutPath = args[++i].Trim().Trim('"');
                }
            }

            var allApps = await locator.GetInstalledAppsAsync(includeWindowsApps: true);

            if (isList)
            {
                Console.WriteLine($"Found {allApps.Count} installed applications:");
                foreach (var app in allApps)
                {
                    Console.WriteLine($"  - {app.DisplayName} | v{app.VersionDisplay} | {app.PublisherDisplay} | {app.InstallLocation}");
                }
                return 0;
            }

            if (string.IsNullOrWhiteSpace(targetQuery))
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  RevoSharp.App.exe --cli --list");
                Console.WriteLine("  RevoSharp.App.exe --cli --scan \"<AppNameOrPath>\" [--mode Safe|Moderate|Advanced] [--clean] [--json-out \"<report.json>\"]");
                Console.WriteLine("  RevoSharp.App.exe --cli --uninstall \"<AppName>\" [--silent] [--clean] [--mode Safe|Moderate|Advanced] [--json-out \"<report.json>\"]");
                return 1;
            }

            var targetApp = allApps.FirstOrDefault(a =>
                a.DisplayName.Equals(targetQuery, StringComparison.OrdinalIgnoreCase) ||
                a.Id.Equals(targetQuery, StringComparison.OrdinalIgnoreCase) ||
                a.DisplayName.Contains(targetQuery, StringComparison.OrdinalIgnoreCase));

            if (targetApp == null)
            {
                if (Directory.Exists(targetQuery) || File.Exists(targetQuery))
                {
                    targetApp = new InstalledApp
                    {
                        Id = $"CLI_Forced_{Guid.NewGuid():N}",
                        DisplayName = Path.GetFileNameWithoutExtension(targetQuery.TrimEnd('\\')),
                        InstallLocation = Directory.Exists(targetQuery) ? targetQuery : (Path.GetDirectoryName(targetQuery) ?? string.Empty),
                        DisplayIcon = File.Exists(targetQuery) ? targetQuery : string.Empty
                    };
                }
                else
                {
                    Console.WriteLine($"[ERROR] Target application not found: {targetQuery}");
                    return 2;
                }
            }

            Console.WriteLine($"[TARGET] {targetApp.DisplayName} ({targetApp.VersionDisplay})");

            if (isUninstall && !string.IsNullOrWhiteSpace(targetApp.UninstallString))
            {
                Console.WriteLine($"[STEP 1] Running uninstaller (Silent={isSilent})...");
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));
                await runner.RunAndTrackUninstallerAsync(
                    targetApp,
                    forceInteractive: !isSilent,
                    status => Console.WriteLine($"  -> {status}"),
                    cts.Token);
            }

            Console.WriteLine($"[STEP 2] Scanning residuals (Mode={scanMode})...");
            var residuals = await scanner.ScanResidualsAsync(targetApp, scanMode, allApps);
            Console.WriteLine($"[RESULT] Discovered {residuals.Count} residual items.");
            foreach (var r in residuals.Take(50))
            {
                Console.WriteLine($"  [{r.Confidence}] [{r.TypeDisplay}] {r.FullDisplayPath} ({r.Reason})");
            }

            if (!string.IsNullOrWhiteSpace(jsonOutPath))
            {
                var reportObj = new
                {
                    TargetApp = targetApp.DisplayName,
                    ScanMode = scanMode.ToString(),
                    GeneratedAt = DateTime.Now,
                    TotalResiduals = residuals.Count,
                    Items = residuals.Select(r => new
                    {
                        r.TypeDisplay,
                        Confidence = r.Confidence.ToString(),
                        r.Path,
                        r.ValueName,
                        r.SizeInBytes,
                        r.Reason
                    })
                };
                await File.WriteAllTextAsync(
                    jsonOutPath,
                    JsonSerializer.Serialize(reportObj, new JsonSerializerOptions { WriteIndented = true }),
                    Encoding.UTF8);
                Console.WriteLine($"[REPORT] Saved JSON report to: {jsonOutPath}");
            }

            if (autoClean && residuals.Count > 0)
            {
                var toClean = residuals.Where(r => r.Confidence is ConfidenceLevel.High or ConfidenceLevel.Medium).ToList();
                Console.WriteLine($"[STEP 3] Backing up and cleaning {toClean.Count} high/medium confidence residuals...");

                var manifest = new BackupManifest
                {
                    AppName = targetApp.DisplayName,
                    BackupCategory = "CLI 自动化卸载清理",
                    CreatedTime = DateTime.Now
                };

                var regMerged = await RegistryBackup.SynthesizeMergedRegBackupAsync(toClean, targetApp.DisplayName);
                foreach (var (regFile, is64) in regMerged)
                {
                    manifest.RegBackupFiles.Add(regFile);
                    manifest.RegBackupViewMap[regFile] = is64;
                }

                foreach (var regItem in toClean.Where(i => i.Type is ResidualType.RegistryKey or ResidualType.RegistryValue))
                {
                    if (regItem.Category == ResidualCategory.EnvironmentPath && !string.IsNullOrEmpty(regItem.PathSegmentToRemove))
                    {
                        RegistryBackup.BackupAndCleanEnvironmentPathSegment(regItem.IsSystemEnvironmentVariable, regItem.PathSegmentToRemove, manifest);
                        continue;
                    }

                    string? svcName = !string.IsNullOrEmpty(regItem.ServiceName) ? regItem.ServiceName : regItem.ValueName;
                    if ((regItem.Category is ResidualCategory.Service or ResidualCategory.DriverPackage) && !string.IsNullOrEmpty(svcName))
                    {
                        await RegistryBackup.StopAndDeleteServiceAsync(svcName);
                        if (!string.IsNullOrEmpty(regItem.DriverPublishedInfName))
                        {
                            await RegistryBackup.UninstallDriverPackageAsync(regItem.DriverPublishedInfName);
                        }
                    }

                    int slash = regItem.Path.IndexOf('\\');
                    if (slash <= 0) continue;
                    string hive = regItem.Path[..slash];
                    string sub = regItem.Path[(slash + 1)..];
                    if (regItem.Type == ResidualType.RegistryKey)
                    {
                        RegistryBackup.DeleteKey(hive, sub, regItem.Is64BitRegistryView);
                    }
                    else if (!string.IsNullOrEmpty(regItem.ValueName))
                    {
                        RegistryBackup.DeleteValue(hive, sub, regItem.ValueName, regItem.Is64BitRegistryView);
                    }
                }

                foreach (var taskItem in toClean.Where(i => i.Category == ResidualCategory.ScheduledTask))
                {
                    var (taskBak, resolvedTn) = await RegistryBackup.BackupAndDeleteScheduledTaskWithNameAsync(
                        taskItem.Path,
                        taskItem.TaskSchedulerName,
                        targetApp.DisplayName);
                    if (!string.IsNullOrEmpty(taskBak))
                    {
                        manifest.TaskXmlBackupFiles.Add(taskBak);
                        if (!string.IsNullOrEmpty(resolvedTn))
                        {
                            manifest.TaskScheduleMap[taskBak] = resolvedTn;
                        }
                    }
                }

                var filePaths = toClean
                    .Where(i => i.Type is ResidualType.File or ResidualType.Directory && i.Category != ResidualCategory.ScheduledTask)
                    .Select(i => i.Path)
                    .ToList();

                if (filePaths.Count > 0)
                {
                    await FileLockUnlocker.UnlockFilesAsync(filePaths, allowExplorerRestart: false);
                    var recycled = FileBackup.SendToRecycleBinBatch(filePaths);
                    manifest.RecycledFilePaths.AddRange(recycled);
                }

                await RegistryBackup.SaveBackupManifestAsync(manifest);
                Console.WriteLine($"[DONE] Cleaned {toClean.Count} items. Backup saved to: {manifest.ManifestPath}");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FATAL] {ex.Message}");
            return 99;
        }
        finally
        {
            FreeConsole();
        }
    }

    public static string CycleThemeMode()
    {
        var next = CurrentThemeMode switch
        {
            AppThemeMode.Dark => AppThemeMode.Light,
            AppThemeMode.Light => AppThemeMode.System,
            _ => AppThemeMode.Dark
        };
        ApplyThemeMode(next, persistToSettings: true);
        return CurrentThemeDisplay;
    }

    public static void ApplyThemeMode(AppThemeMode mode, bool persistToSettings = true)
    {
        CurrentThemeMode = mode;
        if (persistToSettings)
        {
            SettingsSerializer.Current.ThemeMode = mode.ToString();
            SettingsSerializer.Save();
        }

        bool isDark = mode switch
        {
            AppThemeMode.Dark => true,
            AppThemeMode.Light => false,
            AppThemeMode.System => IsSystemUsingDarkTheme(),
            _ => true
        };

        ApplicationTheme targetTheme = isDark ? ApplicationTheme.Dark : ApplicationTheme.Light;
        ApplicationThemeManager.Apply(targetTheme);

        if (Current?.Resources == null) return;
        var res = Current.Resources;

        if (isDark)
        {
            SetBrush(res, "RevoPillSelectedBackgroundBrush", Color.FromArgb(0x2E, 0x00, 0x78, 0xD4));
            SetBrush(res, "RevoPillSelectedBorderBrush", Color.FromRgb(0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoAccentCyanBrush", Color.FromRgb(0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoAccentCyanTextBrush", Color.FromRgb(0x88, 0xCC, 0xFF));
            SetBrush(res, "RevoAccentGreenBrush", Color.FromRgb(0x6C, 0xCB, 0x5F));
            SetBrush(res, "RevoAccentGreenTextBrush", Color.FromRgb(0x88, 0xEE, 0xAA));
            SetBrush(res, "RevoAccentPurpleBrush", Color.FromRgb(0xC3, 0x95, 0xFF));
            SetBrush(res, "RevoAccentAmberBrush", Color.FromRgb(0xFF, 0xAA, 0x44));
            SetBrush(res, "RevoAccentRedBrush", Color.FromRgb(0xFF, 0x66, 0x66));
            SetBrush(res, "RevoWarningIconBrush", Color.FromRgb(0xFF, 0x99, 0x55));
            SetBrush(res, "RevoWarningBadgeBgBrush", Color.FromArgb(0x28, 0xFF, 0x66, 0x44));

            SetBrush(res, "RevoTagBlueBgBrush", Color.FromArgb(0x24, 0x00, 0x78, 0xD4));
            SetBrush(res, "RevoTagBlueBorderBrush", Color.FromArgb(0x44, 0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoTagPurpleBgBrush", Color.FromArgb(0x24, 0x9E, 0x77, 0xED));
            SetBrush(res, "RevoTagPurpleBorderBrush", Color.FromArgb(0x44, 0xC3, 0x95, 0xFF));
            SetBrush(res, "RevoTagGreenBgBrush", Color.FromArgb(0x22, 0x44, 0xDD, 0x88));
            SetBrush(res, "RevoTagRedBgBrush", Color.FromArgb(0x2E, 0xFF, 0x44, 0x44));
            SetBrush(res, "RevoTagRedBorderBrush", Color.FromArgb(0x55, 0xFF, 0x66, 0x66));
            SetBrush(res, "RevoTagAmberBgBrush", Color.FromArgb(0x28, 0xFF, 0xAA, 0x33));
            SetBrush(res, "RevoTagAmberBorderBrush", Color.FromArgb(0x55, 0xFF, 0xAA, 0x33));
            SetBrush(res, "RevoTagNeutralBgBrush", Color.FromArgb(0x22, 0xFF, 0xFF, 0xFF));

            SetBrush(res, "RevoOverlayMaskBrush", Color.FromArgb(0xB8, 0x12, 0x14, 0x18));
            SetBrush(res, "RevoFloatingBarBgBrush", Color.FromArgb(0xF2, 0x1A, 0x20, 0x2C));
            SetBrush(res, "RevoFloatingBarBorderBrush", Color.FromArgb(0x55, 0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoHudCardBgBrush", Color.FromArgb(0xF8, 0x1C, 0x1E, 0x26));
            SetBrush(res, "RevoHudCardBorderBrush", Color.FromArgb(0x3A, 0xFF, 0xFF, 0xFF));
        }
        else
        {
            SetBrush(res, "RevoPillSelectedBackgroundBrush", Color.FromArgb(0x1E, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoPillSelectedBorderBrush", Color.FromRgb(0x00, 0x67, 0xC0));
            SetBrush(res, "RevoAccentCyanBrush", Color.FromRgb(0x00, 0x5F, 0xB8));
            SetBrush(res, "RevoAccentCyanTextBrush", Color.FromRgb(0x00, 0x4E, 0x98));
            SetBrush(res, "RevoAccentGreenBrush", Color.FromRgb(0x10, 0x7C, 0x10));
            SetBrush(res, "RevoAccentGreenTextBrush", Color.FromRgb(0x0E, 0x6A, 0x0E));
            SetBrush(res, "RevoAccentPurpleBrush", Color.FromRgb(0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoAccentAmberBrush", Color.FromRgb(0xC5, 0x65, 0x00));
            SetBrush(res, "RevoAccentRedBrush", Color.FromRgb(0xD1, 0x34, 0x38));
            SetBrush(res, "RevoWarningIconBrush", Color.FromRgb(0xC5, 0x55, 0x00));
            SetBrush(res, "RevoWarningBadgeBgBrush", Color.FromArgb(0x20, 0xD1, 0x55, 0x00));

            SetBrush(res, "RevoTagBlueBgBrush", Color.FromArgb(0x18, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoTagBlueBorderBrush", Color.FromArgb(0x44, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoTagPurpleBgBrush", Color.FromArgb(0x18, 0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoTagPurpleBorderBrush", Color.FromArgb(0x44, 0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoTagGreenBgBrush", Color.FromArgb(0x1A, 0x10, 0x7C, 0x10));
            SetBrush(res, "RevoTagRedBgBrush", Color.FromArgb(0x1A, 0xD1, 0x34, 0x38));
            SetBrush(res, "RevoTagRedBorderBrush", Color.FromArgb(0x55, 0xD1, 0x34, 0x38));
            SetBrush(res, "RevoTagAmberBgBrush", Color.FromArgb(0x1E, 0xC5, 0x65, 0x00));
            SetBrush(res, "RevoTagAmberBorderBrush", Color.FromArgb(0x55, 0xC5, 0x65, 0x00));
            SetBrush(res, "RevoTagNeutralBgBrush", Color.FromArgb(0x14, 0x00, 0x00, 0x00));

            SetBrush(res, "RevoOverlayMaskBrush", Color.FromArgb(0xCC, 0xF3, 0xF5, 0xF8));
            SetBrush(res, "RevoFloatingBarBgBrush", Color.FromArgb(0xF6, 0xFF, 0xFF, 0xFF));
            SetBrush(res, "RevoFloatingBarBorderBrush", Color.FromArgb(0x55, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoHudCardBgBrush", Color.FromArgb(0xFA, 0xFF, 0xFF, 0xFF));
            SetBrush(res, "RevoHudCardBorderBrush", Color.FromArgb(0x28, 0x00, 0x00, 0x00));
        }
    }

    private static void SetBrush(ResourceDictionary dict, string key, Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        dict[key] = brush;
    }

    private static bool IsSystemUsingDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int useLight)
            {
                return useLight == 0;
            }
        }
        catch { }
        return true;
    }
}
