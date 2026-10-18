using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Execution;
using RevoSharp.Engine.Safety;
using RevoSharp.Engine.Scanning;

namespace RevoSharp.Engine.Hunter;

public class HunterService
{
    private static readonly HashSet<string> SystemCriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "lsass.exe", "services.exe", "dwm.exe", "smss.exe",
        "wininit.exe", "winlogon.exe", "svchost.exe", "ntoskrnl.exe", "fontdrvhost.exe",
        "sihost.exe", "taskhostw.exe", "spoolsv.exe", "explorer.exe", "taskmgr.exe",
        "regedit.exe", "mmc.exe", "SearchHost.exe", "ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe", "ApplicationFrameHost.exe", "RuntimeBroker.exe",
        "ctfmon.exe", "dllhost.exe", "conhost.exe", "registry", "system", "idle"
    };

    private static readonly HashSet<string> GenericBinaryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "app.exe", "update.exe", "updater.exe", "launcher.exe", "helper.exe",
        "service.exe", "daemon.exe", "agent.exe", "client.exe", "server.exe", "main.exe"
    };

    private static readonly HashSet<string> AutostartTriggerElementNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "LogonTrigger",
        "BootTrigger",
        "SessionStateChangeTrigger",
        "RegistrationTrigger"
    };

    #region Win32 P/Invoke
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public int Width => Right - Left;
        public int Height => Bottom - Top;
    }

    private const uint GA_ROOT = 2;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;

    [DllImport("user32.dll")]
    private static extern IntPtr WindowFromPoint(POINT Point);

    [DllImport("user32.dll")]
    private static extern IntPtr GetAncestor(IntPtr hwnd, uint gaFlags);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    #endregion

    public IntPtr GetRootWindowAtPoint(int screenX, int screenY)
    {
        var point = new POINT { X = screenX, Y = screenY };
        IntPtr rawHwnd = WindowFromPoint(point);
        if (rawHwnd == IntPtr.Zero) return IntPtr.Zero;

        IntPtr rootHwnd = GetAncestor(rawHwnd, GA_ROOT);
        IntPtr targetHwnd = rootHwnd != IntPtr.Zero ? rootHwnd : rawHwnd;

        GetWindowThreadProcessId(targetHwnd, out uint pid);
        if (pid == 0 || pid == (uint)Environment.ProcessId) return IntPtr.Zero;

        return targetHwnd;
    }

    public HunterTargetInfo? InspectPoint(int screenX, int screenY, List<InstalledApp>? installedApps = null, bool includeDeepAutostartScan = true)
    {
        IntPtr targetHwnd = GetRootWindowAtPoint(screenX, screenY);
        if (targetHwnd == IntPtr.Zero) return null;

        return InspectWindowHandle(targetHwnd, installedApps, includeDeepAutostartScan);
    }

    public HunterTargetInfo? InspectWindowHandle(IntPtr targetHwnd, List<InstalledApp>? installedApps = null, bool includeDeepAutostartScan = true)
    {
        if (targetHwnd == IntPtr.Zero) return null;

        GetWindowThreadProcessId(targetHwnd, out uint pid);
        if (pid == 0 || pid == (uint)Environment.ProcessId) return null;

        var sbTitle = new StringBuilder(512);
        GetWindowText(targetHwnd, sbTitle, 512);
        string windowTitle = sbTitle.ToString();

        var sbClass = new StringBuilder(256);
        GetClassName(targetHwnd, sbClass, 256);
        string windowClass = sbClass.ToString();

        string exePath = GetProcessExecutablePath((int)pid);
        string processName = string.Empty;
        if (!string.IsNullOrEmpty(exePath))
        {
            processName = Path.GetFileName(exePath);
        }
        else
        {
            try
            {
                using var p = Process.GetProcessById((int)pid);
                processName = p.ProcessName + ".exe";
            }
            catch { }
        }

        if (string.IsNullOrEmpty(processName)) return null;

        var info = new HunterTargetInfo
        {
            WindowHandle = targetHwnd,
            WindowTitle = windowTitle,
            WindowClassName = windowClass,
            ProcessId = (int)pid,
            ProcessName = processName,
            ExecutablePath = exePath,
            DirectoryPath = !string.IsNullOrEmpty(exePath) ? (Path.GetDirectoryName(exePath) ?? string.Empty) : string.Empty
        };

        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(exePath);
                info.Publisher = vi.CompanyName ?? string.Empty;
                info.ProductVersion = vi.ProductVersion ?? vi.FileVersion ?? string.Empty;
                if (string.IsNullOrEmpty(info.WindowTitle))
                {
                    info.WindowTitle = vi.FileDescription ?? Path.GetFileNameWithoutExtension(exePath);
                }
            }
            catch { }
        }

        if (string.IsNullOrWhiteSpace(info.WindowTitle))
        {
            info.WindowTitle = processName;
        }

        try
        {
            using var p = Process.GetProcessById((int)pid);
            info.Is64Bit = Environment.Is64BitOperatingSystem && !IsWow64(p);
            info.Architecture = info.Is64Bit ? "64 位" : "32 位";
        }
        catch
        {
            info.Is64Bit = Environment.Is64BitProcess;
            info.Architecture = info.Is64Bit ? "64 位" : "32 位";
        }

        string winFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
        if (SystemCriticalProcesses.Contains(processName) ||
            (!string.IsNullOrEmpty(exePath) && exePath.StartsWith(winFolder, StringComparison.OrdinalIgnoreCase)))
        {
            info.IsSystemCritical = true;
            info.SystemProtectionReason = "Windows 系统核心组件或外壳进程，已启用主动防护以防系统崩溃或桌面消失";
        }

        ResolveInstalledApp(info, installedApps);

        if (includeDeepAutostartScan && !info.IsSystemCritical)
        {
            ScanAutostartPersistence(info);
        }

        return info;
    }

    public HunterTargetInfo? InspectFileOrShortcut(string filePath, List<InstalledApp>? installedApps = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || (!File.Exists(filePath) && !Directory.Exists(filePath)))
            return null;

        string resolvedExe = filePath;
        if (Directory.Exists(filePath))
        {
            var topExe = Directory.GetFiles(filePath, "*.exe", SearchOption.TopDirectoryOnly)
                .FirstOrDefault(f => !Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(topExe))
            {
                resolvedExe = topExe;
            }
        }
        else if (filePath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            string? target = ResolveShortcutTarget(filePath);
            if (!string.IsNullOrEmpty(target) && (File.Exists(target) || Directory.Exists(target)))
            {
                resolvedExe = target;
            }
        }

        bool isDirTarget = Directory.Exists(resolvedExe);
        string procName = isDirTarget ? Path.GetFileName(resolvedExe.TrimEnd('\\')) : Path.GetFileName(resolvedExe);
        string title = Path.GetFileNameWithoutExtension(filePath.TrimEnd('\\'));
        string pub = string.Empty;
        string ver = string.Empty;

        if (!isDirTarget && File.Exists(resolvedExe))
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(resolvedExe);
                pub = vi.CompanyName ?? string.Empty;
                ver = vi.ProductVersion ?? vi.FileVersion ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(vi.FileDescription))
                {
                    title = vi.FileDescription;
                }
            }
            catch { }
        }

        int pid = 0;
        if (!isDirTarget)
        {
            try
            {
                var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(resolvedExe));
                if (procs.Length > 0)
                {
                    pid = procs[0].Id;
                    foreach (var p in procs) p.Dispose();
                }
            }
            catch { }
        }

        string winFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
        bool isCritical = SystemCriticalProcesses.Contains(procName) ||
                          resolvedExe.StartsWith(winFolder, StringComparison.OrdinalIgnoreCase);

        var info = new HunterTargetInfo
        {
            WindowHandle = IntPtr.Zero,
            WindowTitle = title,
            WindowClassName = "ShortcutOrFileTarget",
            ProcessId = pid,
            ProcessName = procName,
            ExecutablePath = resolvedExe,
            DirectoryPath = isDirTarget ? resolvedExe : (Path.GetDirectoryName(resolvedExe) ?? string.Empty),
            Publisher = pub,
            ProductVersion = ver,
            Architecture = Environment.Is64BitOperatingSystem ? "64 位" : "32 位",
            Is64Bit = Environment.Is64BitOperatingSystem,
            IsSystemCritical = isCritical,
            SystemProtectionReason = isCritical ? "Windows 系统核心组件或外壳进程，已启用主动防护" : string.Empty
        };

        ResolveInstalledApp(info, installedApps);
        if (!info.IsSystemCritical)
        {
            ScanAutostartPersistence(info);
        }

        return info;
    }

    public RECT GetWindowBoundingRect(IntPtr hWnd)
    {
        GetWindowRect(hWnd, out RECT rect);
        return rect;
    }

    private static string GetProcessExecutablePath(int pid)
    {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
        if (hProcess != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                uint size = (uint)sb.Capacity;
                if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                {
                    return sb.ToString();
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static bool IsWow64(Process process)
    {
        try
        {
            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

            if (IsWow64Process(process.Handle, out bool isWow64))
            {
                return isWow64;
            }
        }
        catch { }
        return false;
    }

    private static void ResolveInstalledApp(HunterTargetInfo info, List<InstalledApp>? installedApps)
    {
        if (installedApps != null && installedApps.Count > 0 && !string.IsNullOrEmpty(info.ExecutablePath))
        {
            string targetExe = Path.GetFileName(info.ExecutablePath);
            string targetDir = info.DirectoryPath.TrimEnd('\\');

            var matched = installedApps.FirstOrDefault(a =>
                !string.IsNullOrEmpty(a.InstallLocation) &&
                !AppLocator.IsProtectedSharedDirectory(a.InstallLocation) &&
                (targetDir.Equals(a.InstallLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                 targetDir.StartsWith(a.InstallLocation.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)));

            matched ??= installedApps.FirstOrDefault(a =>
                !GenericBinaryNames.Contains(targetExe) &&
                ((!string.IsNullOrEmpty(a.DisplayIcon) && a.DisplayIcon.Contains(targetExe, StringComparison.OrdinalIgnoreCase)) ||
                 (!string.IsNullOrEmpty(a.UninstallString) && a.UninstallString.Contains(targetExe, StringComparison.OrdinalIgnoreCase))));

            if (matched == null)
            {
                string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
                if (exeNoExt.Length >= 4 && !GenericBinaryNames.Contains(targetExe))
                {
                    matched = installedApps.FirstOrDefault(a =>
                        a.DisplayName.Equals(exeNoExt, StringComparison.OrdinalIgnoreCase) ||
                        a.DisplayName.StartsWith(exeNoExt + " ", StringComparison.OrdinalIgnoreCase));
                }
            }

            if (matched != null)
            {
                info.IsRegisteredApp = true;
                info.MatchedApp = matched;
                info.EffectiveApp = matched;
                return;
            }
        }

        string dispName = !string.IsNullOrEmpty(info.WindowTitle) ? info.WindowTitle : Path.GetFileNameWithoutExtension(info.ExecutablePath);
        if (string.IsNullOrWhiteSpace(dispName)) dispName = info.ProcessName;

        bool isSharedDir = AppLocator.IsProtectedSharedDirectory(info.DirectoryPath);
        string safeInstallDir = isSharedDir ? string.Empty : info.DirectoryPath;

        string uninstallStr = string.Empty;
        if (!isSharedDir && !string.IsNullOrEmpty(info.DirectoryPath) && Directory.Exists(info.DirectoryPath))
        {
            try
            {
                var uninstallerFile = Directory.GetFiles(info.DirectoryPath, "*unins*.exe")
                    .Concat(Directory.GetFiles(info.DirectoryPath, "*uninstall*.exe"))
                    .FirstOrDefault();

                if (!string.IsNullOrEmpty(uninstallerFile))
                {
                    uninstallStr = $"\"{uninstallerFile}\"";
                }
            }
            catch { }
        }

        uint safeHash = unchecked((uint)info.ExecutablePath.GetHashCode());
        var virtualApp = new InstalledApp
        {
            Id = $"HunterVirtual_{Path.GetFileNameWithoutExtension(info.ExecutablePath)}_{safeHash}",
            DisplayName = dispName,
            DisplayVersion = info.ProductVersion,
            Publisher = !string.IsNullOrEmpty(info.Publisher) ? info.Publisher : "未知发布者 (便携/独立程序)",
            InstallLocation = safeInstallDir,
            DisplayIcon = info.ExecutablePath,
            UninstallString = uninstallStr,
            QuietUninstallString = string.Empty,
            Architecture = info.Architecture,
            Is64Bit = info.Is64Bit,
            IsProtectedSingleFile = isSharedDir
        };

        info.IsRegisteredApp = false;
        info.MatchedApp = null;
        info.EffectiveApp = virtualApp;
    }

    public void ScanAutostartPersistence(HunterTargetInfo info)
    {
        info.AutostartDescriptions.Clear();
        if (string.IsNullOrEmpty(info.ExecutablePath)) return;

        string exeName = Path.GetFileName(info.ExecutablePath);
        string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
        string exePath = info.ExecutablePath;
        string? safeDirPrefix = (!string.IsNullOrEmpty(info.DirectoryPath) && !AppLocator.IsProtectedSharedDirectory(info.DirectoryPath))
            ? info.DirectoryPath.TrimEnd('\\') + "\\"
            : null;

        CheckRegistryRun(RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, safeDirPrefix, info.AutostartDescriptions);
        CheckRegistryRun(RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, safeDirPrefix, info.AutostartDescriptions);
        CheckRegistryRun(RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, safeDirPrefix, info.AutostartDescriptions);
        CheckRegistryRun(RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, safeDirPrefix, info.AutostartDescriptions);

        if (Environment.Is64BitOperatingSystem)
        {
            CheckRegistryRun(RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, safeDirPrefix, info.AutostartDescriptions);
        }

        string userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        CheckStartupFolder(userStartup, exeName, exeNoExt, exePath, info.AutostartDescriptions);

        string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        CheckStartupFolder(commonStartup, exeName, exeNoExt, exePath, info.AutostartDescriptions);

        CheckScheduledTaskAutorunsForTarget(exeName, exePath, safeDirPrefix, info.AutostartDescriptions);

        info.HasAutostartEntry = info.AutostartDescriptions.Count > 0;
    }

    private static bool IsAutostartCommandMatchingTarget(
        string? commandValue,
        string exeName,
        string exePath,
        string? safeDirPrefix)
    {
        if (string.IsNullOrWhiteSpace(commandValue)) return false;

        if (commandValue.Contains(exePath, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(safeDirPrefix) && commandValue.Contains(safeDirPrefix, StringComparison.OrdinalIgnoreCase))
            return true;

        if (GenericBinaryNames.Contains(exeName))
            return false;

        string extracted = AppLocator.ExtractExeFromCommand(commandValue);
        if (!string.IsNullOrEmpty(extracted))
        {
            if (File.Exists(extracted) && !extracted.Equals(exePath, StringComparison.OrdinalIgnoreCase))
                return false;

            return Path.GetFileName(extracted).Equals(exeName, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static void CheckRegistryRun(
        RegistryHive hive,
        RegistryView view,
        string hiveShort,
        string subKey,
        string exeName,
        string exePath,
        string? safeDirPrefix,
        List<string> list)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subKey);
            if (key == null) return;
            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (IsAutostartCommandMatchingTarget(val, exeName, exePath, safeDirPrefix))
                {
                    string displaySub = view == RegistryView.Registry32
                        ? @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                        : subKey;
                    list.Add($"{hiveShort}\\{displaySub} -> [{valName}]");
                }
            }
        }
        catch { }
    }

    private static void CheckStartupFolder(string folder, string exeName, string exeNoExt, string exePath, List<string> list)
    {
        if (!Directory.Exists(folder)) return;
        try
        {
            foreach (var file in Directory.GetFiles(folder))
            {
                string fnameNoExt = Path.GetFileNameWithoutExtension(file);
                if ((exeNoExt.Length >= 4 && !GenericBinaryNames.Contains(exeName) && fnameNoExt.Equals(exeNoExt, StringComparison.OrdinalIgnoreCase)) ||
                    ShortcutTargetMatches(file, exeName, exePath))
                {
                    list.Add($"启动文件夹: {file}");
                }
            }
        }
        catch { }
    }

    private static void CheckScheduledTaskAutorunsForTarget(
        string exeName,
        string exePath,
        string? safeDirPrefix,
        List<string> list)
    {
        try
        {
            var tasks = new List<AutostartEntry>();
            ScanThirdPartyScheduledTaskAutoruns(tasks);
            foreach (var task in tasks)
            {
                if (task.ExecutablePath.Equals(exePath, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(safeDirPrefix) && task.ExecutablePath.StartsWith(safeDirPrefix, StringComparison.OrdinalIgnoreCase)) ||
                    (!GenericBinaryNames.Contains(exeName) && !File.Exists(task.ExecutablePath) && Path.GetFileName(task.ExecutablePath).Equals(exeName, StringComparison.OrdinalIgnoreCase)))
                {
                    list.Add($"计划任务自启: {task.ScheduledTaskPath}");
                }
            }
        }
        catch { }
    }

    private static bool ShortcutTargetMatches(string lnkFile, string exeName, string exePath)
    {
        if (!lnkFile.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return false;
        string? target = ResolveShortcutTarget(lnkFile);
        if (!string.IsNullOrEmpty(target))
        {
            if (target.Equals(exePath, StringComparison.OrdinalIgnoreCase))
                return true;
            if (!GenericBinaryNames.Contains(exeName) && !File.Exists(target) && Path.GetFileName(target).Equals(exeName, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public async Task<bool> DisableAutostartAsync(HunterTargetInfo info)
    {
        if (string.IsNullOrEmpty(info.ExecutablePath)) return false;

        string exeName = Path.GetFileName(info.ExecutablePath);
        string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
        string exePath = info.ExecutablePath;
        string? safeDirPrefix = (!string.IsNullOrEmpty(info.DirectoryPath) && !AppLocator.IsProtectedSharedDirectory(info.DirectoryPath))
            ? info.DirectoryPath.TrimEnd('\\') + "\\"
            : null;
        string appName = !string.IsNullOrWhiteSpace(info.WindowTitle) ? info.WindowTitle : exeNoExt;

        var manifest = new BackupManifest
        {
            AppName = appName,
            BackupCategory = "猎犬模式自启清理",
            CreatedTime = DateTime.Now
        };

        bool changed = false;

        var regTargets = new (RegistryKey Root, string HiveShort, string SubKey, bool Is64View)[]
        {
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", true),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", true),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", true),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", true),
            (Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", false)
        };

        foreach (var (root, hiveShort, subKey, is64View) in regTargets)
        {
            if (!Environment.Is64BitOperatingSystem && subKey.Contains("WOW6432Node")) continue;
            var backedUp = await RemoveRegistryRunAsync(root, hiveShort, subKey, is64View, exeName, exePath, safeDirPrefix, appName, manifest);
            if (backedUp.Count > 0)
            {
                changed = true;
            }
        }

        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        })
        {
            var recycled = RemoveStartupFiles(folder, exeName, exeNoExt, exePath, appName, manifest);
            if (recycled.Count > 0)
            {
                changed = true;
            }
        }

        var allTaskAutoruns = new List<AutostartEntry>();
        ScanThirdPartyScheduledTaskAutoruns(allTaskAutoruns);
        foreach (var taskEntry in allTaskAutoruns)
        {
            if (taskEntry.ExecutablePath.Equals(exePath, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(safeDirPrefix) && taskEntry.ExecutablePath.StartsWith(safeDirPrefix, StringComparison.OrdinalIgnoreCase)) ||
                (!GenericBinaryNames.Contains(exeName) && !File.Exists(taskEntry.ExecutablePath) && Path.GetFileName(taskEntry.ExecutablePath).Equals(exeName, StringComparison.OrdinalIgnoreCase)))
            {
                var (xmlBak, resolvedTn) = await RegistryBackup.BackupAndDeleteScheduledTaskWithNameAsync(
                    taskEntry.FullLocation,
                    taskEntry.ScheduledTaskPath,
                    appName);
                if (!string.IsNullOrEmpty(xmlBak))
                {
                    manifest.TaskXmlBackupFiles.Add(xmlBak);
                    if (!string.IsNullOrEmpty(resolvedTn))
                    {
                        manifest.TaskScheduleMap[xmlBak] = resolvedTn;
                    }
                    manifest.BackedUpTargetDescriptions.Add($"[计划任务] {resolvedTn}");
                    changed = true;
                }
            }
        }

        if (manifest.TotalBackedUpItems > 0)
        {
            await RegistryBackup.SaveBackupManifestAsync(manifest);
        }

        ScanAutostartPersistence(info);
        return changed;
    }

    private static async Task<List<string>> RemoveRegistryRunAsync(
        RegistryKey root,
        string hiveShort,
        string subKey,
        bool is64View,
        string exeName,
        string exePath,
        string? safeDirPrefix,
        string appName,
        BackupManifest manifest)
    {
        var regBackups = new List<string>();
        try
        {
            using var key = root.OpenSubKey(subKey, true);
            if (key == null) return regBackups;

            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (IsAutostartCommandMatchingTarget(val, exeName, exePath, safeDirPrefix))
                {
                    string fullKey = $@"{hiveShort}\{subKey}";
                    string? bak = await RegistryBackup.ExportValueAsync(fullKey, valName, val, appName, is64View);
                    if (!string.IsNullOrEmpty(bak))
                    {
                        regBackups.Add(bak);
                        manifest.RegBackupFiles.Add(bak);
                        manifest.RegBackupViewMap[bak] = is64View;
                        manifest.BackedUpTargetDescriptions.Add($"[注册表值] {fullKey} [{valName}]");
                        key.DeleteValue(valName, false);
                    }
                }
            }
        }
        catch { }

        return regBackups;
    }

    private static List<string> RemoveStartupFiles(
        string folder,
        string exeName,
        string exeNoExt,
        string exePath,
        string appName,
        BackupManifest manifest)
    {
        var recycled = new List<string>();
        if (!Directory.Exists(folder)) return recycled;
        try
        {
            foreach (var file in Directory.GetFiles(folder))
            {
                string fnameNoExt = Path.GetFileNameWithoutExtension(file);
                if ((exeNoExt.Length >= 4 && !GenericBinaryNames.Contains(exeName) && fnameNoExt.Equals(exeNoExt, StringComparison.OrdinalIgnoreCase)) ||
                    ShortcutTargetMatches(file, exeName, exePath))
                {
                    string? snapshotCopy = FileBackup.TryCreateFileBackupCopy(file, appName);
                    if (FileBackup.SendToRecycleBin(file))
                    {
                        recycled.Add(file);
                        manifest.RecycledFilePaths.Add(file);
                        if (!string.IsNullOrEmpty(snapshotCopy))
                        {
                            manifest.FileBackupCopyMap[file] = snapshotCopy;
                        }
                        manifest.BackedUpTargetDescriptions.Add($"[启动文件] {file}");
                    }
                }
            }
        }
        catch { }
        return recycled;
    }

    public bool KillProcessTree(int rootPid)
    {
        if (rootPid <= 4) return false;
        try
        {
            var pidsToKill = UninstallerRunner.GetDescendantPids(rootPid);
            bool anyKilled = false;

            foreach (int pid in pidsToKill.OrderByDescending(p => p != rootPid))
            {
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    proc.Kill(entireProcessTree: true);
                    anyKilled = true;
                }
                catch { }
            }
            return anyKilled;
        }
        catch
        {
            return false;
        }
    }

    public List<AutostartEntry> GetAllAutostartEntries()
    {
        var entries = new List<AutostartEntry>();

        var regSources = new (RegistryHive Hive, RegistryView View, string HiveName, string SubKey, string ApprovedSubKey, string Label, bool Is64View)[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "当前用户 Run", true),
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                string.Empty, "当前用户 RunOnce", true),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "系统全局 Run (x64)", true),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", "系统全局 Run (x86)", false),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                string.Empty, "系统全局 RunOnce", true)
        };

        foreach (var (hive, view, hiveName, subKey, approvedSubKey, label, is64View) in regSources)
        {
            if (!Environment.Is64BitOperatingSystem && !is64View) continue;

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKey);
                if (key == null) continue;
                using var approvedBase = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);

                string recordedSubKey = !is64View
                    ? @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                    : subKey;

                foreach (var valName in key.GetValueNames())
                {
                    string cmd = key.GetValue(valName)?.ToString() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(cmd)) continue;

                    string exe = AppLocator.ExtractExeFromCommand(cmd);
                    bool exists = !string.IsNullOrEmpty(exe) && File.Exists(exe);
                    string pub = string.Empty;
                    if (exists)
                    {
                        try { pub = FileVersionInfo.GetVersionInfo(exe).CompanyName ?? string.Empty; } catch { }
                    }

                    bool isEnabled = IsStartupApprovedEnabled(approvedBase, approvedSubKey, valName);

                    entries.Add(new AutostartEntry
                    {
                        Name = valName,
                        Command = cmd,
                        ExecutablePath = exe,
                        LocationType = label,
                        FullLocation = $@"{hiveName}\{recordedSubKey} [{valName}]",
                        RegistryHiveName = hiveName,
                        RegistrySubKey = recordedSubKey,
                        Is64BitRegistryView = is64View,
                        IsStartupShortcut = false,
                        FileExists = exists,
                        Publisher = pub,
                        IsEnabled = isEnabled
                    });
                }
            }
            catch { }
        }

        var startupFolders = new (string Folder, RegistryKey ApprovedRoot, string ApprovedSubKey, string Label)[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", "用户启动文件夹"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", "公共启动文件夹")
        };

        foreach (var (folder, approvedRoot, approvedSubKey, label) in startupFolders)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(folder))
                {
                    string fileName = Path.GetFileName(file);
                    string name = Path.GetFileNameWithoutExtension(file);
                    if (name.Equals("desktop", StringComparison.OrdinalIgnoreCase)) continue;

                    string target = file;
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        target = ResolveShortcutTarget(file) ?? file;
                    }

                    bool exists = File.Exists(target);
                    string pub = string.Empty;
                    if (exists)
                    {
                        try { pub = FileVersionInfo.GetVersionInfo(target).CompanyName ?? string.Empty; } catch { }
                    }

                    bool isEnabled = IsStartupApprovedEnabled(approvedRoot, approvedSubKey, fileName);

                    entries.Add(new AutostartEntry
                    {
                        Name = name,
                        Command = target,
                        ExecutablePath = target,
                        LocationType = label,
                        FullLocation = file,
                        IsStartupShortcut = true,
                        FileExists = exists,
                        Publisher = pub,
                        IsEnabled = isEnabled
                    });
                }
            }
            catch { }
        }

        ScanThirdPartyScheduledTaskAutoruns(entries);

        return entries;
    }

    private static void ScanThirdPartyScheduledTaskAutoruns(List<AutostartEntry> entries)
    {
        try
        {
            string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            if (!Directory.Exists(tasksDir)) return;

            foreach (var taskFile in Directory.EnumerateFiles(tasksDir, "*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                MaxRecursionDepth = 3
            }))
            {
                string relPath = taskFile.Substring(tasksDir.Length).TrimStart('\\');
                if (relPath.StartsWith("Microsoft\\", StringComparison.OrdinalIgnoreCase) ||
                    relPath.StartsWith("Windows\\", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    var doc = XDocument.Load(taskFile);
                    XNamespace ns = doc.Root?.Name.Namespace ?? XNamespace.None;

                    var triggersElement = doc.Descendants(ns + "Triggers").FirstOrDefault();
                    if (triggersElement == null ||
                        !triggersElement.Elements().Any(el => AutostartTriggerElementNames.Contains(el.Name.LocalName)))
                    {
                        continue;
                    }

                    string? command = doc.Descendants(ns + "Command").FirstOrDefault()?.Value?.Trim().Trim('"');
                    if (string.IsNullOrWhiteSpace(command)) continue;

                    string? args = doc.Descendants(ns + "Arguments").FirstOrDefault()?.Value?.Trim();
                    string? enabledStr = doc.Descendants(ns + "Settings").Elements(ns + "Enabled").FirstOrDefault()?.Value;
                    bool isEnabled = !string.Equals(enabledStr, "false", StringComparison.OrdinalIgnoreCase);

                    string exe = Environment.ExpandEnvironmentVariables(command);
                    if (!exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        string extracted = AppLocator.ExtractExeFromCommand(exe + " " + args);
                        if (!string.IsNullOrEmpty(extracted)) exe = extracted;
                    }

                    bool exists = File.Exists(exe);
                    string pub = string.Empty;
                    if (exists)
                    {
                        try { pub = FileVersionInfo.GetVersionInfo(exe).CompanyName ?? string.Empty; } catch { }
                    }

                    string fullCmd = string.IsNullOrEmpty(args) ? command : $"\"{command}\" {args}";
                    entries.Add(new AutostartEntry
                    {
                        Name = relPath,
                        Command = fullCmd,
                        ExecutablePath = exe,
                        LocationType = "计划任务自启",
                        FullLocation = taskFile,
                        IsScheduledTask = true,
                        ScheduledTaskPath = "\\" + relPath,
                        FileExists = exists,
                        Publisher = pub,
                        IsEnabled = isEnabled
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static bool IsStartupApprovedEnabled(RegistryKey root, string approvedSubKey, string itemName)
    {
        if (string.IsNullOrEmpty(approvedSubKey)) return true;
        try
        {
            using var key = root.OpenSubKey(approvedSubKey, false);
            if (key?.GetValue(itemName) is byte[] data && data.Length >= 4)
            {
                // Per Windows Shell StartupApproved specification: even first byte = enabled, odd first byte = disabled
                return (data[0] & 1) == 0;
            }
        }
        catch { }
        return true;
    }

    public async Task<bool> ToggleAutostartEntryStateAsync(AutostartEntry entry)
    {
        bool targetEnable = !entry.IsEnabled;

        return await Task.Run(() =>
        {
            try
            {
                if (entry.IsScheduledTask && !string.IsNullOrEmpty(entry.ScheduledTaskPath))
                {
                    string flag = targetEnable ? "/ENABLE" : "/DISABLE";
                    var psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Change /TN \"{entry.ScheduledTaskPath}\" {flag}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(4000);
                    if (proc?.ExitCode == 0)
                    {
                        entry.IsEnabled = targetEnable;
                        return true;
                    }
                    return false;
                }

                RegistryKey root;
                string approvedSubKey;
                string valueName;

                if (entry.IsStartupShortcut)
                {
                    bool isCommon = entry.LocationType.Contains("公共");
                    root = isCommon ? Registry.LocalMachine : Registry.CurrentUser;
                    approvedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
                    valueName = Path.GetFileName(entry.FullLocation);
                }
                else
                {
                    root = entry.RegistryHiveName.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
                        ? Registry.LocalMachine
                        : Registry.CurrentUser;

                    if (entry.RegistrySubKey.Contains("RunOnce", StringComparison.OrdinalIgnoreCase))
                        return false;

                    approvedSubKey = entry.RegistrySubKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
                    valueName = entry.Name;
                }

                using var key = root.CreateSubKey(approvedSubKey, true);
                if (key == null) return false;

                byte[] payload = new byte[12];
                if (targetEnable)
                {
                    payload[0] = 0x02;
                }
                else
                {
                    payload[0] = 0x03;
                    long fileTime = DateTime.UtcNow.ToFileTimeUtc();
                    byte[] timeBytes = BitConverter.GetBytes(fileTime);
                    Buffer.BlockCopy(timeBytes, 0, payload, 4, 8);
                }

                key.SetValue(valueName, payload, RegistryValueKind.Binary);
                entry.IsEnabled = targetEnable;
                return true;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<bool> RemoveAutostartEntryAsync(AutostartEntry entry)
    {
        var manifest = new BackupManifest
        {
            AppName = $"自启动项 - {entry.Name}",
            BackupCategory = "自启动项管理",
            CreatedTime = DateTime.Now
        };

        bool removed = false;

        if (entry.IsScheduledTask)
        {
            var (xmlBak, resolvedTn) = await RegistryBackup.BackupAndDeleteScheduledTaskWithNameAsync(
                entry.FullLocation,
                entry.ScheduledTaskPath,
                entry.Name);
            if (!string.IsNullOrEmpty(xmlBak))
            {
                manifest.TaskXmlBackupFiles.Add(xmlBak);
                if (!string.IsNullOrEmpty(resolvedTn))
                {
                    manifest.TaskScheduleMap[xmlBak] = resolvedTn;
                }
                manifest.BackedUpTargetDescriptions.Add($"[计划任务] {resolvedTn}");
                removed = true;
            }
        }
        else if (entry.IsStartupShortcut)
        {
            string? snapshotCopy = FileBackup.TryCreateFileBackupCopy(entry.FullLocation, $"Autostart_{entry.Name}");
            if (FileBackup.SendToRecycleBin(entry.FullLocation))
            {
                manifest.RecycledFilePaths.Add(entry.FullLocation);
                if (!string.IsNullOrEmpty(snapshotCopy))
                {
                    manifest.FileBackupCopyMap[entry.FullLocation] = snapshotCopy;
                }
                manifest.BackedUpTargetDescriptions.Add($"[启动文件] {entry.FullLocation}");
                removed = true;
            }
        }
        else
        {
            string fullKey = $@"{entry.RegistryHiveName}\{entry.RegistrySubKey}";
            string? regBak = await RegistryBackup.ExportValueAsync(
                fullKey,
                entry.Name,
                entry.Command,
                $"Autostart_{entry.Name}",
                entry.Is64BitRegistryView);

            if (!string.IsNullOrEmpty(regBak))
            {
                manifest.RegBackupFiles.Add(regBak);
                manifest.RegBackupViewMap[regBak] = entry.Is64BitRegistryView;
                manifest.BackedUpTargetDescriptions.Add($"[注册表值] {fullKey} [{entry.Name}]");
                removed = RegistryBackup.DeleteValue(entry.RegistryHiveName, entry.RegistrySubKey, entry.Name, entry.Is64BitRegistryView);
            }
        }

        if (removed && manifest.TotalBackedUpItems > 0)
        {
            await RegistryBackup.SaveBackupManifestAsync(manifest);
        }

        return removed;
    }

    /// <summary>
    /// Resolves a .lnk shortcut's target path using the fast native binary ShellLinkParser (zero COM overhead).
    /// </summary>
    public static string? ResolveShortcutTarget(string lnkPath)
    {
        return ShellLinkParser.ResolveTargetPath(lnkPath);
    }
}
