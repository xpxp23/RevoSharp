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

    /// <summary>
    /// Fast lightweight hit-test that returns only the root window handle (HWND) under the cursor
    /// without performing expensive disk/COM/registry I/O. Used during mouse-move dragging to avoid frame drops.
    /// </summary>
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

    /// <summary>
    /// Creates a HunterTargetInfo directly from a desktop shortcut (.lnk) or executable file dropped onto the reticle
    /// (Revo Uninstaller Pro parity: Hunter Mode supports shortcuts and files in addition to windows).
    /// </summary>
    public HunterTargetInfo? InspectFileOrShortcut(string filePath, List<InstalledApp>? installedApps = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return null;

        string resolvedExe = filePath;
        if (filePath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            string? target = ResolveShortcutTarget(filePath);
            if (!string.IsNullOrEmpty(target) && File.Exists(target))
            {
                resolvedExe = target;
            }
        }

        string procName = Path.GetFileName(resolvedExe);
        string title = Path.GetFileNameWithoutExtension(filePath);
        string pub = string.Empty;
        string ver = string.Empty;

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

        var runningProc = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(resolvedExe)).FirstOrDefault();
        int pid = runningProc?.Id ?? 0;
        runningProc?.Dispose();

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
            DirectoryPath = Path.GetDirectoryName(resolvedExe) ?? string.Empty,
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

            // 1. Exact or Sub-Directory match
            var matched = installedApps.FirstOrDefault(a =>
                !string.IsNullOrEmpty(a.InstallLocation) &&
                !AppLocator.IsProtectedSharedDirectory(a.InstallLocation) &&
                (targetDir.Equals(a.InstallLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                 targetDir.StartsWith(a.InstallLocation.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)));

            // 2. DisplayIcon or UninstallString match
            matched ??= installedApps.FirstOrDefault(a =>
                (!string.IsNullOrEmpty(a.DisplayIcon) && a.DisplayIcon.Contains(targetExe, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(a.UninstallString) && a.UninstallString.Contains(targetExe, StringComparison.OrdinalIgnoreCase)));

            // 3. Name similarity match
            if (matched == null)
            {
                string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
                if (exeNoExt.Length >= 4)
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

        // Fixed OverflowException when GetHashCode() returns int.MinValue by casting to uint unchecked
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

        CheckRegistryRun(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, info.AutostartDescriptions);
        CheckRegistryRun(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, info.AutostartDescriptions);
        CheckRegistryRun(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, info.AutostartDescriptions);
        CheckRegistryRun(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, info.AutostartDescriptions);

        if (Environment.Is64BitOperatingSystem)
        {
            CheckRegistryRun(Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, info.AutostartDescriptions);
        }

        string userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        CheckStartupFolder(userStartup, exeName, exeNoExt, exePath, info.AutostartDescriptions);

        string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        CheckStartupFolder(commonStartup, exeName, exeNoExt, exePath, info.AutostartDescriptions);

        info.HasAutostartEntry = info.AutostartDescriptions.Count > 0;
    }

    private static void CheckRegistryRun(RegistryKey root, string subKey, string exeName, string exePath, List<string> list)
    {
        try
        {
            using var key = root.OpenSubKey(subKey);
            if (key == null) return;
            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (!string.IsNullOrEmpty(val) &&
                    (val.Contains(exeName, StringComparison.OrdinalIgnoreCase) || val.Contains(exePath, StringComparison.OrdinalIgnoreCase)))
                {
                    list.Add($"{root.Name}\\{subKey} -> [{valName}]");
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
                if ((exeNoExt.Length >= 3 && fnameNoExt.Contains(exeNoExt, StringComparison.OrdinalIgnoreCase)) ||
                    ShortcutTargetMatches(file, exeName, exePath))
                {
                    list.Add($"启动文件夹: {file}");
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
            return target.Equals(exePath, StringComparison.OrdinalIgnoreCase) ||
                   Path.GetFileName(target).Equals(exeName, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    /// <summary>
    /// Asynchronously backs up and removes all autostart entries for a Hunter target,
    /// saving a BackupManifest so the user can restore them from the Backup Manager at any time.
    /// </summary>
    public async Task<bool> DisableAutostartAsync(HunterTargetInfo info)
    {
        if (string.IsNullOrEmpty(info.ExecutablePath)) return false;

        string exeName = Path.GetFileName(info.ExecutablePath);
        string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
        string exePath = info.ExecutablePath;
        string appName = !string.IsNullOrWhiteSpace(info.WindowTitle) ? info.WindowTitle : exeNoExt;

        var manifest = new BackupManifest
        {
            AppName = appName,
            BackupCategory = "猎犬模式自启清理",
            CreatedTime = DateTime.Now
        };

        bool changed = false;

        var regTargets = new (RegistryKey Root, string HiveShort, string SubKey)[]
        {
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        };

        foreach (var (root, hiveShort, subKey) in regTargets)
        {
            if (!Environment.Is64BitOperatingSystem && subKey.Contains("WOW6432Node")) continue;
            var backedUp = await RemoveRegistryRunAsync(root, hiveShort, subKey, exeName, exePath, appName);
            if (backedUp.Count > 0)
            {
                manifest.RegBackupFiles.AddRange(backedUp);
                changed = true;
            }
        }

        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        })
        {
            var recycled = RemoveStartupFiles(folder, exeName, exeNoExt, exePath);
            if (recycled.Count > 0)
            {
                manifest.RecycledFilePaths.AddRange(recycled);
                changed = true;
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
        string exeName,
        string exePath,
        string appName)
    {
        var regBackups = new List<string>();
        try
        {
            using var key = root.OpenSubKey(subKey, true);
            if (key == null) return regBackups;

            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (!string.IsNullOrEmpty(val) &&
                    (val.Contains(exeName, StringComparison.OrdinalIgnoreCase) || val.Contains(exePath, StringComparison.OrdinalIgnoreCase)))
                {
                    string? bak = await RegistryBackup.ExportValueAsync($@"{hiveShort}\{subKey}", valName, val, appName);
                    if (!string.IsNullOrEmpty(bak))
                    {
                        regBackups.Add(bak);
                    }
                    key.DeleteValue(valName, false);
                }
            }
        }
        catch { }

        return regBackups;
    }

    private static List<string> RemoveStartupFiles(string folder, string exeName, string exeNoExt, string exePath)
    {
        var recycled = new List<string>();
        if (!Directory.Exists(folder)) return recycled;
        try
        {
            foreach (var file in Directory.GetFiles(folder))
            {
                string fnameNoExt = Path.GetFileNameWithoutExtension(file);
                if ((exeNoExt.Length >= 3 && fnameNoExt.Contains(exeNoExt, StringComparison.OrdinalIgnoreCase)) ||
                    ShortcutTargetMatches(file, exeName, exePath))
                {
                    if (FileBackup.SendToRecycleBin(file))
                    {
                        recycled.Add(file);
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

    /// <summary>
    /// Enumerates all system-wide and current-user autostart entries (Registry Run/RunOnce, Startup Folders, and Logon Scheduled Tasks),
    /// including Windows Task Manager StartupApproved enabled/disabled state!
    /// </summary>
    public List<AutostartEntry> GetAllAutostartEntries()
    {
        var entries = new List<AutostartEntry>();

        var regSources = new (RegistryKey Root, string HiveName, string SubKey, string ApprovedSubKey, string Label, bool Is64View)[]
        {
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "当前用户 Run", true),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                string.Empty, "当前用户 RunOnce", true),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "系统全局 Run (x64)", true),
            (Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", "系统全局 Run (x86)", false),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                string.Empty, "系统全局 RunOnce", true)
        };

        foreach (var (root, hiveName, subKey, approvedSubKey, label, is64View) in regSources)
        {
            try
            {
                using var key = root.OpenSubKey(subKey);
                if (key == null) continue;
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

                    bool isEnabled = IsStartupApprovedEnabled(root, approvedSubKey, valName);

                    entries.Add(new AutostartEntry
                    {
                        Name = valName,
                        Command = cmd,
                        ExecutablePath = exe,
                        LocationType = label,
                        FullLocation = $@"{hiveName}\{subKey} [{valName}]",
                        RegistryHiveName = hiveName,
                        RegistrySubKey = subKey,
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

        // 3. Third-party Scheduled Tasks with Logon/Boot triggers
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
                MaxRecursionDepth = 2
            }))
            {
                string relPath = taskFile.Substring(tasksDir.Length).TrimStart('\\');
                if (relPath.StartsWith("Microsoft\\", StringComparison.OrdinalIgnoreCase) ||
                    relPath.StartsWith("Mozilla\\", StringComparison.OrdinalIgnoreCase) == false && relPath.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    var doc = XDocument.Load(taskFile);
                    XNamespace ns = doc.Root?.Name.Namespace ?? XNamespace.None;

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
                // Windows Task Manager convention: odd first byte (0x03, 0x01) means disabled; 0x02 or 0x06 means enabled
                return data[0] == 0x02 || data[0] == 0x06 || data[0] == 0x00;
            }
        }
        catch { }
        return true;
    }

    /// <summary>
    /// Toggles an autostart entry between Enabled and Disabled non-destructively using Windows Task Manager's
    /// StartupApproved registry binary protocol or schtasks /Change, without deleting the entry!
    /// </summary>
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
                    payload[0] = 0x02; // Enabled in Windows StartupApproved
                }
                else
                {
                    payload[0] = 0x03; // Disabled in Windows StartupApproved
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

    /// <summary>
    /// Backs up an autostart entry and creates a full BackupManifest so it is immediately visible and restorable in the Backup Manager.
    /// </summary>
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
            string? xmlBak = await RegistryBackup.BackupAndDeleteScheduledTaskAsync(entry.FullLocation, entry.ScheduledTaskPath, entry.Name);
            if (!string.IsNullOrEmpty(xmlBak))
            {
                manifest.TaskXmlBackupFiles.Add(xmlBak);
                removed = true;
            }
        }
        else if (entry.IsStartupShortcut)
        {
            if (FileBackup.SendToRecycleBin(entry.FullLocation))
            {
                manifest.RecycledFilePaths.Add(entry.FullLocation);
                removed = true;
            }
        }
        else
        {
            string? regBak = await RegistryBackup.ExportValueAsync(
                $@"{entry.RegistryHiveName}\{entry.RegistrySubKey}",
                entry.Name,
                entry.Command,
                $"Autostart_{entry.Name}",
                entry.Is64BitRegistryView);

            if (!string.IsNullOrEmpty(regBak))
            {
                manifest.RegBackupFiles.Add(regBak);
            }

            removed = RegistryBackup.DeleteValue(entry.RegistryHiveName, entry.RegistrySubKey, entry.Name, entry.Is64BitRegistryView);
        }

        if (removed && manifest.TotalBackedUpItems > 0)
        {
            await RegistryBackup.SaveBackupManifestAsync(manifest);
        }

        return removed;
    }

    public static string? ResolveShortcutTarget(string lnkPath)
    {
        dynamic? wshShell = null;
        dynamic? shortcut = null;
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return null;
            wshShell = Activator.CreateInstance(shellType);
            if (wshShell == null) return null;
            shortcut = wshShell.CreateShortcut(lnkPath);
            return shortcut?.TargetPath as string;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (wshShell != null && Marshal.IsComObject(wshShell)) Marshal.FinalReleaseComObject(wshShell);
        }
    }
}
