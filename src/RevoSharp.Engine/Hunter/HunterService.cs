using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
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

    public HunterTargetInfo? InspectPoint(int screenX, int screenY, List<InstalledApp>? installedApps = null)
    {
        var point = new POINT { X = screenX, Y = screenY };
        IntPtr rawHwnd = WindowFromPoint(point);
        if (rawHwnd == IntPtr.Zero) return null;

        IntPtr rootHwnd = GetAncestor(rawHwnd, GA_ROOT);
        IntPtr targetHwnd = rootHwnd != IntPtr.Zero ? rootHwnd : rawHwnd;

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
        ScanAutostartPersistence(info);

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

        var virtualApp = new InstalledApp
        {
            Id = $"HunterVirtual_{Path.GetFileNameWithoutExtension(info.ExecutablePath)}_{Math.Abs(info.ExecutablePath.GetHashCode())}",
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
        dynamic? wshShell = null;
        dynamic? shortcut = null;
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return false;
            wshShell = Activator.CreateInstance(shellType);
            if (wshShell == null) return false;
            shortcut = wshShell.CreateShortcut(lnkFile);
            string? target = shortcut?.TargetPath as string;
            if (!string.IsNullOrEmpty(target))
            {
                return target.Equals(exePath, StringComparison.OrdinalIgnoreCase) ||
                       Path.GetFileName(target).Equals(exeName, StringComparison.OrdinalIgnoreCase);
            }
        }
        catch { }
        finally
        {
            if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (wshShell != null && Marshal.IsComObject(wshShell)) Marshal.FinalReleaseComObject(wshShell);
        }
        return false;
    }

    public bool DisableAutostart(HunterTargetInfo info)
    {
        if (string.IsNullOrEmpty(info.ExecutablePath)) return false;

        bool changed = false;
        string exeName = Path.GetFileName(info.ExecutablePath);
        string exeNoExt = Path.GetFileNameWithoutExtension(info.ExecutablePath);
        string exePath = info.ExecutablePath;
        string appName = info.WindowTitle;

        changed |= RemoveRegistryRun(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, appName);
        changed |= RemoveRegistryRun(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, appName);
        changed |= RemoveRegistryRun(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, appName);
        changed |= RemoveRegistryRun(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", exeName, exePath, appName);
        if (Environment.Is64BitOperatingSystem)
        {
            changed |= RemoveRegistryRun(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", exeName, exePath, appName);
        }

        changed |= RemoveStartupFiles(Environment.GetFolderPath(Environment.SpecialFolder.Startup), exeName, exeNoExt, exePath);
        changed |= RemoveStartupFiles(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), exeName, exeNoExt, exePath);

        ScanAutostartPersistence(info);
        return changed;
    }

    private static bool RemoveRegistryRun(RegistryKey root, string hiveShort, string subKey, string exeName, string exePath, string appName)
    {
        try
        {
            using var key = root.OpenSubKey(subKey, true);
            if (key == null) return false;
            bool removed = false;
            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (!string.IsNullOrEmpty(val) &&
                    (val.Contains(exeName, StringComparison.OrdinalIgnoreCase) || val.Contains(exePath, StringComparison.OrdinalIgnoreCase)))
                {
                    _ = RegistryBackup.ExportValueAsync($@"{hiveShort}\{subKey}", valName, val, appName).GetAwaiter().GetResult();
                    key.DeleteValue(valName, false);
                    removed = true;
                }
            }
            return removed;
        }
        catch { return false; }
    }

    private static bool RemoveStartupFiles(string folder, string exeName, string exeNoExt, string exePath)
    {
        if (!Directory.Exists(folder)) return false;
        bool removed = false;
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
                        removed = true;
                    }
                }
            }
        }
        catch { }
        return removed;
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
    /// Enumerates all system-wide and current-user autostart entries for the Autorun Manager.
    /// </summary>
    public List<AutostartEntry> GetAllAutostartEntries()
    {
        var entries = new List<AutostartEntry>();

        var regSources = new[]
        {
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", "当前用户 Run"),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "当前用户 RunOnce"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", "系统全局 Run (x64)"),
            (Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "系统全局 Run (x86)"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "系统全局 RunOnce")
        };

        foreach (var (root, hiveName, subKey, label) in regSources)
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

                    entries.Add(new AutostartEntry
                    {
                        Name = valName,
                        Command = cmd,
                        ExecutablePath = exe,
                        LocationType = label,
                        FullLocation = $@"{hiveName}\{subKey} [{valName}]",
                        RegistryHiveName = hiveName,
                        RegistrySubKey = subKey,
                        IsStartupShortcut = false,
                        FileExists = exists,
                        Publisher = pub
                    });
                }
            }
            catch { }
        }

        var startupFolders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "用户启动文件夹"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "公共启动文件夹")
        };

        foreach (var (folder, label) in startupFolders)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(folder))
                {
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

                    entries.Add(new AutostartEntry
                    {
                        Name = name,
                        Command = target,
                        ExecutablePath = target,
                        LocationType = label,
                        FullLocation = file,
                        IsStartupShortcut = true,
                        FileExists = exists,
                        Publisher = pub
                    });
                }
            }
            catch { }
        }

        return entries;
    }

    public bool RemoveAutostartEntry(AutostartEntry entry)
    {
        if (entry.IsStartupShortcut)
        {
            return FileBackup.SendToRecycleBin(entry.FullLocation);
        }

        _ = RegistryBackup.ExportValueAsync($@"{entry.RegistryHiveName}\{entry.RegistrySubKey}", entry.Name, entry.Command, $"Autostart_{entry.Name}").GetAwaiter().GetResult();
        return RegistryBackup.DeleteValue(entry.RegistryHiveName, entry.RegistrySubKey, entry.Name);
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
