using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Execution;

public class UninstallerRunner
{
    private static readonly HashSet<string> IgnoredProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
        "iexplore.exe", "explorer.exe", "cmd.exe", "powershell.exe",
        "conhost.exe", "rundll32.exe", "dllhost.exe", "taskhostw.exe", "svchost.exe"
    };

    private static readonly Regex MsiInstallFlagRegex = new(@"(?<=\s|^)[/-][iI](?=\s*\{|\s+"")", RegexOptions.Compiled);

    #region Toolhelp32 Interop
    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    #endregion

    public async Task<bool> RunAndTrackUninstallerAsync(
        InstalledApp app,
        bool forceInteractive,
        Action<string> onStatusUpdate,
        CancellationToken cancellationToken)
    {
        string commandToRun;
        string arguments;

        // 1. Determine command line
        if (!forceInteractive && !string.IsNullOrWhiteSpace(app.QuietUninstallString))
        {
            (commandToRun, arguments) = ParseCommand(app.QuietUninstallString);
        }
        else
        {
            (commandToRun, arguments) = ParseCommand(app.UninstallString);

            if (!forceInteractive)
            {
                // For MSI packages, /I{GUID} must be converted to /X{GUID} before adding /qn,
                // otherwise msiexec performs a silent repair/reinstall instead of uninstalling!
                if (commandToRun.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
                {
                    arguments = MsiInstallFlagRegex.Replace(arguments, "/X");
                }

                string smartArgs = InferSilentArguments(commandToRun, arguments);
                if (!string.IsNullOrEmpty(smartArgs))
                {
                    arguments = string.IsNullOrWhiteSpace(arguments)
                        ? smartArgs
                        : $"{arguments} {smartArgs}";
                }
            }
        }

        if (string.IsNullOrWhiteSpace(commandToRun)) return false;

        return await Task.Run(async () =>
        {
            Process? initialProcess = null;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = commandToRun,
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                if (File.Exists(commandToRun))
                {
                    string? workDir = Path.GetDirectoryName(commandToRun);
                    if (!string.IsNullOrEmpty(workDir) && Directory.Exists(workDir))
                    {
                        psi.WorkingDirectory = workDir;
                    }
                }

                initialProcess = Process.Start(psi);
                if (initialProcess == null) return false;

                int initialPid = initialProcess.Id;
                onStatusUpdate?.Invoke($"卸载引导进程已启动 (PID: {initialPid})");

                var activePids = new HashSet<int> { initialPid };
                int zeroCountGrace = 0;

                string? validInstallDirPrefix = null;
                if (!string.IsNullOrWhiteSpace(app.InstallLocation) &&
                    Directory.Exists(app.InstallLocation) &&
                    !AppLocator.IsProtectedSharedDirectory(app.InstallLocation))
                {
                    validInstallDirPrefix = app.InstallLocation.TrimEnd('\\', '/') + "\\";
                }

                while (!cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(500, cancellationToken);
                    if (cancellationToken.IsCancellationRequested) break;

                    var snapshot = TakeProcessSnapshot();

                    // 1. Detect new children spawned by currently tracked PIDs
                    foreach (var entry in snapshot)
                    {
                        if (activePids.Contains((int)entry.th32ParentProcessID))
                        {
                            int childPid = (int)entry.th32ProcessID;
                            if (!IgnoredProcessNames.Contains(entry.szExeFile) && activePids.Add(childPid))
                            {
                                onStatusUpdate?.Invoke($"检测到衍生子卸载进程: {entry.szExeFile} (PID: {childPid})");
                            }
                        }
                    }

                    // 2. Detect any process running directly from app.InstallLocation (with strict trailing slash boundary)
                    if (!string.IsNullOrEmpty(validInstallDirPrefix))
                    {
                        foreach (var entry in snapshot)
                        {
                            if (IgnoredProcessNames.Contains(entry.szExeFile)) continue;
                            if (activePids.Contains((int)entry.th32ProcessID)) continue;

                            try
                            {
                                using var p = Process.GetProcessById((int)entry.th32ProcessID);
                                string? modulePath = p.MainModule?.FileName;
                                if (!string.IsNullOrEmpty(modulePath) &&
                                    modulePath.StartsWith(validInstallDirPrefix, StringComparison.OrdinalIgnoreCase))
                                {
                                    activePids.Add((int)entry.th32ProcessID);
                                    onStatusUpdate?.Invoke($"检测到安装目录活动进程: {entry.szExeFile} (PID: {entry.th32ProcessID})");
                                }
                            }
                            catch { }
                        }
                    }

                    // 3. Filter out exited processes (properly disposing Process handles)
                    var stillRunning = new HashSet<int>();
                    var runningNames = new List<string>();

                    foreach (int pid in activePids)
                    {
                        try
                        {
                            using var p = Process.GetProcessById(pid);
                            if (!p.HasExited)
                            {
                                stillRunning.Add(pid);
                                runningNames.Add($"{p.ProcessName}.exe (PID: {pid})");
                            }
                        }
                        catch
                        {
                            // Process already exited
                        }
                    }

                    activePids = stillRunning;

                    if (activePids.Count > 0)
                    {
                        zeroCountGrace = 0;
                        string processListStr = string.Join(", ", runningNames.Take(3));
                        onStatusUpdate?.Invoke($"等待卸载程序完成: {processListStr}");
                    }
                    else
                    {
                        zeroCountGrace++;
                        if (zeroCountGrace >= 2)
                        {
                            onStatusUpdate?.Invoke("所有卸载相关进程已退出。");
                            break;
                        }
                    }
                }

                return true;
            }
            catch (OperationCanceledException)
            {
                return true;
            }
            catch (Exception ex)
            {
                onStatusUpdate?.Invoke($"启动或等待失败: {ex.Message}");
                return false;
            }
            finally
            {
                initialProcess?.Dispose();
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Checks whether the application's Registry Uninstall entry still exists (e.g., if user clicked Cancel in the wizard).
    /// </summary>
    public static bool IsAppRegistryEntryStillPresent(InstalledApp app)
    {
        if (string.IsNullOrWhiteSpace(app.RegistryKeyPath)) return false;

        try
        {
            int slash = app.RegistryKeyPath.IndexOf('\\');
            if (slash <= 0) return false;

            string hiveStr = app.RegistryKeyPath.Substring(0, slash);
            string subKey = app.RegistryKeyPath.Substring(slash + 1);

            RegistryHive hive = hiveStr.ToUpperInvariant() switch
            {
                "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
                "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
                _ => RegistryHive.LocalMachine
            };

            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key != null && key.GetValue("DisplayName") != null)
                    {
                        return true;
                    }
                }
                catch { }
            }
        }
        catch { }

        return false;
    }

    public static List<int> GetDescendantPids(int rootPid)
    {
        var result = new HashSet<int> { rootPid };
        var snapshot = TakeProcessSnapshot();
        bool added;
        do
        {
            added = false;
            foreach (var entry in snapshot)
            {
                int pid = (int)entry.th32ProcessID;
                int parentPid = (int)entry.th32ParentProcessID;
                if (pid > 4 && result.Contains(parentPid) && !result.Contains(pid))
                {
                    result.Add(pid);
                    added = true;
                }
            }
        } while (added);

        return result.ToList();
    }

    public static List<PROCESSENTRY32> TakeProcessSnapshot()
    {
        var list = new List<PROCESSENTRY32>();
        IntPtr handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return list;

        try
        {
            var pe = new PROCESSENTRY32();
            pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();

            if (Process32First(handle, ref pe))
            {
                do
                {
                    list.Add(pe);
                    pe = new PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();
                }
                while (Process32Next(handle, ref pe));
            }
        }
        finally
        {
            CloseHandle(handle);
        }

        return list;
    }

    public static (string FileName, string Arguments) ParseCommand(string raw)
    {
        raw = raw.Trim();
        if (string.IsNullOrEmpty(raw)) return (string.Empty, string.Empty);

        if (raw.StartsWith('"'))
        {
            int closingQuote = raw.IndexOf('"', 1);
            if (closingQuote > 1)
            {
                string file = raw.Substring(1, closingQuote - 1);
                string args = raw.Length > closingQuote + 1 ? raw.Substring(closingQuote + 1).Trim() : string.Empty;
                return (file, args);
            }
        }

        if (raw.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("rundll32", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
        {
            int spaceIdx = raw.IndexOf(' ');
            if (spaceIdx > 0)
            {
                return (raw.Substring(0, spaceIdx), raw.Substring(spaceIdx + 1).Trim());
            }
            return (raw, string.Empty);
        }

        if (raw.Contains(".exe", StringComparison.OrdinalIgnoreCase))
        {
            int exeIdx = raw.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            string file = raw.Substring(0, exeIdx + 4).Trim();
            string args = raw.Length > exeIdx + 4 ? raw.Substring(exeIdx + 4).Trim() : string.Empty;
            return (file, args);
        }

        int firstSpace = raw.IndexOf(' ');
        if (firstSpace > 0)
        {
            return (raw.Substring(0, firstSpace), raw.Substring(firstSpace + 1).Trim());
        }

        return (raw, string.Empty);
    }

    private static string InferSilentArguments(string fileName, string existingArgs)
    {
        string lowerFile = fileName.ToLowerInvariant();
        string lowerArgs = existingArgs.ToLowerInvariant();

        if (lowerFile.Contains("msiexec"))
        {
            if (!lowerArgs.Contains("/qn") && !lowerArgs.Contains("/quiet"))
            {
                return "/qn /norestart";
            }
            return string.Empty;
        }

        if (lowerFile.Contains("unins00") || lowerFile.Contains("unins.exe"))
        {
            if (!lowerArgs.Contains("/verysilent") && !lowerArgs.Contains("/silent"))
            {
                return "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
            }
            return string.Empty;
        }

        if (lowerFile.Contains("uninstall.exe"))
        {
            if (!lowerArgs.Contains("/s"))
            {
                return "/S";
            }
            return string.Empty;
        }

        return string.Empty;
    }
}
