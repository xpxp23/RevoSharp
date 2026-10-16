using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Execution;

public class UninstallerRunner
{
    /// <summary>
    /// Browser and OS shell processes that should never be tracked as part of an uninstaller tree.
    /// </summary>
    private static readonly HashSet<string> ExcludedShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
        "iexplore.exe", "explorer.exe", "dllhost.exe", "taskhostw.exe", "svchost.exe"
    };

    /// <summary>
    /// Script/command hosts that ARE tracked in the parent-child tree so grandchild uninstallers
    /// spawned by cmd/powershell/rundll32 are never lost, but do not block completion once idle if they are conhost.
    /// </summary>
    private static readonly HashSet<string> AuxiliaryHostProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe"
    };

    private static readonly Regex MsiInstallFlagRegex = new(@"(?<=\s|^)[/-][iI](?=\s*\{|\s+"")", RegexOptions.Compiled);

    #region Toolhelp32 & Fast Process Path Interop
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

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
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

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

            // Always convert MSI /I{GUID} to /X{GUID} so interactive mode launches direct Uninstall instead of Modify/Repair,
            // and silent mode performs silent uninstall instead of silent repair!
            if (commandToRun.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
            {
                arguments = MsiInstallFlagRegex.Replace(arguments, "/X");
            }

            if (!forceInteractive)
            {
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

                // trackedTreePids includes intermediate script hosts (cmd/powershell/rundll32) so grandchild uninstallers are caught
                var trackedTreePids = new HashSet<int> { initialPid };
                int zeroCountGrace = 0;
                bool isFirstPoll = true;

                string? validInstallDirPrefix = null;
                if (!string.IsNullOrWhiteSpace(app.InstallLocation) &&
                    Directory.Exists(app.InstallLocation) &&
                    !AppLocator.IsProtectedSharedDirectory(app.InstallLocation))
                {
                    validInstallDirPrefix = app.InstallLocation.TrimEnd('\\', '/') + "\\";
                }

                while (!cancellationToken.IsCancellationRequested)
                {
                    // Short 150ms initial poll catches fast bootstrapper stubs (_iu14D2N.tmp / Au_.exe) before they exit
                    await Task.Delay(isFirstPoll ? 150 : 450, cancellationToken);
                    isFirstPoll = false;
                    if (cancellationToken.IsCancellationRequested) break;

                    var snapshot = TakeProcessSnapshot();

                    // 1. Multi-pass transitive closure to catch child + grandchild processes spawned in the same interval
                    bool addedNewChild;
                    do
                    {
                        addedNewChild = false;
                        foreach (var entry in snapshot)
                        {
                            int childPid = (int)entry.th32ProcessID;
                            int parentPid = (int)entry.th32ParentProcessID;
                            if (childPid > 4 && trackedTreePids.Contains(parentPid) && !trackedTreePids.Contains(childPid))
                            {
                                if (!ExcludedShellProcesses.Contains(entry.szExeFile))
                                {
                                    trackedTreePids.Add(childPid);
                                    addedNewChild = true;
                                    if (!AuxiliaryHostProcesses.Contains(entry.szExeFile))
                                    {
                                        onStatusUpdate?.Invoke($"检测到衍生卸载子进程: {entry.szExeFile} (PID: {childPid})");
                                    }
                                }
                            }
                        }
                    } while (addedNewChild);

                    // 2. Detect any process running directly from app.InstallLocation using fast Win32 QueryFullProcessImageName
                    // (Avoids Process.MainModule cross-bitness Win32Exception storms)
                    if (!string.IsNullOrEmpty(validInstallDirPrefix))
                    {
                        foreach (var entry in snapshot)
                        {
                            int pid = (int)entry.th32ProcessID;
                            if (pid <= 4 || trackedTreePids.Contains(pid)) continue;
                            if (ExcludedShellProcesses.Contains(entry.szExeFile)) continue;

                            string? exePath = TryGetProcessImagePathFast((uint)pid);
                            if (!string.IsNullOrEmpty(exePath) &&
                                exePath.StartsWith(validInstallDirPrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                trackedTreePids.Add(pid);
                                onStatusUpdate?.Invoke($"检测到安装目录活动进程: {entry.szExeFile} (PID: {pid})");
                            }
                        }
                    }

                    // 3. Filter active processes using the snapshot directly + fast alive check
                    var snapshotPidMap = snapshot.ToDictionary(e => (int)e.th32ProcessID, e => e.szExeFile);
                    var stillRunning = new HashSet<int>();
                    var meaningfulRunningNames = new List<string>();

                    foreach (int pid in trackedTreePids)
                    {
                        if (snapshotPidMap.TryGetValue(pid, out string? exeName))
                        {
                            stillRunning.Add(pid);
                            if (!AuxiliaryHostProcesses.Contains(exeName))
                            {
                                meaningfulRunningNames.Add($"{exeName} (PID: {pid})");
                            }
                        }
                    }

                    trackedTreePids = stillRunning;

                    if (meaningfulRunningNames.Count > 0)
                    {
                        zeroCountGrace = 0;
                        string processListStr = string.Join(", ", meaningfulRunningNames.Take(3));
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

    public static string? TryGetProcessImagePathFast(uint pid)
    {
        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return QueryFullProcessImageName(hProc, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(hProc);
        }
    }

    /// <summary>
    /// Checks whether the application's Registry Uninstall entry still exists (e.g., if user clicked Cancel in the wizard).
    /// Accurately handles both UWP Store packages and 64/32-bit desktop apps.
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

            if (app.IsWindowsApp)
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var uwpKey = baseKey.OpenSubKey(subKey);
                return uwpKey != null;
            }

            var targetView = subKey.Contains(@"WOW6432Node\", StringComparison.OrdinalIgnoreCase)
                ? RegistryView.Registry64
                : (app.Is64Bit ? RegistryView.Registry64 : RegistryView.Registry32);

            using var regBase = RegistryKey.OpenBaseKey(hive, targetView);
            using var key = regBase.OpenSubKey(subKey);
            return key != null && key.GetValue("DisplayName") != null;
        }
        catch
        {
            return false;
        }
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

        if (lowerFile.Contains("uninstall.exe") || lowerFile.Contains("uninst.exe"))
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
