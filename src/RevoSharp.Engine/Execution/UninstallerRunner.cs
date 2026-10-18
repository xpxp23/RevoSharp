using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Execution;

public class UninstallerRunner
{
    private static readonly HashSet<string> BrowserBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
        "vivaldi.exe", "iexplore.exe"
    };

    private static readonly HashSet<string> ExcludedShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
        "vivaldi.exe", "iexplore.exe", "explorer.exe", "dllhost.exe", "taskhostw.exe", "svchost.exe"
    };

    private static readonly HashSet<string> AuxiliaryHostProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe"
    };

    private static readonly Regex MsiInstallFlagRegex = new(@"(?<=\s|^)[/-][iI](?=\s*\{|\s+""|\s+[a-zA-Z0-9])", RegexOptions.Compiled);
    private static readonly Regex SurveyUrlRegex = new(@"(?i)(https?://|www\.|--app=https?://|url\.dll\s*,\s*FileProtocolHandler|\bstart\s+(""""""\s+)?https?://)", RegexOptions.Compiled);

    #region Toolhelp32, PEB CommandLine & Fast Process Path Interop
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;

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

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
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

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

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

        if (!forceInteractive && !string.IsNullOrWhiteSpace(app.QuietUninstallString))
        {
            (commandToRun, arguments) = ParseCommand(app.QuietUninstallString);
            if (commandToRun.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
            {
                arguments = MsiInstallFlagRegex.Replace(arguments, "/X");
            }
        }
        else
        {
            (commandToRun, arguments) = ParseCommand(app.UninstallString);

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
                DateTime launchStartUtc = DateTime.UtcNow.AddSeconds(-1);
                var preExistingPids = TakeProcessSnapshot().Select(p => (int)p.th32ProcessID).ToHashSet();

                // UWP Store apps must run under the current user token with CreateNoWindow=true (no UAC SID switch or flashing console)
                var psi = app.IsWindowsApp
                    ? new ProcessStartInfo
                    {
                        FileName = commandToRun,
                        Arguments = arguments,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                    : new ProcessStartInfo
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

                var trackedTreePids = new HashSet<int> { initialPid };
                var allHistoricalTreePids = new HashSet<int> { initialPid };
                var inspectedChildPids = new HashSet<int>();
                int zeroCountGrace = 0;
                bool isFirstPoll = true;
                bool blockSurveys = SettingsSerializer.Current.BlockUninstallSurveyWebpages;

                string? validInstallDirPrefix = null;
                if (!string.IsNullOrWhiteSpace(app.InstallLocation) &&
                    Directory.Exists(app.InstallLocation) &&
                    !AppLocator.IsProtectedSharedDirectory(app.InstallLocation))
                {
                    validInstallDirPrefix = app.InstallLocation.TrimEnd('\\', '/') + "\\";
                }

                while (!cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(isFirstPoll ? 120 : 320, cancellationToken);
                    isFirstPoll = false;
                    if (cancellationToken.IsCancellationRequested) break;

                    var snapshot = TakeProcessSnapshot();

                    // 1. Sub-millisecond PEB command-line inspection to intercept uninstaller survey webpage popups
                    if (blockSurveys)
                    {
                        foreach (var entry in snapshot)
                        {
                            int childPid = (int)entry.th32ProcessID;
                            int parentPid = (int)entry.th32ParentProcessID;
                            if (childPid <= 4 || preExistingPids.Contains(childPid) || !inspectedChildPids.Add(childPid))
                                continue;

                            if (allHistoricalTreePids.Contains(parentPid))
                            {
                                if (TryInterceptSurveyPopupProcess(childPid, entry.szExeFile, launchStartUtc))
                                {
                                    onStatusUpdate?.Invoke($"已自动拦截卸载程序拉起的调查问卷网页弹窗 ({entry.szExeFile}, PID: {childPid})");
                                }
                            }
                        }
                    }

                    // 2. Discover descendant uninstaller child processes (including Temp self-delete scripts)
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
                                    allHistoricalTreePids.Add(childPid);
                                    addedNewChild = true;
                                    if (!AuxiliaryHostProcesses.Contains(entry.szExeFile))
                                    {
                                        onStatusUpdate?.Invoke($"检测到衍生卸载子进程: {entry.szExeFile} (PID: {childPid})");
                                    }
                                }
                            }
                        }
                    } while (addedNewChild);

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
                                allHistoricalTreePids.Add(pid);
                                onStatusUpdate?.Invoke($"检测到安装目录活动进程: {entry.szExeFile} (PID: {pid})");
                            }
                        }
                    }

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

    /// <summary>
    /// Safely checks whether a newly spawned child process of the uninstaller is a browser or shell URL launcher
    /// attempting to open a post-uninstall survey webpage, and terminates ONLY that newly spawned stub process.
    /// </summary>
    private static bool TryInterceptSurveyPopupProcess(int childPid, string exeName, DateTime launchStartUtc)
    {
        bool isBrowser = BrowserBinaries.Contains(exeName);
        bool isUrlHelper = exeName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) ||
                           exeName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                           exeName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase);

        if (!isBrowser && !isUrlHelper)
            return false;

        try
        {
            using var proc = Process.GetProcessById(childPid);
            if (proc.StartTime.ToUniversalTime() < launchStartUtc)
                return false;

            string? cmdLine = TryGetProcessCommandLineFast(childPid);
            if (isBrowser || (!string.IsNullOrEmpty(cmdLine) && SurveyUrlRegex.IsMatch(cmdLine)))
            {
                // Terminate only this newly spawned child process (entireProcessTree: false) so existing user browsers are untouched
                proc.Kill(entireProcessTree: false);
                return true;
            }
        }
        catch { }

        return false;
    }

    /// <summary>
    /// Reads a process's command line in ~15 microseconds via PEB (NtQueryInformationProcess + ReadProcessMemory),
    /// falling back to WMI only if PEB read is unavailable (e.g. WOW64 cross-bitness).
    /// </summary>
    private static string? TryGetProcessCommandLineFast(int pid)
    {
        if (IntPtr.Size == 8)
        {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
            if (hProc != IntPtr.Zero)
            {
                try
                {
                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int status = NtQueryInformationProcess(hProc, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
                    if (status == 0 && pbi.PebBaseAddress != IntPtr.Zero)
                    {
                        byte[] ptrBuf = new byte[8];
                        // x64 PEB.ProcessParameters is at offset 0x20
                        if (ReadProcessMemory(hProc, IntPtr.Add(pbi.PebBaseAddress, 0x20), ptrBuf, 8, out _))
                        {
                            IntPtr procParamsPtr = new(BitConverter.ToInt64(ptrBuf, 0));
                            if (procParamsPtr != IntPtr.Zero)
                            {
                                // x64 RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) is at offset 0x70
                                byte[] uniBuf = new byte[16];
                                if (ReadProcessMemory(hProc, IntPtr.Add(procParamsPtr, 0x70), uniBuf, 16, out _))
                                {
                                    ushort byteLen = BitConverter.ToUInt16(uniBuf, 0);
                                    IntPtr strPtr = new(BitConverter.ToInt64(uniBuf, 8));
                                    if (byteLen > 0 && byteLen <= 8192 && strPtr != IntPtr.Zero)
                                    {
                                        byte[] strBytes = new byte[byteLen];
                                        if (ReadProcessMemory(hProc, strPtr, strBytes, byteLen, out _))
                                        {
                                            return Encoding.Unicode.GetString(strBytes);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
                finally
                {
                    CloseHandle(hProc);
                }
            }
        }

        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString();
            }
        }
        catch { }

        return null;
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

            var targetView = !Environment.Is64BitOperatingSystem
                ? RegistryView.Default
                : (subKey.Contains(@"WOW6432Node\", StringComparison.OrdinalIgnoreCase)
                    ? RegistryView.Registry64
                    : (app.Is64Bit ? RegistryView.Registry64 : RegistryView.Registry32));

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
        raw = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (string.IsNullOrEmpty(raw)) return (string.Empty, string.Empty);

        if (raw.StartsWith('"'))
        {
            int closingQuote = raw.IndexOf('"', 1);
            if (closingQuote > 1)
            {
                string file = raw.Substring(1, closingQuote - 1).Trim();
                string args = raw.Length > closingQuote + 1 ? raw.Substring(closingQuote + 1).Trim() : string.Empty;
                return (file, args);
            }
        }

        if (raw.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("rundll32", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("powershell", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("cmd ", StringComparison.OrdinalIgnoreCase))
        {
            int spaceIdx = raw.IndexOf(' ');
            if (spaceIdx > 0)
            {
                return (raw.Substring(0, spaceIdx), raw.Substring(spaceIdx + 1).Trim());
            }
            return (raw, string.Empty);
        }

        string extractedExe = AppLocator.ExtractExeFromCommand(raw);
        if (!string.IsNullOrEmpty(extractedExe))
        {
            int idx = raw.IndexOf(extractedExe, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int afterIdx = idx + extractedExe.Length;
                if (afterIdx < raw.Length && raw[afterIdx] == '"') afterIdx++;
                string args = afterIdx < raw.Length ? raw.Substring(afterIdx).Trim() : string.Empty;
                return (extractedExe, args);
            }
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
        string lowerFile = Path.GetFileName(fileName).ToLowerInvariant();
        string lowerArgs = existingArgs.ToLowerInvariant();

        if (lowerFile.Contains("msiexec"))
        {
            if (!lowerArgs.Contains("/qn") && !lowerArgs.Contains("/quiet"))
            {
                return "/qn /norestart";
            }
            return string.Empty;
        }

        // Inspect PE FileVersionInfo metadata first to identify Inno Setup, NSIS, WiX Burn, or Squirrel accurately
        if (File.Exists(fileName))
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(fileName);
                string meta = $"{vi.FileDescription} {vi.ProductName} {vi.CompanyName} {vi.Comments}";
                if (meta.Contains("Inno Setup", StringComparison.OrdinalIgnoreCase))
                {
                    return !lowerArgs.Contains("/verysilent") && !lowerArgs.Contains("/silent")
                        ? "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
                        : string.Empty;
                }
                if (meta.Contains("Nullsoft", StringComparison.OrdinalIgnoreCase) ||
                    meta.Contains("NSIS", StringComparison.OrdinalIgnoreCase))
                {
                    return !lowerArgs.Contains("/s") ? "/S" : string.Empty;
                }
                if (meta.Contains("WiX", StringComparison.OrdinalIgnoreCase) ||
                    meta.Contains("Burn", StringComparison.OrdinalIgnoreCase))
                {
                    return !lowerArgs.Contains("/quiet") ? "/uninstall /quiet /norestart" : string.Empty;
                }
            }
            catch { }
        }

        if (lowerFile.StartsWith("unins00") || lowerFile.Equals("unins.exe"))
        {
            if (!lowerArgs.Contains("/verysilent") && !lowerArgs.Contains("/silent"))
            {
                return "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
            }
            return string.Empty;
        }

        if (lowerFile.Equals("update.exe") && lowerArgs.Contains("--uninstall"))
        {
            return !lowerArgs.Contains("-s") ? "-s" : string.Empty;
        }

        if (lowerFile.Equals("uninstall.exe") || lowerFile.Equals("uninst.exe"))
        {
            if (!lowerArgs.Contains("/s") && !lowerArgs.Contains("--uninstall") && !lowerArgs.Contains("/quiet"))
            {
                return "/S";
            }
            return string.Empty;
        }

        return string.Empty;
    }
}
