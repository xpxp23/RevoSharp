using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Safety;

/// <summary>
/// Integrates Windows Restart Manager API (rstrtmgr.dll) to identify processes holding open handles
/// to residual files or shell extension DLLs, and supports 1-click process termination or graceful Explorer restart.
/// </summary>
public static class FileLockUnlocker
{
    private const int RM_SESSION_KEY_LEN = 32;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;
    private const int ERROR_MORE_DATA = 234;

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint pSessionHandle,
        uint nFiles,
        string[]? rgsFileNames,
        uint nApplications,
        IntPtr rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[]? rgAffectedApps,
        ref uint lpdwRebootReasons);

    /// <summary>
    /// Queries Windows Restart Manager for all processes currently locking the specified files or directories.
    /// </summary>
    public static List<LockingProcessInfo> FindLockingProcesses(IEnumerable<string> targetPaths)
    {
        var results = new Dictionary<int, LockingProcessInfo>();
        var candidateFiles = ExpandCandidateLockableFiles(targetPaths, maxFiles: 120);
        if (candidateFiles.Count == 0) return [];

        foreach (var batch in candidateFiles.Chunk(40))
        {
            QueryRestartManagerBatch(batch, string.Empty, results);
        }

        return results.Values.OrderByDescending(p => p.IsExplorerShell).ThenBy(p => p.ProcessName).ToList();
    }

    /// <summary>
    /// Scans all file/directory ResidualItems, attaches locking process metadata to each locked item,
    /// and returns the total number of locked residual items discovered.
    /// </summary>
    public static async Task<int> ScanAndAttachLocksToResidualsAsync(IEnumerable<ResidualItem> items)
    {
        return await Task.Run(() =>
        {
            int lockedItemCount = 0;
            var fileItems = items
                .Where(i => i.Type is ResidualType.File or ResidualType.Directory &&
                            i.Category != ResidualCategory.ScheduledTask)
                .ToList();

            foreach (var item in fileItems)
            {
                var singleFiles = ExpandCandidateLockableFiles([item.Path], maxFiles: 32);
                if (singleFiles.Count == 0)
                {
                    item.UpdateLockingProcesses([]);
                    continue;
                }

                var dict = new Dictionary<int, LockingProcessInfo>();
                QueryRestartManagerBatch(singleFiles.ToArray(), item.Path, dict);
                var list = dict.Values.ToList();
                item.UpdateLockingProcesses(list);
                if (list.Count > 0)
                {
                    lockedItemCount++;
                }
            }

            return lockedItemCount;
        });
    }

    /// <summary>
    /// Unlocks the specified files/directories by terminating non-critical locking processes
    /// and optionally restarting Windows Explorer if a Shell Extension DLL is locked by explorer.exe.
    /// </summary>
    public static async Task<(int KilledProcesses, bool ExplorerRestarted)> UnlockFilesAsync(
        IEnumerable<string> targetPaths,
        bool allowExplorerRestart = true)
    {
        return await Task.Run(async () =>
        {
            var lockers = FindLockingProcesses(targetPaths);
            if (lockers.Count == 0) return (0, false);

            int killed = 0;
            bool needsExplorerRestart = false;

            foreach (var locker in lockers)
            {
                if (locker.IsCriticalSystemProcess || locker.ProcessId <= 4 || locker.ProcessId == Environment.ProcessId)
                    continue;

                if (locker.IsExplorerShell)
                {
                    needsExplorerRestart = true;
                    continue;
                }

                try
                {
                    using var proc = Process.GetProcessById(locker.ProcessId);
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(1500);
                    killed++;
                }
                catch { }
            }

            bool explorerRestarted = false;
            if (needsExplorerRestart && allowExplorerRestart)
            {
                explorerRestarted = await RestartExplorerGracefullyAsync();
            }

            return (killed, explorerRestarted);
        });
    }

    /// <summary>
    /// Gracefully restarts Windows Explorer (explorer.exe) so locked ContextMenuHandler / ShellExtension DLLs
    /// are immediately released and can be moved to the Recycle Bin without rebooting Windows.
    /// </summary>
    public static async Task<bool> RestartExplorerGracefullyAsync()
    {
        try
        {
            var explorers = Process.GetProcessesByName("explorer");
            foreach (var exp in explorers)
            {
                try
                {
                    exp.Kill();
                    exp.WaitForExit(2000);
                }
                catch { }
                finally
                {
                    exp.Dispose();
                }
            }

            await Task.Delay(450);

            if (Process.GetProcessesByName("explorer").Length == 0)
            {
                string explorerExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                Process.Start(new ProcessStartInfo
                {
                    FileName = File.Exists(explorerExe) ? explorerExe : "explorer.exe",
                    UseShellExecute = true
                });
            }

            await Task.Delay(350);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<string> ExpandCandidateLockableFiles(IEnumerable<string> paths, int maxFiles)
    {
        var files = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawPath in paths)
        {
            if (string.IsNullOrWhiteSpace(rawPath)) continue;
            if (files.Count >= maxFiles) break;

            try
            {
                if (File.Exists(rawPath))
                {
                    if (seen.Add(rawPath)) files.Add(rawPath);
                }
                else if (Directory.Exists(rawPath))
                {
                    var dirInfo = new DirectoryInfo(rawPath);
                    foreach (var fi in dirInfo.EnumerateFiles("*", new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        MaxRecursionDepth = 3
                    }))
                    {
                        string ext = fi.Extension;
                        if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".db", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".log", StringComparison.OrdinalIgnoreCase))
                        {
                            if (seen.Add(fi.FullName))
                            {
                                files.Add(fi.FullName);
                                if (files.Count >= maxFiles) break;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        return files;
    }

    private static void QueryRestartManagerBatch(
        string[] fileBatch,
        string sourcePathLabel,
        Dictionary<int, LockingProcessInfo> results)
    {
        if (fileBatch.Length == 0) return;

        string sessionKey = Guid.NewGuid().ToString("N");
        if (RmStartSession(out uint sessionHandle, 0, sessionKey) != 0)
            return;

        try
        {
            int res = RmRegisterResources(sessionHandle, (uint)fileBatch.Length, fileBatch, 0, IntPtr.Zero, 0, null);
            if (res != 0) return;

            uint pnProcInfoNeeded = 0;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = 0;

            res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
            if (res == ERROR_MORE_DATA && pnProcInfoNeeded > 0)
            {
                var processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;
                res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (res == 0)
                {
                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        var info = processInfo[i];
                        int pid = info.Process.dwProcessId;
                        if (pid <= 0 || pid == Environment.ProcessId || results.ContainsKey(pid))
                            continue;

                        string procName = string.Empty;
                        try
                        {
                            using var p = Process.GetProcessById(pid);
                            procName = p.ProcessName + ".exe";
                        }
                        catch
                        {
                            procName = !string.IsNullOrWhiteSpace(info.strAppName) ? info.strAppName : $"PID_{pid}";
                        }

                        bool isExplorer = info.ApplicationType == RM_APP_TYPE.RmExplorer ||
                                          procName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
                        bool isCritical = info.ApplicationType == RM_APP_TYPE.RmCritical || pid <= 4;

                        results[pid] = new LockingProcessInfo
                        {
                            ProcessId = pid,
                            ProcessName = procName,
                            ApplicationName = info.strAppName ?? string.Empty,
                            ServiceShortName = info.strServiceShortName ?? string.Empty,
                            IsExplorerShell = isExplorer,
                            IsCriticalSystemProcess = isCritical,
                            LockedFilePath = !string.IsNullOrEmpty(sourcePathLabel) ? sourcePathLabel : fileBatch[0]
                        };
                    }
                }
            }
        }
        catch { }
        finally
        {
            RmEndSession(sessionHandle);
        }
    }
}
