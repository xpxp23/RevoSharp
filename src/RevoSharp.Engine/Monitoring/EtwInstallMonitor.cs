using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Monitoring;

public class EtwInstallMonitor : IDisposable
{
    private static readonly string LogDirectory = AppLocator.LogDirectory;
    private const string CustomSessionName = "RevoSharp_InstallMonitor_Session";

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    private TraceEventSession? _session;
    private readonly HashSet<int> _trackedPids = [];
    private readonly HashSet<string> _createdFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _createdRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _modifiedRegistryValues = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ulong, string> _kcbHandleToPath = [];
    private readonly Dictionary<string, string> _deviceToDriveMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _preInstallUninstallKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    private Process? _installerProcess;
    private string _appName = string.Empty;
    private string _installerPath = string.Empty;
    private DateTime _monitorStartUtc;
    private volatile bool _isMonitoring;
    private volatile bool _installerLaunched;

    public bool IsMonitoring => _isMonitoring;
    public int CapturedFileCount { get { lock (_lock) return _createdFiles.Count; } }
    public int CapturedRegCount { get { lock (_lock) return _createdRegistryKeys.Count + _modifiedRegistryValues.Count; } }
    public int TrackedProcessCount { get { lock (_lock) return _trackedPids.Count; } }

    public event Action<string>? OnItemCaptured;

    public async Task StartAsync(string installerPath, string appName)
    {
        _appName = appName;
        _installerPath = installerPath;
        _monitorStartUtc = DateTime.UtcNow;
        _installerLaunched = false;

        lock (_lock)
        {
            _trackedPids.Clear();
            _createdFiles.Clear();
            _createdRegistryKeys.Clear();
            _modifiedRegistryValues.Clear();
            _kcbHandleToPath.Clear();
        }

        BuildDeviceDriveMap();
        CaptureUninstallSnapshot(_preInstallUninstallKeys);

        var sessionReadyTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        // 1. Start ETW session FIRST so no early installer events are missed
        var etwTask = Task.Run(() =>
        {
            try
            {
                try
                {
                    TraceEventSession.GetActiveSession(CustomSessionName)?.Dispose();
                    _session = new TraceEventSession(CustomSessionName) { StopOnDispose = true };
                    _session.EnableKernelProvider(
                        KernelTraceEventParser.Keywords.FileIOInit |
                        KernelTraceEventParser.Keywords.FileIO |
                        KernelTraceEventParser.Keywords.Registry |
                        KernelTraceEventParser.Keywords.Process
                    );
                }
                catch
                {
                    _session?.Dispose();
                    _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName) { StopOnDispose = true };
                    _session.EnableKernelProvider(
                        KernelTraceEventParser.Keywords.FileIOInit |
                        KernelTraceEventParser.Keywords.FileIO |
                        KernelTraceEventParser.Keywords.Registry |
                        KernelTraceEventParser.Keywords.Process
                    );
                }

                // Track child installer processes AND msiexec service worker processes once installer is active
                _session.Source.Kernel.ProcessStart += (ProcessTraceData data) =>
                {
                    if (!_installerLaunched) return;
                    bool attachMsiWorkers = false;
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ParentID))
                        {
                            _trackedPids.Add(data.ProcessID);
                            if (data.ImageFileName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                attachMsiWorkers = true;
                            }
                        }
                        else if (data.ImageFileName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase) && _trackedPids.Count > 0)
                        {
                            _trackedPids.Add(data.ProcessID);
                        }
                    }

                    if (attachMsiWorkers)
                    {
                        AttachRunningMsiExecProcesses();
                    }
                };

                // Track KCB (Key Control Block) lifecycle (Create, Rundown, Open, and Delete) so recycled KCB handles never cross-pollinate
                _session.Source.Kernel.RegistryKCBCreate += (RegistryTraceData data) =>
                {
                    CacheKcbHandle(data.KeyHandle, data.KeyName);
                };

                _session.Source.Kernel.RegistryKCBRundownBegin += (RegistryTraceData data) =>
                {
                    CacheKcbHandle(data.KeyHandle, data.KeyName);
                };

                _session.Source.Kernel.RegistryKCBDelete += (RegistryTraceData data) =>
                {
                    if (data.KeyHandle != 0)
                    {
                        lock (_lock)
                        {
                            _kcbHandleToPath.Remove(data.KeyHandle);
                        }
                    }
                };

                _session.Source.Kernel.RegistryOpen += (RegistryTraceData data) =>
                {
                    CacheKcbHandle(data.KeyHandle, data.KeyName);
                };

                // Record files actually written to
                _session.Source.Kernel.FileIOWrite += (FileIOReadWriteTraceData data) =>
                {
                    RecordFileActivity(data.ProcessID, data.FileName, isWrite: true);
                };

                // Record newly created files
                _session.Source.Kernel.FileIOCreate += (FileIOCreateTraceData data) =>
                {
                    RecordFileActivity(data.ProcessID, data.FileName, isWrite: false);
                };

                // Remove temporary files that the installer deleted itself
                _session.Source.Kernel.FileIODelete += data =>
                {
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ProcessID) && !string.IsNullOrWhiteSpace(data.FileName))
                        {
                            string norm = NormalizeFilePath(data.FileName);
                            if (!string.IsNullOrEmpty(norm))
                            {
                                _createdFiles.Remove(norm);
                            }
                        }
                    }
                };

                // Listen to registry key creation
                _session.Source.Kernel.RegistryCreate += (RegistryTraceData data) =>
                {
                    lock (_lock)
                    {
                        CacheKcbHandle(data.KeyHandle, data.KeyName);
                        if (_trackedPids.Contains(data.ProcessID))
                        {
                            string fullRaw = ResolveRegistryFullPath(data.KeyHandle, data.KeyName);
                            string norm = NormalizeRegistryPath(fullRaw);
                            if (IsValidTargetRegistryKey(norm) && _createdRegistryKeys.Add(norm))
                            {
                                OnItemCaptured?.Invoke($"[注册表项] {norm}");
                            }
                        }
                    }
                };

                // Listen to registry value creation/modification (including Default '@' values where ValueName is empty)
                _session.Source.Kernel.RegistrySetValue += (RegistryTraceData data) =>
                {
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ProcessID))
                        {
                            string fullRaw = ResolveRegistryFullPath(data.KeyHandle, data.KeyName);
                            string normKey = NormalizeRegistryPath(fullRaw);
                            if (IsValidTargetRegistryKey(normKey))
                            {
                                string valName = string.IsNullOrEmpty(data.ValueName) ? "(Default)" : data.ValueName;
                                string token = $"{normKey}||{valName}";
                                if (_modifiedRegistryValues.Add(token))
                                {
                                    OnItemCaptured?.Invoke($"[注册表值] {normKey} ➔ [{valName}]");
                                }
                            }
                        }
                    }
                };

                sessionReadyTcs.TrySetResult(true);
                _session.Source.Process();
            }
            catch (Exception ex)
            {
                sessionReadyTcs.TrySetException(ex);
            }
        });

        await sessionReadyTcs.Task;

        // 2. Launch the installer process AFTER ETW is actively listening.
        try
        {
            bool isMsiPackage = installerPath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) ||
                                installerPath.EndsWith(".msp", StringComparison.OrdinalIgnoreCase);

            var psi = isMsiPackage
                ? new ProcessStartInfo
                {
                    FileName = "msiexec.exe",
                    Arguments = $"/i \"{installerPath}\"",
                    UseShellExecute = true,
                    Verb = "runas"
                }
                : new ProcessStartInfo
                {
                    FileName = installerPath,
                    UseShellExecute = true,
                    Verb = "runas"
                };

            _installerProcess = Process.Start(psi) ?? throw new InvalidOperationException("无法启动安装程序");
            lock (_lock)
            {
                _trackedPids.Add(_installerProcess.Id);
            }
            _installerLaunched = true;

            if (isMsiPackage)
            {
                AttachRunningMsiExecProcesses();
            }
        }
        catch
        {
            Dispose();
            throw;
        }

        _isMonitoring = true;
        await etwTask;
    }

    private void AttachRunningMsiExecProcesses()
    {
        try
        {
            foreach (var proc in Process.GetProcessesByName("msiexec"))
            {
                try
                {
                    lock (_lock)
                    {
                        _trackedPids.Add(proc.Id);
                    }
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }
    }

    public bool TryLaunchDetectedInstalledApp(out string launchedExePath)
    {
        launchedExePath = string.Empty;
        var (_, _, detectedLoc) = DetectNewUninstallEntry();
        if (string.IsNullOrWhiteSpace(detectedLoc) || !Directory.Exists(detectedLoc))
            return false;

        try
        {
            var mainExe = Directory.GetFiles(detectedLoc, "*.exe", SearchOption.TopDirectoryOnly)
                .FirstOrDefault(f => !Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(mainExe)) return false;

            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = mainExe,
                WorkingDirectory = detectedLoc,
                UseShellExecute = true
            });

            if (p != null)
            {
                lock (_lock)
                {
                    _trackedPids.Add(p.Id);
                }
                launchedExePath = mainExe;
                return true;
            }
        }
        catch { }

        return false;
    }

    private void CacheKcbHandle(ulong handle, string? keyName)
    {
        if (handle == 0 || string.IsNullOrWhiteSpace(keyName)) return;
        string trimmed = keyName.Trim();
        lock (_lock)
        {
            if (trimmed.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase))
            {
                _kcbHandleToPath[handle] = trimmed;
            }
            else if (_kcbHandleToPath.TryGetValue(handle, out string? existingBase) &&
                     !existingBase.EndsWith("\\" + trimmed, StringComparison.OrdinalIgnoreCase))
            {
                _kcbHandleToPath[handle] = $@"{existingBase.TrimEnd('\\')}\{trimmed.TrimStart('\\')}";
            }
        }
    }

    private string ResolveRegistryFullPath(ulong handle, string? keyName)
    {
        string raw = keyName?.Trim() ?? string.Empty;
        if (raw.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase))
        {
            return raw;
        }

        if (handle != 0 && _kcbHandleToPath.TryGetValue(handle, out string? baseKcbPath))
        {
            if (string.IsNullOrEmpty(raw))
                return baseKcbPath;
            if (baseKcbPath.EndsWith("\\" + raw, StringComparison.OrdinalIgnoreCase))
                return baseKcbPath;
            return $@"{baseKcbPath.TrimEnd('\\')}\{raw.TrimStart('\\')}";
        }

        return raw;
    }

    private void RecordFileActivity(int processId, string? rawFileName, bool isWrite)
    {
        if (string.IsNullOrWhiteSpace(rawFileName)) return;

        lock (_lock)
        {
            if (!_trackedPids.Contains(processId)) return;

            string norm = NormalizeFilePath(rawFileName);
            if (!IsValidTargetFile(norm, isWrite)) return;

            if (_createdFiles.Add(norm))
            {
                OnItemCaptured?.Invoke($"[文件] {norm}");
            }
        }
    }

    public async Task<TraceLog> StopAsync()
    {
        _isMonitoring = false;
        _installerLaunched = false;

        try
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
        }
        catch { }

        try
        {
            _installerProcess?.Dispose();
            _installerProcess = null;
        }
        catch { }

        var (detectedName, detectedKeyId, detectedLoc) = DetectNewUninstallEntry();

        TraceLog log;
        lock (_lock)
        {
            var finalFiles = _createdFiles
                .Where(f => File.Exists(f) || Directory.Exists(f))
                .OrderBy(x => x)
                .ToList();

            log = new TraceLog
            {
                AppName = !string.IsNullOrWhiteSpace(_appName) ? _appName : detectedName,
                DetectedDisplayName = !string.IsNullOrWhiteSpace(detectedName) ? detectedName : _appName,
                UninstallKeyId = detectedKeyId,
                DetectedInstallLocation = detectedLoc,
                InstallerPath = _installerPath,
                CreatedTime = DateTime.Now,
                CreatedFiles = finalFiles,
                CreatedRegistryKeys = _createdRegistryKeys.OrderBy(x => x).ToList(),
                ModifiedRegistryValues = _modifiedRegistryValues.OrderBy(x => x).ToList()
            };
        }

        // Save a single canonical .revolog.json.gz file (trace_index.json already indexes both AppName and DetectedDisplayName,
        // avoiding duplicate physical files in the Traced Programs library!)
        string primaryName = !string.IsNullOrWhiteSpace(log.DetectedDisplayName) ? log.DetectedDisplayName : log.AppName;
        string safePrimary = AppLocator.SanitizeFileName(primaryName);
        string logPath = Path.Combine(LogDirectory, $"{safePrimary}.revolog.json.gz");
        log.FilePath = logPath;
        await TraceLogSerializer.SaveAsync(log, logPath);

        return log;
    }

    private void BuildDeviceDriveMap()
    {
        _deviceToDriveMap.Clear();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                string driveLetter = drive.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                if (QueryDosDevice(driveLetter, sb, sb.Capacity) > 0)
                {
                    string devicePath = sb.ToString();
                    int nullIdx = devicePath.IndexOf('\0');
                    if (nullIdx > 0) devicePath = devicePath.Substring(0, nullIdx);
                    if (!string.IsNullOrEmpty(devicePath))
                    {
                        _deviceToDriveMap[devicePath] = driveLetter;
                    }
                }
            }
        }
        catch { }
    }

    private string NormalizeFilePath(string raw)
    {
        if (raw.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var kvp in _deviceToDriveMap)
            {
                if (raw.StartsWith(kvp.Key + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value + raw.Substring(kvp.Key.Length);
                }
            }

            return string.Empty;
        }
        return raw;
    }

    private static string NormalizeRegistryPath(string raw)
    {
        string trimmed = raw.Trim();
        if (trimmed.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            return @"HKLM\" + trimmed.Substring(18);
        }
        if (trimmed.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
        {
            string rest = trimmed.Substring(15);
            int nextSlash = rest.IndexOf('\\');
            if (nextSlash > 0)
            {
                string sidPart = rest.Substring(0, nextSlash);
                string subPath = rest.Substring(nextSlash + 1);
                if (sidPart.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                {
                    return @"HKCU\Software\Classes\" + subPath;
                }
                return @"HKCU\" + subPath;
            }
        }
        return trimmed;
    }

    private bool IsValidTargetFile(string path, bool isWrite)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length < 4) return false;
        if (path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".etl", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            return false;

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(winDir) && path.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            return false;

        if (path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!isWrite)
        {
            try
            {
                if (File.Exists(path))
                {
                    DateTime createdUtc = File.GetCreationTimeUtc(path);
                    if (createdUtc < _monitorStartUtc.AddSeconds(-3))
                        return false;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsValidTargetRegistryKey(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) return false;
        if (!keyPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) &&
            !keyPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) &&
            !keyPath.StartsWith("HKCR\\", StringComparison.OrdinalIgnoreCase))
            return false;

        if (keyPath.Contains(@"\BAM\State\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.Contains(@"\Session Manager\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.Contains(@"\MuiCache", StringComparison.OrdinalIgnoreCase) ||
            keyPath.Contains(@"\Explorer\RecentDocs", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private static IEnumerable<(RegistryHive Hive, RegistryView View, string Path)> GetUninstallRoots()
    {
        yield return (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        if (Environment.Is64BitOperatingSystem)
        {
            yield return (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        }
        yield return (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
    }

    private static void CaptureUninstallSnapshot(HashSet<string> targetSet)
    {
        targetSet.Clear();
        foreach (var (hive, view, path) in GetUninstallRoots())
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uKey = baseKey.OpenSubKey(path);
                if (uKey == null) continue;
                foreach (var name in uKey.GetSubKeyNames())
                {
                    targetSet.Add($"{hive}_{view}_{name}");
                }
            }
            catch { }
        }
    }

    public (string DisplayName, string KeyId, string InstallLocation) DetectNewUninstallEntry()
    {
        foreach (var (hive, view, path) in GetUninstallRoots())
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uKey = baseKey.OpenSubKey(path);
                if (uKey == null) continue;
                foreach (var name in uKey.GetSubKeyNames())
                {
                    string token = $"{hive}_{view}_{name}";
                    if (!_preInstallUninstallKeys.Contains(token))
                    {
                        using var appKey = uKey.OpenSubKey(name);
                        string? disp = appKey?.GetValue("DisplayName") as string;
                        string? loc = appKey?.GetValue("InstallLocation") as string;
                        string? icon = appKey?.GetValue("DisplayIcon") as string;
                        string? uninst = appKey?.GetValue("UninstallString") as string;
                        if (!string.IsNullOrWhiteSpace(disp))
                        {
                            string resolvedLoc = AppLocator.DeduceInstallLocation(loc, icon, uninst, null);
                            return (disp.Trim(), name, resolvedLoc);
                        }
                    }
                }
            }
            catch { }
        }

        return (string.Empty, string.Empty, string.Empty);
    }

    public void Dispose()
    {
        _isMonitoring = false;
        _installerLaunched = false;
        try
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
        }
        catch { }

        try
        {
            _installerProcess?.Dispose();
            _installerProcess = null;
        }
        catch { }
    }
}
