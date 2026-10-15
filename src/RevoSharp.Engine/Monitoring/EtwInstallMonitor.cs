using System.Diagnostics;
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    private TraceEventSession? _session;
    private readonly HashSet<int> _trackedPids = [];
    private readonly HashSet<string> _createdFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _createdRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _deviceToDriveMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _preInstallUninstallKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    private Process? _installerProcess;
    private string _appName = string.Empty;
    private string _installerPath = string.Empty;
    private DateTime _monitorStartUtc;
    private bool _isMonitoring;

    public bool IsMonitoring => _isMonitoring;
    public int CapturedFileCount { get { lock (_lock) return _createdFiles.Count; } }
    public int CapturedRegCount { get { lock (_lock) return _createdRegistryKeys.Count; } }

    public event Action<string>? OnItemCaptured;

    public async Task StartAsync(string installerPath, string appName)
    {
        _appName = appName;
        _installerPath = installerPath;
        _monitorStartUtc = DateTime.UtcNow;

        lock (_lock)
        {
            _trackedPids.Clear();
            _createdFiles.Clear();
            _createdRegistryKeys.Clear();
        }

        BuildDeviceDriveMap();
        CaptureUninstallSnapshot(_preInstallUninstallKeys);

        var sessionReadyTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        // 1. Start ETW Kernel session FIRST so no early installer events are missed
        var etwTask = Task.Run(() =>
        {
            try
            {
                TraceEventSession.GetActiveSession(KernelTraceEventParser.KernelSessionName)?.Dispose();

                _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName)
                {
                    StopOnDispose = true
                };

                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.FileIOInit |
                    KernelTraceEventParser.Keywords.FileIO |
                    KernelTraceEventParser.Keywords.Registry |
                    KernelTraceEventParser.Keywords.Process
                );

                // Track child installer processes
                _session.Source.Kernel.ProcessStart += (ProcessTraceData data) =>
                {
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ParentID))
                        {
                            _trackedPids.Add(data.ProcessID);
                        }
                    }
                };

                // Record files actually written to
                _session.Source.Kernel.FileIOWrite += (FileIOReadWriteTraceData data) =>
                {
                    RecordFileActivity(data.ProcessID, data.FileName, isWrite: true);
                };

                // Record newly created files (filtering out mere read opens of existing system files)
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
                            _createdFiles.Remove(norm);
                        }
                    }
                };

                // Listen to registry key creation
                _session.Source.Kernel.RegistryCreate += (RegistryTraceData data) =>
                {
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ProcessID) && !string.IsNullOrWhiteSpace(data.KeyName))
                        {
                            string norm = NormalizeRegistryPath(data.KeyName);
                            if (IsValidTargetRegistryKey(norm) && _createdRegistryKeys.Add(norm))
                            {
                                OnItemCaptured?.Invoke($"[注册表] {norm}");
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

        // Wait until ETW session is initialized and ready
        await sessionReadyTcs.Task;

        // 2. Launch the installer process AFTER ETW is actively listening
        var psi = new ProcessStartInfo
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

        _isMonitoring = true;
        await etwTask;
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

        try
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
        }
        catch { }

        // Detect newly created Uninstall registry entry during installation
        var (detectedName, detectedKeyId, detectedLoc) = DetectNewUninstallEntry();

        TraceLog log;
        lock (_lock)
        {
            // Keep only files that still exist on disk after installation completes
            var finalFiles = _createdFiles
                .Where(f => File.Exists(f) || Directory.Exists(f))
                .OrderBy(x => x)
                .ToList();

            log = new TraceLog
            {
                AppName = !string.IsNullOrWhiteSpace(detectedName) ? detectedName : _appName,
                DetectedDisplayName = detectedName,
                UninstallKeyId = detectedKeyId,
                DetectedInstallLocation = detectedLoc,
                InstallerPath = _installerPath,
                CreatedFiles = finalFiles,
                CreatedRegistryKeys = _createdRegistryKeys.OrderBy(x => x).ToList()
            };
        }

        string primaryName = !string.IsNullOrWhiteSpace(log.DetectedDisplayName) ? log.DetectedDisplayName : _appName;
        string safePrimary = AppLocator.SanitizeFileName(primaryName);
        string logPath = Path.Combine(LogDirectory, $"{safePrimary}.revolog.json.gz");
        log.FilePath = logPath;
        await TraceLogSerializer.SaveAsync(log, logPath);

        // If user entered a custom name different from DetectedDisplayName, also save under user name
        string safeUser = AppLocator.SanitizeFileName(_appName);
        if (!string.IsNullOrWhiteSpace(safeUser) && !safeUser.Equals(safePrimary, StringComparison.OrdinalIgnoreCase))
        {
            string aliasPath = Path.Combine(LogDirectory, $"{safeUser}.revolog.json.gz");
            await TraceLogSerializer.SaveAsync(log, aliasPath);
        }

        return log;
    }

    private void BuildDeviceDriveMap()
    {
        _deviceToDriveMap.Clear();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                string driveLetter = drive.Name.TrimEnd('\\'); // e.g. "C:"
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

            // Fallback if QueryDosDevice did not match
            int slashIdx = raw.IndexOf('\\', 22);
            if (slashIdx > 0)
            {
                return "C:" + raw.Substring(slashIdx);
            }
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
            path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
            return false;

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(winDir) && path.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            return false;

        if (path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
            return false;

        // If this came from FileIOCreate (which also fires when opening existing files for read),
        // verify the file was actually created after monitoring started
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
            keyPath.Contains(@"\MuiCache", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private static void CaptureUninstallSnapshot(HashSet<string> targetSet)
    {
        targetSet.Clear();
        var roots = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        };

        foreach (var (hive, view, path) in roots)
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

    private (string DisplayName, string KeyId, string InstallLocation) DetectNewUninstallEntry()
    {
        var roots = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        };

        foreach (var (hive, view, path) in roots)
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
                        if (!string.IsNullOrWhiteSpace(disp))
                        {
                            return (disp.Trim(), name, loc?.Trim() ?? string.Empty);
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
        try
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
        }
        catch { }
    }
}
