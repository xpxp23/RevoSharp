using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;

namespace RevoSharp.Engine.Monitoring;

public class EtwInstallMonitor : IDisposable
{
    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp",
        "Logs"
    );

    private TraceEventSession? _session;
    private readonly HashSet<int> _trackedPids = [];
    private readonly HashSet<string> _createdFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _createdRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    private Process? _installerProcess;
    private string _appName = string.Empty;
    private string _installerPath = string.Empty;
    private bool _isMonitoring;

    public bool IsMonitoring => _isMonitoring;
    public int CapturedFileCount { get { lock (_lock) return _createdFiles.Count; } }
    public int CapturedRegCount { get { lock (_lock) return _createdRegistryKeys.Count; } }

    public event Action<string>? OnItemCaptured;

    public async Task StartAsync(string installerPath, string appName)
    {
        _appName = appName;
        _installerPath = installerPath;
        _trackedPids.Clear();
        _createdFiles.Clear();
        _createdRegistryKeys.Clear();

        // 1. Launch the installer process
        var psi = new ProcessStartInfo
        {
            FileName = installerPath,
            UseShellExecute = true,
            Verb = "runas"
        };

        _installerProcess = Process.Start(psi) ?? throw new InvalidOperationException("无法启动安装程序");
        _trackedPids.Add(_installerProcess.Id);

        _isMonitoring = true;

        // 2. Start ETW Kernel session in background
        await Task.Run(() =>
        {
            try
            {
                // Ensure any previous session with the same name is stopped
                TraceEventSession.GetActiveSession(KernelTraceEventParser.KernelSessionName)?.Dispose();

                _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
                _session.StopOnDispose = true;

                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.FileIOInit |
                    KernelTraceEventParser.Keywords.FileIO |
                    KernelTraceEventParser.Keywords.Registry |
                    KernelTraceEventParser.Keywords.Process
                );

                // Listen to process creation to capture child installers (e.g. setup -> sub-setup)
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

                // Listen to file creations
                _session.Source.Kernel.FileIOCreate += (FileIOCreateTraceData data) =>
                {
                    lock (_lock)
                    {
                        if (_trackedPids.Contains(data.ProcessID) && !string.IsNullOrWhiteSpace(data.FileName))
                        {
                            string norm = NormalizePath(data.FileName);
                            if (IsValidTargetFile(norm) && _createdFiles.Add(norm))
                            {
                                OnItemCaptured?.Invoke($"[文件] {norm}");
                            }
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
                            string norm = data.KeyName.Trim();
                            if (_createdRegistryKeys.Add(norm))
                            {
                                OnItemCaptured?.Invoke($"[注册表] {norm}");
                            }
                        }
                    }
                };

                // Processing loop (blocks current task thread until session is stopped)
                _session.Source.Process();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ETW Session Error: {ex.Message}");
            }
        });
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

        TraceLog log;
        lock (_lock)
        {
            log = new TraceLog
            {
                AppName = _appName,
                InstallerPath = _installerPath,
                CreatedFiles = _createdFiles.OrderBy(x => x).ToList(),
                CreatedRegistryKeys = _createdRegistryKeys.OrderBy(x => x).ToList()
            };
        }

        // Save log to disk
        string safeName = string.Join("_", _appName.Split(Path.GetInvalidFileNameChars()));
        string logPath = Path.Combine(LogDirectory, $"{safeName}.revolog.json.gz");
        await TraceLogSerializer.SaveAsync(log, logPath);

        return log;
    }

    private static string NormalizePath(string raw)
    {
        if (raw.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
        {
            // Simple drive letter mapping fallback
            int slashIdx = raw.IndexOf('\\', 22);
            if (slashIdx > 0)
            {
                string relative = raw.Substring(slashIdx);
                return "C:" + relative;
            }
        }
        return raw;
    }

    private static bool IsValidTargetFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)) return false;
        if (path.Contains(@"\Windows\Prefetch\", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    public void Dispose()
    {
        _session?.Dispose();
    }
}
