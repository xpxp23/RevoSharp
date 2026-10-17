namespace RevoSharp.Core.Models;

public class LockingProcessInfo
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public string ApplicationName { get; init; } = string.Empty;
    public string ServiceShortName { get; init; } = string.Empty;
    public bool IsExplorerShell { get; init; }
    public bool IsCriticalSystemProcess { get; init; }
    public string LockedFilePath { get; init; } = string.Empty;

    public string DisplaySummary => IsExplorerShell
        ? $"资源管理器 (explorer.exe, PID: {ProcessId})"
        : (!string.IsNullOrWhiteSpace(ApplicationName) && !ApplicationName.Equals(ProcessName, StringComparison.OrdinalIgnoreCase)
            ? $"{ApplicationName} ({ProcessName}, PID: {ProcessId})"
            : $"{ProcessName} (PID: {ProcessId})");
}
