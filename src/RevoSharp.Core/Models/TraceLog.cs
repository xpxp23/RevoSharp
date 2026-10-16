namespace RevoSharp.Core.Models;

public class TraceLog
{
    public required string AppName { get; set; }
    public string DetectedDisplayName { get; set; } = string.Empty;
    public string UninstallKeyId { get; set; } = string.Empty;
    public string DetectedInstallLocation { get; set; } = string.Empty;
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public string InstallerPath { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public List<string> CreatedFiles { get; set; } = [];
    public List<string> ModifiedFiles { get; set; } = [];
    public List<string> CreatedRegistryKeys { get; set; } = [];
    public List<string> ModifiedRegistryValues { get; set; } = [];

    public string SummaryText =>
        $"文件: {CreatedFiles.Count} 项 | 注册表键: {CreatedRegistryKeys.Count} 项 | 注册表值: {ModifiedRegistryValues.Count} 项 | 记录于 {CreatedTime:yyyy-MM-dd HH:mm}";
}

public class TraceLogIndexEntry
{
    public required string FilePath { get; set; }
    public required string AppName { get; set; }
    public string DetectedDisplayName { get; set; } = string.Empty;
    public string UninstallKeyId { get; set; } = string.Empty;
    public string DetectedInstallLocation { get; set; } = string.Empty;
    public DateTime CreatedTime { get; set; }
    public DateTime FileLastWriteUtc { get; set; }
}
