namespace RevoSharp.Core.Models;

public class BackupManifest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public required string AppName { get; set; }
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public string ManifestPath { get; set; } = string.Empty;
    public List<string> RegBackupFiles { get; set; } = [];
    public List<string> RecycledFilePaths { get; set; } = [];
    public List<string> RebootScheduledPaths { get; set; } = [];
    public bool SystemRestorePointCreated { get; set; }

    public int TotalBackedUpItems => RegBackupFiles.Count + RecycledFilePaths.Count;
    public string CreatedTimeDisplay => CreatedTime.ToString("yyyy-MM-dd HH:mm:ss");
    public string SummaryText => $"注册表备份: {RegBackupFiles.Count} 份 | 回收站文件: {RecycledFilePaths.Count} 项" +
                                 (RebootScheduledPaths.Count > 0 ? $" | 重启延迟删除: {RebootScheduledPaths.Count} 项" : "");
}
