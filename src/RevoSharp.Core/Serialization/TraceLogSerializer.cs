using System.IO.Compression;
using System.Text;
using System.Text.Json;
using RevoSharp.Core.Models;

namespace RevoSharp.Core.Serialization;

public static class TraceLogSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static async Task SaveAsync(TraceLog log, string destinationFilePath)
    {
        string? dir = Path.GetDirectoryName(destinationFilePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        await using (var fileStream = File.Create(destinationFilePath))
        await using (var gzipStream = new GZipStream(fileStream, CompressionLevel.Optimal))
        {
            await JsonSerializer.SerializeAsync(gzipStream, log, JsonOptions);
        }

        if (!string.IsNullOrEmpty(dir))
        {
            await UpsertIndexEntryAsync(dir, log, destinationFilePath);
        }
    }

    public static async Task<TraceLog?> LoadAsync(string sourceFilePath)
    {
        if (!File.Exists(sourceFilePath)) return null;

        await using var fileStream = File.OpenRead(sourceFilePath);
        await using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        var log = await JsonSerializer.DeserializeAsync<TraceLog>(gzipStream, JsonOptions);
        if (log != null)
        {
            log.FilePath = sourceFilePath;
        }
        return log;
    }

    /// <summary>
    /// Fast metadata lookup using a lightweight JSON index file so startup never has to GZip-decompress all trace logs.
    /// Automatically rebuilds index entries for any newly added or modified .revolog.json.gz files.
    /// </summary>
    public static async Task<List<TraceLogIndexEntry>> LoadOrSyncIndexAsync(string logDirectory)
    {
        if (!Directory.Exists(logDirectory)) return [];

        string indexPath = Path.Combine(logDirectory, "trace_index.json");
        var existingMap = new Dictionary<string, TraceLogIndexEntry>(StringComparer.OrdinalIgnoreCase);

        if (File.Exists(indexPath))
        {
            try
            {
                string json = await File.ReadAllTextAsync(indexPath, Encoding.UTF8);
                var list = JsonSerializer.Deserialize<List<TraceLogIndexEntry>>(json, JsonOptions);
                if (list != null)
                {
                    foreach (var item in list)
                    {
                        existingMap[item.FilePath] = item;
                    }
                }
            }
            catch { }
        }

        bool dirty = false;
        var currentFiles = Directory.GetFiles(logDirectory, "*.revolog.json.gz");
        var activeEntries = new List<TraceLogIndexEntry>(currentFiles.Length);

        foreach (var file in currentFiles)
        {
            try
            {
                DateTime lastWriteUtc = File.GetLastWriteTimeUtc(file);
                if (existingMap.TryGetValue(file, out var cached) &&
                    Math.Abs((cached.FileLastWriteUtc - lastWriteUtc).TotalSeconds) < 1.0)
                {
                    activeEntries.Add(cached);
                    continue;
                }

                var log = await LoadAsync(file);
                if (log != null)
                {
                    var entry = new TraceLogIndexEntry
                    {
                        FilePath = file,
                        AppName = log.AppName,
                        DetectedDisplayName = log.DetectedDisplayName,
                        UninstallKeyId = log.UninstallKeyId,
                        DetectedInstallLocation = log.DetectedInstallLocation,
                        CreatedTime = log.CreatedTime,
                        FileLastWriteUtc = lastWriteUtc
                    };
                    activeEntries.Add(entry);
                    dirty = true;
                }
            }
            catch { }
        }

        if (dirty || activeEntries.Count != existingMap.Count)
        {
            try
            {
                string outJson = JsonSerializer.Serialize(activeEntries, JsonOptions);
                await File.WriteAllTextAsync(indexPath, outJson, Encoding.UTF8);
            }
            catch { }
        }

        return activeEntries;
    }

    private static async Task UpsertIndexEntryAsync(string logDirectory, TraceLog log, string filePath)
    {
        try
        {
            string indexPath = Path.Combine(logDirectory, "trace_index.json");
            var entries = new List<TraceLogIndexEntry>();
            if (File.Exists(indexPath))
            {
                string json = await File.ReadAllTextAsync(indexPath, Encoding.UTF8);
                entries = JsonSerializer.Deserialize<List<TraceLogIndexEntry>>(json, JsonOptions) ?? [];
            }

            entries.RemoveAll(e => e.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase));
            entries.Add(new TraceLogIndexEntry
            {
                FilePath = filePath,
                AppName = log.AppName,
                DetectedDisplayName = log.DetectedDisplayName,
                UninstallKeyId = log.UninstallKeyId,
                DetectedInstallLocation = log.DetectedInstallLocation,
                CreatedTime = log.CreatedTime,
                FileLastWriteUtc = File.Exists(filePath) ? File.GetLastWriteTimeUtc(filePath) : DateTime.UtcNow
            });

            string outJson = JsonSerializer.Serialize(entries, JsonOptions);
            await File.WriteAllTextAsync(indexPath, outJson, Encoding.UTF8);
        }
        catch { }
    }

    public static async Task ExportReadableReportAsync(TraceLog log, string outputReportPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("====================================================================");
        sb.AppendLine($"  RevoSharp 安装监控追踪报告 - {log.AppName}");
        sb.AppendLine("====================================================================");
        sb.AppendLine($"监控时间: {log.CreatedTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"关联程序: {(!string.IsNullOrEmpty(log.DetectedDisplayName) ? log.DetectedDisplayName : log.AppName)}");
        sb.AppendLine($"注册表ID: {log.UninstallKeyId}");
        sb.AppendLine($"安装目录: {log.DetectedInstallLocation}");
        sb.AppendLine($"安装包源: {log.InstallerPath}");
        sb.AppendLine();
        sb.AppendLine($"[一、新建/修改文件与目录 ({log.CreatedFiles.Count} 项)]");
        foreach (var f in log.CreatedFiles)
        {
            sb.AppendLine($"  + {f}");
        }
        sb.AppendLine();
        sb.AppendLine($"[二、新建注册表项 ({log.CreatedRegistryKeys.Count} 项)]");
        foreach (var k in log.CreatedRegistryKeys)
        {
            sb.AppendLine($"  + {k}");
        }
        sb.AppendLine();
        sb.AppendLine($"[三、修改/写入注册表键值 ({log.ModifiedRegistryValues.Count} 项)]");
        foreach (var v in log.ModifiedRegistryValues)
        {
            sb.AppendLine($"  ~ {v}");
        }

        await File.WriteAllTextAsync(outputReportPath, sb.ToString(), Encoding.UTF8);
    }
}
