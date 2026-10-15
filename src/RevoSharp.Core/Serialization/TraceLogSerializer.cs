using System.IO.Compression;
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

        await using var fileStream = File.Create(destinationFilePath);
        await using var gzipStream = new GZipStream(fileStream, CompressionLevel.Optimal);
        await JsonSerializer.SerializeAsync(gzipStream, log, JsonOptions);
    }

    public static async Task<TraceLog?> LoadAsync(string sourceFilePath)
    {
        if (!File.Exists(sourceFilePath)) return null;

        await using var fileStream = File.OpenRead(sourceFilePath);
        await using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        return await JsonSerializer.DeserializeAsync<TraceLog>(gzipStream, JsonOptions);
    }
}
