using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RevoSharp.Core.Models;

namespace RevoSharp.Core.Serialization;

public static class SettingsSerializer
{
    public static readonly string AppDataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RevoSharp"
    );

    public static readonly string SettingsFilePath = Path.Combine(AppDataRoot, "settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly object SyncLock = new();
    private static AppSettings? _current;

    public static AppSettings Current
    {
        get
        {
            if (_current != null) return _current;
            lock (SyncLock)
            {
                _current ??= LoadInternal();
                return _current;
            }
        }
    }

    public static AppSettings Load()
    {
        lock (SyncLock)
        {
            _current = LoadInternal();
            return _current;
        }
    }

    public static void Save(AppSettings? settings = null)
    {
        lock (SyncLock)
        {
            var target = settings ?? _current ?? new AppSettings();
            _current = target;
            try
            {
                if (!Directory.Exists(AppDataRoot))
                {
                    Directory.CreateDirectory(AppDataRoot);
                }

                string tempPath = SettingsFilePath + ".tmp";
                string json = JsonSerializer.Serialize(target, JsonOptions);
                File.WriteAllText(tempPath, json, Encoding.UTF8);
                File.Move(tempPath, SettingsFilePath, overwrite: true);
            }
            catch { }
        }
    }

    public static bool IsPathWhitelisted(string? candidatePath, AppSettings? settings = null)
    {
        if (string.IsNullOrWhiteSpace(candidatePath)) return false;
        var cfg = settings ?? Current;
        if (cfg.WhitelistedPaths == null || cfg.WhitelistedPaths.Count == 0) return false;

        string normCandidate = candidatePath.Trim().Trim('"').TrimEnd('\\', '/');
        foreach (var rawRule in cfg.WhitelistedPaths)
        {
            if (string.IsNullOrWhiteSpace(rawRule)) continue;
            string rule = Environment.ExpandEnvironmentVariables(rawRule.Trim().Trim('"')).TrimEnd('\\', '/');
            if (rule.Length < 2) continue;

            if (normCandidate.Equals(rule, StringComparison.OrdinalIgnoreCase) ||
                normCandidate.StartsWith(rule + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static AppSettings LoadInternal()
    {
        try
        {
            if (File.Exists(SettingsFilePath))
            {
                string json = File.ReadAllText(SettingsFilePath, Encoding.UTF8);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions);
                if (loaded != null)
                {
                    loaded.WhitelistedPaths ??= [];
                    loaded.WhitelistedPublishers ??= [];
                    return loaded;
                }
            }
        }
        catch { }

        return new AppSettings();
    }
}
