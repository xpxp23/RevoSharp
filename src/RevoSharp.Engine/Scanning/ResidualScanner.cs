using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;

namespace RevoSharp.Engine.Scanning;

public class ResidualScanner
{
    private static readonly HashSet<string> BlacklistedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Common Files", "System32", "SysWOW64", "Program Files",
        "Users", "AppData", "Local", "Roaming", "LocalLow", "Temp", "Software",
        "Classes", "Google", "Intel", "AMD", "NVIDIA", "Default", "All Users", "CurrentVersion"
    };

    private readonly ReverseReferenceScanner _refScanner = new();
    private readonly ShortcutScanner _shortcutScanner = new();

    public async Task<List<ResidualItem>> ScanResidualsAsync(InstalledApp app, ScanMode mode = ScanMode.Moderate)
    {
        return await Task.Run(async () =>
        {
            var results = new List<ResidualItem>();

            // 1. If trace log exists from monitoring, load recorded exact items first
            if (app.HasTraceLog && !string.IsNullOrEmpty(app.TraceLogPath) && File.Exists(app.TraceLogPath))
            {
                var traceLog = await TraceLogSerializer.LoadAsync(app.TraceLogPath);
                if (traceLog != null)
                {
                    AppendTraceLogResiduals(traceLog, results);
                    return results;
                }
            }

            // 2. Build multi-dimensional target profile
            var profile = ProfileBuilder.Build(app);

            // 3. Level 1: Safe Mode checks
            ScanSafeItems(app, profile, results);

            // 4. Level 2: Moderate Mode checks (Reverse References + Shortcuts + AppData)
            if (mode >= ScanMode.Moderate)
            {
                _refScanner.ScanReferences(profile, results);
                _shortcutScanner.ScanShortcuts(profile, results);
                ScanCommonDirectories(profile, results);
                ScanSoftwareHives(profile, results, deepFuzzy: false);
            }

            // 5. Level 3: Advanced Mode checks (Deep fuzzy token scan)
            if (mode >= ScanMode.Advanced)
            {
                ScanSoftwareHives(profile, results, deepFuzzy: true);
                ScanTempDirectory(profile, results);
            }

            return results;
        });
    }

    private static void AppendTraceLogResiduals(TraceLog traceLog, List<ResidualItem> results)
    {
        foreach (var file in traceLog.CreatedFiles)
        {
            if (File.Exists(file))
            {
                results.Add(new ResidualItem
                {
                    Type = ResidualType.File,
                    Path = file,
                    Confidence = ConfidenceLevel.High,
                    Reason = "安装监视记录文件",
                    IsSelected = true
                });
            }
            else if (Directory.Exists(file))
            {
                results.Add(new ResidualItem
                {
                    Type = ResidualType.Directory,
                    Path = file,
                    Confidence = ConfidenceLevel.High,
                    Reason = "安装监视记录目录",
                    IsSelected = true
                });
            }
        }

        foreach (var key in traceLog.CreatedRegistryKeys)
        {
            results.Add(new ResidualItem
            {
                Type = ResidualType.RegistryKey,
                Path = key,
                Confidence = ConfidenceLevel.High,
                Reason = "安装监视记录注册表项",
                IsSelected = true
            });
        }
    }

    private static void ScanSafeItems(InstalledApp app, TargetProfile profile, List<ResidualItem> results)
    {
        // 1. Primary Install Directory
        if (profile.HasValidLocation && Directory.Exists(profile.InstallLocation))
        {
            results.Add(new ResidualItem
            {
                Type = ResidualType.Directory,
                Path = profile.InstallLocation,
                Confidence = ConfidenceLevel.High,
                Reason = "原安装主目录",
                IsSelected = true
            });
        }

        // 2. Uninstall registry key if it wasn't cleaned up by the native uninstaller
        if (!string.IsNullOrEmpty(profile.UninstallKeyName))
        {
            var uninstallHives = new[]
            {
                (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, "HKLM"),
                (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, "HKLM"),
                (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, "HKCU")
            };

            foreach (var (hive, path, hiveName) in uninstallHives)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(path);
                    if (key != null)
                    {
                        results.Add(new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Path = $@"{hiveName}\{path}",
                            Confidence = ConfidenceLevel.High,
                            Reason = "原厂残留卸载注册表主键",
                            IsSelected = true
                        });
                    }
                }
                catch { }
            }
        }
    }

    private static void ScanCommonDirectories(TargetProfile profile, List<ResidualItem> results)
    {
        var targetSearchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        };

        foreach (var root in targetSearchRoots)
        {
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.GetDirectories(root))
                {
                    string dirName = Path.GetFileName(dir);
                    if (BlacklistedNames.Contains(dirName)) continue;

                    if (MatchesProfile(dirName, profile, out string matchReason))
                    {
                        if (!results.Any(r => r.Path.Equals(dir, StringComparison.OrdinalIgnoreCase)))
                        {
                            results.Add(new ResidualItem
                            {
                                Type = ResidualType.Directory,
                                Path = dir,
                                Confidence = ConfidenceLevel.High,
                                Reason = $"应用存储与缓存目录 ({matchReason})",
                                IsSelected = true
                            });
                        }
                    }
                    // Publisher subfolder check
                    else if (!string.IsNullOrEmpty(profile.Publisher) && MatchesName(dirName, profile.Publisher))
                    {
                        try
                        {
                            foreach (var subDir in Directory.GetDirectories(dir))
                            {
                                string subName = Path.GetFileName(subDir);
                                if (MatchesProfile(subName, profile, out string subMatchReason))
                                {
                                    if (!results.Any(r => r.Path.Equals(subDir, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        results.Add(new ResidualItem
                                        {
                                            Type = ResidualType.Directory,
                                            Path = subDir,
                                            Confidence = ConfidenceLevel.High,
                                            Reason = $"厂商目录下专用程序目录 ({dirName}\\{subName})",
                                            IsSelected = true
                                        });
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanSoftwareHives(TargetProfile profile, List<ResidualItem> results, bool deepFuzzy)
    {
        var hives = new[]
        {
            (RegistryHive.CurrentUser, @"Software", "HKCU"),
            (RegistryHive.LocalMachine, @"SOFTWARE", "HKLM"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node", "HKLM")
        };

        foreach (var (hive, subPath, hiveName) in hives)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var swKey = baseKey.OpenSubKey(subPath);
                if (swKey == null) continue;

                foreach (var keyName in swKey.GetSubKeyNames())
                {
                    if (BlacklistedNames.Contains(keyName)) continue;

                    string fullKeyPath = $@"{hiveName}\{subPath}\{keyName}";

                    if (MatchesProfile(keyName, profile, out string reason))
                    {
                        if (!results.Any(r => r.Path.Equals(fullKeyPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            results.Add(new ResidualItem
                            {
                                Type = ResidualType.RegistryKey,
                                Path = fullKeyPath,
                                Confidence = ConfidenceLevel.High,
                                Reason = $"注册表软件配置主键 ({reason})",
                                IsSelected = true
                            });
                        }
                    }
                    // Publisher subfolder check
                    else if (!string.IsNullOrEmpty(profile.Publisher) && MatchesName(keyName, profile.Publisher))
                    {
                        try
                        {
                            using var pubKey = swKey.OpenSubKey(keyName);
                            if (pubKey == null) continue;

                            foreach (var subAppKey in pubKey.GetSubKeyNames())
                            {
                                if (MatchesProfile(subAppKey, profile, out string subReason))
                                {
                                    string fullSub = $@"{hiveName}\{subPath}\{keyName}\{subAppKey}";
                                    if (!results.Any(r => r.Path.Equals(fullSub, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        results.Add(new ResidualItem
                                        {
                                            Type = ResidualType.RegistryKey,
                                            Path = fullSub,
                                            Confidence = ConfidenceLevel.High,
                                            Reason = $"厂商分支下软件子键 ({keyName}\\{subAppKey})",
                                            IsSelected = true
                                        });
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanTempDirectory(TargetProfile profile, List<ResidualItem> results)
    {
        string tempDir = Path.GetTempPath();
        if (!Directory.Exists(tempDir)) return;

        try
        {
            foreach (var dir in Directory.GetDirectories(tempDir))
            {
                string name = Path.GetFileName(dir);
                if (MatchesProfile(name, profile, out string reason))
                {
                    results.Add(new ResidualItem
                    {
                        Type = ResidualType.Directory,
                        Path = dir,
                        Confidence = ConfidenceLevel.Medium,
                        Reason = "临时解压与安装缓存目录",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static bool MatchesProfile(string candidate, TargetProfile profile, out string matchReason)
    {
        matchReason = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate)) return false;

        if (MatchesName(candidate, profile.DisplayName))
        {
            matchReason = "完全匹配软件名";
            return true;
        }

        foreach (var exe in profile.MainExeNames)
        {
            string exeNoExt = Path.GetFileNameWithoutExtension(exe);
            if (MatchesName(candidate, exeNoExt))
            {
                matchReason = $"匹配可执行文件名称 ({exe})";
                return true;
            }
        }

        if (!string.IsNullOrEmpty(profile.GuidString) && candidate.Contains(profile.GuidString, StringComparison.OrdinalIgnoreCase))
        {
            matchReason = "匹配产品代码 GUID";
            return true;
        }

        return false;
    }

    private static bool MatchesName(string candidate, string target)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(target)) return false;
        if (candidate.Equals(target, StringComparison.OrdinalIgnoreCase)) return true;

        string cleanCandidate = CleanName(candidate);
        string cleanTarget = CleanName(target);

        if (cleanCandidate.Length >= 4 && cleanTarget.Length >= 4)
        {
            if (cleanCandidate.IndexOf(cleanTarget, StringComparison.OrdinalIgnoreCase) >= 0 ||
                cleanTarget.IndexOf(cleanCandidate, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string CleanName(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        var chars = raw.Where(c => char.IsLetterOrDigit(c) || c == ' ').ToArray();
        return new string(chars).Trim();
    }
}
