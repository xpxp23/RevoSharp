using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Scanning;

public class ResidualScanner
{
    private static readonly HashSet<string> BlacklistedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Common Files", "System32", "SysWOW64", "Program Files",
        "Users", "AppData", "Local", "Roaming", "LocalLow", "Temp", "Software",
        "Classes", "Google", "Intel", "AMD", "NVIDIA", "Default", "All Users", "CurrentVersion",
        "Adobe", "Apple", "JetBrains", "Tencent", "ByteDance", "Valve", "Steam", "Epic Games",
        "Ubisoft", "Electronic Arts", "Mozilla", "Oracle", "Java", "Python", "Package Cache",
        "WindowsApps", "Reference Assemblies", "MSBuild", "dotnet", "Policies", "RegisteredApplications",
        "Clients", "Shared", "Common", "Packages", "Programs"
    };

    private readonly ReverseReferenceScanner _refScanner = new();
    private readonly ShortcutScanner _shortcutScanner = new();

    public async Task<List<ResidualItem>> ScanResidualsAsync(InstalledApp app, ScanMode mode = ScanMode.Moderate)
    {
        return await Task.Run(async () =>
        {
            var results = new List<ResidualItem>();

            // 1. If trace log exists from monitoring, load recorded exact items AND continue scanning runtime residuals
            if (app.HasTraceLog && !string.IsNullOrEmpty(app.TraceLogPath) && File.Exists(app.TraceLogPath))
            {
                var traceLog = await TraceLogSerializer.LoadAsync(app.TraceLogPath);
                if (traceLog != null)
                {
                    AppendTraceLogResiduals(traceLog, results);
                }
            }

            // 2. Build multi-dimensional target profile
            var profile = ProfileBuilder.Build(app);

            // 3. Level 1: Safe Mode checks
            ScanSafeItems(profile, results);

            // 4. Level 2: Moderate Mode checks (Reverse References + Shortcuts + AppData + Software Hives)
            if (mode >= ScanMode.Moderate)
            {
                _refScanner.ScanReferences(profile, results);
                _shortcutScanner.ScanShortcuts(profile, results);
                ScanCommonDirectories(profile, results, deepFuzzy: false);
                ScanSoftwareHives(profile, results, deepFuzzy: false);
            }

            // 5. Level 3: Advanced Mode checks (Deep fuzzy token scan + Temp directory)
            if (mode >= ScanMode.Advanced)
            {
                ScanCommonDirectories(profile, results, deepFuzzy: true);
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
            if (AppLocator.IsProtectedSharedDirectory(file)) continue;

            if (File.Exists(file))
            {
                AddResidualIfUnique(results, new ResidualItem
                {
                    Type = ResidualType.File,
                    Category = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? ResidualCategory.Shortcut : ResidualCategory.File,
                    Path = file,
                    SizeInBytes = CalculatePathSize(file, isDirectory: false),
                    Confidence = ConfidenceLevel.High,
                    Reason = "ETW 安装监控精确捕获文件",
                    IsSelected = true
                });
            }
            else if (Directory.Exists(file))
            {
                AddResidualIfUnique(results, new ResidualItem
                {
                    Type = ResidualType.Directory,
                    Category = ResidualCategory.Directory,
                    Path = file,
                    SizeInBytes = CalculatePathSize(file, isDirectory: true),
                    Confidence = ConfidenceLevel.High,
                    Reason = "ETW 安装监控精确捕获目录",
                    IsSelected = true
                });
            }
        }

        foreach (var key in traceLog.CreatedRegistryKeys)
        {
            AddResidualIfUnique(results, new ResidualItem
            {
                Type = ResidualType.RegistryKey,
                Category = ResidualCategory.RegistryKey,
                Path = key,
                Confidence = ConfidenceLevel.High,
                Reason = "ETW 安装监控精确捕获注册表项",
                IsSelected = true
            });
        }
    }

    private static void ScanSafeItems(TargetProfile profile, List<ResidualItem> results)
    {
        // 1. Primary Install Directory (strictly verified not to be a shared folder)
        if (profile.HasValidLocation &&
            !AppLocator.IsProtectedSharedDirectory(profile.InstallLocation) &&
            Directory.Exists(profile.InstallLocation))
        {
            AddResidualIfUnique(results, new ResidualItem
            {
                Type = ResidualType.Directory,
                Category = ResidualCategory.Directory,
                Path = profile.InstallLocation,
                SizeInBytes = CalculatePathSize(profile.InstallLocation, isDirectory: true),
                Confidence = ConfidenceLevel.High,
                Reason = "原安装主目录",
                IsSelected = true
            });
        }
        else if (!string.IsNullOrEmpty(profile.SingleExecutableFile) && File.Exists(profile.SingleExecutableFile))
        {
            AddResidualIfUnique(results, new ResidualItem
            {
                Type = ResidualType.File,
                Category = ResidualCategory.File,
                Path = profile.SingleExecutableFile,
                SizeInBytes = CalculatePathSize(profile.SingleExecutableFile, isDirectory: false),
                Confidence = ConfidenceLevel.High,
                Reason = "独立单文件程序本体 (已保护所在共享目录)",
                IsSelected = true
            });
        }

        // 2. Uninstall registry key if it wasn't cleaned up by the native uninstaller
        if (!string.IsNullOrEmpty(profile.UninstallKeyName))
        {
            var uninstallHives = new[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, "HKLM"),
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName),
                (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName, "HKCU")
            };

            foreach (var (hive, view, path, displayPrefix) in uninstallHives)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(path);
                    if (key != null)
                    {
                        string fullPath = displayPrefix.StartsWith("HKLM\\SOFTWARE\\WOW6432Node")
                            ? displayPrefix
                            : $@"{displayPrefix}\{path}";

                        AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Category = ResidualCategory.RegistryKey,
                            Path = fullPath,
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

    private static void ScanCommonDirectories(TargetProfile profile, List<ResidualItem> results, bool deepFuzzy)
    {
        var targetSearchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        };

        string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\LocalLow");
        if (Directory.Exists(localLow)) targetSearchRoots.Add(localLow);

        foreach (var root in targetSearchRoots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.GetDirectories(root))
                {
                    string dirName = Path.GetFileName(dir);

                    // IMPORTANT FIX: Check if dirName is the Publisher root directory FIRST
                    // so we drill into publisher subdirectories instead of deleting the whole publisher root!
                    bool isPublisherRoot = BlacklistedNames.Contains(dirName) ||
                        (!string.IsNullOrEmpty(profile.Publisher) &&
                         IsPublisherNameMatch(dirName, profile.Publisher) &&
                         !dirName.Equals(profile.DisplayName, StringComparison.OrdinalIgnoreCase));

                    if (isPublisherRoot)
                    {
                        if (!string.IsNullOrEmpty(profile.Publisher) && IsPublisherNameMatch(dirName, profile.Publisher))
                        {
                            try
                            {
                                foreach (var subDir in Directory.GetDirectories(dir))
                                {
                                    string subName = Path.GetFileName(subDir);
                                    if (BlacklistedNames.Contains(subName)) continue;

                                    if (MatchesProfile(subName, profile, deepFuzzy, out string subReason, out var conf))
                                    {
                                        AddResidualIfUnique(results, new ResidualItem
                                        {
                                            Type = ResidualType.Directory,
                                            Category = ResidualCategory.Directory,
                                            Path = subDir,
                                            SizeInBytes = CalculatePathSize(subDir, isDirectory: true),
                                            Confidence = conf,
                                            Reason = $"厂商子目录 ({dirName}\\{subName} - {subReason})",
                                            IsSelected = conf != ConfidenceLevel.Low
                                        });
                                    }
                                }
                            }
                            catch { }
                        }
                        continue;
                    }

                    if (MatchesProfile(dirName, profile, deepFuzzy, out string matchReason, out var confidence))
                    {
                        AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.Directory,
                            Category = ResidualCategory.Directory,
                            Path = dir,
                            SizeInBytes = CalculatePathSize(dir, isDirectory: true),
                            Confidence = confidence,
                            Reason = $"应用数据与缓存目录 ({matchReason})",
                            IsSelected = confidence != ConfidenceLevel.Low
                        });
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
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software", "HKCU"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE", "HKLM"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE", @"HKLM\SOFTWARE\WOW6432Node")
        };

        foreach (var (hive, view, subPath, hivePrefix) in hives)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var swKey = baseKey.OpenSubKey(subPath);
                if (swKey == null) continue;

                foreach (var keyName in swKey.GetSubKeyNames())
                {
                    string fullKeyPath = hivePrefix == @"HKLM\SOFTWARE\WOW6432Node"
                        ? $@"{hivePrefix}\{keyName}"
                        : $@"{hivePrefix}\{subPath}\{keyName}";

                    bool isPublisherRoot = BlacklistedNames.Contains(keyName) ||
                        (!string.IsNullOrEmpty(profile.Publisher) &&
                         IsPublisherNameMatch(keyName, profile.Publisher) &&
                         !keyName.Equals(profile.DisplayName, StringComparison.OrdinalIgnoreCase));

                    if (isPublisherRoot)
                    {
                        if (!string.IsNullOrEmpty(profile.Publisher) && IsPublisherNameMatch(keyName, profile.Publisher))
                        {
                            try
                            {
                                using var pubKey = swKey.OpenSubKey(keyName);
                                if (pubKey == null) continue;

                                foreach (var subAppKey in pubKey.GetSubKeyNames())
                                {
                                    if (BlacklistedNames.Contains(subAppKey)) continue;
                                    if (MatchesProfile(subAppKey, profile, deepFuzzy, out string subReason, out var conf))
                                    {
                                        string fullSub = $@"{fullKeyPath}\{subAppKey}";
                                        AddResidualIfUnique(results, new ResidualItem
                                        {
                                            Type = ResidualType.RegistryKey,
                                            Category = ResidualCategory.RegistryKey,
                                            Path = fullSub,
                                            Confidence = conf,
                                            Reason = $"厂商分支下软件子键 ({keyName}\\{subAppKey} - {subReason})",
                                            IsSelected = conf != ConfidenceLevel.Low
                                        });
                                    }
                                }
                            }
                            catch { }
                        }
                        continue;
                    }

                    if (MatchesProfile(keyName, profile, deepFuzzy, out string reason, out var confidence))
                    {
                        AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Category = ResidualCategory.RegistryKey,
                            Path = fullKeyPath,
                            Confidence = confidence,
                            Reason = $"注册表软件配置主键 ({reason})",
                            IsSelected = confidence != ConfidenceLevel.Low
                        });
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
                if (BlacklistedNames.Contains(name)) continue;

                if (MatchesProfile(name, profile, deepFuzzy: true, out string reason, out _))
                {
                    AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.Directory,
                        Category = ResidualCategory.Directory,
                        Path = dir,
                        SizeInBytes = CalculatePathSize(dir, isDirectory: true),
                        Confidence = ConfidenceLevel.Medium,
                        Reason = $"临时解压与安装缓存目录 ({reason})",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static bool MatchesProfile(
        string candidate,
        TargetProfile profile,
        bool deepFuzzy,
        out string matchReason,
        out ConfidenceLevel confidence)
    {
        matchReason = string.Empty;
        confidence = ConfidenceLevel.High;
        if (string.IsNullOrWhiteSpace(candidate)) return false;

        if (MatchesExactOrContainedTarget(candidate, profile.DisplayName))
        {
            matchReason = "匹配软件名称";
            confidence = ConfidenceLevel.High;
            return true;
        }

        foreach (var exe in profile.MainExeNames)
        {
            string exeNoExt = Path.GetFileNameWithoutExtension(exe);
            if (exeNoExt.Length >= 4 && MatchesExactOrContainedTarget(candidate, exeNoExt))
            {
                matchReason = $"匹配主程序名称 ({exe})";
                confidence = ConfidenceLevel.High;
                return true;
            }
        }

        if (!string.IsNullOrEmpty(profile.GuidString) && candidate.Contains(profile.GuidString, StringComparison.OrdinalIgnoreCase))
        {
            matchReason = "匹配产品 GUID";
            confidence = ConfidenceLevel.High;
            return true;
        }

        // Deep fuzzy token scan (only in Advanced mode)
        if (deepFuzzy && profile.CleanTokens.Count > 0)
        {
            string cleanCand = CleanName(candidate);
            foreach (var token in profile.CleanTokens)
            {
                if (token.Length >= 5 &&
                    !IsPublisherNameMatch(token, profile.Publisher) &&
                    cleanCand.Contains(token, StringComparison.OrdinalIgnoreCase))
                {
                    matchReason = $"深度特征词匹配 ({token})";
                    confidence = ConfidenceLevel.Low;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool MatchesExactOrContainedTarget(string candidate, string target)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(target)) return false;
        if (candidate.Equals(target, StringComparison.OrdinalIgnoreCase)) return true;

        string cleanCandidate = CleanName(candidate);
        string cleanTarget = CleanName(target);

        if (cleanCandidate.Length >= 4 && cleanTarget.Length >= 4)
        {
            if (cleanCandidate.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase))
                return true;

            // Candidate contains the full target name (e.g. candidate "Google Chrome Beta" contains target "Google Chrome")
            if (cleanCandidate.Contains(cleanTarget, StringComparison.OrdinalIgnoreCase))
                return true;

            // Compact no-space comparison (e.g. candidate "RevoSharp" vs target "Revo Sharp")
            string compactCand = cleanCandidate.Replace(" ", "");
            string compactTarget = cleanTarget.Replace(" ", "");
            if (compactCand.Length >= 5 && compactCand.Equals(compactTarget, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsPublisherNameMatch(string candidate, string publisher)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(publisher)) return false;
        string cleanCand = CleanName(candidate);
        string cleanPub = CleanName(publisher);
        if (cleanCand.Length < 3 || cleanPub.Length < 3) return false;

        return cleanCand.Equals(cleanPub, StringComparison.OrdinalIgnoreCase) ||
               cleanPub.StartsWith(cleanCand + " ", StringComparison.OrdinalIgnoreCase) ||
               cleanCand.StartsWith(cleanPub + " ", StringComparison.OrdinalIgnoreCase);
    }

    private static string CleanName(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        var chars = raw.Where(c => char.IsLetterOrDigit(c) || c == ' ').ToArray();
        return new string(chars).Trim();
    }

    public static void AddResidualIfUnique(List<ResidualItem> results, ResidualItem item)
    {
        bool exists = results.Any(r =>
            r.Path.Equals(item.Path, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ValueName ?? string.Empty, item.ValueName ?? string.Empty, StringComparison.OrdinalIgnoreCase));

        if (!exists)
        {
            results.Add(item);
        }
    }

    public static long CalculatePathSize(string path, bool isDirectory)
    {
        try
        {
            if (!isDirectory)
            {
                return File.Exists(path) ? new FileInfo(path).Length : 0;
            }

            if (!Directory.Exists(path)) return 0;

            long total = 0;
            int fileCount = 0;
            foreach (var file in Directory.EnumerateFiles(path, "*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                MaxRecursionDepth = 6
            }))
            {
                try
                {
                    total += new FileInfo(file).Length;
                    if (++fileCount > 2500) break; // Cap to keep UI responsive
                }
                catch { }
            }
            return total;
        }
        catch
        {
            return 0;
        }
    }
}
