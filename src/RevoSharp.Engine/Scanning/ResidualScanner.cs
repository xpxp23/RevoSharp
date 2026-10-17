using System.IO;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Safety;

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

    /// <summary>
    /// Sibling edition/variant tokens that indicate a separate side-by-side product installation
    /// (e.g., "Google Chrome Beta" vs "Google Chrome", "FooPlayer Pro" vs "FooPlayer", "Visual Studio Code" vs "Visual Studio").
    /// Prevents accidental high/medium-confidence collateral deletion of sibling products!
    /// </summary>
    private static readonly HashSet<string> SiblingVariantTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "beta", "canary", "dev", "nightly", "insiders", "preview", "server", "agent",
        "sdk", "runtime", "redist", "viewer", "helper", "bridge", "updater", "code", "studio",
        "pro", "plus", "max", "ultra", "lite", "ultimate", "professional", "enterprise",
        "community", "standard", "se", "ce", "express", "workstation", "player", "creator"
    };

    private readonly ReverseReferenceScanner _refScanner = new();
    private readonly ShortcutScanner _shortcutScanner = new();

    public async Task<List<ResidualItem>> ScanResidualsAsync(
        InstalledApp app,
        ScanMode mode = ScanMode.Moderate,
        IEnumerable<InstalledApp>? otherInstalledApps = null)
    {
        return await Task.Run(async () =>
        {
            var results = new List<ResidualItem>();

            // Build set of active installation directories belonging to OTHER currently installed apps
            // so we never flag a sibling product's active installation folder as a residual!
            var protectedSiblingDirs = BuildActiveSiblingDirectorySet(app, otherInstalledApps);

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
                ScanCommonDirectories(profile, results, protectedSiblingDirs, deepFuzzy: false);
                ScanSoftwareHives(profile, results, deepFuzzy: false);
            }

            // 5. Level 3: Advanced Mode checks (Deep fuzzy token scan + Temp directory)
            if (mode >= ScanMode.Advanced)
            {
                ScanCommonDirectories(profile, results, protectedSiblingDirs, deepFuzzy: true);
                ScanSoftwareHives(profile, results, deepFuzzy: true);
                ScanTempDirectory(profile, results);
            }

            foreach (var item in results)
            {
                if (string.IsNullOrEmpty(item.SourceAppName))
                {
                    item.SourceAppName = app.DisplayName;
                }
            }

            // Automatically run a lightweight Restart Manager file-lock check on discovered residual files/folders
            await FileLockUnlocker.ScanAndAttachLocksToResidualsAsync(results);

            return results;
        });
    }

    private static HashSet<string> BuildActiveSiblingDirectorySet(InstalledApp targetApp, IEnumerable<InstalledApp>? otherInstalledApps)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string targetLoc = targetApp.InstallLocation.Trim().TrimEnd('\\', '/');

        if (otherInstalledApps != null)
        {
            foreach (var other in otherInstalledApps)
            {
                if (other.Id.Equals(targetApp.Id, StringComparison.OrdinalIgnoreCase)) continue;
                string loc = other.InstallLocation.Trim().TrimEnd('\\', '/');
                if (!string.IsNullOrEmpty(loc) && !loc.Equals(targetLoc, StringComparison.OrdinalIgnoreCase))
                {
                    set.Add(loc);
                }
            }
            return set;
        }

        // If caller didn't pass the cached app list, quickly scan Uninstall registry InstallLocations
        var roots = new (RegistryHive Hive, RegistryView View, string SubPath)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        };

        foreach (var (hive, view, subPath) in roots)
        {
            if (!Environment.Is64BitOperatingSystem && view == RegistryView.Registry32) continue;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uKey = baseKey.OpenSubKey(subPath);
                if (uKey == null) continue;

                foreach (var subName in uKey.GetSubKeyNames())
                {
                    if (!string.IsNullOrEmpty(targetApp.UninstallKeyName) &&
                        subName.Equals(targetApp.UninstallKeyName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    using var appKey = uKey.OpenSubKey(subName);
                    string? rawLoc = appKey?.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrWhiteSpace(rawLoc))
                    {
                        string norm = rawLoc.Trim().Trim('"').TrimEnd('\\', '/');
                        if (!string.IsNullOrEmpty(norm) && !norm.Equals(targetLoc, StringComparison.OrdinalIgnoreCase))
                        {
                            set.Add(norm);
                        }
                    }
                }
            }
            catch { }
        }

        return set;
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
                Path = RegistryBackup.NormalizeHivePrefix(key),
                Confidence = ConfidenceLevel.High,
                Reason = "ETW 安装监控精确捕获注册表项",
                IsSelected = true
            });
        }

        foreach (var rawValToken in traceLog.ModifiedRegistryValues)
        {
            int sep = rawValToken.IndexOf("||", StringComparison.Ordinal);
            if (sep <= 0) continue;

            string keyPath = RegistryBackup.NormalizeHivePrefix(rawValToken.Substring(0, sep));
            string valName = rawValToken.Substring(sep + 2);

            AddResidualIfUnique(results, new ResidualItem
            {
                Type = ResidualType.RegistryValue,
                Category = ResidualCategory.RegistryValue,
                Path = keyPath,
                ValueName = valName,
                Confidence = ConfidenceLevel.High,
                Reason = "ETW 安装监控精确捕获写入键值",
                IsSelected = true
            });
        }
    }

    private static void ScanSafeItems(TargetProfile profile, List<ResidualItem> results)
    {
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

        if (!string.IsNullOrEmpty(profile.UninstallKeyName))
        {
            var uninstallHives = new (RegistryHive Hive, RegistryView View, string SubPath, string FullDisplayPath, bool Is64View)[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    true),
                (RegistryHive.LocalMachine, RegistryView.Registry32,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    false),
                (RegistryHive.CurrentUser, RegistryView.Default,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + profile.UninstallKeyName,
                    Environment.Is64BitOperatingSystem)
            };

            foreach (var (hive, view, subPath, fullDisplayPath, is64View) in uninstallHives)
            {
                if (!Environment.Is64BitOperatingSystem && !is64View) continue;

                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subPath);
                    if (key != null)
                    {
                        AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Category = ResidualCategory.RegistryKey,
                            Path = fullDisplayPath,
                            Is64BitRegistryView = is64View,
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

    private static void ScanCommonDirectories(
        TargetProfile profile,
        List<ResidualItem> results,
        HashSet<string> protectedSiblingDirs,
        bool deepFuzzy)
    {
        string progFiles64 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var targetSearchRoots = new List<(string RootPath, bool IsProgramFilesRoot)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), false),
            (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), false),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), false),
            (progFiles64, true),
            (progFiles86, true)
        };

        string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\LocalLow");
        if (Directory.Exists(localLow)) targetSearchRoots.Add((localLow, false));

        foreach (var (root, isProgFiles) in targetSearchRoots
                     .Where(r => !string.IsNullOrEmpty(r.RootPath))
                     .DistinctBy(r => r.RootPath, StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.GetDirectories(root))
                {
                    string normDir = dir.TrimEnd('\\', '/');
                    if (protectedSiblingDirs.Contains(normDir))
                        continue;

                    string dirName = Path.GetFileName(dir);
                    string categoryLabel = isProgFiles ? "程序安装残留目录" : "应用数据与缓存目录";

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
                                    if (protectedSiblingDirs.Contains(subDir.TrimEnd('\\', '/')))
                                        continue;

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
                                            IsSelected = conf == ConfidenceLevel.High || conf == ConfidenceLevel.Medium
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
                            Reason = $"{categoryLabel} ({matchReason})",
                            IsSelected = confidence == ConfidenceLevel.High || confidence == ConfidenceLevel.Medium
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanSoftwareHives(TargetProfile profile, List<ResidualItem> results, bool deepFuzzy)
    {
        var hives = new (RegistryHive Hive, RegistryView View, string SubPath, string HivePrefix, bool Is64View)[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software", "HKCU", Environment.Is64BitOperatingSystem),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE", "HKLM", true),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE", @"HKLM\SOFTWARE\WOW6432Node", false)
        };

        foreach (var (hive, view, subPath, hivePrefix, is64View) in hives)
        {
            if (!Environment.Is64BitOperatingSystem && !is64View) continue;

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
                                            Is64BitRegistryView = is64View,
                                            Confidence = conf,
                                            Reason = $"厂商分支下软件子键 ({keyName}\\{subAppKey} - {subReason})",
                                            IsSelected = conf == ConfidenceLevel.High || conf == ConfidenceLevel.Medium
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
                            Is64BitRegistryView = is64View,
                            Confidence = confidence,
                            Reason = $"注册表软件配置主键 ({reason})",
                            IsSelected = confidence == ConfidenceLevel.High || confidence == ConfidenceLevel.Medium
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

        if (EvaluateNameMatch(candidate, profile.DisplayName, deepFuzzy, out ConfidenceLevel nameConf, out string nameNote))
        {
            matchReason = string.IsNullOrEmpty(nameNote) ? "精确匹配软件名称" : nameNote;
            confidence = nameConf;
            return true;
        }

        foreach (var exe in profile.MainExeNames)
        {
            string exeNoExt = Path.GetFileNameWithoutExtension(exe);
            if (GetEffectiveLength(exeNoExt) >= 4 && EvaluateNameMatch(candidate, exeNoExt, deepFuzzy, out ConfidenceLevel exeConf, out string exeNote))
            {
                matchReason = string.IsNullOrEmpty(exeNote) ? $"匹配主程序名称 ({exe})" : $"{exeNote} ({exe})";
                confidence = exeConf;
                return true;
            }
        }

        if (!string.IsNullOrEmpty(profile.GuidString) && candidate.Contains(profile.GuidString, StringComparison.OrdinalIgnoreCase))
        {
            matchReason = "匹配产品 GUID";
            confidence = ConfidenceLevel.High;
            return true;
        }

        if (deepFuzzy && profile.CleanTokens.Count > 0)
        {
            string cleanCand = CleanName(candidate);
            foreach (var token in profile.CleanTokens)
            {
                if (GetEffectiveLength(token) >= 5 &&
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

    private static bool EvaluateNameMatch(
        string candidate,
        string target,
        bool allowSiblingInAdvanced,
        out ConfidenceLevel confidence,
        out string note)
    {
        confidence = ConfidenceLevel.High;
        note = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(target))
            return false;

        if (candidate.Equals(target, StringComparison.OrdinalIgnoreCase))
            return true;

        string cleanCandidate = CleanName(candidate);
        string cleanTarget = CleanName(target);

        if (GetEffectiveLength(cleanCandidate) < 4 || GetEffectiveLength(cleanTarget) < 4)
            return false;

        if (cleanCandidate.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase))
            return true;

        string compactCand = cleanCandidate.Replace(" ", "");
        string compactTarget = cleanTarget.Replace(" ", "");
        if (GetEffectiveLength(compactCand) >= 5 && compactCand.Equals(compactTarget, StringComparison.OrdinalIgnoreCase))
            return true;

        if (cleanCandidate.StartsWith(cleanTarget + " ", StringComparison.OrdinalIgnoreCase))
        {
            string suffix = cleanCandidate.Substring(cleanTarget.Length).Trim();
            string[] suffixWords = suffix.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (suffixWords.All(w => w.All(c => char.IsDigit(c) || c == '.' || c == 'v' || c == 'V')))
            {
                confidence = ConfidenceLevel.High;
                note = "匹配软件名称及版本号";
                return true;
            }

            if (suffixWords.Any(w => SiblingVariantTokens.Contains(w)))
            {
                if (!allowSiblingInAdvanced)
                    return false;

                confidence = ConfidenceLevel.Low;
                note = $"疑似同系列独立版本 ({suffix})，默认不勾选";
                return true;
            }

            if (GetEffectiveLength(cleanTarget) >= 6)
            {
                confidence = ConfidenceLevel.Medium;
                note = "包含完整软件名称前缀";
                return true;
            }
        }

        return false;
    }

    private static int GetEffectiveLength(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0;
        int len = 0;
        foreach (char c in text)
        {
            len += (c >= 0x4E00 && c <= 0x9FFF) ? 2 : 1;
        }
        return len;
    }

    private static bool IsPublisherNameMatch(string candidate, string publisher)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(publisher)) return false;
        string cleanCand = CleanName(candidate);
        string cleanPub = CleanName(publisher);
        if (GetEffectiveLength(cleanCand) < 3 || GetEffectiveLength(cleanPub) < 3) return false;

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
        string normItemPath = item.Type is ResidualType.RegistryKey or ResidualType.RegistryValue
            ? RegistryBackup.NormalizeHivePrefix(item.Path)
            : item.Path.Trim().TrimEnd('\\', '/');

        bool exists = results.Any(r =>
        {
            string normExisting = r.Type is ResidualType.RegistryKey or ResidualType.RegistryValue
                ? RegistryBackup.NormalizeHivePrefix(r.Path)
                : r.Path.Trim().TrimEnd('\\', '/');

            return normExisting.Equals(normItemPath, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(r.ValueName ?? string.Empty, item.ValueName ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        });

        if (!exists)
        {
            results.Add(item);
        }
    }

    /// <summary>
    /// Fast directory size calculation using DirectoryInfo.EnumerateFiles directly so FileInfo.Length
    /// is read straight from the WIN32_FIND_DATA enumeration buffer with zero extra GetFileAttributesEx syscalls.
    /// </summary>
    public static long CalculatePathSize(string path, bool isDirectory)
    {
        try
        {
            if (!isDirectory)
            {
                return File.Exists(path) ? new FileInfo(path).Length : 0;
            }

            var dirInfo = new DirectoryInfo(path);
            if (!dirInfo.Exists) return 0;

            long total = 0;
            int fileCount = 0;
            foreach (var fi in dirInfo.EnumerateFiles("*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                MaxRecursionDepth = 6
            }))
            {
                try
                {
                    total += fi.Length;
                    if (++fileCount > 2500) break;
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
