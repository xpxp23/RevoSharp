using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Safety;

namespace RevoSharp.Engine.Scanning;

public class ReverseReferenceScanner
{
    private readonly record struct ClsidSnapshotEntry(
        string Clsid,
        string FullKeyPath,
        string ServerSubKey,
        string ServerPath,
        bool Is64View);

    private static List<ClsidSnapshotEntry>? _cachedClsidSnapshot;
    private static DateTime _clsidSnapshotTimeUtc = DateTime.MinValue;
    private static readonly object ClsidCacheLock = new();

    private static readonly Regex OemInfRegex = new(@"oem\d+\.inf", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public void ScanReferences(TargetProfile profile, List<ResidualItem> results)
    {
        if (!profile.HasValidLocation && profile.MainExeNames.Count == 0 && string.IsNullOrEmpty(profile.GuidString))
        {
            return;
        }

        var matchedClsids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(profile.GuidString))
        {
            matchedClsids.Add(profile.GuidString);
        }

        // 1. Scan COM Classes (CLSID & TypeLib) using short-lived snapshot cache so batch queues run instantaneously
        ScanClsidHives(profile, matchedClsids, results);

        // 2. Scan Windows Services & Kernel/FileSystem Driver Packages (.sys / DriverStore / oem*.inf)
        ScanServicesAndDrivers(profile, results);

        // 3. Scan App Paths across both 64-bit and 32-bit views
        ScanAppPaths(profile, results);

        // 4. Scan Firewall Rules
        ScanFirewallRules(profile, results);

        // 5. Scan MuiCache
        ScanMuiCache(profile, results);

        // 6. Scan Windows Scheduled Tasks (with TaskSchedulerName for clean schtasks unregistration)
        ScanScheduledTasks(profile, results);

        // 7. Scan MSI Installer Database (msi.dll APIs, packed GUID components, and Installer\Folders)
        MsiDatabaseScanner.ScanMsiComponentsAndMetadata(profile, results);

        // 8. Scan Explorer Shell Extensions & ContextMenuHandlers using collected CLSIDs
        ScanShellExtensions(profile, matchedClsids, results);

        // 9. Scan System & User PATH Environment Variables for orphaned directory dead-links
        ScanEnvironmentPaths(profile, results);

        // 10. Scan Browser Extensions, NativeMessagingHosts, and Enterprise Policies (Chrome / Edge / Brave / Firefox)
        ScanBrowserExtensionsAndPolicies(profile, matchedClsids, results);
    }

    private static void ScanClsidHives(TargetProfile profile, HashSet<string> matchedClsids, List<ResidualItem> results)
    {
        var snapshot = GetOrBuildClsidSnapshot();

        foreach (var entry in snapshot)
        {
            if (IsPathMatching(entry.ServerPath, profile))
            {
                matchedClsids.Add(entry.Clsid);

                ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                {
                    Type = ResidualType.RegistryKey,
                    Category = ResidualCategory.RegistryKey,
                    Path = entry.FullKeyPath,
                    ValuePreview = entry.ServerPath,
                    Is64BitRegistryView = entry.Is64View,
                    Confidence = ConfidenceLevel.High,
                    Reason = $"反向引用：关联 COM / CLSID 组件死链 ({entry.ServerSubKey})",
                    IsSelected = true
                });
            }
        }
    }

    private static List<ClsidSnapshotEntry> GetOrBuildClsidSnapshot()
    {
        lock (ClsidCacheLock)
        {
            if (_cachedClsidSnapshot != null && (DateTime.UtcNow - _clsidSnapshotTimeUtc).TotalSeconds < 45)
            {
                return _cachedClsidSnapshot;
            }

            var list = new List<ClsidSnapshotEntry>(4096);
            var clsidRoots = new (RegistryHive Hive, RegistryView View, string SubPath, string DisplayRoot, bool Is64View)[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Classes\CLSID", "HKLM", true),
                (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Classes\CLSID", "HKCU", Environment.Is64BitOperatingSystem),
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Classes\CLSID", @"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID", false)
            };

            foreach (var (hive, view, subPath, displayRoot, is64View) in clsidRoots)
            {
                if (!Environment.Is64BitOperatingSystem && !is64View) continue;

                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var clsidKey = baseKey.OpenSubKey(subPath);
                    if (clsidKey == null) continue;

                    foreach (var clsid in clsidKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var singleKey = clsidKey.OpenSubKey(clsid);
                            if (singleKey == null) continue;

                            foreach (var sub in new[] { "InprocServer32", "LocalServer32", "DefaultIcon" })
                            {
                                using var serverKey = singleKey.OpenSubKey(sub);
                                if (serverKey == null) continue;

                                string? serverPath = serverKey.GetValue(string.Empty) as string;
                                if (!string.IsNullOrWhiteSpace(serverPath))
                                {
                                    string fullKey = displayRoot.StartsWith(@"HKLM\SOFTWARE\WOW6432Node", StringComparison.OrdinalIgnoreCase)
                                        ? $@"{displayRoot}\{clsid}"
                                        : $@"{displayRoot}\{subPath}\{clsid}";

                                    list.Add(new ClsidSnapshotEntry(clsid, fullKey, sub, serverPath, is64View));
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            _cachedClsidSnapshot = list;
            _clsidSnapshotTimeUtc = DateTime.UtcNow;
            return list;
        }
    }

    private static void ScanServicesAndDrivers(TargetProfile profile, List<ResidualItem> results)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var servicesKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            foreach (var serviceName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var sKey = servicesKey.OpenSubKey(serviceName);
                    if (sKey == null) continue;

                    string? imagePath = sKey.GetValue("ImagePath") as string;
                    if (!IsPathMatching(imagePath, profile))
                        continue;

                    int svcType = sKey.GetValue("Type") is int t ? t : 0x10;
                    bool isKernelOrFsDriver = svcType is 1 or 2 ||
                                              (imagePath != null && imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase));

                    string? oemInf = null;
                    string? owners = sKey.GetValue("Owners") is string[] arr ? string.Join(";", arr) : sKey.GetValue("Owners") as string;
                    if (!string.IsNullOrWhiteSpace(owners))
                    {
                        var m = OemInfRegex.Match(owners);
                        if (m.Success) oemInf = m.Value;
                    }

                    string fullKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}";
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.RegistryKey,
                        Category = isKernelOrFsDriver ? ResidualCategory.DriverPackage : ResidualCategory.Service,
                        ValueName = serviceName,
                        ValuePreview = imagePath,
                        DriverPublishedInfName = oemInf,
                        Path = fullKey,
                        Is64BitRegistryView = true,
                        Confidence = ConfidenceLevel.High,
                        Reason = isKernelOrFsDriver
                            ? $"反向引用：遗留内核驱动服务 ({serviceName}{(oemInf != null ? $", {oemInf}" : "")})"
                            : $"反向引用：遗留 Windows 服务项 ({serviceName})",
                        IsSelected = true
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanEnvironmentPaths(TargetProfile profile, List<ResidualItem> results)
    {
        if (!profile.HasValidLocation) return;

        var envTargets = new (RegistryHive Hive, string SubKey, string HivePrefix, bool IsSystem, string ScopeLabel)[]
        {
            (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "HKLM", true, "系统环境变量 PATH"),
            (RegistryHive.CurrentUser, @"Environment", "HKCU", false, "用户环境变量 PATH")
        };

        foreach (var (hive, subKey, hivePrefix, isSystem, scopeLabel) in envTargets)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var envKey = baseKey.OpenSubKey(subKey, false);
                if (envKey == null) continue;

                string? rawPath = envKey.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if (string.IsNullOrWhiteSpace(rawPath)) continue;

                var segments = rawPath.Split(';', StringSplitOptions.RemoveEmptyEntries);
                foreach (var seg in segments)
                {
                    string cleanSeg = seg.Trim().Trim('"');
                    if (string.IsNullOrWhiteSpace(cleanSeg)) continue;

                    if (IsPathMatching(cleanSeg, profile))
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryValue,
                            Category = ResidualCategory.EnvironmentPath,
                            Path = $@"{hivePrefix}\{subKey}",
                            ValueName = $"Path [{cleanSeg}]",
                            ValuePreview = cleanSeg,
                            EnvironmentVariableName = "Path",
                            IsSystemEnvironmentVariable = isSystem,
                            PathSegmentToRemove = cleanSeg,
                            Is64BitRegistryView = true,
                            Confidence = ConfidenceLevel.High,
                            Reason = $"反向引用：{scopeLabel} 残留路径死链",
                            IsSelected = true
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanBrowserExtensionsAndPolicies(
        TargetProfile profile,
        HashSet<string> matchedClsids,
        List<ResidualItem> results)
    {
        // 1. NativeMessagingHosts across Chrome, Edge, Brave, and Mozilla
        var browserHostPaths = new[]
        {
            @"SOFTWARE\Google\Chrome\NativeMessagingHosts",
            @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts",
            @"SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts",
            @"SOFTWARE\Mozilla\NativeMessagingHosts"
        };

        var rootViews = new (RegistryHive Hive, RegistryView View, string Prefix, bool Is64View)[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", Environment.Is64BitOperatingSystem),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", true),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"HKLM\SOFTWARE\WOW6432Node", false)
        };

        foreach (var (hive, view, prefix, is64View) in rootViews)
        {
            if (!Environment.Is64BitOperatingSystem && !is64View) continue;

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (var relHostPath in browserHostPaths)
                {
                    using var hostRoot = baseKey.OpenSubKey(relHostPath);
                    if (hostRoot == null) continue;

                    foreach (var hostName in hostRoot.GetSubKeyNames())
                    {
                        using var singleHost = hostRoot.OpenSubKey(hostName);
                        string? manifestPath = singleHost?.GetValue(string.Empty) as string;
                        if (IsPathMatching(manifestPath, profile))
                        {
                            string fullKey = prefix.StartsWith(@"HKLM\SOFTWARE\WOW6432Node", StringComparison.OrdinalIgnoreCase)
                                ? $@"{prefix}\{relHostPath.Substring(9)}\{hostName}"
                                : $@"{prefix}\{relHostPath}\{hostName}";

                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryKey,
                                Category = ResidualCategory.BrowserExtension,
                                Path = fullKey,
                                ValuePreview = manifestPath,
                                Is64BitRegistryView = is64View,
                                Confidence = ConfidenceLevel.High,
                                Reason = $"反向引用：浏览器 NativeMessaging 宿主扩展 ({hostName})",
                                IsSelected = true
                            });
                        }
                    }
                }
            }
            catch { }
        }

        // 2. Enterprise Policy ExtensionInstallForcelist & Software\Policies vendor keys
        var policyBrowsers = new[]
        {
            @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
            @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
            @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist"
        };

        foreach (var (hive, view, prefix, is64View) in rootViews.Where(r => r.Is64View))
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (var polPath in policyBrowsers)
                {
                    using var polKey = baseKey.OpenSubKey(polPath);
                    if (polKey == null) continue;

                    foreach (var valName in polKey.GetValueNames())
                    {
                        string? valData = polKey.GetValue(valName) as string;
                        if (IsPathMatching(valData, profile))
                        {
                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryValue,
                                Category = ResidualCategory.BrowserExtension,
                                Path = $@"{prefix}\{polPath}",
                                ValueName = valName,
                                ValuePreview = valData,
                                Is64BitRegistryView = is64View,
                                Confidence = ConfidenceLevel.High,
                                Reason = "反向引用：浏览器强制策略扩展登记项",
                                IsSelected = true
                            });
                        }
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanAppPaths(TargetProfile profile, List<ResidualItem> results)
    {
        var appPathRoots = new (RegistryHive Hive, RegistryView View, string SubPath, string HivePrefix, bool Is64View)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "HKLM", true),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths", false),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\App Paths", "HKCU", Environment.Is64BitOperatingSystem)
        };

        foreach (var (hive, view, subPath, hivePrefix, is64View) in appPathRoots)
        {
            if (!Environment.Is64BitOperatingSystem && !is64View) continue;

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var apKey = baseKey.OpenSubKey(subPath);
                if (apKey == null) continue;

                foreach (var exeName in apKey.GetSubKeyNames())
                {
                    try
                    {
                        using var singleAp = apKey.OpenSubKey(exeName);
                        if (singleAp == null) continue;

                        string? defaultVal = singleAp.GetValue(string.Empty) as string;
                        string? pathVal = singleAp.GetValue("Path") as string;

                        bool pathMatched = IsPathMatching(defaultVal, profile) || IsPathMatching(pathVal, profile);
                        bool exeMatched = !profile.HasValidLocation && profile.MainExeNames.Contains(exeName) &&
                                          (string.IsNullOrEmpty(defaultVal) || !File.Exists(Environment.ExpandEnvironmentVariables(defaultVal.Trim('"'))));

                        if (pathMatched || exeMatched)
                        {
                            string fullKey = hivePrefix.StartsWith(@"HKLM\SOFTWARE\WOW6432Node", StringComparison.OrdinalIgnoreCase)
                                ? $@"{hivePrefix}\{exeName}"
                                : $@"{hivePrefix}\{subPath}\{exeName}";

                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryKey,
                                Category = ResidualCategory.RegistryKey,
                                Path = fullKey,
                                ValuePreview = defaultVal,
                                Is64BitRegistryView = is64View,
                                Confidence = ConfidenceLevel.High,
                                Reason = $"反向引用：App Paths 快捷命令 ({exeName})",
                                IsSelected = true
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static void ScanFirewallRules(TargetProfile profile, List<ResidualItem> results)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var fwKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (fwKey == null) return;

            foreach (var valName in fwKey.GetValueNames())
            {
                string? data = fwKey.GetValue(valName) as string;
                if (IsPathMatching(data, profile))
                {
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.RegistryValue,
                        Category = ResidualCategory.FirewallRule,
                        Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                        ValueName = valName,
                        ValuePreview = RegistryBackup.TryGetRegistryValuePreview(fwKey, valName),
                        Is64BitRegistryView = true,
                        Confidence = ConfidenceLevel.High,
                        Reason = "反向引用：Windows 防火墙进出站规则",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static void ScanMuiCache(TargetProfile profile, List<ResidualItem> results)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var muiKey = baseKey.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (muiKey == null) return;

            foreach (var valName in muiKey.GetValueNames())
            {
                if (IsPathMatching(valName, profile))
                {
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.RegistryValue,
                        Category = ResidualCategory.RegistryValue,
                        Path = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                        ValueName = valName,
                        ValuePreview = RegistryBackup.TryGetRegistryValuePreview(muiKey, valName),
                        Confidence = ConfidenceLevel.High,
                        Reason = "反向引用：Explorer 界面显示缓存 (MuiCache)",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static void ScanScheduledTasks(TargetProfile profile, List<ResidualItem> results)
    {
        try
        {
            string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            if (!Directory.Exists(tasksDir)) return;

            foreach (var taskFile in Directory.EnumerateFiles(tasksDir, "*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                MaxRecursionDepth = 3
            }))
            {
                string relPath = taskFile.Substring(tasksDir.Length).TrimStart('\\');
                if (relPath.StartsWith("Microsoft\\", StringComparison.OrdinalIgnoreCase) ||
                    relPath.StartsWith("Windows\\", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    string content = File.ReadAllText(taskFile);
                    if (IsPathMatching(content, profile))
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.File,
                            Category = ResidualCategory.ScheduledTask,
                            Path = taskFile,
                            TaskSchedulerName = "\\" + relPath,
                            SizeInBytes = ResidualScanner.CalculatePathSize(taskFile, false),
                            Confidence = ConfidenceLevel.High,
                            Reason = $"反向引用：Windows 计划任务 ({relPath})",
                            IsSelected = true
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanShellExtensions(TargetProfile profile, HashSet<string> matchedClsids, List<ResidualItem> results)
    {
        if (matchedClsids.Count == 0 && string.IsNullOrWhiteSpace(profile.DisplayName)) return;

        var approvedRoots = new (RegistryHive Hive, RegistryView View, string SubPath, string FullDisplayPath, bool Is64View)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                true),
            (RegistryHive.LocalMachine, RegistryView.Registry32,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                false),
            (RegistryHive.CurrentUser, RegistryView.Default,
                @"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                Environment.Is64BitOperatingSystem)
        };

        foreach (var (hive, view, subPath, fullDisplayPath, is64View) in approvedRoots)
        {
            if (!Environment.Is64BitOperatingSystem && !is64View) continue;

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var approvedKey = baseKey.OpenSubKey(subPath);
                if (approvedKey == null) continue;

                foreach (var valName in approvedKey.GetValueNames())
                {
                    string? desc = approvedKey.GetValue(valName) as string;
                    bool isClsidMatch = matchedClsids.Contains(valName);
                    bool isDescMatch = !string.IsNullOrWhiteSpace(desc) &&
                                       profile.DisplayName.Length >= 4 &&
                                       desc.Contains(profile.DisplayName, StringComparison.OrdinalIgnoreCase);

                    if (isClsidMatch || isDescMatch)
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryValue,
                            Category = ResidualCategory.ShellExtension,
                            Path = fullDisplayPath,
                            ValueName = valName,
                            ValuePreview = desc,
                            Is64BitRegistryView = is64View,
                            Confidence = ConfidenceLevel.High,
                            Reason = $"反向引用：资源管理器外壳扩展 ({desc ?? valName})",
                            IsSelected = true
                        });
                    }
                }
            }
            catch { }
        }

        if (matchedClsids.Count > 0)
        {
            var handlerPaths = new[]
            {
                @"*\shellex\ContextMenuHandlers",
                @"Directory\shellex\ContextMenuHandlers",
                @"Directory\Background\shellex\ContextMenuHandlers",
                @"Folder\shellex\ContextMenuHandlers"
            };

            foreach (var relHandlerPath in handlerPaths)
            {
                try
                {
                    using var classesRoot = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry64);
                    using var cmKey = classesRoot.OpenSubKey(relHandlerPath);
                    if (cmKey == null) continue;

                    foreach (var subName in cmKey.GetSubKeyNames())
                    {
                        using var handlerSub = cmKey.OpenSubKey(subName);
                        string? defaultGuid = handlerSub?.GetValue(string.Empty) as string;
                        if (matchedClsids.Contains(subName) || (!string.IsNullOrEmpty(defaultGuid) && matchedClsids.Contains(defaultGuid)))
                        {
                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryKey,
                                Category = ResidualCategory.ShellExtension,
                                Path = $@"HKCR\{relHandlerPath}\{subName}",
                                Is64BitRegistryView = true,
                                Confidence = ConfidenceLevel.High,
                                Reason = $"反向引用：右键菜单上下文扩展 ({subName})",
                                IsSelected = true
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }

    private static bool IsPathMatching(string? text, TargetProfile profile)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string lower = Environment.ExpandEnvironmentVariables(text).ToLowerInvariant().Trim('"', ' ');

        // 1. Primary path prefix check when the target app has a known installation directory
        if (profile.HasValidLocation)
        {
            string locWithSlash = profile.NormalizedLocation.TrimEnd('\\') + "\\";
            if (lower.Contains(locWithSlash) || lower.EndsWith(profile.NormalizedLocation))
                return true;

            if (!string.IsNullOrEmpty(profile.ShortLocation))
            {
                string shortWithSlash = profile.ShortLocation.TrimEnd('\\') + "\\";
                if (lower.Contains(shortWithSlash) || lower.EndsWith(profile.ShortLocation))
                    return true;
            }

            // Critical safety guard: When the app HAS a known InstallLocation, do NOT match full paths
            // pointing to a completely different existing directory on disk just because the .exe filename is similar!
            return false;
        }

        if (!string.IsNullOrEmpty(profile.SingleExecutableFile) &&
            lower.Contains(profile.SingleExecutableFile.ToLowerInvariant()))
        {
            return true;
        }

        // 2. Fallback for apps without a recorded InstallLocation: match distinctive MainExeNames
        // only if the referenced executable path does NOT still exist inside another intact application folder.
        foreach (var exe in profile.MainExeNames)
        {
            string exeLower = exe.ToLowerInvariant();
            if (exeLower.Length < 8) continue;

            if (lower.Contains("\\" + exeLower) || lower.Equals(exeLower))
            {
                if (lower.Contains(@"\windows\") || lower.Contains(@"\system32\") || lower.Contains(@"\syswow64\"))
                    continue;

                string extractedExe = AppLocator.ExtractExeFromCommand(text);
                if (!string.IsNullOrEmpty(extractedExe) && File.Exists(extractedExe))
                {
                    continue;
                }
                return true;
            }
        }

        return false;
    }
}
