using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Safety;

namespace RevoSharp.Engine.Scanning;

public class ReverseReferenceScanner
{
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

        // 1. Scan COM Classes (CLSID & TypeLib) and collect matched CLSIDs for downstream ShellExtension lookup
        ScanClsidHives(profile, matchedClsids, results);

        // 2. Scan Windows Services
        ScanServices(profile, results);

        // 3. Scan App Paths across both 64-bit and 32-bit views
        ScanAppPaths(profile, results);

        // 4. Scan Firewall Rules
        ScanFirewallRules(profile, results);

        // 5. Scan MuiCache
        ScanMuiCache(profile, results);

        // 6. Scan Windows Scheduled Tasks (with TaskSchedulerName for clean schtasks unregistration)
        ScanScheduledTasks(profile, results);

        // 7. Scan MSI Installer Metadata & Folders
        ScanMsiMetadata(profile, results);

        // 8. Scan Explorer Shell Extensions & ContextMenuHandlers using collected CLSIDs
        ScanShellExtensions(profile, matchedClsids, results);
    }

    private static void ScanClsidHives(TargetProfile profile, HashSet<string> matchedClsids, List<ResidualItem> results)
    {
        var clsidRoots = new (RegistryHive Hive, RegistryView View, string SubPath, string DisplayRoot, bool Is64View)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Classes\CLSID", "HKLM", true),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Classes\CLSID", "HKCU", Environment.Is64BitOperatingSystem),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Classes\CLSID", @"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID", false)
        };

        foreach (var (hive, view, subPath, displayRoot, is64View) in clsidRoots)
        {
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
                            if (IsPathMatching(serverPath, profile))
                            {
                                matchedClsids.Add(clsid);

                                string fullKey = displayRoot.StartsWith("HKLM\\SOFTWARE\\WOW6432Node")
                                    ? $@"{displayRoot}\{clsid}"
                                    : $@"{displayRoot}\{subPath}\{clsid}";

                                ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                                {
                                    Type = ResidualType.RegistryKey,
                                    Category = ResidualCategory.RegistryKey,
                                    Path = fullKey,
                                    Is64BitRegistryView = is64View,
                                    Confidence = ConfidenceLevel.High,
                                    Reason = $"反向引用：关联 COM / CLSID 组件死链 ({sub})",
                                    IsSelected = true
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static void ScanServices(TargetProfile profile, List<ResidualItem> results)
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
                    if (IsPathMatching(imagePath, profile))
                    {
                        string fullKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}";
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Category = ResidualCategory.Service,
                            ValueName = serviceName,
                            ValuePreview = imagePath,
                            Path = fullKey,
                            Is64BitRegistryView = true,
                            Confidence = ConfidenceLevel.High,
                            Reason = $"反向引用：遗留 Windows 服务项 ({serviceName})",
                            IsSelected = true
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
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

                        if (profile.MainExeNames.Contains(exeName) ||
                            IsPathMatching(defaultVal, profile) ||
                            IsPathMatching(pathVal, profile))
                        {
                            string fullKey = hivePrefix.StartsWith("HKLM\\SOFTWARE\\WOW6432Node")
                                ? $@"{hivePrefix}\{exeName}"
                                : $@"{hivePrefix}\{subPath}\{exeName}";

                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryKey,
                                Category = ResidualCategory.RegistryKey,
                                Path = fullKey,
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
                if (relPath.StartsWith("Microsoft\\", StringComparison.OrdinalIgnoreCase)) continue;

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

    private static void ScanMsiMetadata(TargetProfile profile, List<ResidualItem> results)
    {
        if (!profile.HasValidLocation) return;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var foldersKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders");
            if (foldersKey == null) return;

            foreach (var valName in foldersKey.GetValueNames())
            {
                if (IsPathMatching(valName, profile))
                {
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.RegistryValue,
                        Category = ResidualCategory.MsiMetadata,
                        Path = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
                        ValueName = valName,
                        Is64BitRegistryView = true,
                        Confidence = ConfidenceLevel.High,
                        Reason = "反向引用：Windows Installer 目录登记项",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static void ScanShellExtensions(TargetProfile profile, HashSet<string> matchedClsids, List<ResidualItem> results)
    {
        if (matchedClsids.Count == 0 && string.IsNullOrWhiteSpace(profile.DisplayName)) return;

        // 1. Approved Shell Extensions across HKLM (64/32) and HKCU
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

        // 2. ContextMenuHandlers under HKCR (*, Directory, Directory\Background, Folder)
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
        string lower = text.ToLowerInvariant();

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
        }

        foreach (var exe in profile.MainExeNames)
        {
            string exeLower = exe.ToLowerInvariant();
            if (lower.Contains("\\" + exeLower) || lower.Equals(exeLower))
            {
                if (lower.Contains(@"\windows\") || lower.Contains(@"\system32\") || lower.Contains(@"\syswow64\"))
                    continue;
                return true;
            }
        }

        return false;
    }
}
