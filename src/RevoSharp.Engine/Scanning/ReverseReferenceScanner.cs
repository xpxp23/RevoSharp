using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Scanning;

public class ReverseReferenceScanner
{
    public void ScanReferences(TargetProfile profile, List<ResidualItem> results)
    {
        if (!profile.HasValidLocation && profile.MainExeNames.Count == 0 && string.IsNullOrEmpty(profile.GuidString))
        {
            return;
        }

        // 1. Scan COM Classes (CLSID)
        ScanClsidHives(profile, results);

        // 2. Scan Windows Services
        ScanServices(profile, results);

        // 3. Scan App Paths
        ScanAppPaths(profile, results);

        // 4. Scan Firewall Rules
        ScanFirewallRules(profile, results);

        // 5. Scan MuiCache
        ScanMuiCache(profile, results);
    }

    private static void ScanClsidHives(TargetProfile profile, List<ResidualItem> results)
    {
        var clsidRoots = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Classes\CLSID", "HKLM"),
            (RegistryHive.CurrentUser, @"Software\Classes\CLSID", "HKCU"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Classes\TypeLib", "HKLM"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Classes\CLSID", "HKLM")
        };

        foreach (var (hive, subPath, hiveName) in clsidRoots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var clsidKey = baseKey.OpenSubKey(subPath);
                if (clsidKey == null) continue;

                foreach (var clsid in clsidKey.GetSubKeyNames())
                {
                    try
                    {
                        using var singleKey = clsidKey.OpenSubKey(clsid);
                        if (singleKey == null) continue;

                        // Check common server keys: InprocServer32, LocalServer32, DefaultIcon
                        foreach (var sub in new[] { "InprocServer32", "LocalServer32", "DefaultIcon" })
                        {
                            using var serverKey = singleKey.OpenSubKey(sub);
                            if (serverKey == null) continue;

                            string? serverPath = serverKey.GetValue(string.Empty) as string;
                            if (IsPathMatching(serverPath, profile))
                            {
                                string fullKey = $@"{hiveName}\{subPath}\{clsid}";
                                AddRegistryResidual(results, fullKey, "反向引用：关联 COM / CLSID 组件死链", ConfidenceLevel.High);
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
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
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
                        AddRegistryResidual(results, fullKey, $"反向引用：已失效 Windows 服务项 ({serviceName})", ConfidenceLevel.High);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanAppPaths(TargetProfile profile, List<ResidualItem> results)
    {
        var appPathRoots = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "HKLM"),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\App Paths", "HKCU")
        };

        foreach (var (hive, subPath, hiveName) in appPathRoots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var apKey = baseKey.OpenSubKey(subPath);
                if (apKey == null) continue;

                foreach (var exeName in apKey.GetSubKeyNames())
                {
                    if (profile.MainExeNames.Contains(exeName))
                    {
                        string fullKey = $@"{hiveName}\{subPath}\{exeName}";
                        AddRegistryResidual(results, fullKey, $"反向引用：App Paths 运行命令 ({exeName})", ConfidenceLevel.High);
                        continue;
                    }

                    try
                    {
                        using var singleAp = apKey.OpenSubKey(exeName);
                        if (singleAp == null) continue;

                        string? defaultVal = singleAp.GetValue(string.Empty) as string;
                        string? pathVal = singleAp.GetValue("Path") as string;

                        if (IsPathMatching(defaultVal, profile) || IsPathMatching(pathVal, profile))
                        {
                            string fullKey = $@"{hiveName}\{subPath}\{exeName}";
                            AddRegistryResidual(results, fullKey, $"反向引用：App Paths 运行命令 ({exeName})", ConfidenceLevel.High);
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
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var fwKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (fwKey == null) return;

            foreach (var valName in fwKey.GetValueNames())
            {
                string? data = fwKey.GetValue(valName) as string;
                if (IsPathMatching(data, profile))
                {
                    results.Add(new ResidualItem
                    {
                        Type = ResidualType.RegistryValue,
                        Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                        ValueName = valName,
                        Confidence = ConfidenceLevel.High,
                        Reason = "反向引用：Windows 防火墙残留进出站规则",
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
                    results.Add(new ResidualItem
                    {
                        Type = ResidualType.RegistryValue,
                        Path = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                        ValueName = valName,
                        Confidence = ConfidenceLevel.High,
                        Reason = "反向引用：Explorer 界面显示缓存 (MuiCache)",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static bool IsPathMatching(string? text, TargetProfile profile)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string lower = text.ToLowerInvariant();

        if (profile.HasValidLocation)
        {
            if (lower.Contains(profile.NormalizedLocation)) return true;
            if (!string.IsNullOrEmpty(profile.ShortLocation) && lower.Contains(profile.ShortLocation)) return true;
        }

        foreach (var exe in profile.MainExeNames)
        {
            if (lower.Contains(exe.ToLowerInvariant()))
            {
                // Verify it is not a system binary with the same name
                if (lower.Contains(@"\windows\") || lower.Contains(@"\system32\")) continue;
                return true;
            }
        }

        return false;
    }

    private static void AddRegistryResidual(List<ResidualItem> results, string fullPath, string reason, ConfidenceLevel confidence)
    {
        if (results.Any(r => r.Path.Equals(fullPath, StringComparison.OrdinalIgnoreCase))) return;
        results.Add(new ResidualItem
        {
            Type = ResidualType.RegistryKey,
            Path = fullPath,
            Confidence = confidence,
            Reason = reason,
            IsSelected = true
        });
    }
}
