using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Scanning;

/// <summary>
/// Queries the Windows Installer (msi.dll) component database and HKLM\...\Installer\UserData packed GUID trees
/// to locate scattered MSI components, product registration metadata, and orphaned shared files.
/// </summary>
public static class MsiDatabaseScanner
{
    private const int ERROR_SUCCESS = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int INSTALLSTATE_LOCAL = 3;
    private const int INSTALLSTATE_SOURCE = 4;

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiEnumComponents(uint iComponentIndex, StringBuilder lpComponentBuf);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiGetComponentPath(
        string szProduct,
        string szComponent,
        StringBuilder lpPathBuf,
        ref uint pcchBuf);

    public static void ScanMsiComponentsAndMetadata(TargetProfile profile, List<ResidualItem> results)
    {
        // 1. Scan Installer\Folders registry values matching the installation directory
        if (profile.HasValidLocation)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var foldersKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders");
                if (foldersKey != null)
                {
                    string prefix = profile.NormalizedLocation.TrimEnd('\\') + "\\";
                    foreach (var valName in foldersKey.GetValueNames())
                    {
                        string lowerVal = valName.ToLowerInvariant();
                        if (lowerVal.StartsWith(prefix) || lowerVal.TrimEnd('\\').Equals(profile.NormalizedLocation))
                        {
                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.RegistryValue,
                                Category = ResidualCategory.MsiMetadata,
                                Path = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
                                ValueName = valName,
                                Is64BitRegistryView = true,
                                Confidence = ConfidenceLevel.High,
                                Reason = "MSI 数据库：Windows Installer 目录登记项",
                                IsSelected = true
                            });
                        }
                    }
                }
            }
            catch { }
        }

        // 2. If the target has a valid MSI ProductCode GUID, query packed GUID metadata & msi.dll component paths
        if (!string.IsNullOrEmpty(profile.GuidString))
        {
            int foundViaUserData = 0;
            string? packedGuid = TryConvertToPackedGuid(profile.GuidString);
            if (!string.IsNullOrEmpty(packedGuid))
            {
                ScanPackedGuidMetadata(packedGuid, profile.GuidString, results);
                foundViaUserData = ScanUserDataComponentsForProduct(packedGuid, profile, results);
            }

            // Only fall back to global MsiEnumComponents enumeration if UserData registry tree yielded no component mappings
            if (foundViaUserData == 0)
            {
                ScanNativeMsiApiForProduct(profile.GuidString, results);
            }
        }
    }

    private static void ScanPackedGuidMetadata(string packedGuid, string rawGuid, List<ResidualItem> results)
    {
        var candidateKeys = new[]
        {
            $@"SOFTWARE\Classes\Installer\Products\{packedGuid}",
            $@"SOFTWARE\Classes\Installer\Features\{packedGuid}",
            $@"SOFTWARE\Classes\Installer\UpgradeCodes\{packedGuid}",
            $@"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{packedGuid}"
        };

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            foreach (var subPath in candidateKeys)
            {
                using var testKey = baseKey.OpenSubKey(subPath);
                if (testKey != null)
                {
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.RegistryKey,
                        Category = ResidualCategory.MsiMetadata,
                        Path = $@"HKLM\{subPath}",
                        Is64BitRegistryView = true,
                        Confidence = ConfidenceLevel.High,
                        Reason = $"MSI 数据库：产品压缩 GUID 元数据 ({rawGuid})",
                        IsSelected = true
                    });
                }
            }
        }
        catch { }
    }

    private static int ScanUserDataComponentsForProduct(string packedProductGuid, TargetProfile profile, List<ResidualItem> results)
    {
        int matchedCount = 0;
        const string componentsRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var compRootKey = baseKey.OpenSubKey(componentsRoot);
            if (compRootKey == null) return 0;

            foreach (var compName in compRootKey.GetSubKeyNames())
            {
                try
                {
                    using var compKey = compRootKey.OpenSubKey(compName);
                    if (compKey == null) continue;

                    string? compTarget = compKey.GetValue(packedProductGuid) as string;
                    if (compTarget == null) continue;

                    matchedCount++;
                    string[] valueNames = compKey.GetValueNames();
                    if (valueNames.Length == 1)
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryKey,
                            Category = ResidualCategory.MsiMetadata,
                            Path = $@"HKLM\{componentsRoot}\{compName}",
                            ValuePreview = compTarget,
                            Is64BitRegistryView = true,
                            Confidence = ConfidenceLevel.High,
                            Reason = "MSI 数据库：独占组件注册表节点",
                            IsSelected = true
                        });
                    }
                    else
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.RegistryValue,
                            Category = ResidualCategory.MsiMetadata,
                            Path = $@"HKLM\{componentsRoot}\{compName}",
                            ValueName = packedProductGuid,
                            ValuePreview = compTarget,
                            Is64BitRegistryView = true,
                            Confidence = ConfidenceLevel.High,
                            Reason = "MSI 数据库：共享组件产品引用键值",
                            IsSelected = true
                        });
                    }

                    if (compTarget.Length > 3 && compTarget[1] == ':' && compTarget[2] == '\\' &&
                        !AppLocator.IsProtectedSharedDirectory(Path.GetDirectoryName(compTarget)) &&
                        File.Exists(compTarget))
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.File,
                            Category = ResidualCategory.MsiMetadata,
                            Path = compTarget,
                            SizeInBytes = ResidualScanner.CalculatePathSize(compTarget, isDirectory: false),
                            Confidence = ConfidenceLevel.High,
                            Reason = "MSI 数据库：组件关联物理文件",
                            IsSelected = true
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        return matchedCount;
    }

    private static void ScanNativeMsiApiForProduct(string productCode, List<ResidualItem> results)
    {
        try
        {
            var compBuf = new StringBuilder(39);
            var pathBuf = new StringBuilder(1024);
            uint index = 0;

            while (index < 200000 && MsiEnumComponents(index, compBuf) == ERROR_SUCCESS)
            {
                index++;
                string compCode = compBuf.ToString();
                uint cch = (uint)pathBuf.Capacity;
                int state = MsiGetComponentPath(productCode, compCode, pathBuf, ref cch);

                if (state == ERROR_MORE_DATA && cch > pathBuf.Capacity)
                {
                    pathBuf.EnsureCapacity((int)cch + 4);
                    cch = (uint)pathBuf.Capacity;
                    state = MsiGetComponentPath(productCode, compCode, pathBuf, ref cch);
                }

                if ((state == INSTALLSTATE_LOCAL || state == INSTALLSTATE_SOURCE) && cch > 0)
                {
                    string resolvedPath = pathBuf.ToString();
                    if (resolvedPath.Length > 3 && resolvedPath[1] == ':' && File.Exists(resolvedPath))
                    {
                        string? parentDir = Path.GetDirectoryName(resolvedPath);
                        if (!AppLocator.IsProtectedSharedDirectory(parentDir))
                        {
                            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                            {
                                Type = ResidualType.File,
                                Category = ResidualCategory.MsiMetadata,
                                Path = resolvedPath,
                                SizeInBytes = ResidualScanner.CalculatePathSize(resolvedPath, isDirectory: false),
                                Confidence = ConfidenceLevel.High,
                                Reason = $"msi.dll API：关联组件文件 ({compCode})",
                                IsSelected = true
                            });
                        }
                    }
                }
            }
        }
        catch { }
    }

    public static string? TryConvertToPackedGuid(string guidString)
    {
        if (string.IsNullOrWhiteSpace(guidString)) return null;
        string clean = guidString.Trim().Trim('{', '}').Replace("-", "").ToUpperInvariant();
        if (clean.Length != 32 || !clean.All(Uri.IsHexDigit)) return null;

        char[] packed = new char[32];
        for (int i = 0; i < 8; i++) packed[i] = clean[7 - i];
        for (int i = 0; i < 4; i++) packed[8 + i] = clean[11 - i];
        for (int i = 0; i < 4; i++) packed[12 + i] = clean[15 - i];
        for (int i = 16; i < 32; i += 2)
        {
            packed[i] = clean[i + 1];
            packed[i + 1] = clean[i];
        }

        return new string(packed);
    }
}
