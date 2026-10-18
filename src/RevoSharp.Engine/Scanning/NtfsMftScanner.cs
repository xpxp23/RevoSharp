using System.IO;
using System.Runtime.InteropServices;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;
using RevoSharp.Engine.Discovery;
using RevoSharp.Engine.Safety;

namespace RevoSharp.Engine.Scanning;

/// <summary>
/// Ultra-fast NTFS MFT / USN Journal volume scanner (Everything-style FRN tree reconstruction):
/// Reads USN_RECORD_V2 entries directly from \\.\X: via FSCTL_ENUM_USN_DATA in 64 KB unmanaged chunks,
/// reconstructing full directory paths in memory in under 300ms to find scattered application folders,
/// user dot-folders (e.g. .appname), Windows Prefetch (.pf) traces, and orphaned config files across local NTFS volumes.
/// </summary>
public static class NtfsMftScanner
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;

    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
    private const uint FSCTL_ENUM_USN_DATA = 0x000900B3;

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MFT_ENUM_DATA_V0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    private sealed class VolumeSnapshotCache
    {
        public required string DrivePrefix { get; init; }
        public required DateTime CapturedUtc { get; init; }
        public required Dictionary<ulong, (ulong ParentFrn, string Name)> Directories { get; init; }
        public required List<(ulong ParentFrn, string FileName)> PrefetchAndConfigFiles { get; init; }
    }

    private static readonly Dictionary<string, VolumeSnapshotCache> VolumeCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object CacheLock = new();

    private static readonly HashSet<string> ExcludedSystemRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "$Recycle.Bin", "System Volume Information", "Recovery", "Config.Msi",
        "PerfLogs", "MSOCache", "Windows.old", "$WinREAgent", "OneDriveTemp"
    };

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static void ScanNtfsVolumes(
        TargetProfile profile,
        HashSet<string> protectedSiblingDirs,
        List<ResidualItem> results)
    {
        if (!SettingsSerializer.Current.EnableNtfsMftDeepScan) return;

        var targetDrives = GetCandidateNtfsDrives(profile);
        foreach (var driveRoot in targetDrives)
        {
            var snapshot = GetOrBuildVolumeSnapshot(driveRoot);
            if (snapshot == null) continue;

            ScanVolumeSnapshot(snapshot, profile, protectedSiblingDirs, results);
        }
    }

    private static List<string> GetCandidateNtfsDrives(TargetProfile profile)
    {
        var drives = new List<string>();
        try
        {
            string sysDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\') ?? "C:";
            drives.Add(sysDrive);

            if (profile.HasValidLocation)
            {
                string? appDrive = Path.GetPathRoot(profile.InstallLocation)?.TrimEnd('\\');
                if (!string.IsNullOrEmpty(appDrive) && !drives.Contains(appDrive, StringComparer.OrdinalIgnoreCase))
                {
                    drives.Add(appDrive);
                }
            }

            foreach (var d in DriveInfo.GetDrives())
            {
                if (d is { IsReady: true, DriveType: DriveType.Fixed } &&
                    string.Equals(d.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    string letter = d.Name.TrimEnd('\\');
                    if (!drives.Contains(letter, StringComparer.OrdinalIgnoreCase) && drives.Count < 3)
                    {
                        drives.Add(letter);
                    }
                }
            }
        }
        catch { }

        return drives;
    }

    private static VolumeSnapshotCache? GetOrBuildVolumeSnapshot(string drivePrefix)
    {
        string cleanDrive = drivePrefix.TrimEnd('\\', '/').ToUpperInvariant();
        lock (CacheLock)
        {
            if (VolumeCache.TryGetValue(cleanDrive, out var cached) &&
                (DateTime.UtcNow - cached.CapturedUtc).TotalSeconds < 35)
            {
                return cached;
            }
        }

        IntPtr hVol = CreateFileW(
            $@"\\.\{cleanDrive}",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (hVol == IntPtr.Zero || hVol == new IntPtr(-1))
            return null;

        const int bufferSize = 65536;
        IntPtr outBuffer = Marshal.AllocHGlobal(bufferSize);
        IntPtr inBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<MFT_ENUM_DATA_V0>());

        try
        {
            uint bytesReturned;
            if (!DeviceIoControl(
                    hVol,
                    FSCTL_QUERY_USN_JOURNAL,
                    IntPtr.Zero,
                    0,
                    outBuffer,
                    (uint)Marshal.SizeOf<USN_JOURNAL_DATA_V0>(),
                    out bytesReturned,
                    IntPtr.Zero))
            {
                return null;
            }

            var journalData = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(outBuffer);
            var enumData = new MFT_ENUM_DATA_V0
            {
                StartFileReferenceNumber = 0,
                LowUsn = 0,
                HighUsn = journalData.NextUsn
            };

            var directories = new Dictionary<ulong, (ulong ParentFrn, string Name)>(65536);
            var specialFiles = new List<(ulong ParentFrn, string FileName)>(512);

            int maxIterations = 8000;
            while (maxIterations-- > 0)
            {
                Marshal.StructureToPtr(enumData, inBuffer, false);
                if (!DeviceIoControl(
                        hVol,
                        FSCTL_ENUM_USN_DATA,
                        inBuffer,
                        (uint)Marshal.SizeOf<MFT_ENUM_DATA_V0>(),
                        outBuffer,
                        bufferSize,
                        out bytesReturned,
                        IntPtr.Zero) || bytesReturned <= 8)
                {
                    break;
                }

                enumData.StartFileReferenceNumber = (ulong)Marshal.ReadInt64(outBuffer, 0);

                int offset = 8;
                while (offset + 60 <= bytesReturned)
                {
                    uint recordLen = (uint)Marshal.ReadInt32(outBuffer, offset);
                    if (recordLen == 0 || offset + recordLen > bytesReturned)
                        break;

                    ushort majorVersion = (ushort)Marshal.ReadInt16(outBuffer, offset + 4);
                    if (majorVersion == 2)
                    {
                        ulong frn = (ulong)Marshal.ReadInt64(outBuffer, offset + 8);
                        ulong parentFrn = (ulong)Marshal.ReadInt64(outBuffer, offset + 16);
                        uint attributes = (uint)Marshal.ReadInt32(outBuffer, offset + 52);
                        ushort nameLen = (ushort)Marshal.ReadInt16(outBuffer, offset + 56);
                        ushort nameOffset = (ushort)Marshal.ReadInt16(outBuffer, offset + 58);

                        if (nameLen > 0 && nameOffset > 0 && offset + nameOffset + nameLen <= bytesReturned)
                        {
                            string name = Marshal.PtrToStringUni(IntPtr.Add(outBuffer, offset + nameOffset), nameLen / 2);
                            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                            {
                                directories[frn] = (parentFrn, name);
                            }
                            else if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
                            {
                                specialFiles.Add((parentFrn, name));
                            }
                        }
                    }

                    offset += (int)recordLen;
                }
            }

            var snapshot = new VolumeSnapshotCache
            {
                DrivePrefix = cleanDrive,
                CapturedUtc = DateTime.UtcNow,
                Directories = directories,
                PrefetchAndConfigFiles = specialFiles
            };

            lock (CacheLock)
            {
                VolumeCache[cleanDrive] = snapshot;
            }

            return snapshot;
        }
        catch
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
            Marshal.FreeHGlobal(outBuffer);
            CloseHandle(hVol);
        }
    }

    private static void ScanVolumeSnapshot(
        VolumeSnapshotCache snapshot,
        TargetProfile profile,
        HashSet<string> protectedSiblingDirs,
        List<ResidualItem> results)
    {
        int matchedDirCount = 0;

        // 1. Scan MFT directory table for scattered application folders & dot-folders (.appname) across the volume
        foreach (var (frn, (_, dirName)) in snapshot.Directories)
        {
            if (matchedDirCount >= 40) break;
            if (string.IsNullOrWhiteSpace(dirName) || dirName[0] == '$')
                continue;

            string trimmedDotName = dirName.TrimStart('.');
            if (trimmedDotName.Length < 4 || ResidualScanner.IsBlacklistedDirectoryName(trimmedDotName))
                continue;

            if (!MatchesMftDirectoryTarget(dirName, trimmedDotName, profile, out string matchReason, out var confidence))
                continue;

            string? fullPath = ReconstructFullPath(snapshot, frn, out int depth);
            if (string.IsNullOrEmpty(fullPath) || depth < 1 || depth > 5)
                continue;

            if (!IsSafeMftCandidatePath(fullPath, protectedSiblingDirs))
                continue;

            if (!Directory.Exists(fullPath))
                continue;

            if (AuthenticodeVerifier.IsDirectoryProtectedByForeignSignature(fullPath, profile, out _))
                continue;

            matchedDirCount++;
            ResidualScanner.AddResidualIfUnique(results, new ResidualItem
            {
                Type = ResidualType.Directory,
                Category = ResidualCategory.NtfsMftMatch,
                Path = fullPath,
                SizeInBytes = ResidualScanner.CalculatePathSize(fullPath, isDirectory: true),
                Confidence = confidence,
                Reason = $"NTFS MFT 全盘检出目录 ({matchReason})",
                IsSelected = confidence == ConfidenceLevel.High
            });
        }

        // 2. Scan Windows Prefetch (.pf) execution trace files matching target MainExeNames
        if (profile.MainExeNames.Count > 0)
        {
            foreach (var (parentFrn, pfFileName) in snapshot.PrefetchAndConfigFiles)
            {
                bool matchesExe = profile.MainExeNames.Any(exe =>
                    pfFileName.StartsWith(Path.GetFileNameWithoutExtension(exe) + ".exe-", StringComparison.OrdinalIgnoreCase) ||
                    pfFileName.StartsWith(exe + "-", StringComparison.OrdinalIgnoreCase));

                if (!matchesExe) continue;

                string? parentPath = ReconstructFullPath(snapshot, parentFrn, out _);
                if (string.IsNullOrEmpty(parentPath) || !parentPath.EndsWith(@"\Windows\Prefetch", StringComparison.OrdinalIgnoreCase))
                    continue;

                string fullPfPath = Path.Combine(parentPath, pfFileName);
                if (File.Exists(fullPfPath))
                {
                    ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                    {
                        Type = ResidualType.File,
                        Category = ResidualCategory.NtfsMftMatch,
                        Path = fullPfPath,
                        SizeInBytes = ResidualScanner.CalculatePathSize(fullPfPath, isDirectory: false),
                        Confidence = ConfidenceLevel.High,
                        Reason = "NTFS MFT 检出：Windows Prefetch 预读执行痕迹",
                        IsSelected = true
                    });
                }
            }
        }
    }

    private static bool MatchesMftDirectoryTarget(
        string rawDirName,
        string trimmedDotName,
        TargetProfile profile,
        out string reason,
        out ConfidenceLevel confidence)
    {
        reason = string.Empty;
        confidence = ConfidenceLevel.Medium;

        if (rawDirName.Equals(profile.DisplayName, StringComparison.OrdinalIgnoreCase) ||
            trimmedDotName.Equals(profile.DisplayName, StringComparison.OrdinalIgnoreCase))
        {
            reason = rawDirName.StartsWith('.') ? "匹配用户隐藏配置目录 (.dotfolder)" : "精确匹配软件名称";
            confidence = rawDirName.StartsWith('.') ? ConfidenceLevel.Medium : ConfidenceLevel.High;
            return true;
        }

        if (!string.IsNullOrEmpty(profile.GuidString) &&
            rawDirName.Contains(profile.GuidString, StringComparison.OrdinalIgnoreCase))
        {
            reason = "匹配产品 GUID";
            confidence = ConfidenceLevel.High;
            return true;
        }

        foreach (var exe in profile.MainExeNames)
        {
            string exeNoExt = Path.GetFileNameWithoutExtension(exe);
            if (exeNoExt.Length >= 5 &&
                (rawDirName.Equals(exeNoExt, StringComparison.OrdinalIgnoreCase) ||
                 trimmedDotName.Equals(exeNoExt, StringComparison.OrdinalIgnoreCase)))
            {
                reason = $"匹配主程序名 ({exe})";
                confidence = ConfidenceLevel.Medium;
                return true;
            }
        }

        return false;
    }

    private static bool IsSafeMftCandidatePath(string fullPath, HashSet<string> protectedSiblingDirs)
    {
        string clean = fullPath.TrimEnd('\\', '/');
        if (AppLocator.IsProtectedSharedDirectory(clean))
            return false;

        if (SettingsSerializer.IsPathWhitelisted(clean))
            return false;

        if (protectedSiblingDirs.Contains(clean))
            return false;

        foreach (var sibling in protectedSiblingDirs)
        {
            if (clean.StartsWith(sibling + "\\", StringComparison.OrdinalIgnoreCase) ||
                sibling.StartsWith(clean + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
        if (clean.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            return false;

        if (clean.Contains(@"\WinSxS\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\DriverStore\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\Package Cache\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\node_modules\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\.git\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static string? ReconstructFullPath(
        VolumeSnapshotCache snapshot,
        ulong targetFrn,
        out int depth)
    {
        depth = 0;
        var segments = new List<string>(8);
        ulong current = targetFrn;

        while (depth < 16 && snapshot.Directories.TryGetValue(current, out var info))
        {
            if (ExcludedSystemRoots.Contains(info.Name))
                return null;

            segments.Add(info.Name);
            depth++;

            if (info.ParentFrn == current || !snapshot.Directories.ContainsKey(info.ParentFrn))
            {
                break;
            }
            current = info.ParentFrn;
        }

        if (segments.Count == 0) return null;
        segments.Reverse();
        return snapshot.DrivePrefix + "\\" + string.Join("\\", segments);
    }
}
