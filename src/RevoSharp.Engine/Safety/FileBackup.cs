using System.IO;
using System.Runtime.InteropServices;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Safety;

public static class FileBackup
{
    private const int FO_DELETE = 0x0003;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_SILENT = 0x0004;
    private const ushort FOF_NOERRORUI = 0x0400;

    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;
    private static int _fileBackupSeq;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT64
    {
        public IntPtr hwnd;
        public int wFunc;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszProgressTitle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    private struct SHFILEOPSTRUCT32
    {
        public IntPtr hwnd;
        public int wFunc;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszProgressTitle;
    }

    [DllImport("shell32.dll", EntryPoint = "SHFileOperationW", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation64(ref SHFILEOPSTRUCT64 FileOp);

    [DllImport("shell32.dll", EntryPoint = "SHFileOperationW", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation32(ref SHFILEOPSTRUCT32 FileOp);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

    private static (int Result, bool Aborted) ExecuteShDeleteWithUndo(string doubleNullJoinedPaths)
    {
        const ushort flags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
        if (IntPtr.Size == 8)
        {
            var op64 = new SHFILEOPSTRUCT64
            {
                wFunc = FO_DELETE,
                pFrom = doubleNullJoinedPaths,
                fFlags = flags
            };
            int res = SHFileOperation64(ref op64);
            return (res, op64.fAnyOperationsAborted);
        }
        else
        {
            var op32 = new SHFILEOPSTRUCT32
            {
                wFunc = FO_DELETE,
                pFrom = doubleNullJoinedPaths,
                fFlags = flags
            };
            int res = SHFileOperation32(ref op32);
            return (res, op32.fAnyOperationsAborted);
        }
    }

    /// <summary>
    /// Creates a direct snapshot copy of a small file (e.g. .lnk shortcut, config file up to 16 MB)
    /// inside BackupDir so the Backup Manager can restore it with 1 click even if the Recycle Bin is emptied.
    /// </summary>
    public static string? TryCreateFileBackupCopy(string filePath, string appName)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return null;

        try
        {
            var info = new FileInfo(filePath);
            if (info.Length > 16L * 1024 * 1024) return null;

            if (!Directory.Exists(RegistryBackup.BackupDir))
            {
                Directory.CreateDirectory(RegistryBackup.BackupDir);
            }

            string safeApp = AppLocator.SanitizeFileName(appName);
            string safeLeaf = AppLocator.SanitizeFileName(Path.GetFileName(filePath));
            int seq = Interlocked.Increment(ref _fileBackupSeq);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
            string destPath = Path.Combine(RegistryBackup.BackupDir, $"{safeApp}_file_{timestamp}_{seq:D3}_{safeLeaf}.bak");

            File.Copy(filePath, destPath, overwrite: true);
            return destPath;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// High-speed batch Recycle Bin transaction: coalesces descendant paths covered by an ancestor directory in the same batch,
    /// joins top-level paths with '\0' and terminates with '\0\0' in a single SHFileOperation call, and falls back to per-item
    /// recycling if any locked file in the batch causes partial failure.
    /// </summary>
    public static HashSet<string> SendToRecycleBinBatch(IEnumerable<string> paths)
    {
        var succeeded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalizedMap = new List<(string RawPath, string CleanPath, bool IsDirectory)>();

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            try
            {
                string clean = Path.GetFullPath(raw.Trim().Trim('"')).TrimEnd('\\', '/');
                bool isDir = Directory.Exists(clean);
                bool isFile = !isDir && File.Exists(clean);
                if (isDir || isFile)
                {
                    ClearReadOnlyAttributes(clean);
                    normalizedMap.Add((raw, clean, isDir));
                }
            }
            catch { }
        }

        if (normalizedMap.Count == 0) return succeeded;

        // Collect all directories in the batch so child files/subfolders already inside a batch-deleted parent directory
        // are not redundantly passed to SHFileOperation (which would fail on missing path after parent is recycled).
        var batchDirs = normalizedMap
            .Where(x => x.IsDirectory)
            .Select(x => x.CleanPath + "\\")
            .OrderBy(x => x.Length)
            .ToList();

        var topLevelTargets = normalizedMap
            .Where(x => !batchDirs.Any(dirPrefix =>
                x.CleanPath.Length > dirPrefix.Length &&
                x.CleanPath.StartsWith(dirPrefix, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        // Execute in chunks of 64 top-level paths per SHFileOperation transaction
        foreach (var chunk in topLevelTargets.Chunk(64))
        {
            try
            {
                string multiNullJoined = string.Join("\0", chunk.Select(x => x.CleanPath)) + "\0\0";
                ExecuteShDeleteWithUndo(multiNullJoined);
            }
            catch { }

            foreach (var (raw, clean, _) in chunk)
            {
                if (!File.Exists(clean) && !Directory.Exists(clean))
                {
                    succeeded.Add(raw);
                }
                else if (SendToRecycleBin(clean))
                {
                    succeeded.Add(raw);
                }
            }
        }

        // Mark descendant items as succeeded if their parent directory was successfully recycled
        foreach (var (raw, clean, _) in normalizedMap)
        {
            if (!succeeded.Contains(raw) && !File.Exists(clean) && !Directory.Exists(clean))
            {
                succeeded.Add(raw);
            }
        }

        return succeeded;
    }

    /// <summary>
    /// Safely moves a file or folder into the Windows Recycle Bin after clearing read-only attributes.
    /// </summary>
    public static bool SendToRecycleBin(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (!File.Exists(path) && !Directory.Exists(path)) return false;

        try
        {
            string cleanPath = Path.GetFullPath(path.Trim().Trim('"')).TrimEnd('\\', '/');
            ClearReadOnlyAttributes(cleanPath);

            string doubleNullTerminatedPath = cleanPath + "\0\0";
            var (result, aborted) = ExecuteShDeleteWithUndo(doubleNullTerminatedPath);
            return result == 0 && !aborted && !File.Exists(cleanPath) && !Directory.Exists(cleanPath);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Schedules a locked file or directory tree to be deleted by Windows Session Manager (smss.exe) on next reboot.
    /// Uses strict bottom-up post-order traversal (files -> deepest subdirectories -> root directory)
    /// so smss.exe never fails due to non-empty child directories.
    /// </summary>
    public static bool ScheduleDeleteOnReboot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        try
        {
            string cleanPath = Path.GetFullPath(path.Trim().Trim('"')).TrimEnd('\\', '/');
            ClearReadOnlyAttributes(cleanPath);

            if (Directory.Exists(cleanPath))
            {
                foreach (var file in Directory.EnumerateFiles(cleanPath, "*", new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true
                }))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                    }
                    catch { }
                    MoveFileEx(file, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                }

                var subDirs = Directory.EnumerateDirectories(cleanPath, "*", new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true
                })
                .OrderByDescending(d => d.Length)
                .ToList();

                foreach (var subDir in subDirs)
                {
                    MoveFileEx(subDir, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
            }

            return MoveFileEx(cleanPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
        catch
        {
            return false;
        }
    }

    private static void ClearReadOnlyAttributes(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var attr = File.GetAttributes(path);
                if ((attr & FileAttributes.ReadOnly) != 0)
                {
                    File.SetAttributes(path, attr & ~FileAttributes.ReadOnly);
                }
            }
            else if (Directory.Exists(path))
            {
                var dirInfo = new DirectoryInfo(path);
                if ((dirInfo.Attributes & FileAttributes.ReadOnly) != 0)
                {
                    dirInfo.Attributes &= ~FileAttributes.ReadOnly;
                }
            }
        }
        catch { }
    }
}
