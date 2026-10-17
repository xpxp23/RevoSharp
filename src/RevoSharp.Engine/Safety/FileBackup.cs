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
    private struct SHFILEOPSTRUCT
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

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT FileOp);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

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
    /// High-speed batch Recycle Bin transaction: joins multiple file/folder paths with '\0' and terminates with '\0\0'
    /// in a single SHFileOperation call, falling back to per-item recycling if any locked file in the batch causes partial failure.
    /// Returns the set of original paths that were confirmed moved to the Recycle Bin.
    /// </summary>
    public static HashSet<string> SendToRecycleBinBatch(IEnumerable<string> paths)
    {
        var succeeded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalizedMap = new List<(string RawPath, string CleanPath)>();

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            try
            {
                string clean = Path.GetFullPath(raw.Trim().Trim('"')).TrimEnd('\\', '/');
                if (File.Exists(clean) || Directory.Exists(clean))
                {
                    ClearReadOnlyAttributes(clean);
                    normalizedMap.Add((raw, clean));
                }
            }
            catch { }
        }

        if (normalizedMap.Count == 0) return succeeded;

        // Execute in chunks of 64 paths per SHFileOperation transaction
        foreach (var chunk in normalizedMap.Chunk(64))
        {
            try
            {
                string multiNullJoined = string.Join("\0", chunk.Select(x => x.CleanPath)) + "\0\0";
                var fileOp = new SHFILEOPSTRUCT
                {
                    wFunc = FO_DELETE,
                    pFrom = multiNullJoined,
                    fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
                };

                SHFileOperation(ref fileOp);
            }
            catch { }

            foreach (var (raw, clean) in chunk)
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

            var fileOp = new SHFILEOPSTRUCT
            {
                wFunc = FO_DELETE,
                pFrom = doubleNullTerminatedPath,
                fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
            };

            int result = SHFileOperation(ref fileOp);
            return result == 0 && !fileOp.fAnyOperationsAborted && !File.Exists(cleanPath) && !Directory.Exists(cleanPath);
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
