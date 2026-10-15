using System.Runtime.InteropServices;

namespace RevoSharp.Engine.Safety;

public static class FileBackup
{
    private const int FO_DELETE = 0x0003;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_SILENT = 0x0004;
    private const ushort FOF_NOERRORUI = 0x0400;

    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

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
    /// Safely moves a file or folder into the Windows Recycle Bin.
    /// </summary>
    public static bool SendToRecycleBin(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return false;

        try
        {
            string cleanPath = path.TrimEnd('\\', '/');
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
    /// Schedules a locked file or empty directory to be deleted by Windows Session Manager on next reboot.
    /// </summary>
    public static bool ScheduleDeleteOnReboot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        try
        {
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
                {
                    MoveFileEx(file, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
            }
            return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
        catch
        {
            return false;
        }
    }
}
