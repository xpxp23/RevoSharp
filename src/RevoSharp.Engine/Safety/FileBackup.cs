using System.Runtime.InteropServices;

namespace RevoSharp.Engine.Safety;

public static class FileBackup
{
    private const int FO_DELETE = 0x0003;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_SILENT = 0x0004;

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

    /// <summary>
    /// Safely moves a file or folder into the Windows Recycle Bin (0 data loss risk).
    /// </summary>
    public static bool SendToRecycleBin(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return false;

        try
        {
            // SHFileOperation requires double null-terminated string
            string doubleNullTerminatedPath = path + "\0\0";

            var fileOp = new SHFILEOPSTRUCT
            {
                wFunc = FO_DELETE,
                pFrom = doubleNullTerminatedPath,
                fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
            };

            int result = SHFileOperation(ref fileOp);
            return result == 0 && !fileOp.fAnyOperationsAborted;
        }
        catch
        {
            return false;
        }
    }
}
