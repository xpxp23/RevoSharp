using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.Engine.Scanning;

public static class ProfileBuilder
{
    private static readonly Regex GuidRegex = new(@"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", RegexOptions.Compiled);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, uint cchBuffer);

    private static readonly HashSet<string> StopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "windows", "installer", "setup", "uninstaller", "update", "patch",
        "corporation", "software", "edition", "system", "package", "application",
        "tool", "client", "service", "desktop", "portable", "x86", "x64", "64-bit", "32-bit",
        "inc", "ltd", "co", "studio", "pro", "free", "version", "official", "app", "driver",
        "官方版", "正式版", "客户端", "安装程序", "软件", "有限公司", "科技", "网络"
    };

    private static readonly HashSet<string> GenericExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "app.exe", "update.exe", "updater.exe", "launcher.exe", "crashreporter.exe",
        "crashhandler.exe", "crashhandler64.exe", "helper.exe", "service.exe", "daemon.exe",
        "agent.exe", "cli.exe", "console.exe", "python.exe", "pythonw.exe", "java.exe",
        "javaw.exe", "node.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "msiexec.exe",
        "vcredist_x86.exe", "vcredist_x64.exe", "dxsetup.exe", "7z.exe", "curl.exe", "git.exe",
        "config.exe", "settings.exe", "server.exe", "client.exe", "plugin.exe", "host.exe",
        "elevate.exe", "webview2.exe", "cefsharp.browsersubprocess.exe"
    };

    public static TargetProfile Build(InstalledApp app)
    {
        string rawLoc = app.InstallLocation.Trim().Trim('"').TrimEnd('\\', '/');
        string singleExeFile = string.Empty;

        // Guard against protected shared folders (Desktop, Downloads, C:\Windows, etc.)
        if (AppLocator.IsProtectedSharedDirectory(rawLoc))
        {
            rawLoc = string.Empty;
        }

        if (app.IsProtectedSingleFile && !string.IsNullOrEmpty(app.DisplayIcon) && File.Exists(app.DisplayIcon))
        {
            singleExeFile = app.DisplayIcon;
        }

        string shortLoc = string.Empty;
        if (!string.IsNullOrEmpty(rawLoc) && Directory.Exists(rawLoc))
        {
            var sb = new StringBuilder(260);
            if (GetShortPathName(rawLoc, sb, (uint)sb.Capacity) > 0)
            {
                shortLoc = sb.ToString().TrimEnd('\\', '/');
            }
        }

        string guid = string.Empty;
        var guidMatch = GuidRegex.Match(app.Id + " " + app.UninstallKeyName + " " + app.UninstallString + " " + app.QuietUninstallString);
        if (guidMatch.Success)
        {
            guid = guidMatch.Value;
        }

        var exes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ExtractExeName(app.DisplayIcon, exes);
        ExtractExeName(app.UninstallString, exes);

        if (!string.IsNullOrEmpty(rawLoc) && Directory.Exists(rawLoc))
        {
            try
            {
                foreach (var file in Directory.GetFiles(rawLoc, "*.exe"))
                {
                    string name = Path.GetFileName(file);
                    if (!IsExcludedExeName(name))
                    {
                        exes.Add(name);
                    }
                }
            }
            catch { }
        }

        var tokens = new List<string>();
        foreach (var word in (app.DisplayName + " " + app.Publisher).Split([' ', '_', '-', '.', '(', ')', '[', ']', '（', '）'], StringSplitOptions.RemoveEmptyEntries))
        {
            string clean = word.Trim();
            bool hasCjk = clean.Any(c => c >= 0x4E00 && c <= 0x9FFF);
            int minLen = hasCjk ? 2 : 4;

            if (clean.Length >= minLen && !StopWords.Contains(clean) && !int.TryParse(clean, out _))
            {
                if (!tokens.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    tokens.Add(clean);
                }
            }
        }

        string uninstallKeyName = !string.IsNullOrWhiteSpace(app.UninstallKeyName)
            ? app.UninstallKeyName
            : string.Empty;

        return new TargetProfile
        {
            DisplayName = app.DisplayName,
            Publisher = app.Publisher,
            InstallLocation = rawLoc,
            NormalizedLocation = rawLoc.ToLowerInvariant(),
            ShortLocation = shortLoc.ToLowerInvariant(),
            SingleExecutableFile = singleExeFile,
            GuidString = guid,
            UninstallKeyName = uninstallKeyName,
            MainExeNames = exes,
            CleanTokens = tokens
        };
    }

    private static bool IsExcludedExeName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return true;
        if (fileName.StartsWith("unins", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("setup", StringComparison.OrdinalIgnoreCase))
            return true;

        return GenericExecutableNames.Contains(fileName);
    }

    private static void ExtractExeName(string text, HashSet<string> set)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        string candidate = AppLocator.ExtractExeFromCommand(text);
        if (!string.IsNullOrEmpty(candidate))
        {
            string fileName = Path.GetFileName(candidate);
            if (!IsExcludedExeName(fileName))
            {
                set.Add(fileName);
            }
        }
    }
}
