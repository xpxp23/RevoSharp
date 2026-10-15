using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using RevoSharp.Core.Models;

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
        "tool", "client", "service", "desktop", "portable", "x86", "x64", "64-bit", "32-bit"
    };

    public static TargetProfile Build(InstalledApp app)
    {
        string rawLoc = app.InstallLocation.Trim().Trim('"').TrimEnd('\\');
        string shortLoc = string.Empty;

        if (!string.IsNullOrEmpty(rawLoc) && Directory.Exists(rawLoc))
        {
            var sb = new StringBuilder(260);
            if (GetShortPathName(rawLoc, sb, (uint)sb.Capacity) > 0)
            {
                shortLoc = sb.ToString();
            }
        }

        // Extract GUID from ID, UninstallString, or QuietUninstallString
        string guid = string.Empty;
        var guidMatch = GuidRegex.Match(app.Id + " " + app.UninstallString + " " + app.QuietUninstallString);
        if (guidMatch.Success)
        {
            guid = guidMatch.Value;
        }

        // Extract Main Exe Names
        var exes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ExtractExeName(app.DisplayIcon, exes);
        ExtractExeName(app.UninstallString, exes);

        if (Directory.Exists(rawLoc))
        {
            try
            {
                foreach (var file in Directory.GetFiles(rawLoc, "*.exe"))
                {
                    string name = Path.GetFileName(file);
                    if (!name.StartsWith("unins", StringComparison.OrdinalIgnoreCase) &&
                        !name.StartsWith("setup", StringComparison.OrdinalIgnoreCase))
                    {
                        exes.Add(name);
                    }
                }
            }
            catch { }
        }

        // Tokenize DisplayName and Publisher
        var tokens = new List<string>();
        foreach (var word in (app.DisplayName + " " + app.Publisher).Split([' ', '_', '-', '.', '(', ')'], StringSplitOptions.RemoveEmptyEntries))
        {
            string clean = word.Trim();
            if (clean.Length >= 3 && !StopWords.Contains(clean) && !int.TryParse(clean, out _))
            {
                if (!tokens.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    tokens.Add(clean);
                }
            }
        }

        // Extract Uninstall Key Name
        string uninstallKeyName = app.Id;
        int lastUnder = uninstallKeyName.IndexOf('_');
        if (lastUnder >= 0)
        {
            uninstallKeyName = uninstallKeyName.Substring(lastUnder + 1);
        }

        return new TargetProfile
        {
            DisplayName = app.DisplayName,
            Publisher = app.Publisher,
            InstallLocation = rawLoc,
            NormalizedLocation = rawLoc.ToLowerInvariant(),
            ShortLocation = shortLoc.ToLowerInvariant(),
            GuidString = guid,
            UninstallKeyName = uninstallKeyName,
            MainExeNames = exes,
            CleanTokens = tokens
        };
    }

    private static void ExtractExeName(string text, HashSet<string> set)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        int exeIdx = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
        {
            string candidate = text.Substring(0, exeIdx + 4).Trim('"', ' ', '\'');
            string fileName = Path.GetFileName(candidate);
            if (!string.IsNullOrEmpty(fileName) && !fileName.StartsWith("unins", StringComparison.OrdinalIgnoreCase))
            {
                set.Add(fileName);
            }
        }
    }
}
