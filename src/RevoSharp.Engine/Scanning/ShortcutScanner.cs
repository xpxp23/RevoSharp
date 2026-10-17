using System.IO;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Scanning;

public class ShortcutScanner
{
    public void ScanShortcuts(TargetProfile profile, List<ResidualItem> results)
    {
        // Note: StartMenu and CommonStartMenu already contain Programs and CommonPrograms as subdirectories.
        // Deduplicating parent roots prevents scanning every Start Menu .lnk twice!
        var foldersToCheck = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
        };

        var scannedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var folder in foldersToCheck.Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(folder)) continue;

            try
            {
                foreach (var lnk in Directory.EnumerateFiles(folder, "*.lnk", new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 5
                }))
                {
                    if (!scannedFiles.Add(lnk)) continue;

                    var parsed = ShellLinkParser.TryParse(lnk);
                    if (parsed == null || !parsed.Value.HasAnyMetadata) continue;

                    if (IsShortcutMatch(parsed.Value, profile, out string matchDetail))
                    {
                        ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                        {
                            Type = ResidualType.File,
                            Category = ResidualCategory.Shortcut,
                            Path = lnk,
                            ValuePreview = !string.IsNullOrEmpty(parsed.Value.TargetPath) ? parsed.Value.TargetPath : parsed.Value.Arguments,
                            SizeInBytes = ResidualScanner.CalculatePathSize(lnk, isDirectory: false),
                            Confidence = ConfidenceLevel.High,
                            Reason = $"快捷方式死链 ({matchDetail})",
                            IsSelected = true
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static bool IsShortcutMatch(ShellLinkInfo link, TargetProfile profile, out string matchDetail)
    {
        matchDetail = "指向目标程序路径";

        if (IsSinglePathMatch(link.TargetPath, profile))
        {
            return true;
        }

        // Check command-line arguments (catches Electron Update.exe --processStart, PWA --app-id, cmd/java/python wrappers)
        if (!string.IsNullOrWhiteSpace(link.Arguments) && IsArgumentOrDirMatch(link.Arguments, profile))
        {
            matchDetail = "启动参数指向目标程序";
            return true;
        }

        // Check WorkingDirectory if TargetPath is missing or points to a generic wrapper
        if (!string.IsNullOrWhiteSpace(link.WorkingDirectory) && profile.HasValidLocation && IsArgumentOrDirMatch(link.WorkingDirectory, profile))
        {
            matchDetail = "起始工作目录指向目标安装路径";
            return true;
        }

        // Check IconLocation if main target was already wiped or wrapped
        if (!string.IsNullOrWhiteSpace(link.IconLocation) && profile.HasValidLocation && IsArgumentOrDirMatch(link.IconLocation, profile))
        {
            matchDetail = "图标资源指向目标安装路径";
            return true;
        }

        return false;
    }

    private static bool IsArgumentOrDirMatch(string rawText, TargetProfile profile)
    {
        string lower = Environment.ExpandEnvironmentVariables(rawText).ToLowerInvariant().Trim('"', ' ');
        if (profile.HasValidLocation)
        {
            string prefix = profile.NormalizedLocation.TrimEnd('\\') + "\\";
            if (lower.Contains(prefix) || lower.Equals(profile.NormalizedLocation))
                return true;

            if (!string.IsNullOrEmpty(profile.ShortLocation))
            {
                string shortPrefix = profile.ShortLocation.TrimEnd('\\') + "\\";
                if (lower.Contains(shortPrefix) || lower.Equals(profile.ShortLocation))
                    return true;
            }
        }

        return false;
    }

    private static bool IsSinglePathMatch(string? targetPath, TargetProfile profile)
    {
        if (string.IsNullOrWhiteSpace(targetPath)) return false;
        string lower = Environment.ExpandEnvironmentVariables(targetPath).ToLowerInvariant().Trim('"', ' ');

        if (profile.HasValidLocation)
        {
            string prefix = profile.NormalizedLocation.TrimEnd('\\') + "\\";
            if (lower.StartsWith(prefix) || lower.Equals(profile.NormalizedLocation))
            {
                return true;
            }

            if (!string.IsNullOrEmpty(profile.ShortLocation))
            {
                string shortPrefix = profile.ShortLocation.TrimEnd('\\') + "\\";
                if (lower.StartsWith(shortPrefix) || lower.Equals(profile.ShortLocation))
                {
                    return true;
                }
            }

            return false;
        }

        if (!string.IsNullOrEmpty(profile.SingleExecutableFile) &&
            lower.Equals(profile.SingleExecutableFile, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string fileName = Path.GetFileName(lower);
        if (profile.MainExeNames.Contains(fileName) && !lower.Contains(@"\windows\"))
        {
            return !File.Exists(lower);
        }

        return false;
    }
}
