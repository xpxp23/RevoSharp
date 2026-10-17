using System.Runtime.InteropServices;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Scanning;

public class ShortcutScanner
{
    public void ScanShortcuts(TargetProfile profile, List<ResidualItem> results)
    {
        var foldersToCheck = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.Programs),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
        };

        dynamic? wshShell = null;
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                wshShell = Activator.CreateInstance(shellType);
            }

            if (wshShell == null) return;

            foreach (var folder in foldersToCheck.Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(folder)) continue;

                try
                {
                    foreach (var lnk in Directory.GetFiles(folder, "*.lnk", SearchOption.AllDirectories))
                    {
                        dynamic? shortcut = null;
                        try
                        {
                            shortcut = wshShell.CreateShortcut(lnk);
                            string? targetPath = shortcut?.TargetPath as string;

                            if (IsTargetMatch(targetPath, profile))
                            {
                                ResidualScanner.AddResidualIfUnique(results, new ResidualItem
                                {
                                    Type = ResidualType.File,
                                    Category = ResidualCategory.Shortcut,
                                    Path = lnk,
                                    SizeInBytes = ResidualScanner.CalculatePathSize(lnk, isDirectory: false),
                                    Confidence = ConfidenceLevel.High,
                                    Reason = "快捷方式死链 (指向目标程序路径)",
                                    IsSelected = true
                                });
                            }
                        }
                        catch { }
                        finally
                        {
                            if (shortcut != null && Marshal.IsComObject(shortcut))
                            {
                                Marshal.FinalReleaseComObject(shortcut);
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        finally
        {
            if (wshShell != null && Marshal.IsComObject(wshShell))
            {
                Marshal.FinalReleaseComObject(wshShell);
            }
        }
    }

    private static bool IsTargetMatch(string? targetPath, TargetProfile profile)
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
            // When InstallLocation is unknown, only flag as a broken shortcut if the target binary no longer exists on disk
            return !File.Exists(lower);
        }

        return false;
    }
}
