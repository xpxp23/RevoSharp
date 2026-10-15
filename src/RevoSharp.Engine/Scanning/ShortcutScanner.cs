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
            Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms)
        };

        dynamic? wshShell = null;
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                wshShell = Activator.CreateInstance(shellType);
            }
        }
        catch { }

        if (wshShell == null) return;

        foreach (var folder in foldersToCheck.Distinct())
        {
            if (!Directory.Exists(folder)) continue;

            try
            {
                foreach (var lnk in Directory.GetFiles(folder, "*.lnk", SearchOption.AllDirectories))
                {
                    try
                    {
                        dynamic shortcut = wshShell.CreateShortcut(lnk);
                        string? targetPath = shortcut.TargetPath as string;

                        if (IsTargetMatch(targetPath, profile))
                        {
                            if (!results.Any(r => r.Path.Equals(lnk, StringComparison.OrdinalIgnoreCase)))
                            {
                                results.Add(new ResidualItem
                                {
                                    Type = ResidualType.File,
                                    Path = lnk,
                                    Confidence = ConfidenceLevel.High,
                                    Reason = "快捷方式死链 (指向已卸载程序目标)",
                                    IsSelected = true
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static bool IsTargetMatch(string? targetPath, TargetProfile profile)
    {
        if (string.IsNullOrWhiteSpace(targetPath)) return false;
        string lower = targetPath.ToLowerInvariant();

        if (profile.HasValidLocation && lower.StartsWith(profile.NormalizedLocation))
        {
            return true;
        }

        string fileName = Path.GetFileName(lower);
        if (profile.MainExeNames.Contains(fileName))
        {
            return true;
        }

        return false;
    }
}
