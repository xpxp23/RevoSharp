using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using RevoSharp.Core.Models;
using RevoSharp.Engine.Discovery;

namespace RevoSharp.App.Converters;

public class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is bool flag && flag;
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Visibility v && (Invert ? v != Visibility.Visible : v == Visibility.Visible);
}

public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return !(value is bool flag && flag);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return !(value is bool flag && flag);
    }
}

public class NullToBoolConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isNotNull = value != null;
        return Invert ? !isNotNull : isNotNull;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
}

public class CountToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        int count = value is int c ? c : 0;
        bool hasItems = count > 0;
        if (Invert) hasItems = !hasItems;
        return hasItems ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
}

public class AppIconConverter : IValueConverter
{
    private static readonly ConcurrentDictionary<string, ImageSource?> IconCache = new(StringComparer.OrdinalIgnoreCase);

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    private static extern uint ExtractIconEx(string szFileName, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not InstalledApp app) return null;
        return IconCache.GetOrAdd(app.Id, _ => ExtractAppIcon(app));
    }

    private static ImageSource? ExtractAppIcon(InstalledApp app)
    {
        var candidates = new List<(string FilePath, int IconIndex)>();

        if (!string.IsNullOrWhiteSpace(app.DisplayIcon))
        {
            var (parsedPath, parsedIdx) = ParseIconLocation(app.DisplayIcon);
            if (!string.IsNullOrEmpty(parsedPath))
            {
                candidates.Add((parsedPath, parsedIdx));
                if (parsedIdx != 0)
                {
                    candidates.Add((parsedPath, 0));
                }
            }
        }

        string uninstallExe = AppLocator.ExtractExeFromCommand(app.UninstallString);
        if (!string.IsNullOrEmpty(uninstallExe) && !uninstallExe.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add((uninstallExe, 0));
        }

        if (!string.IsNullOrWhiteSpace(app.InstallLocation) && Directory.Exists(app.InstallLocation))
        {
            try
            {
                var firstExe = Directory.GetFiles(app.InstallLocation, "*.exe")
                    .FirstOrDefault(f => !Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrEmpty(firstExe))
                {
                    candidates.Add((firstExe, 0));
                }
            }
            catch { }
        }

        foreach (var (path, iconIndex) in candidates)
        {
            if (!File.Exists(path)) continue;

            IntPtr[] large = new IntPtr[1];
            IntPtr[] small = new IntPtr[1];
            try
            {
                uint extracted = ExtractIconEx(path, iconIndex, large, small, 1);
                IntPtr chosenHandle = large[0] != IntPtr.Zero ? large[0] : small[0];
                if (extracted > 0 && chosenHandle != IntPtr.Zero)
                {
                    var bs = Imaging.CreateBitmapSourceFromHIcon(
                        chosenHandle,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    bs.Freeze();
                    return bs;
                }
            }
            catch { }
            finally
            {
                if (large[0] != IntPtr.Zero) DestroyIcon(large[0]);
                if (small[0] != IntPtr.Zero) DestroyIcon(small[0]);
            }
        }

        return null;
    }

    private static (string FilePath, int IconIndex) ParseIconLocation(string rawIcon)
    {
        string trimmed = rawIcon.Trim().Trim('"', '\'');
        int iconIndex = 0;
        int comma = trimmed.LastIndexOf(',');
        if (comma > 0)
        {
            string indexPart = trimmed.Substring(comma + 1).Trim();
            if (int.TryParse(indexPart, out int parsed))
            {
                iconIndex = parsed;
            }
            trimmed = trimmed.Substring(0, comma).Trim().Trim('"', '\'');
        }
        return (trimmed, iconIndex);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
}
