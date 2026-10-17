using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using Wpf.Ui.Appearance;

namespace RevoSharp.App;

public enum AppThemeMode
{
    Dark,
    Light,
    System
}

public partial class App : Application
{
    public static AppThemeMode CurrentThemeMode { get; private set; } = AppThemeMode.Dark;

    public static string CurrentThemeDisplay => CurrentThemeMode switch
    {
        AppThemeMode.Dark => "深色",
        AppThemeMode.Light => "浅色",
        AppThemeMode.System => "跟随系统",
        _ => "深色"
    };

    public static string CycleThemeMode()
    {
        var next = CurrentThemeMode switch
        {
            AppThemeMode.Dark => AppThemeMode.Light,
            AppThemeMode.Light => AppThemeMode.System,
            _ => AppThemeMode.Dark
        };
        ApplyThemeMode(next);
        return CurrentThemeDisplay;
    }

    public static void ApplyThemeMode(AppThemeMode mode)
    {
        CurrentThemeMode = mode;
        bool isDark = mode switch
        {
            AppThemeMode.Dark => true,
            AppThemeMode.Light => false,
            AppThemeMode.System => IsSystemUsingDarkTheme(),
            _ => true
        };

        ApplicationTheme targetTheme = isDark ? ApplicationTheme.Dark : ApplicationTheme.Light;
        ApplicationThemeManager.Apply(targetTheme);

        if (Current?.Resources == null) return;
        var res = Current.Resources;

        if (isDark)
        {
            SetBrush(res, "RevoPillSelectedBackgroundBrush", Color.FromArgb(0x2E, 0x00, 0x78, 0xD4));
            SetBrush(res, "RevoPillSelectedBorderBrush", Color.FromRgb(0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoAccentCyanBrush", Color.FromRgb(0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoAccentCyanTextBrush", Color.FromRgb(0x88, 0xCC, 0xFF));
            SetBrush(res, "RevoAccentGreenBrush", Color.FromRgb(0x6C, 0xCB, 0x5F));
            SetBrush(res, "RevoAccentGreenTextBrush", Color.FromRgb(0x88, 0xEE, 0xAA));
            SetBrush(res, "RevoAccentPurpleBrush", Color.FromRgb(0xC3, 0x95, 0xFF));
            SetBrush(res, "RevoAccentAmberBrush", Color.FromRgb(0xFF, 0xAA, 0x44));
            SetBrush(res, "RevoAccentRedBrush", Color.FromRgb(0xFF, 0x66, 0x66));

            SetBrush(res, "RevoTagBlueBgBrush", Color.FromArgb(0x24, 0x00, 0x78, 0xD4));
            SetBrush(res, "RevoTagBlueBorderBrush", Color.FromArgb(0x44, 0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoTagPurpleBgBrush", Color.FromArgb(0x24, 0x9E, 0x77, 0xED));
            SetBrush(res, "RevoTagPurpleBorderBrush", Color.FromArgb(0x44, 0xC3, 0x95, 0xFF));
            SetBrush(res, "RevoTagGreenBgBrush", Color.FromArgb(0x22, 0x44, 0xDD, 0x88));
            SetBrush(res, "RevoTagRedBgBrush", Color.FromArgb(0x2E, 0xFF, 0x44, 0x44));
            SetBrush(res, "RevoTagRedBorderBrush", Color.FromArgb(0x55, 0xFF, 0x66, 0x66));
            SetBrush(res, "RevoTagNeutralBgBrush", Color.FromArgb(0x22, 0xFF, 0xFF, 0xFF));

            SetBrush(res, "RevoOverlayMaskBrush", Color.FromArgb(0xB8, 0x12, 0x14, 0x18));
            SetBrush(res, "RevoFloatingBarBgBrush", Color.FromArgb(0xF2, 0x1A, 0x20, 0x2C));
            SetBrush(res, "RevoFloatingBarBorderBrush", Color.FromArgb(0x55, 0x60, 0xCD, 0xFF));
            SetBrush(res, "RevoHudCardBgBrush", Color.FromArgb(0xF8, 0x1C, 0x1E, 0x26));
            SetBrush(res, "RevoHudCardBorderBrush", Color.FromArgb(0x3A, 0xFF, 0xFF, 0xFF));
        }
        else
        {
            SetBrush(res, "RevoPillSelectedBackgroundBrush", Color.FromArgb(0x1E, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoPillSelectedBorderBrush", Color.FromRgb(0x00, 0x67, 0xC0));
            SetBrush(res, "RevoAccentCyanBrush", Color.FromRgb(0x00, 0x5F, 0xB8));
            SetBrush(res, "RevoAccentCyanTextBrush", Color.FromRgb(0x00, 0x4E, 0x98));
            SetBrush(res, "RevoAccentGreenBrush", Color.FromRgb(0x10, 0x7C, 0x10));
            SetBrush(res, "RevoAccentGreenTextBrush", Color.FromRgb(0x0E, 0x6A, 0x0E));
            SetBrush(res, "RevoAccentPurpleBrush", Color.FromRgb(0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoAccentAmberBrush", Color.FromRgb(0xC5, 0x65, 0x00));
            SetBrush(res, "RevoAccentRedBrush", Color.FromRgb(0xD1, 0x34, 0x38));

            SetBrush(res, "RevoTagBlueBgBrush", Color.FromArgb(0x18, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoTagBlueBorderBrush", Color.FromArgb(0x44, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoTagPurpleBgBrush", Color.FromArgb(0x18, 0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoTagPurpleBorderBrush", Color.FromArgb(0x44, 0x6B, 0x2F, 0xBA));
            SetBrush(res, "RevoTagGreenBgBrush", Color.FromArgb(0x1A, 0x10, 0x7C, 0x10));
            SetBrush(res, "RevoTagRedBgBrush", Color.FromArgb(0x1A, 0xD1, 0x34, 0x38));
            SetBrush(res, "RevoTagRedBorderBrush", Color.FromArgb(0x55, 0xD1, 0x34, 0x38));
            SetBrush(res, "RevoTagNeutralBgBrush", Color.FromArgb(0x14, 0x00, 0x00, 0x00));

            SetBrush(res, "RevoOverlayMaskBrush", Color.FromArgb(0xCC, 0xF3, 0xF5, 0xF8));
            SetBrush(res, "RevoFloatingBarBgBrush", Color.FromArgb(0xF6, 0xFF, 0xFF, 0xFF));
            SetBrush(res, "RevoFloatingBarBorderBrush", Color.FromArgb(0x55, 0x00, 0x67, 0xC0));
            SetBrush(res, "RevoHudCardBgBrush", Color.FromArgb(0xFA, 0xFF, 0xFF, 0xFF));
            SetBrush(res, "RevoHudCardBorderBrush", Color.FromArgb(0x28, 0x00, 0x00, 0x00));
        }
    }

    private static void SetBrush(ResourceDictionary dict, string key, Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        dict[key] = brush;
    }

    private static bool IsSystemUsingDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int useLight)
            {
                return useLight == 0;
            }
        }
        catch { }
        return true;
    }
}
