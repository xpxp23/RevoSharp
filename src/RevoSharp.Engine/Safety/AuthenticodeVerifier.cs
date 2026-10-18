using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using RevoSharp.Core.Models;
using RevoSharp.Core.Serialization;

namespace RevoSharp.Engine.Safety;

public readonly record struct BinarySignatureResult(
    bool IsSignedAndTrusted,
    string SignerName,
    string CompanyName);

/// <summary>
/// Verifies PE Authenticode digital signatures via WinVerifyTrust (wintrust.dll) with cache-only offline revocation checks
/// and X.509 certificate subject inspection. Protects third-party and system-signed directories from false-positive
/// token matches during Advanced deep fuzzy scanning and NTFS MFT volume searches.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly ConcurrentDictionary<string, BinarySignatureResult> SignatureCache = new(StringComparer.OrdinalIgnoreCase);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static BinarySignatureResult InspectBinarySignature(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return new BinarySignatureResult(false, string.Empty, string.Empty);

        return SignatureCache.GetOrAdd(filePath, static path =>
        {
            bool trusted = VerifyEmbeddedAuthenticodeFast(path);
            string signer = string.Empty;
            string company = string.Empty;

            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(path);
                using var cert2 = new X509Certificate2(cert);
                signer = cert2.GetNameInfo(X509NameType.SimpleName, false)?.Trim() ?? string.Empty;
            }
            catch { }

            try
            {
                company = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim() ?? string.Empty;
            }
            catch { }

            return new BinarySignatureResult(trusted, signer, company);
        });
    }

    /// <summary>
    /// Inspects PE executables/DLLs inside a candidate directory to determine whether it belongs to a trusted
    /// whitelisted vendor (e.g., Microsoft, NVIDIA, Intel, Apple) or a verified foreign publisher unrelated to the target app.
    /// </summary>
    public static bool IsDirectoryProtectedByForeignSignature(
        string directoryPath,
        TargetProfile targetProfile,
        out string foreignSignerDescription)
    {
        foreignSignerDescription = string.Empty;
        if (!SettingsSerializer.Current.EnableAuthenticodeGuard) return false;
        if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath)) return false;

        try
        {
            var settings = SettingsSerializer.Current;
            var candidateBinaries = Directory.EnumerateFiles(directoryPath, "*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                MaxRecursionDepth = 2
            })
            .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            .Take(4)
            .ToList();

            foreach (var bin in candidateBinaries)
            {
                var sig = InspectBinarySignature(bin);
                string effectivePublisher = !string.IsNullOrWhiteSpace(sig.SignerName) ? sig.SignerName : sig.CompanyName;
                if (string.IsNullOrWhiteSpace(effectivePublisher)) continue;

                // If the binary's publisher matches the target app's own Publisher or DisplayName, it belongs to the target app!
                if (DoesPublisherMatchTarget(effectivePublisher, targetProfile))
                {
                    return false;
                }

                // If the binary is signed by a whitelisted system/hardware vendor (and the target app is NOT from that vendor), protect it!
                bool isWhitelistedVendor = settings.WhitelistedPublishers.Any(wp =>
                    !string.IsNullOrWhiteSpace(wp) &&
                    (effectivePublisher.Contains(wp, StringComparison.OrdinalIgnoreCase) ||
                     wp.Contains(effectivePublisher, StringComparison.OrdinalIgnoreCase)));

                if (isWhitelistedVendor || sig.IsSignedAndTrusted)
                {
                    foreignSignerDescription = sig.IsSignedAndTrusted
                        ? $"受数字签名保护 ({effectivePublisher})"
                        : $"受白名单发行商保护 ({effectivePublisher})";
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    private static bool DoesPublisherMatchTarget(string binaryPublisher, TargetProfile profile)
    {
        if (!string.IsNullOrWhiteSpace(profile.Publisher))
        {
            if (binaryPublisher.Contains(profile.Publisher, StringComparison.OrdinalIgnoreCase) ||
                profile.Publisher.Contains(binaryPublisher, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (!string.IsNullOrWhiteSpace(profile.DisplayName) && profile.DisplayName.Length >= 4)
        {
            if (binaryPublisher.Contains(profile.DisplayName, StringComparison.OrdinalIgnoreCase) ||
                profile.DisplayName.Contains(binaryPublisher, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var token in profile.CleanTokens)
        {
            if (token.Length >= 4 && binaryPublisher.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool VerifyEmbeddedAuthenticodeFast(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, pFileInfo, false);

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = pFileInfo,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
        };

        try
        {
            Guid action = WintrustActionGenericVerifyV2;
            int status = WinVerifyTrust(new IntPtr(-1), action, ref trustData);
            return status == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            try
            {
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                Guid action = WintrustActionGenericVerifyV2;
                WinVerifyTrust(new IntPtr(-1), action, ref trustData);
            }
            catch { }
            Marshal.FreeHGlobal(pFileInfo);
        }
    }
}
