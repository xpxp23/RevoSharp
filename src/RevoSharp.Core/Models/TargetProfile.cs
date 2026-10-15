namespace RevoSharp.Core.Models;

public class TargetProfile
{
    public required string DisplayName { get; init; }
    public string Publisher { get; init; } = string.Empty;
    public string InstallLocation { get; init; } = string.Empty;
    public string NormalizedLocation { get; init; } = string.Empty;
    public string ShortLocation { get; init; } = string.Empty;
    public string GuidString { get; init; } = string.Empty;
    public string UninstallKeyName { get; init; } = string.Empty;
    public HashSet<string> MainExeNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> CleanTokens { get; init; } = [];

    public bool HasValidLocation => !string.IsNullOrWhiteSpace(NormalizedLocation) && NormalizedLocation.Length > 3;
}
