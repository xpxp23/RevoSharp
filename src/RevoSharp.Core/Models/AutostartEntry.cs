namespace RevoSharp.Core.Models;

public class AutostartEntry
{
    public required string Name { get; init; }
    public required string Command { get; init; }
    public required string ExecutablePath { get; init; }
    public required string LocationType { get; init; }
    public required string FullLocation { get; init; }
    public string RegistryHiveName { get; init; } = string.Empty;
    public string RegistrySubKey { get; init; } = string.Empty;
    public bool IsStartupShortcut { get; init; }
    public bool FileExists { get; init; }
    public string Publisher { get; init; } = string.Empty;
}
