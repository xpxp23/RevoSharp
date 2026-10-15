namespace RevoSharp.Core.Models;

public class TraceLog
{
    public required string AppName { get; set; }
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public string InstallerPath { get; set; } = string.Empty;
    public List<string> CreatedFiles { get; set; } = [];
    public List<string> ModifiedFiles { get; set; } = [];
    public List<string> CreatedRegistryKeys { get; set; } = [];
    public List<string> ModifiedRegistryValues { get; set; } = [];
}
