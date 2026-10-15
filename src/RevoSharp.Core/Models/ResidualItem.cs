using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class ResidualItem
{
    public required ResidualType Type { get; init; }
    public required string Path { get; init; }
    public string? ValueName { get; init; }
    public required ConfidenceLevel Confidence { get; init; }
    public required string Reason { get; init; }
    public bool IsSelected { get; set; }

    public string DisplayIcon => Type switch
    {
        ResidualType.Directory => "Folder24",
        ResidualType.File => "Document24",
        ResidualType.RegistryKey => "Code24",
        ResidualType.RegistryValue => "Tag24",
        _ => "QuestionCircle24"
    };

    public string ConfidenceDisplay => Confidence switch
    {
        ConfidenceLevel.High => "高 (推荐清除)",
        ConfidenceLevel.Medium => "中 (建议核对)",
        ConfidenceLevel.Low => "低 (谨慎清除)",
        _ => "未知"
    };
}
