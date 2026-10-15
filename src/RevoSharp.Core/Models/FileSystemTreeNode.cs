using System.Collections.ObjectModel;
using System.ComponentModel;
using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class FileSystemTreeNode : INotifyPropertyChanged
{
    public required string Name { get; set; }
    public required string FullPath { get; set; }
    public bool IsFile { get; set; }
    public bool IsMatched { get; set; }
    public string? MatchReason { get; set; }
    public ResidualCategory Category { get; set; } = ResidualCategory.Directory;

    public ObservableCollection<FileSystemTreeNode> Children { get; set; } = [];

    private bool? _isChecked = true;
    public bool? IsChecked
    {
        get => _isChecked;
        set
        {
            if (_isChecked != value)
            {
                _isChecked = value;
                OnPropertyChanged(nameof(IsChecked));

                if (value.HasValue)
                {
                    foreach (var child in Children)
                    {
                        child.SetCheckedFromParent(value.Value);
                    }
                }
            }
        }
    }

    private bool _isExpanded = true;
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded != value)
            {
                _isExpanded = value;
                OnPropertyChanged(nameof(IsExpanded));
            }
        }
    }

    public void SetCheckedFromParent(bool isChecked)
    {
        _isChecked = isChecked;
        OnPropertyChanged(nameof(IsChecked));
        foreach (var child in Children)
        {
            child.SetCheckedFromParent(isChecked);
        }
    }

    public string IconGlyph => Category switch
    {
        ResidualCategory.Shortcut => "🔗",
        ResidualCategory.File => "📄",
        _ => "📁"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged(string propName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
