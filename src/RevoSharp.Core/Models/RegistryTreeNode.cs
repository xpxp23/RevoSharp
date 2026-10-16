using System.Collections.ObjectModel;
using System.ComponentModel;
using RevoSharp.Core.Enums;

namespace RevoSharp.Core.Models;

public class RegistryTreeNode : INotifyPropertyChanged
{
    public required string Name { get; set; }
    public required string FullPath { get; set; }
    public bool IsMatched { get; set; }
    public string? MatchReason { get; set; }
    public ResidualCategory Category { get; set; } = ResidualCategory.RegistryKey;
    public string? ValueName { get; set; }
    public RegistryTreeNode? Parent { get; set; }
    public ResidualItem? AssociatedItem { get; set; }

    public ObservableCollection<RegistryTreeNode> Children { get; set; } = [];

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
                    if (AssociatedItem != null)
                    {
                        AssociatedItem.IsSelected = value.Value;
                    }

                    foreach (var child in Children)
                    {
                        child.SetCheckedFromParent(value.Value);
                    }
                }

                Parent?.RecalculateCheckStateFromChildren();
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
        if (_isChecked != isChecked)
        {
            _isChecked = isChecked;
            OnPropertyChanged(nameof(IsChecked));
        }

        if (AssociatedItem != null)
        {
            AssociatedItem.IsSelected = isChecked;
        }

        foreach (var child in Children)
        {
            child.SetCheckedFromParent(isChecked);
        }
    }

    public void SyncFromItemSelection()
    {
        foreach (var child in Children)
        {
            child.SyncFromItemSelection();
        }

        if (Children.Count > 0)
        {
            RecalculateCheckStateFromChildren(notifyParent: false);
        }
        else if (AssociatedItem != null)
        {
            _isChecked = AssociatedItem.IsSelected;
            OnPropertyChanged(nameof(IsChecked));
        }
    }

    public void RecalculateCheckStateFromChildren(bool notifyParent = true)
    {
        if (Children.Count == 0) return;

        bool allChecked = Children.All(c => c.IsChecked == true);
        bool allUnchecked = Children.All(c => c.IsChecked == false);

        bool? newState = allChecked ? true : (allUnchecked ? false : null);
        if (AssociatedItem != null && newState.HasValue)
        {
            AssociatedItem.IsSelected = newState.Value;
        }

        if (_isChecked != newState)
        {
            _isChecked = newState;
            OnPropertyChanged(nameof(IsChecked));
            if (notifyParent)
            {
                Parent?.RecalculateCheckStateFromChildren();
            }
        }
    }

    public string IconGlyph => Category switch
    {
        ResidualCategory.Service => "⚙️",
        ResidualCategory.FirewallRule => "🛡️",
        ResidualCategory.ShellExtension => "🧩",
        ResidualCategory.MsiMetadata => "📦",
        ResidualCategory.RegistryValue => "🏷️",
        _ => "🔑"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged(string propName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
