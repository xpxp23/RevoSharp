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
    public Dictionary<string, RegistryTreeNode> ChildLookup { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IsContainerOnly => !IsMatched;
    public double NodeOpacity => IsMatched ? 1.0 : 0.72;
    public bool IsLowConfidence => AssociatedItem?.Confidence == ConfidenceLevel.Low;

    private bool? _isChecked = true;
    public bool? IsChecked
    {
        get => _isChecked;
        set
        {
            bool targetValue = value ?? false;
            if (_isChecked != targetValue)
            {
                using var _ = TreeSelectionSyncScope.BeginBatch();
                _isChecked = targetValue;
                OnPropertyChanged(nameof(IsChecked));

                if (AssociatedItem != null)
                {
                    AssociatedItem.IsDemotedByChildUncheck = false;
                    AssociatedItem.IsSelected = targetValue;
                }

                foreach (var child in Children)
                {
                    child.SetCheckedFromParent(targetValue);
                }

                Parent?.RecalculateCheckStateFromChildren();
            }
            else if (value == null && _isChecked == true)
            {
                OnPropertyChanged(nameof(IsChecked));
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
            AssociatedItem.IsDemotedByChildUncheck = false;
            AssociatedItem.IsSelected = isChecked;
        }

        foreach (var child in Children)
        {
            child.SetCheckedFromParent(isChecked);
        }
    }

    /// <summary>
    /// Synchronizes TreeNode check state from ResidualItem.IsSelected and automatically protects parent registry keys
    /// if any child key or value under them was deselected in either Flat or Tree mode.
    /// </summary>
    public void SyncFromItemSelection()
    {
        foreach (var child in Children)
        {
            child.SyncFromItemSelection();
        }

        if (Children.Count > 0)
        {
            bool allChildrenChecked = Children.All(c => c.IsChecked == true);
            bool allChildrenUnchecked = Children.All(c => c.IsChecked == false);

            if (!allChildrenChecked && AssociatedItem != null && AssociatedItem.IsSelected)
            {
                AssociatedItem.IsDemotedByChildUncheck = !allChildrenUnchecked;
                AssociatedItem.IsSelected = false;
            }

            bool? selfState = AssociatedItem?.IsSelected;
            bool isAllTrue = allChildrenChecked && (selfState ?? true);
            bool isAllFalse = allChildrenUnchecked && !(selfState ?? false);
            bool? computed = isAllTrue ? true : (isAllFalse ? false : null);

            if (AssociatedItem != null && computed == null)
            {
                AssociatedItem.IsDemotedByChildUncheck = true;
            }

            if (_isChecked != computed)
            {
                _isChecked = computed;
                OnPropertyChanged(nameof(IsChecked));
            }
        }
        else if (AssociatedItem != null)
        {
            if (_isChecked != AssociatedItem.IsSelected)
            {
                _isChecked = AssociatedItem.IsSelected;
                OnPropertyChanged(nameof(IsChecked));
            }
        }
    }

    public void RecalculateCheckStateFromChildren(bool notifyParent = true)
    {
        if (Children.Count == 0) return;

        bool allChecked = Children.All(c => c.IsChecked == true);
        bool allUnchecked = Children.All(c => c.IsChecked == false);

        bool? newState = allChecked ? true : (allUnchecked ? false : null);

        if (AssociatedItem != null)
        {
            AssociatedItem.IsDemotedByChildUncheck = newState == null;
            AssociatedItem.IsSelected = newState == true;
        }

        if (_isChecked != newState)
        {
            _isChecked = newState;
            OnPropertyChanged(nameof(IsChecked));
        }

        if (notifyParent)
        {
            Parent?.RecalculateCheckStateFromChildren();
        }
    }

    public string SymbolIconName => Category switch
    {
        ResidualCategory.Service => "Settings24",
        ResidualCategory.FirewallRule => "Shield24",
        ResidualCategory.ShellExtension => "Apps24",
        ResidualCategory.MsiMetadata => "Box24",
        ResidualCategory.EnvironmentPath => "Code24",
        ResidualCategory.BrowserExtension => "GlobeSearch24",
        ResidualCategory.UrlProtocol => "Link24",
        ResidualCategory.DriverPackage => "Wrench24",
        ResidualCategory.RegistryValue => "Tag24",
        _ => "Code24"
    };

    public string IconGlyph => Category switch
    {
        ResidualCategory.Service => "⚙️",
        ResidualCategory.FirewallRule => "🛡️",
        ResidualCategory.ShellExtension => "🧩",
        ResidualCategory.MsiMetadata => "📦",
        ResidualCategory.EnvironmentPath => "🌐",
        ResidualCategory.BrowserExtension => "🧭",
        ResidualCategory.UrlProtocol => "🔗",
        ResidualCategory.DriverPackage => "🔧",
        ResidualCategory.RegistryValue => "🏷️",
        _ => "🔑"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged(string propName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
