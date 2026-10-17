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
    public FileSystemTreeNode? Parent { get; set; }
    public ResidualItem? AssociatedItem { get; set; }

    public ObservableCollection<FileSystemTreeNode> Children { get; set; } = [];

    private bool? _isChecked = true;
    public bool? IsChecked
    {
        get => _isChecked;
        set
        {
            // Coerce user clicks from indeterminate (null) to false so 1-click unchecking always works cleanly
            bool targetValue = value ?? false;
            if (_isChecked != targetValue)
            {
                _isChecked = targetValue;
                OnPropertyChanged(nameof(IsChecked));

                if (AssociatedItem != null)
                {
                    AssociatedItem.IsSelected = targetValue;
                }

                foreach (var child in Children)
                {
                    child.SetCheckedFromParent(targetValue);
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

    /// <summary>
    /// Pure read-only projection from ResidualItem.IsSelected onto TreeNode.IsChecked without mutating AssociatedItem.IsSelected.
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
            bool? selfState = AssociatedItem?.IsSelected;

            bool isAllTrue = allChildrenChecked && (selfState ?? true);
            bool isAllFalse = allChildrenUnchecked && !(selfState ?? false);
            bool? computed = isAllTrue ? true : (isAllFalse ? false : null);

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

        // When user interactively unchecks a child node in the TreeView, ensure the parent directory's own
        // AssociatedItem is deselected unless all children are checked, preventing whole-folder collateral deletion.
        if (AssociatedItem != null)
        {
            AssociatedItem.IsSelected = newState == true;
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

    public string SymbolIconName => Category switch
    {
        ResidualCategory.Shortcut => "Link24",
        ResidualCategory.ScheduledTask => "Clock24",
        ResidualCategory.File => "Document24",
        _ => IsFile ? "Document24" : "Folder24"
    };

    public string IconGlyph => Category switch
    {
        ResidualCategory.Shortcut => "🔗",
        ResidualCategory.ScheduledTask => "⏰",
        ResidualCategory.File => "📄",
        _ => "📁"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged(string propName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
