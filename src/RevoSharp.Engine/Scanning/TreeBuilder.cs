using System.Collections.ObjectModel;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Scanning;

public static class TreeBuilder
{
    public static ObservableCollection<RegistryTreeNode> BuildRegistryTree(IEnumerable<ResidualItem> items)
    {
        var roots = new Dictionary<string, RegistryTreeNode>(StringComparer.OrdinalIgnoreCase);

        var regItems = items.Where(i => i.Type == ResidualType.RegistryKey || i.Type == ResidualType.RegistryValue);

        foreach (var item in regItems)
        {
            string fullPath = item.Path.Trim();
            string[] parts = fullPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            string rootName = NormalizeRootName(parts[0]);
            if (!roots.TryGetValue(rootName, out var currentNode))
            {
                currentNode = new RegistryTreeNode
                {
                    Name = rootName,
                    FullPath = rootName,
                    IsMatched = false,
                    IsExpanded = true
                };
                roots[rootName] = currentNode;
            }

            string currentPath = rootName;

            for (int i = 1; i < parts.Length; i++)
            {
                string part = parts[i];
                currentPath += "\\" + part;

                if (!currentNode.ChildLookup.TryGetValue(part, out var child))
                {
                    child = new RegistryTreeNode
                    {
                        Name = part,
                        FullPath = currentPath,
                        Parent = currentNode,
                        IsMatched = false,
                        IsExpanded = i <= 2
                    };
                    currentNode.ChildLookup[part] = child;
                    currentNode.Children.Add(child);
                }
                currentNode = child;
            }

            // If this is a RegistryValue residual, attach a dedicated leaf node for the value name so multiple values under the same key don't overwrite each other
            if (item.Type == ResidualType.RegistryValue && !string.IsNullOrEmpty(item.ValueName))
            {
                string valDisplay = string.IsNullOrEmpty(item.ValuePreview)
                    ? $"[{item.ValueName}]"
                    : $"[{item.ValueName}] = {item.ValuePreview}";

                string valKey = $"__VAL__{item.ValueName}";
                if (!currentNode.ChildLookup.TryGetValue(valKey, out var valNode))
                {
                    valNode = new RegistryTreeNode
                    {
                        Name = valDisplay,
                        FullPath = $"{currentPath} [{item.ValueName}]",
                        Parent = currentNode,
                        IsMatched = true,
                        MatchReason = item.Reason,
                        ValueName = item.ValueName,
                        Category = item.Category,
                        AssociatedItem = item,
                        IsExpanded = false
                    };
                    currentNode.ChildLookup[valKey] = valNode;
                    currentNode.Children.Add(valNode);
                }
            }
            else
            {
                currentNode.IsMatched = true;
                currentNode.MatchReason = item.Reason;
                currentNode.ValueName = item.ValueName;
                currentNode.Category = item.Category;
                currentNode.AssociatedItem = item;
            }
        }

        foreach (var root in roots.Values)
        {
            root.SyncFromItemSelection();
        }

        return new ObservableCollection<RegistryTreeNode>(roots.Values);
    }

    public static ObservableCollection<FileSystemTreeNode> BuildFileSystemTree(IEnumerable<ResidualItem> items)
    {
        var roots = new Dictionary<string, FileSystemTreeNode>(StringComparer.OrdinalIgnoreCase);

        var fileItems = items.Where(i => i.Type == ResidualType.Directory || i.Type == ResidualType.File);

        foreach (var item in fileItems)
        {
            string fullPath = item.Path.Trim();
            string[] parts = fullPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            string rootName = parts[0];
            if (rootName.Length == 2 && rootName[1] == ':')
            {
                rootName = rootName.ToUpperInvariant();
            }

            if (!roots.TryGetValue(rootName, out var currentNode))
            {
                currentNode = new FileSystemTreeNode
                {
                    Name = rootName,
                    FullPath = rootName,
                    IsFile = false,
                    IsMatched = false,
                    IsExpanded = true
                };
                roots[rootName] = currentNode;
            }

            string currentPath = rootName;

            for (int i = 1; i < parts.Length; i++)
            {
                string part = parts[i];
                currentPath += "\\" + part;
                bool isLast = i == parts.Length - 1;

                if (!currentNode.ChildLookup.TryGetValue(part, out var child))
                {
                    child = new FileSystemTreeNode
                    {
                        Name = part,
                        FullPath = currentPath,
                        Parent = currentNode,
                        IsFile = isLast && item.Type == ResidualType.File,
                        IsMatched = false,
                        IsExpanded = i <= 2
                    };
                    currentNode.ChildLookup[part] = child;
                    currentNode.Children.Add(child);
                }
                currentNode = child;
            }

            currentNode.IsMatched = true;
            currentNode.MatchReason = item.Reason;
            currentNode.Category = item.Category;
            currentNode.AssociatedItem = item;
        }

        foreach (var root in roots.Values)
        {
            root.SyncFromItemSelection();
        }

        return new ObservableCollection<FileSystemTreeNode>(roots.Values);
    }

    private static string NormalizeRootName(string raw)
    {
        return raw.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => "HKEY_LOCAL_MACHINE",
            "HKCU" or "HKEY_CURRENT_USER" => "HKEY_CURRENT_USER",
            "HKCR" or "HKEY_CLASSES_ROOT" => "HKEY_CLASSES_ROOT",
            _ => raw
        };
    }
}
