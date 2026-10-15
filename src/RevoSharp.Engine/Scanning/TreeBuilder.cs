using System.Collections.ObjectModel;
using RevoSharp.Core.Enums;
using RevoSharp.Core.Models;

namespace RevoSharp.Engine.Scanning;

public static class TreeBuilder
{
    public static ObservableCollection<RegistryTreeNode> BuildRegistryTree(List<ResidualItem> items)
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

                var child = currentNode.Children.FirstOrDefault(c => c.Name.Equals(part, StringComparison.OrdinalIgnoreCase));
                if (child == null)
                {
                    child = new RegistryTreeNode
                    {
                        Name = part,
                        FullPath = currentPath,
                        IsMatched = false,
                        IsExpanded = true
                    };
                    currentNode.Children.Add(child);
                }
                currentNode = child;
            }

            // Mark the leaf node as the matched residual item
            currentNode.IsMatched = true;
            currentNode.MatchReason = item.Reason;
            currentNode.IsChecked = item.IsSelected;
            currentNode.ValueName = item.ValueName;
            currentNode.Category = item.Type == ResidualType.RegistryValue
                ? ResidualCategory.RegistryValue
                : ResidualCategory.RegistryKey;
        }

        return new ObservableCollection<RegistryTreeNode>(roots.Values);
    }

    public static ObservableCollection<FileSystemTreeNode> BuildFileSystemTree(List<ResidualItem> items)
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

                var child = currentNode.Children.FirstOrDefault(c => c.Name.Equals(part, StringComparison.OrdinalIgnoreCase));
                if (child == null)
                {
                    child = new FileSystemTreeNode
                    {
                        Name = part,
                        FullPath = currentPath,
                        IsFile = isLast && item.Type == ResidualType.File,
                        IsMatched = false,
                        IsExpanded = true
                    };
                    currentNode.Children.Add(child);
                }
                currentNode = child;
            }

            currentNode.IsMatched = true;
            currentNode.MatchReason = item.Reason;
            currentNode.IsChecked = item.IsSelected;
            currentNode.Category = item.Reason.Contains("快捷方式") ? ResidualCategory.Shortcut :
                                   item.Type == ResidualType.File ? ResidualCategory.File : ResidualCategory.Directory;
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
