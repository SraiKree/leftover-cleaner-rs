use serde::{Serialize, Deserialize};

/// Type of leftover item
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeftoverKind {
    /// File leftover
    File,
    /// Directory leftover
    Directory,
    /// Registry value leftover
    RegistryValue,
    /// Registry key leftover
    RegistryKey,
}

impl LeftoverKind {
    /// Get a human-readable description of the kind
    pub fn description(&self) -> &'static str {
        match self {
            LeftoverKind::File => "File",
            LeftoverKind::Directory => "Directory",
            LeftoverKind::RegistryValue => "Registry Value",
            LeftoverKind::RegistryKey => "Registry Key",
        }
    }
    
    /// Check if this kind represents a filesystem item
    pub fn is_filesystem(&self) -> bool {
        matches!(self, LeftoverKind::File | LeftoverKind::Directory)
    }
    
    /// Check if this kind represents a registry item
    pub fn is_registry(&self) -> bool {
        matches!(self, LeftoverKind::RegistryValue | LeftoverKind::RegistryKey)
    }
}

/// Physical category of leftover item matching Geek Uninstaller
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeftoverCategory {
    /// Files, directories, shortcuts
    FileSystem,
    /// Registry keys and values
    Registry,
}

impl LeftoverCategory {
    /// Human-readable label
    pub fn description(&self) -> &'static str {
        match self {
            LeftoverCategory::FileSystem => "Files & Folders",
            LeftoverCategory::Registry => "Registry Entries",
        }
    }
}

/// A verified leftover item found after application uninstallation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverItem {
    /// Path to the leftover item
    /// - For files/directories: filesystem path
    /// - For registry items: registry path
    pub path: String,
    
    /// Type of leftover item
    pub kind: LeftoverKind,
    
    /// Category matching Geek Uninstaller categorization (FileSystem or Registry)
    pub category: LeftoverCategory,
    
    /// Source of detection (e.g., "Install path", "AppData", "MSI database", etc.)
    pub source: String,

    /// Whether this item is cleanable (false if blocked by SharedDLL ref count, etc.)
    pub cleanable: bool,
}

impl LeftoverItem {
    /// Create a new leftover item
    pub fn new(path: String, kind: LeftoverKind, category: LeftoverCategory, source: String) -> Self {
        Self {
            path,
            kind,
            category,
            source,
            cleanable: true,
        }
    }
    
    /// Create a file leftover item
    pub fn file(path: String, source: String) -> Self {
        Self::new(path, LeftoverKind::File, LeftoverCategory::FileSystem, source)
    }
    
    /// Create a directory leftover item
    pub fn directory(path: String, source: String) -> Self {
        Self::new(path, LeftoverKind::Directory, LeftoverCategory::FileSystem, source)
    }
    
    /// Create a registry value leftover item
    pub fn registry_value(path: String, source: String) -> Self {
        Self::new(path, LeftoverKind::RegistryValue, LeftoverCategory::Registry, source)
    }
    
    /// Create a registry key leftover item
    pub fn registry_key(path: String, source: String) -> Self {
        Self::new(path, LeftoverKind::RegistryKey, LeftoverCategory::Registry, source)
    }
    
    /// Get a human-readable description of the leftover item
    pub fn description(&self) -> String {
        format!("{} [{}]", self.path, self.category.description())
    }
    
    /// Check if this item can be safely deleted
    pub fn can_be_deleted(&self) -> bool {
        self.cleanable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leftover_kind_methods() {
        assert!(LeftoverKind::File.is_filesystem());
        assert!(LeftoverKind::Directory.is_filesystem());
        assert!(!LeftoverKind::File.is_registry());
        assert!(!LeftoverKind::Directory.is_registry());
        
        assert!(LeftoverKind::RegistryValue.is_registry());
        assert!(LeftoverKind::RegistryKey.is_registry());
        assert!(!LeftoverKind::RegistryValue.is_filesystem());
        assert!(!LeftoverKind::RegistryKey.is_filesystem());
    }
    
    #[test]
    fn test_leftover_category() {
        assert_eq!(LeftoverCategory::FileSystem.description(), "Files & Folders");
        assert_eq!(LeftoverCategory::Registry.description(), "Registry Entries");
    }
    
    #[test]
    fn test_leftover_item_creation() {
        let file_item = LeftoverItem::file(
            "C:\\Program Files\\TestApp\\leftover.dll".to_string(),
            "File system scan".to_string(),
        );
        
        assert_eq!(file_item.kind, LeftoverKind::File);
        assert_eq!(file_item.category, LeftoverCategory::FileSystem);
        assert!(file_item.can_be_deleted());
        assert!(file_item.description().contains("Files & Folders"));
    }
}