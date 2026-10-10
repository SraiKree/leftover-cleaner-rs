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

/// Confidence level for leftover detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// High confidence (direct match with application)
    High,
    /// Medium confidence (probable match)
    Medium,
    /// Low confidence (possible match)
    Low,
}

impl ConfidenceLevel {
    /// Get a human-readable description of the confidence level
    pub fn description(&self) -> &'static str {
        match self {
            ConfidenceLevel::High => "High",
            ConfidenceLevel::Medium => "Medium",
            ConfidenceLevel::Low => "Low",
        }
    }
    
    /// Get a numeric value for sorting (higher = more confident)
    pub fn numeric_value(&self) -> u8 {
        match self {
            ConfidenceLevel::High => 3,
            ConfidenceLevel::Medium => 2,
            ConfidenceLevel::Low => 1,
        }
    }
}

/// A leftover item found after application uninstallation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverItem {
    /// Path to the leftover item
    /// - For files/directories: filesystem path
    /// - For registry items: registry path
    pub path: String,
    
    /// Type of leftover item
    pub kind: LeftoverKind,
    
    /// Confidence level for this detection
    pub confidence: ConfidenceLevel,
    
    /// Source of the detection (e.g., "File system scan", "Registry scan", "MSI database")
    pub source: String,
}

impl LeftoverItem {
    /// Create a new leftover item
    pub fn new(path: String, kind: LeftoverKind, confidence: ConfidenceLevel, source: String) -> Self {
        Self {
            path,
            kind,
            confidence,
            source,
        }
    }
    
    /// Create a file leftover item
    pub fn file(path: String, confidence: ConfidenceLevel, source: String) -> Self {
        Self::new(path, LeftoverKind::File, confidence, source)
    }
    
    /// Create a directory leftover item
    pub fn directory(path: String, confidence: ConfidenceLevel, source: String) -> Self {
        Self::new(path, LeftoverKind::Directory, confidence, source)
    }
    
    /// Create a registry value leftover item
    pub fn registry_value(path: String, confidence: ConfidenceLevel, source: String) -> Self {
        Self::new(path, LeftoverKind::RegistryValue, confidence, source)
    }
    
    /// Create a registry key leftover item
    pub fn registry_key(path: String, confidence: ConfidenceLevel, source: String) -> Self {
        Self::new(path, LeftoverKind::RegistryKey, confidence, source)
    }
    
    /// Get a human-readable description of the leftover item
    pub fn description(&self) -> String {
        format!("{} ({} confidence)", self.path, self.confidence.description())
    }
    
    /// Check if this item can be safely deleted
    /// (Currently always returns true, but will be enhanced with safety checks later)
    pub fn can_be_deleted(&self) -> bool {
        // TODO: Add safety checks (system files, shared dependencies, etc.)
        true
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
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::High.numeric_value() > ConfidenceLevel::Medium.numeric_value());
        assert!(ConfidenceLevel::Medium.numeric_value() > ConfidenceLevel::Low.numeric_value());
    }
    
    #[test]
    fn test_leftover_item_creation() {
        let file_item = LeftoverItem::file(
            "C:\\Program Files\\TestApp\\leftover.dll".to_string(),
            ConfidenceLevel::High,
            "File system scan".to_string(),
        );
        
        assert_eq!(file_item.kind, LeftoverKind::File);
        assert_eq!(file_item.confidence, ConfidenceLevel::High);
        assert!(file_item.description().contains("High confidence"));
    }
}