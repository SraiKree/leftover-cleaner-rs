use crate::domain::error::{CleanError, DomainError};
use crate::domain::leftover::{LeftoverItem, LeftoverKind};
use tracing::{debug, info, warn};
use winreg::enums::*;
use winreg::RegKey;

use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows::core::PCWSTR;

/// Safe deletion engine for files and registry entries
pub struct SafeDeletionEngine {
    /// Track deleted items for reporting
    deleted_items: Vec<LeftoverItem>,
    /// Track items scheduled for reboot deletion
    reboot_scheduled: Vec<LeftoverItem>,
    /// Track failed deletions
    failed_items: Vec<(LeftoverItem, String)>,
}

impl SafeDeletionEngine {
    /// Create new deletion engine
    pub fn new() -> Self {
        Self {
            deleted_items: Vec::new(),
            reboot_scheduled: Vec::new(),
            failed_items: Vec::new(),
        }
    }

    /// Delete selected leftover items
    /// Order: registry values → registry keys → files → directories
    pub fn delete_leftovers(&mut self, leftovers: Vec<LeftoverItem>) -> Result<DeletionReport, DomainError> {
        info!("Starting deletion of {} leftover items", leftovers.len());

        // Separate by type for correct deletion order
        let mut reg_values = Vec::new();
        let mut reg_keys = Vec::new();
        let mut files = Vec::new();
        let mut directories = Vec::new();

        for item in leftovers {
            match item.kind {
                LeftoverKind::RegistryValue => reg_values.push(item),
                LeftoverKind::RegistryKey => reg_keys.push(item),
                LeftoverKind::File => files.push(item),
                LeftoverKind::Directory => directories.push(item),
            }
        }

        // Delete in safe order
        self.delete_registry_values(&reg_values)?;
        self.delete_registry_keys(&reg_keys)?;
        self.delete_files(&files)?;
        self.delete_directories(&directories)?;

        Ok(self.generate_report())
    }

    /// Delete registry values
    fn delete_registry_values(&mut self, items: &[LeftoverItem]) -> Result<(), DomainError> {
        for item in items {
            debug!("Deleting registry value: {}", item.path);
            match self.delete_registry_value(&item.path) {
                Ok(_) => {
                    info!("Deleted registry value: {}", item.path);
                    self.deleted_items.push(item.clone());
                }
                Err(e) => {
                    warn!("Failed to delete registry value {}: {}", item.path, e);
                    self.failed_items.push((item.clone(), e.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Delete registry keys (recursively, bottom-up)
    fn delete_registry_keys(&mut self, items: &[LeftoverItem]) -> Result<(), DomainError> {
        // Sort by depth (deepest first) to ensure bottom-up deletion
        let mut sorted_items: Vec<_> = items.iter().collect();
        sorted_items.sort_by(|a, b| {
            let depth_a = a.path.matches('\\').count();
            let depth_b = b.path.matches('\\').count();
            depth_b.cmp(&depth_a) // Reverse order (deepest first)
        });

        for item in sorted_items {
            debug!("Deleting registry key: {}", item.path);
            match self.delete_registry_key(&item.path) {
                Ok(_) => {
                    info!("Deleted registry key: {}", item.path);
                    self.deleted_items.push(item.clone());
                }
                Err(e) => {
                    warn!("Failed to delete registry key {}: {}", item.path, e);
                    self.failed_items.push((item.clone(), e.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Delete files
    fn delete_files(&mut self, items: &[LeftoverItem]) -> Result<(), DomainError> {
        for item in items {
            debug!("Deleting file: {}", item.path);
            match std::fs::remove_file(&item.path) {
                Ok(_) => {
                    info!("Deleted file: {}", item.path);
                    self.deleted_items.push(item.clone());
                }
                Err(e) if self.is_file_locked(&e) => {
                    // File locked, schedule for reboot deletion
                    warn!("File locked {}, scheduling for reboot deletion", item.path);
                    match self.schedule_reboot_deletion(&item.path) {
                        Ok(_) => {
                            info!("Scheduled file for reboot deletion: {}", item.path);
                            self.reboot_scheduled.push(item.clone());
                        }
                        Err(sched_err) => {
                            warn!("Failed to schedule reboot deletion for {}: {}", item.path, sched_err);
                            self.failed_items.push((item.clone(), format!("Locked and schedule failed: {}", sched_err)));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to delete file {}: {}", item.path, e);
                    self.failed_items.push((item.clone(), e.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Delete directories (only if empty)
    fn delete_directories(&mut self, items: &[LeftoverItem]) -> Result<(), DomainError> {
        // Sort by depth (deepest first) to ensure bottom-up deletion
        let mut sorted_items: Vec<_> = items.iter().collect();
        sorted_items.sort_by(|a, b| {
            let depth_a = a.path.matches('\\').count();
            let depth_b = b.path.matches('\\').count();
            depth_b.cmp(&depth_a) // Reverse order (deepest first)
        });

        for item in sorted_items {
            debug!("Deleting directory: {}", item.path);
            match std::fs::remove_dir(&item.path) {
                Ok(_) => {
                    info!("Deleted directory: {}", item.path);
                    self.deleted_items.push(item.clone());
                }
                Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                    // Try recursive removal if directory not empty
                    match std::fs::remove_dir_all(&item.path) {
                        Ok(_) => {
                            info!("Recursively deleted directory: {}", item.path);
                            self.deleted_items.push(item.clone());
                        }
                        Err(e2) => {
                            warn!("Failed to delete directory {}: {}", item.path, e2);
                            self.failed_items.push((item.clone(), e2.to_string()));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to delete directory {}: {}", item.path, e);
                    self.failed_items.push((item.clone(), e.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Delete a single registry value
    fn delete_registry_value(&self, path: &str) -> Result<(), CleanError> {
        let (root, subkey_and_value) = self.parse_registry_path(path)?;
        
        // Split subkey and value name
        let parts: Vec<&str> = subkey_and_value.rsplitn(2, '\\').collect();
        if parts.len() != 2 {
            return Err(CleanError::RegistryValueDeletion(format!("Invalid registry value path: {}", path)));
        }
        
        let value_name = parts[0];
        let subkey_path = parts[1];
        
        let root_key = self.get_root_key(root)?;
        let key = RegKey::predef(root_key).open_subkey_with_flags(subkey_path, KEY_SET_VALUE)
            .map_err(|e| CleanError::RegistryValueDeletion(format!("Cannot open key: {}", e)))?;
        
        key.delete_value(value_name)
            .map_err(|e| CleanError::RegistryValueDeletion(format!("Cannot delete value: {}", e)))?;
        
        Ok(())
    }

    /// Delete a registry key recursively
    fn delete_registry_key(&self, path: &str) -> Result<(), CleanError> {
        let (root, subkey_path) = self.parse_registry_path(path)?;
        
        // Split parent and key name
        let parts: Vec<&str> = subkey_path.rsplitn(2, '\\').collect();
        if parts.is_empty() {
            return Err(CleanError::RegistryKeyDeletion(format!("Invalid registry key path: {}", path)));
        }
        
        let root_key = self.get_root_key(root)?;
        
        if parts.len() == 1 {
            // Root-level key
            let key_name = parts[0];
            RegKey::predef(root_key).delete_subkey_all(key_name)
                .map_err(|e| CleanError::RegistryKeyDeletion(format!("Cannot delete key: {}", e)))?;
        } else {
            // Nested key
            let key_name = parts[0];
            let parent_path = parts[1];
            let parent = RegKey::predef(root_key).open_subkey_with_flags(parent_path, KEY_SET_VALUE)
                .map_err(|e| CleanError::RegistryKeyDeletion(format!("Cannot open parent key: {}", e)))?;
            
            parent.delete_subkey_all(key_name)
                .map_err(|e| CleanError::RegistryKeyDeletion(format!("Cannot delete key: {}", e)))?;
        }
        
        Ok(())
    }

    /// Parse registry path into root and subkey
    fn parse_registry_path<'a>(&self, path: &'a str) -> Result<(&'a str, &'a str), CleanError> {
        let parts: Vec<&str> = path.splitn(2, '\\').collect();
        if parts.len() != 2 {
            return Err(CleanError::RegistryKeyDeletion(format!("Invalid registry path: {}", path)));
        }
        Ok((parts[0], parts[1]))
    }

    /// Get winreg root key from string
    fn get_root_key(&self, root: &str) -> Result<winreg::HKEY, CleanError> {
        match root {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Ok(HKEY_LOCAL_MACHINE),
            "HKEY_CURRENT_USER" | "HKCU" => Ok(HKEY_CURRENT_USER),
            "HKEY_CLASSES_ROOT" | "HKCR" => Ok(HKEY_CLASSES_ROOT),
            "HKEY_USERS" | "HKU" => Ok(HKEY_USERS),
            _ => Err(CleanError::RegistryKeyDeletion(format!("Unknown registry root: {}", root))),
        }
    }

    /// Check if error indicates file is locked
    fn is_file_locked(&self, error: &std::io::Error) -> bool {
        matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
    }

    /// Schedule file for deletion on next reboot using MoveFileExW
    fn schedule_reboot_deletion(&self, path: &str) -> Result<(), CleanError> {
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        
        unsafe {
            let result = MoveFileExW(
                PCWSTR(path_wide.as_ptr()),
                PCWSTR::null(),
                MOVEFILE_DELAY_UNTIL_REBOOT,
            );
            
            if result.is_ok() {
                Ok(())
            } else {
                Err(CleanError::ResourceInUse(format!("Failed to schedule reboot deletion: {}", path)))
            }
        }
    }

    /// Generate deletion report
    fn generate_report(&self) -> DeletionReport {
        DeletionReport {
            deleted_count: self.deleted_items.len(),
            reboot_scheduled_count: self.reboot_scheduled.len(),
            failed_count: self.failed_items.len(),
            deleted_items: self.deleted_items.clone(),
            reboot_scheduled: self.reboot_scheduled.clone(),
            failed_items: self.failed_items.clone(),
        }
    }
}

impl Default for SafeDeletionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Report of deletion operation
#[derive(Debug, Clone)]
pub struct DeletionReport {
    pub deleted_count: usize,
    pub reboot_scheduled_count: usize,
    pub failed_count: usize,
    pub deleted_items: Vec<LeftoverItem>,
    pub reboot_scheduled: Vec<LeftoverItem>,
    pub failed_items: Vec<(LeftoverItem, String)>,
}

impl DeletionReport {
    /// Get total bytes freed (estimated)
    pub fn total_bytes_freed(&self) -> u64 {
        // TODO: Track actual file sizes during scanning
        0
    }

    /// Print summary to console
    pub fn print_summary(&self) {
        info!("=== Deletion Summary ===");
        info!("Successfully deleted: {} items", self.deleted_count);
        if self.reboot_scheduled_count > 0 {
            info!("Scheduled for reboot deletion: {} items", self.reboot_scheduled_count);
        }
        if self.failed_count > 0 {
            warn!("Failed to delete: {} items", self.failed_count);
            for (item, reason) in &self.failed_items {
                warn!("  - {}: {}", item.path, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deletion_engine_creation() {
        let engine = SafeDeletionEngine::new();
        assert_eq!(engine.deleted_items.len(), 0);
        assert_eq!(engine.reboot_scheduled.len(), 0);
        assert_eq!(engine.failed_items.len(), 0);
    }

    #[test]
    fn test_parse_registry_path() {
        let engine = SafeDeletionEngine::new();
        let result = engine.parse_registry_path("HKLM\\Software\\TestApp");
        assert!(result.is_ok());
        let (root, subkey) = result.unwrap();
        assert_eq!(root, "HKLM");
        assert_eq!(subkey, "Software\\TestApp");
    }

    #[test]
    fn test_get_root_key() {
        let engine = SafeDeletionEngine::new();
        assert!(engine.get_root_key("HKLM").is_ok());
        assert!(engine.get_root_key("HKEY_LOCAL_MACHINE").is_ok());
        assert!(engine.get_root_key("HKCU").is_ok());
        assert!(engine.get_root_key("INVALID").is_err());
    }
}
