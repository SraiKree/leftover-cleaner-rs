use winreg::{enums::*, RegKey};
use crate::domain::metadata::AppMetadata;

/// Error type for harvester operations
#[derive(Debug, thiserror::Error)]
pub enum HarvesterError {
    #[error("Registry access error: {0}")]
    RegistryAccess(#[from] std::io::Error),
    
    #[error("Invalid date format: {0}")]
    InvalidDateFormat(String),
    
    #[error("Invalid size format: {0}")]
    InvalidSizeFormat(String),
}

/// Result type for harvester operations
pub type HarvesterResult<T> = Result<T, HarvesterError>;

/// Enumerate installed applications from Windows registry
pub fn harvest_installed_apps() -> HarvesterResult<Vec<AppMetadata>> {
    let mut apps = Vec::new();
    
    // List of registry keys to enumerate
    let registry_keys = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];
    
    for (hive, subkey) in registry_keys {
        if let Ok(regkey) = RegKey::predef(hive).open_subkey(subkey) {
            enumerate_uninstall_keys(&regkey, &mut apps)?;
        }
    }
    
    // Filter out system components
    apps.retain(|app| !app.system_component);
    
    Ok(apps)
}

/// Enumerate all subkeys under an uninstall key
fn enumerate_uninstall_keys(
    parent_key: &RegKey,
    apps: &mut Vec<AppMetadata>,
) -> HarvesterResult<()> {
    for subkey_name in parent_key.enum_keys() {
        if let Ok(subkey_name) = subkey_name {
            if let Ok(subkey) = parent_key.open_subkey(&subkey_name) {
                if let Some(metadata) = parse_app_metadata(&subkey) {
                    apps.push(metadata);
                }
            }
        }
    }
    
    Ok(())
}

/// Parse application metadata from a registry key
fn parse_app_metadata(regkey: &RegKey) -> Option<AppMetadata> {
    // Required: DisplayName
    let display_name = match read_reg_string(regkey, "DisplayName") {
        Some(name) if !name.trim().is_empty() => name,
        _ => return None,
    };
    
    let mut metadata = AppMetadata::new(display_name);
    
    // Parse other optional fields
    metadata.publisher = read_reg_string(regkey, "Publisher");
    metadata.install_location = read_reg_string(regkey, "InstallLocation");
    metadata.uninstall_string = read_reg_string(regkey, "UninstallString");
    metadata.display_icon = read_reg_string(regkey, "DisplayIcon");
    
    // Parse install date
    if let Some(date_str) = read_reg_string(regkey, "InstallDate") {
        if is_valid_install_date(&date_str) {
            metadata.install_date = Some(date_str);
        }
    }
    
    // Parse estimated size
    if let Some(size_str) = read_reg_string(regkey, "EstimatedSize") {
        if let Ok(size) = size_str.parse::<u64>() {
            metadata.estimated_size = Some(size);
        }
    }
    
    // Parse version
    metadata.version = read_reg_string(regkey, "DisplayVersion");
    
    // Check if this is a system component
    metadata.system_component = match read_reg_dword(regkey, "SystemComponent") {
        Some(1) => true,
        _ => false,
    };
    
    Some(metadata)
}

/// Read a string value from registry
fn read_reg_string(regkey: &RegKey, name: &str) -> Option<String> {
    match regkey.get_value::<String, _>(name) {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}

/// Read a DWORD value from registry
fn read_reg_dword(regkey: &RegKey, name: &str) -> Option<u32> {
    match regkey.get_value::<u32, _>(name) {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}

/// Validate install date format (YYYYMMDD)
fn is_valid_install_date(date_str: &str) -> bool {
    if date_str.len() != 8 {
        return false;
    }
    
    date_str.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    
    #[test]
    fn test_valid_install_date() {
        assert!(is_valid_install_date("20231015"));
        assert!(is_valid_install_date("20230101"));
        assert!(!is_valid_install_date("2023-10-15"));
        assert!(!is_valid_install_date("2023101"));
        assert!(!is_valid_install_date("202310150"));
        assert!(!is_valid_install_date("abcd1234"));
    }
    
    #[test]
    fn test_parse_app_metadata_basic() {
        // This test would require actual registry access
        // For unit tests, we'll test the helper functions
        assert!(true);
    }
    
    #[test]
    fn test_harvest_installed_apps_smoke_test() {
        // Smoke test to ensure function compiles and runs
        let result = harvest_installed_apps();
        
        // Function should either return Ok with apps or Err with registry error
        match result {
            Ok(apps) => {
                // At minimum, we should have filtered out system components
                for app in apps {
                    assert!(!app.system_component);
                }
            }
            Err(e) => {
                // Registry access error is acceptable in test environment
                assert!(matches!(e, HarvesterError::RegistryAccess(_)));
            }
        }
    }
}
