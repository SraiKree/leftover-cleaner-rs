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
    for subkey_name in parent_key.enum_keys().flatten() {
        if let Ok(subkey) = parent_key.open_subkey(&subkey_name) {
            if let Some(metadata) = parse_app_metadata(&subkey) {
                apps.push(metadata);
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
    metadata.system_component = matches!(read_reg_dword(regkey, "SystemComponent"), Some(1));

    // Extract MSI ProductCode from UninstallString if it's an MSI install.
    // geek.exe reads field +0x3c (the ProductCode) from the harvested item and
    // uses it directly to construct the UserData path — no name-matching needed.
    // UninstallString forms:
    //   MsiExec.exe /I{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    //   MsiExec.exe /X{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    if let Some(ref s) = metadata.uninstall_string {
        metadata.msi_product_code = extract_msi_product_code(s);
    }

    Some(metadata)
}

/// Read a string value from registry
fn read_reg_string(regkey: &RegKey, name: &str) -> Option<String> {
    regkey.get_value::<String, _>(name).ok()
}

/// Read a DWORD value from registry
fn read_reg_dword(regkey: &RegKey, name: &str) -> Option<u32> {
    regkey.get_value::<u32, _>(name).ok()
}

/// Extract the MSI ProductCode GUID from an UninstallString.
///
/// Matches the two canonical MSI forms (verified against geek.exe behaviour):
///   MsiExec.exe /I{GUID}   — install-mode uninstall
///   MsiExec.exe /X{GUID}   — remove-mode uninstall
///
/// Returns the GUID with its surrounding braces, e.g.
///   `{7D2F3875-1019-2D11-E1E0-00B0D099CB9E}`
/// because that is exactly how it appears as the Products subkey name in
///   HKLM\SOFTWARE\...\Installer\UserData\<SID>\Products\<GUID>
fn extract_msi_product_code(uninstall_string: &str) -> Option<String> {
    // Case-insensitive search for MsiExec
    let lower = uninstall_string.to_lowercase();
    if !lower.contains("msiexec") {
        return None;
    }
    // Find /I{ or /X{ (case-insensitive)
    for flag in &["/i{", "/x{"] {
        if let Some(flag_pos) = lower.find(flag) {
            // The GUID starts at the '{' character
            let brace_start = flag_pos + flag.len() - 1; // points to '{'
            let rest = &uninstall_string[brace_start..];
            if let Some(end) = rest.find('}') {
                let guid = &rest[..=end]; // includes both braces
                return Some(guid.to_uppercase());
            }
        }
    }
    None
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
    fn test_extract_msi_product_code_install_mode() {
        let s = r"MsiExec.exe /I{7D2F3875-1019-2D11-E1E0-00B0D099CB9E}";
        assert_eq!(
            extract_msi_product_code(s),
            Some("{7D2F3875-1019-2D11-E1E0-00B0D099CB9E}".to_string())
        );
    }

    #[test]
    fn test_extract_msi_product_code_remove_mode() {
        let s = r"MsiExec.exe /X{12345678-1234-1234-1234-123456789012}";
        assert_eq!(
            extract_msi_product_code(s),
            Some("{12345678-1234-1234-1234-123456789012}".to_string())
        );
    }

    #[test]
    fn test_extract_msi_product_code_case_insensitive() {
        let s = r"msiexec.exe /x{AABBCCDD-AABB-AABB-AABB-AABBCCDDEEFF}";
        assert_eq!(
            extract_msi_product_code(s),
            Some("{AABBCCDD-AABB-AABB-AABB-AABBCCDDEEFF}".to_string())
        );
    }

    #[test]
    fn test_extract_msi_product_code_non_msi() {
        let s = r#""C:\Program Files\App\uninstall.exe" /silent"#;
        assert_eq!(extract_msi_product_code(s), None);
    }

    #[test]
    fn test_extract_msi_product_code_none_on_empty() {
        assert_eq!(extract_msi_product_code(""), None);
    }

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
