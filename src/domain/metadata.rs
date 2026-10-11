use std::path::PathBuf;
use serde::{Serialize, Deserialize};

/// Application metadata extracted from Windows registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMetadata {
    /// Display name of the application
    pub display_name: String,
    
    /// Publisher name (optional)
    pub publisher: Option<String>,
    
    /// Installation location (optional)
    pub install_location: Option<String>,
    
    /// Uninstall command string (optional)
    pub uninstall_string: Option<String>,
    
    /// Path to display icon (optional)
    pub display_icon: Option<String>,
    
    /// Installation date (optional)
    pub install_date: Option<String>,
    
    /// Estimated size in bytes (optional)
    pub estimated_size: Option<u64>,
    
    /// Application version (optional)
    pub version: Option<String>,
    
    /// Whether this is a system component
    pub system_component: bool,

    /// MSI ProductCode GUID, extracted from UninstallString when it contains
    /// `MsiExec.exe /I{GUID}` or `MsiExec.exe /X{GUID}`.
    /// This is the exact key used in:
    ///   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\<SID>\Products\<msi_product_code>
    /// Only present for MSI-installed applications.
    pub msi_product_code: Option<String>,
}

impl AppMetadata {
    /// Create a new AppMetadata with required display name
    pub fn new(display_name: String) -> Self {
        Self {
            display_name,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            display_icon: None,
            install_date: None,
            estimated_size: None,
            version: None,
            system_component: false,
            msi_product_code: None,
        }
    }
    
    /// Check if the application has an install location
    pub fn has_install_location(&self) -> bool {
        self.install_location.is_some()
    }
    
    /// Get the install location as a PathBuf if it exists
    pub fn install_location_path(&self) -> Option<PathBuf> {
        self.install_location.as_ref().map(PathBuf::from)
    }
    
    /// Check if the application can be uninstalled (has uninstall string)
    pub fn can_be_uninstalled(&self) -> bool {
        self.uninstall_string.is_some()
    }
    
    /// Get a short description of the application
    pub fn short_description(&self) -> String {
        let mut desc = self.display_name.clone();
        
        if let Some(publisher) = &self.publisher {
            desc.push_str(&format!(" by {}", publisher));
        }
        
        if let Some(version) = &self.version {
            desc.push_str(&format!(" (v{})", version));
        }
        
        desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_metadata_creation() {
        let metadata = AppMetadata::new("Test Application".to_string());
        
        assert_eq!(metadata.display_name, "Test Application");
        assert_eq!(metadata.publisher, None);
        assert_eq!(metadata.system_component, false);
    }
    
    #[test]
    fn test_short_description() {
        let mut metadata = AppMetadata::new("Test Application".to_string());
        metadata.publisher = Some("Test Corp".to_string());
        metadata.version = Some("1.0.0".to_string());
        
        let desc = metadata.short_description();
        assert!(desc.contains("Test Application"));
        assert!(desc.contains("Test Corp"));
        assert!(desc.contains("v1.0.0"));
    }
    
    #[test]
    fn test_install_location() {
        let mut metadata = AppMetadata::new("Test Application".to_string());
        
        assert!(!metadata.has_install_location());
        assert!(metadata.install_location_path().is_none());
        
        metadata.install_location = Some("C:\\Program Files\\TestApp".to_string());
        
        assert!(metadata.has_install_location());
        assert!(metadata.install_location_path().is_some());
    }
}