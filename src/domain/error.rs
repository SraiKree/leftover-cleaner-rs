use std::io;
use thiserror::Error;

/// Main domain error type that encompasses all domain-specific errors
#[derive(Error, Debug)]
pub enum DomainError {
    /// Scanner-related errors
    #[error("Scanner error: {0}")]
    Scanner(#[from] ScannerError),
    
    /// Process-related errors
    #[error("Process error: {0}")]
    Process(#[from] ProcessError),
    
    /// Cleanup-related errors
    #[error("Clean error: {0}")]
    Clean(#[from] CleanError),
    
    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    /// Windows API errors
    #[error("Windows API error: {0}")]
    Windows(String),
    
    /// Invalid state transition
    #[error("Invalid state transition: {0}")]
    InvalidState(String),
}

/// Scanner-related errors
#[derive(Error, Debug)]
pub enum ScannerError {
    /// Failed to read registry
    #[error("Failed to read registry: {0}")]
    RegistryRead(String),
    
    /// Failed to parse registry data
    #[error("Failed to parse registry data: {0}")]
    RegistryParse(String),
    
    /// Failed to scan filesystem
    #[error("Failed to scan filesystem: {0}")]
    FilesystemScan(String),
    
    /// Failed to access Windows Installer database
    #[error("Failed to access Windows Installer database: {0}")]
    MsiAccess(String),
    
    /// Invalid path encountered during scanning
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    
    /// Access denied during scanning
    #[error("Access denied while scanning: {0}")]
    AccessDenied(String),
}

/// Process-related errors
#[derive(Error, Debug)]
pub enum ProcessError {
    /// Failed to create job object
    #[error("Failed to create job object: {0}")]
    JobObjectCreation(String),
    
    /// Failed to assign process to job object
    #[error("Failed to assign process to job object: {0}")]
    JobAssignment(String),
    
    /// Process execution failed
    #[error("Process execution failed: {0}")]
    Execution(String),
    
    /// Process timeout
    #[error("Process timeout: {0}")]
    Timeout(String),
    
    /// Failed to terminate process
    #[error("Failed to terminate process: {0}")]
    Termination(String),
}

/// Cleanup-related errors
#[derive(Error, Debug)]
pub enum CleanError {
    /// Failed to delete file
    #[error("Failed to delete file: {0}")]
    FileDeletion(String),
    
    /// Failed to delete directory
    #[error("Failed to delete directory: {0}")]
    DirectoryDeletion(String),
    
    /// Failed to delete registry value
    #[error("Failed to delete registry value: {0}")]
    RegistryValueDeletion(String),
    
    /// Failed to delete registry key
    #[error("Failed to delete registry key: {0}")]
    RegistryKeyDeletion(String),
    
    /// Safety check failed
    #[error("Safety check failed: {0}")]
    SafetyCheck(String),
    
    /// Resource in use
    #[error("Resource in use: {0}")]
    ResourceInUse(String),
    
    /// Insufficient permissions
    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),
}

impl From<DomainError> for io::Error {
    fn from(err: DomainError) -> Self {
        io::Error::other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversions() {
        let scanner_err = ScannerError::RegistryRead("Failed to open key".to_string());
        let domain_err: DomainError = scanner_err.into();
        
        match domain_err {
            DomainError::Scanner(_) => (),
            _ => panic!("Expected Scanner variant"),
        }
        
        assert!(domain_err.to_string().contains("Scanner error"));
    }
    
    #[test]
    fn test_error_display() {
        let clean_err = CleanError::FileDeletion("Access denied".to_string());
        let err_str = clean_err.to_string();
        
        assert!(err_str.contains("Failed to delete file"));
        assert!(err_str.contains("Access denied"));
    }
}