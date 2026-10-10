use std::path::{Path, PathBuf};
use regex::Regex;
use strsim::normalized_levenshtein;
use crate::domain::metadata::AppMetadata;

/// Error type for resolver operations
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("Failed to parse uninstall string: {0}")]
    UninstallStringParse(String),
    
    #[error("Install location not found for: {0}")]
    LocationNotFound(String),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Result type for resolver operations
pub type ResolverResult<T> = Result<T, ResolverError>;

/// Resolve the installation location for an application
/// Uses a two-fallback strategy:
/// 1. Parse uninstall string to extract parent directory
/// 2. Use fuzzy matching to find matching directory
pub fn resolve_install_location(app: &AppMetadata) -> ResolverResult<PathBuf> {
    // Fallback 1: Try to parse from uninstall string
    if let Some(location) = parse_install_location_from_uninstall(app) {
        if validate_install_location(&location) {
            return Ok(location);
        }
    }
    
    // Fallback 2: Use fuzzy matching
    if let Some(location) = fuzzy_match_install_location(app) {
        if validate_install_location(&location) {
            return Ok(location);
        }
    }
    
    Err(ResolverError::LocationNotFound(app.display_name.clone()))
}

/// Parse install location from uninstall string
fn parse_install_location_from_uninstall(app: &AppMetadata) -> Option<PathBuf> {
    let uninstall_string = app.uninstall_string.as_ref()?;
    
    // Clean the entire uninstall string first
    let mut clean_string = uninstall_string.clone();
    clean_uninstall_path(&mut clean_string);
    
    // Check if the cleaned string ends with .exe
    if clean_string.ends_with(".exe") {
        if let Some(parent) = PathBuf::from(&clean_string).parent() {
            return Some(parent.to_path_buf());
        }
    }
    
    // Try to extract .exe from the original string (before cleaning)
    if let Some(exe_pos) = uninstall_string.find(".exe") {
        // Try to find the start of the path
        let start = if let Some(quote_start) = uninstall_string[..exe_pos].rfind('"') {
            quote_start + 1
        } else {
            // Find the last whitespace before .exe
            let before_exe = &uninstall_string[..exe_pos];
            if let Some(ws_pos) = before_exe.rfind(char::is_whitespace) {
                ws_pos + 1
            } else {
                0
            }
        };
        
        if start < exe_pos {
            let exe_path = &uninstall_string[start..exe_pos + 4];
            let mut clean_exe = exe_path.to_string();
            clean_uninstall_path(&mut clean_exe);
            
            if let Some(parent) = PathBuf::from(&clean_exe).parent() {
                return Some(parent.to_path_buf());
            }
        }
    }
    
    None
}

/// Clean up common arguments and quotes from uninstall path
fn clean_uninstall_path(path: &mut String) {
    // Special case for MSI uninstall strings - they don't contain install location
    if path.contains("MsiExec.exe") {
        path.clear();
        return;
    }
    
    // Remove common arguments first (handle both with and without quotes)
    let args_to_remove = [
        " /uninstall",
        " /silent",
        " /quiet",
        " /S",
        " /X",
        " /I",
        " -uninstall",
        " -silent",
        " -quiet",
    ];
    
    for arg in args_to_remove {
        if let Some(pos) = path.find(arg) {
            path.truncate(pos);
        }
    }
    
    // Remove quotes that might be around the entire path
    if path.starts_with('"') && path.ends_with('"') {
        *path = path[1..path.len() - 1].to_string();
    }
    
    // Trim any remaining whitespace
    *path = path.trim().to_string();
}

/// Sanitize display name for fuzzy matching
fn sanitize_display_name(display_name: &str) -> String {
    let mut sanitized = display_name.to_string();
    
    // Remove version numbers (e.g., "App v1.2.3", "App 2.0")
    let version_patterns = [
        r"\s*v?\d+\.\d+(?:\.\d+)?(?:\s+|$)",
        r"\s*\d+\.\d+(?:\.\d+)?(?:\s+|$)",
        r"\s*\(v?\d+\.\d+(?:\.\d+)?\)",
        r"\s*\[\d+\.\d+(?:\.\d+)?\]",
    ];
    
    for pattern in version_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            sanitized = regex.replace_all(&sanitized, "").to_string();
        }
    }
    
    // Remove common edition suffixes
    let edition_patterns = [
        r"\s*(?:Professional|Pro|Enterprise|Ultimate|Home|Basic|Standard|Premium)(?:\s+|$)",
        r"\s*(?:Edition|Version|Release)(?:\s+|$)",
        r"\s*\(.*?\)(?:\s+|$)",
        r"\s*\[.*?\](?:\s+|$)",
    ];
    
    for pattern in edition_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            sanitized = regex.replace_all(&sanitized, "").to_string();
        }
    }
    
    // Trim and return
    sanitized.trim().to_string()
}

/// Use fuzzy matching to find install location
fn fuzzy_match_install_location(app: &AppMetadata) -> Option<PathBuf> {
    let sanitized_name = sanitize_display_name(&app.display_name);
    if sanitized_name.is_empty() {
        return None;
    }
    
    // Standard Windows installation directories
    let standard_dirs = [
        PathBuf::from(std::env::var("ProgramFiles").unwrap_or(r"C:\Program Files".to_string())),
        PathBuf::from(std::env::var("ProgramFiles(x86)").unwrap_or(r"C:\Program Files (x86)".to_string())),
        PathBuf::from(std::env::var("LocalAppData").unwrap_or(r"C:\Users\USERNAME\AppData\Local".to_string()))
            .join("Programs"),
        PathBuf::from(r"C:\ProgramData"),
    ];
    
    // Search for matching directories
    for base_dir in standard_dirs {
        if let Ok(entries) = std::fs::read_dir(&base_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let dir_name = entry.file_name().to_string_lossy().to_string();
                        let similarity = normalized_levenshtein(&sanitized_name, &dir_name);
                        
                        if similarity >= 0.82 {
                            return Some(entry.path());
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Validate that a location exists and is a directory
fn validate_install_location(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::metadata::AppMetadata;
    
    #[test]
    fn test_sanitize_display_name() {
        assert_eq!(
            sanitize_display_name("MyApp v1.2.3 Professional Edition"),
            "MyApp"
        );
        
        assert_eq!(
            sanitize_display_name("MyApp 2.0 (64-bit)"),
            "MyApp"
        );
        
        assert_eq!(
            sanitize_display_name("MyApp [2023 Release]"),
            "MyApp"
        );
        
        assert_eq!(
            sanitize_display_name("Simple App"),
            "Simple App"
        );
    }
    
    #[test]
    fn test_clean_uninstall_path() {
        let test_cases = [
            (r#""C:\Program Files\App\uninstall.exe" /silent"#.to_string(), r#"C:\Program Files\App\uninstall.exe"#),
            (r#"C:\Program Files\App\uninstall.exe /quiet"#.to_string(), r#"C:\Program Files\App\uninstall.exe"#),
            (r#"C:\Program Files\App\uninstall.exe -uninstall"#.to_string(), r#"C:\Program Files\App\uninstall.exe"#),
            (r#"C:\Program Files\App\uninstall.exe"#.to_string(), r#"C:\Program Files\App\uninstall.exe"#),
        ];
        
        for (mut input, expected) in test_cases {
            clean_uninstall_path(&mut input);
            assert_eq!(input, expected);
        }
    }
    
    #[test]
    fn test_parse_install_location_from_uninstall() {
        let mut app = AppMetadata::new("TestApp".to_string());
        
        // Test quoted path with arguments
        app.uninstall_string = Some(r#""C:\Program Files\TestApp\uninstall.exe" /S"#.to_string());
        let result = parse_install_location_from_uninstall(&app);
        assert_eq!(result, Some(PathBuf::from(r"C:\Program Files\TestApp")));
        
        // Test unquoted path
        app.uninstall_string = Some(r#"C:\Program Files\TestApp\uninstall.exe /silent"#.to_string());
        let result = parse_install_location_from_uninstall(&app);
        assert_eq!(result, Some(PathBuf::from(r"C:\Program Files\TestApp")));
        
        // Test MSI uninstall string
        app.uninstall_string = Some(r#"MsiExec.exe /I{12345678-1234-1234-1234-123456789012}"#.to_string());
        let result = parse_install_location_from_uninstall(&app);
        assert!(result.is_none()); // MSI strings don't give us install location
        
        // Test no uninstall string
        app.uninstall_string = None;
        let result = parse_install_location_from_uninstall(&app);
        assert!(result.is_none());
    }
    
    #[test]
    fn test_validate_install_location() {
        // Test with a non-existent path
        let fake_path = Path::new(r"C:\This\Path\Does\Not\Exist");
        assert!(!validate_install_location(fake_path));
        
        // Test with current directory (should exist)
        let current_dir = Path::new(".");
        assert!(validate_install_location(current_dir));
    }
    
    #[test]
    fn test_fuzzy_matching_similarity() {
        // Test similarity calculation
        let name1 = "Google Chrome";
        let name2 = "Google Chrme";
        let similarity = normalized_levenshtein(name1, name2);
        
        // Should be reasonably similar
        assert!(similarity > 0.8);
    }
}
