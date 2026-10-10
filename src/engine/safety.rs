// Safety validation before any deletion.
// Two checks:
//   1. Blacklist — block system-critical paths (exact + prefix)
//   2. SharedDLLs — DLLs with ref-count > 0 in registry = shared, block
//
// Confidence assignment:
//   install location match  → High
//   AppData match           → Medium
//   CLSID / other           → Low

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

use crate::domain::{
    error::CleanError,
    leftover::{ConfidenceLevel, LeftoverItem, LeftoverKind},
};

// Source tag constants used by scanners
pub const SOURCE_INSTALL_PATH: &str = "Install path";
pub const SOURCE_APPDATA: &str = "AppData";
pub const SOURCE_CLSID: &str = "CLSID";

// Registry path for shared DLL reference counts
const SHARED_DLLS_KEY: &str =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs";

/// Classifies a path by its detection source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionSource {
    /// Matches app's recorded install location — most trustworthy
    InstallPath,
    /// Found in user/app data directories
    AppData,
    /// Found via CLSID / COM registration
    Clsid,
    /// Custom source string (passed through as Low)
    Other(String),
}

impl DetectionSource {
    /// Map source tag string (from LeftoverItem.source) to enum variant
    pub fn from_source_str(s: &str) -> Self {
        match s {
            SOURCE_INSTALL_PATH => DetectionSource::InstallPath,
            SOURCE_APPDATA => DetectionSource::AppData,
            SOURCE_CLSID => DetectionSource::Clsid,
            other => DetectionSource::Other(other.to_string()),
        }
    }

    /// Confidence level for this source
    pub fn confidence(&self) -> ConfidenceLevel {
        match self {
            DetectionSource::InstallPath => ConfidenceLevel::High,
            DetectionSource::AppData => ConfidenceLevel::Medium,
            DetectionSource::Clsid | DetectionSource::Other(_) => ConfidenceLevel::Low,
        }
    }
}

/// Validates candidate leftovers before deletion.
pub struct SafetyValidator {
    // Canonical absolute paths that must never be deleted
    blacklist: HashSet<PathBuf>,
}

impl SafetyValidator {
    /// Build validator with default Windows system blacklist.
    pub fn new() -> Self {
        Self {
            blacklist: default_blacklist(),
        }
    }

    /// Validate one leftover item.
    /// Returns Err if blocked, Ok(()) if safe to proceed.
    pub fn validate(&self, item: &LeftoverItem) -> Result<(), CleanError> {
        // Registry items don't go through path blacklist or shared-dll check
        if item.kind.is_registry() {
            return Ok(());
        }

        let raw_path = Path::new(&item.path);

        // Canonicalize if path exists; else use raw (may not exist yet)
        let canonical = std::fs::canonicalize(raw_path).unwrap_or_else(|_| raw_path.to_path_buf());
        let canonical = normalize_path(&canonical);

        // Exact match check
        if self.blacklist.contains(&canonical) {
            return Err(CleanError::SafetyCheck(format!(
                "Blacklisted path (exact): {}",
                canonical.display()
            )));
        }

        // Prefix match — block anything inside a blacklisted directory
        for blocked in &self.blacklist {
            if canonical.starts_with(blocked) {
                return Err(CleanError::SafetyCheck(format!(
                    "Path inside blacklisted dir: {} (blocked by {})",
                    canonical.display(),
                    blocked.display()
                )));
            }
        }

        // SharedDLLs check only applies to .dll files
        if item.kind == LeftoverKind::File {
            if let Some(ext) = raw_path.extension() {
                if ext.eq_ignore_ascii_case("dll") {
                    self.check_shared_dll(raw_path)?;
                }
            }
        }

        Ok(())
    }

    /// Check HKLM SharedDLLs registry — if ref count > 0, it's in use.
    fn check_shared_dll(&self, path: &Path) -> Result<(), CleanError> {
        let path_str = path.to_string_lossy().to_string();

        // Open key — if absent, no shared DLL entries at all → safe
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let shared_dlls = match hklm.open_subkey(SHARED_DLLS_KEY) {
            Ok(k) => k,
            Err(_) => return Ok(()), // key doesn't exist → not tracked
        };

        // Value name is the full path of the DLL; value is DWORD ref count
        match shared_dlls.get_value::<u32, _>(&path_str) {
            Ok(ref_count) if ref_count > 0 => Err(CleanError::SafetyCheck(format!(
                "Shared DLL in use (ref_count={}): {}",
                ref_count, path_str
            ))),
            Ok(_) => Ok(()), // ref count = 0 → no active users
            Err(_) => Ok(()), // not in SharedDLLs → not tracked
        }
    }

    /// Assign confidence to a leftover item based on its source tag.
    /// Mutates in place for convenience.
    pub fn assign_confidence(item: &mut LeftoverItem) {
        let source = DetectionSource::from_source_str(&item.source);
        item.confidence = source.confidence();
    }

    /// Batch validate: filter list to only safe items, log blocked ones.
    /// Returns (safe_items, blocked_count).
    pub fn filter_safe<'a>(
        &self,
        items: &'a [LeftoverItem],
    ) -> (Vec<&'a LeftoverItem>, usize) {
        let mut safe = Vec::new();
        let mut blocked = 0usize;

        for item in items {
            match self.validate(item) {
                Ok(()) => safe.push(item),
                Err(_e) => {
                    tracing::warn!("Blocked: {} — {}", item.path, _e);
                    blocked += 1;
                }
            }
        }

        (safe, blocked)
    }
}

impl Default for SafetyValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a Windows path for consistent comparison.
/// Strips \\?\ prefix (extended-length prefix from canonicalize) and lowercases.
fn normalize_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    // Strip \\?\ or \\?\ variations added by canonicalize
    let stripped = if let Some(s_stripped) = s.strip_prefix(r"\\?\") {
        s_stripped
    } else {
        s.as_ref()
    };
    // Lowercase for case-insensitive Windows comparison
    PathBuf::from(stripped.to_lowercase())
}

/// Hardcoded critical-path blacklist.
/// Paths are lowercase-normalised for case-insensitive prefix matching.
fn default_blacklist() -> HashSet<PathBuf> {
    // Collect %SystemDrive% (usually C:) and well-known system dirs
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| format!(r"{}\Windows", system_drive));
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| format!(r"{}\Program Files", system_drive));
    let program_files_x86 = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| format!(r"{}\Program Files (x86)", system_drive));
    let userprofile =
        std::env::var("USERPROFILE").unwrap_or_else(|_| format!(r"{}\Users", system_drive));

    let raw_paths = [
        // Drive root itself
        format!("{}\\", system_drive),
        system_drive.clone(),
        // Windows directories
        windir.clone(),
        format!(r"{}\System32", windir),
        format!(r"{}\SysWOW64", windir),
        format!(r"{}\WinSxS", windir),
        // Program Files roots (not individual app folders)
        program_files.clone(),
        program_files_x86.clone(),
        // Users root (not individual profiles)
        userprofile,
        // Fallbacks using literal paths
        r"C:\".to_string(),
        r"C:\Windows".to_string(),
        r"C:\Windows\System32".to_string(),
        r"C:\Windows\SysWOW64".to_string(),
        r"C:\Program Files".to_string(),
        r"C:\Program Files (x86)".to_string(),
        r"C:\Users".to_string(),
    ];

    raw_paths
        .iter()
        .map(|p| {
            let pb = PathBuf::from(p);
            // Canonicalize so paths match what validate() produces.
            // Fall back to raw if the path doesn't exist on this machine.
            let canonical = std::fs::canonicalize(&pb).unwrap_or(pb);
            normalize_path(&canonical)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_item(path: &str) -> LeftoverItem {
        LeftoverItem::file(
            path.to_string(),
            ConfidenceLevel::High,
            SOURCE_INSTALL_PATH.to_string(),
        )
    }

    fn make_dir_item(path: &str) -> LeftoverItem {
        LeftoverItem::directory(
            path.to_string(),
            ConfidenceLevel::High,
            SOURCE_INSTALL_PATH.to_string(),
        )
    }

    #[test]
    fn blacklist_blocks_exact_drive_root() {
        let validator = SafetyValidator::new();
        let item = make_dir_item(r"C:\");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_blocks_windows_dir() {
        let validator = SafetyValidator::new();
        let item = make_dir_item(r"C:\Windows");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_blocks_system32() {
        let validator = SafetyValidator::new();
        let item = make_dir_item(r"C:\Windows\System32");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_blocks_path_inside_system32() {
        let validator = SafetyValidator::new();
        // A file inside System32 should be blocked by prefix check
        let item = make_file_item(r"C:\Windows\System32\kernel32.dll");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_blocks_program_files_root() {
        let validator = SafetyValidator::new();
        let item = make_dir_item(r"C:\Program Files");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_blocks_path_under_program_files() {
        // C:\Program Files\SomeApp starts with C:\Program Files → blocked by prefix
        let validator = SafetyValidator::new();
        let item = make_dir_item(r"C:\Program Files\SomeApp");
        assert!(validator.validate(&item).is_err());
    }

    #[test]
    fn blacklist_allows_non_system_path() {
        let validator = SafetyValidator::new();
        // A temp path far from system dirs should pass
        let item = make_dir_item(r"D:\LeftoverApp\Residue");
        assert!(validator.validate(&item).is_ok());
    }

    #[test]
    fn registry_items_always_pass_blacklist() {
        let validator = SafetyValidator::new();
        let reg_item = LeftoverItem::registry_key(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\LeftoverApp".to_string(),
            ConfidenceLevel::High,
            SOURCE_INSTALL_PATH.to_string(),
        );
        // Registry items bypass path checks entirely
        assert!(validator.validate(&reg_item).is_ok());
    }

    #[test]
    fn confidence_assignment_install_path() {
        let mut item = LeftoverItem::file(
            r"C:\SomeApp\file.txt".to_string(),
            ConfidenceLevel::Low, // start Low
            SOURCE_INSTALL_PATH.to_string(),
        );
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn confidence_assignment_appdata() {
        let mut item = LeftoverItem::file(
            r"C:\Users\user\AppData\Local\SomeApp\cache".to_string(),
            ConfidenceLevel::High, // start High
            SOURCE_APPDATA.to_string(),
        );
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::Medium);
    }

    #[test]
    fn confidence_assignment_clsid() {
        let mut item = LeftoverItem::registry_key(
            r"HKEY_CLASSES_ROOT\CLSID\{12345678-1234-1234-1234-123456789ABC}".to_string(),
            ConfidenceLevel::High, // start High
            SOURCE_CLSID.to_string(),
        );
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::Low);
    }

    #[test]
    fn detection_source_from_str_roundtrip() {
        assert_eq!(
            DetectionSource::from_source_str(SOURCE_INSTALL_PATH),
            DetectionSource::InstallPath
        );
        assert_eq!(
            DetectionSource::from_source_str(SOURCE_APPDATA),
            DetectionSource::AppData
        );
        assert_eq!(
            DetectionSource::from_source_str(SOURCE_CLSID),
            DetectionSource::Clsid
        );
        assert!(matches!(
            DetectionSource::from_source_str("unknown"),
            DetectionSource::Other(_)
        ));
    }
}
