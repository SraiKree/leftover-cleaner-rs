// Safety validation before any deletion.
//
// Two-tier blacklist per the original reverse-engineered plan (Phase 5):
//
//   prefix_blacklist — Windows OS tree (C:\Windows and subtree).
//                      Any subpath is rejected. NO subpath is ever a valid leftover.
//
//   exact_blacklist  — Root guards only: drive root, C:\Program Files root,
//                      C:\Program Files (x86) root, C:\Users root.
//                      The root itself is blocked (e.g. can't delete Program Files entirely)
//                      but subdirectories like C:\Program Files\OldApp ARE valid leftover targets.
//
// SharedDLLs: DLLs with ref-count > 0 in HKLM SharedDLLs registry = shared, block.
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
const SHARED_DLLS_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs";

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
    // Windows OS tree — prefix-matched; any subpath is rejected
    prefix_blacklist: HashSet<PathBuf>,
    // Root guards — exact-matched only; subdirs are valid leftover targets
    exact_blacklist: HashSet<PathBuf>,
}

impl SafetyValidator {
    /// Build validator with default Windows system blacklist.
    pub fn new() -> Self {
        let (prefix_blacklist, exact_blacklist) = build_blacklists();
        Self { prefix_blacklist, exact_blacklist }
    }

    /// Validate one leftover item.
    /// Returns Err if blocked, Ok(()) if safe to proceed.
    pub fn validate(&self, item: &LeftoverItem) -> Result<(), CleanError> {
        // Registry items skip path blacklist and shared-DLL check
        if item.kind.is_registry() {
            return Ok(());
        }

        let raw_path = Path::new(&item.path);

        // Canonicalize when path exists; fall back to raw for not-yet-deleted paths
        let canonical = std::fs::canonicalize(raw_path)
            .unwrap_or_else(|_| raw_path.to_path_buf());
        let canonical = normalize_path(&canonical);

        // Exact guard — blocks the root dirs themselves.
        // C:\Program Files\OldApp is NOT caught here, only C:\Program Files itself.
        if self.exact_blacklist.contains(&canonical) {
            return Err(CleanError::SafetyCheck(format!(
                "Blocked root path: {}",
                canonical.display()
            )));
        }

        // Prefix guard — blocks anything inside the Windows OS tree.
        // C:\Windows\System32\foo.dll is caught here via the C:\Windows prefix.
        for blocked in &self.prefix_blacklist {
            if canonical.starts_with(blocked) {
                return Err(CleanError::SafetyCheck(format!(
                    "Path inside OS directory: {} (blocked by {})",
                    canonical.display(),
                    blocked.display()
                )));
            }
        }

        // SharedDLLs check — only for .dll files
        if item.kind == LeftoverKind::File {
            if let Some(ext) = raw_path.extension() {
                if ext.eq_ignore_ascii_case("dll") {
                    self.check_shared_dll(raw_path)?;
                }
            }
        }

        Ok(())
    }

    /// Check HKLM SharedDLLs — if ref count > 0 the DLL is still in use.
    fn check_shared_dll(&self, path: &Path) -> Result<(), CleanError> {
        let path_str = path.to_string_lossy().to_string();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let shared_dlls = match hklm.open_subkey(SHARED_DLLS_KEY) {
            Ok(k) => k,
            Err(_) => return Ok(()), // key absent = not tracked
        };
        match shared_dlls.get_value::<u32, _>(&path_str) {
            Ok(ref_count) if ref_count > 0 => Err(CleanError::SafetyCheck(format!(
                "Shared DLL in use (ref_count={}): {}",
                ref_count, path_str
            ))),
            _ => Ok(()), // ref count 0 or not tracked = safe
        }
    }

    /// Assign confidence to a leftover based on its source tag. Mutates in place.
    pub fn assign_confidence(item: &mut LeftoverItem) {
        let source = DetectionSource::from_source_str(&item.source);
        item.confidence = source.confidence();
    }

    /// Batch filter — returns (safe_items, blocked_count).
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

/// Strip \\?\ and lowercase for consistent cross-source comparison.
fn normalize_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let stripped = s.strip_prefix(r"\\?\").unwrap_or(s.as_ref());
    PathBuf::from(stripped.to_lowercase())
}

fn canonicalize_and_normalize(raw: &str) -> PathBuf {
    let pb = PathBuf::from(raw);
    let canonical = std::fs::canonicalize(&pb).unwrap_or(pb);
    normalize_path(&canonical)
}

/// Build two-tier blacklist per the original plan (Phase 5).
fn build_blacklists() -> (HashSet<PathBuf>, HashSet<PathBuf>) {
    let system_drive =
        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| format!(r"{}\Windows", system_drive));
    let program_files = std::env::var("ProgramFiles")
        .unwrap_or_else(|_| format!(r"{}\Program Files", system_drive));
    let program_files_x86 = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| format!(r"{}\Program Files (x86)", system_drive));
    let users_root = format!(r"{}\Users", system_drive);

    // Prefix-blocked: the entire Windows OS tree — no subpath is a leftover
    let prefix_raw: &[&str] = &[
        &windir,
        &format!(r"{}\System32", windir),
        &format!(r"{}\SysWOW64", windir),
        &format!(r"{}\WinSxS", windir),
        &format!(r"{}\SystemApps", windir),
        r"C:\Windows",
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Windows\WinSxS",
    ];

    // Exact-blocked: root guards — subfolders are valid leftover targets
    let exact_raw: &[&str] = &[
        &format!("{}\\", system_drive),
        &system_drive,
        &program_files,
        &program_files_x86,
        &users_root,
        r"C:\",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\Users",
    ];

    let prefix_blacklist = prefix_raw
        .iter()
        .map(|s| canonicalize_and_normalize(s))
        .collect();
    let exact_blacklist = exact_raw
        .iter()
        .map(|s| canonicalize_and_normalize(s))
        .collect();

    (prefix_blacklist, exact_blacklist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_item(path: &str) -> LeftoverItem {
        LeftoverItem::file(path.to_string(), ConfidenceLevel::High, SOURCE_INSTALL_PATH.to_string())
    }

    fn dir_item(path: &str) -> LeftoverItem {
        LeftoverItem::directory(path.to_string(), ConfidenceLevel::High, SOURCE_INSTALL_PATH.to_string())
    }

    // --- Exact-blocked roots ---

    #[test]
    fn blocks_drive_root() {
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\")).is_err());
    }

    #[test]
    fn blocks_program_files_root() {
        // Root itself is blocked
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Program Files")).is_err());
    }

    #[test]
    fn blocks_users_root() {
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Users")).is_err());
    }

    // --- Subdirs of exact-blocked roots must be ALLOWED (primary leftover targets) ---

    #[test]
    fn allows_app_subdir_under_program_files() {
        // C:\Program Files\OldApp is a classic leftover — must pass
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Program Files\OldApp")).is_ok());
    }

    #[test]
    fn allows_user_profile_dir() {
        // C:\Users\Bob\AppData\Local\OldApp is a valid leftover target
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Users\Bob\AppData\Local\OldApp")).is_ok());
    }

    // --- Prefix-blocked Windows OS tree ---

    #[test]
    fn blocks_windows_dir() {
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Windows")).is_err());
    }

    #[test]
    fn blocks_system32() {
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"C:\Windows\System32")).is_err());
    }

    #[test]
    fn blocks_file_inside_system32() {
        let v = SafetyValidator::new();
        assert!(v.validate(&file_item(r"C:\Windows\System32\kernel32.dll")).is_err());
    }

    // --- Non-system paths ---

    #[test]
    fn allows_non_system_path() {
        let v = SafetyValidator::new();
        assert!(v.validate(&dir_item(r"D:\LeftoverApp\Residue")).is_ok());
    }

    // --- Registry items always pass ---

    #[test]
    fn registry_items_bypass_blacklist() {
        let v = SafetyValidator::new();
        let item = LeftoverItem::registry_key(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\LeftoverApp".to_string(),
            ConfidenceLevel::High,
            SOURCE_INSTALL_PATH.to_string(),
        );
        assert!(v.validate(&item).is_ok());
    }

    // --- Confidence assignment ---

    #[test]
    fn confidence_install_path_is_high() {
        let mut item = file_item(r"C:\SomeApp\file.txt");
        item.confidence = ConfidenceLevel::Low;
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn confidence_appdata_is_medium() {
        let mut item = LeftoverItem::file(
            r"C:\Users\user\AppData\Local\SomeApp\cache".to_string(),
            ConfidenceLevel::High,
            SOURCE_APPDATA.to_string(),
        );
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::Medium);
    }

    #[test]
    fn confidence_clsid_is_low() {
        let mut item = LeftoverItem::registry_key(
            r"HKEY_CLASSES_ROOT\CLSID\{12345678-1234-1234-1234-123456789ABC}".to_string(),
            ConfidenceLevel::High,
            SOURCE_CLSID.to_string(),
        );
        SafetyValidator::assign_confidence(&mut item);
        assert_eq!(item.confidence, ConfidenceLevel::Low);
    }

    #[test]
    fn detection_source_roundtrip() {
        assert_eq!(DetectionSource::from_source_str(SOURCE_INSTALL_PATH), DetectionSource::InstallPath);
        assert_eq!(DetectionSource::from_source_str(SOURCE_APPDATA), DetectionSource::AppData);
        assert_eq!(DetectionSource::from_source_str(SOURCE_CLSID), DetectionSource::Clsid);
        assert!(matches!(DetectionSource::from_source_str("unknown"), DetectionSource::Other(_)));
    }
}
