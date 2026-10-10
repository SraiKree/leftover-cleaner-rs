// Filesystem scanner — Phase 4A of the reconstruction plan.
//
// Three scan targets per the masterplan:
//   1. Install location residue  — jwalk the recorded install dir, flag everything left
//   2. AppData/ProgramData       — search for folders matching publisher or app name
//   3. Shortcuts (.lnk)          — Desktop + Start Menu; flag .lnk whose target is inside install dir
//
// All items are tagged SOURCE_INSTALL_PATH, SOURCE_APPDATA, or SOURCE_APPDATA (shortcuts).
// Confidence is assigned by SafetyValidator::assign_confidence after items reach scan_all.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crossbeam_channel::Sender;
use jwalk::WalkDir;
use tracing::warn;

use crate::{
    domain::{
        error::ScannerError,
        leftover::{ConfidenceLevel, LeftoverItem},
        metadata::AppMetadata,
    },
    engine::safety::{SOURCE_APPDATA, SOURCE_INSTALL_PATH},
};

// ── Known-folder helpers ─────────────────────────────────────────────────────

/// Expand a known env-based folder or fall back to the literal path.
fn env_path(var: &str, fallback: &str) -> PathBuf {
    std::env::var(var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(fallback))
}

/// Returns the set of AppData roots we scan for leftover profile data.
///
/// Matches: APPDATA (Roaming), LOCALAPPDATA, LOCALAPPDATA\Low, PROGRAMDATA.
fn appdata_roots() -> Vec<PathBuf> {
    // APPDATA  = %USERPROFILE%\AppData\Roaming
    let appdata = env_path("APPDATA", r"C:\Users\Default\AppData\Roaming");
    // LOCALAPPDATA = %USERPROFILE%\AppData\Local
    let local = env_path("LOCALAPPDATA", r"C:\Users\Default\AppData\Local");
    // Low integrity bucket
    let low = local.join("Low");
    // Machine-wide app data
    let programdata = env_path("PROGRAMDATA", r"C:\ProgramData");

    vec![appdata, local, low, programdata]
}

/// Start Menu + Desktop shortcuts locations.
fn shortcut_roots() -> Vec<PathBuf> {
    let programdata = env_path("PROGRAMDATA", r"C:\ProgramData");
    let appdata = env_path("APPDATA", r"C:\Users\Default\AppData\Roaming");

    vec![
        // Machine-wide Start Menu programs
        programdata.join(r"Microsoft\Windows\Start Menu\Programs"),
        // Per-user Start Menu programs
        appdata.join(r"Microsoft\Windows\Start Menu\Programs"),
        // Common Desktop
        PathBuf::from(r"C:\Users\Public\Desktop"),
        // Per-user Desktop
        env_path("USERPROFILE", r"C:\Users\Default").join("Desktop"),
    ]
}

// ── Name matching helper ─────────────────────────────────────────────────────

/// True if `dir_name` contains `app_token` or `publisher_token` as a substring.
/// Case-insensitive. Only called with non-empty tokens.
fn name_matches(dir_name: &str, app_token: &str, publisher_token: Option<&str>) -> bool {
    let lower = dir_name.to_lowercase();
    if lower.contains(app_token) {
        return true;
    }
    if let Some(pub_tok) = publisher_token {
        if !pub_tok.is_empty() && lower.contains(pub_tok) {
            return true;
        }
    }
    false
}

/// Produce a lowercase search token from a display name / publisher.
/// Strips common version/edition noise so "MyApp 2.0 (x64)" → "myapp".
fn tokenize(s: &str) -> String {
    // Remove anything inside parentheses, common edition suffixes, version numbers
    let stripped = regex::Regex::new(r"\(.*?\)|\d+(\.\d+)+|[_\-\.]{2,}|Edition|Professional|Standard|Enterprise|x64|x86|64-bit|32-bit")
        .map(|re| re.replace_all(s, " ").to_string())
        .unwrap_or_else(|_| s.to_string());
    stripped.trim().to_lowercase()
}

// ── Scan 1: Install location residue ─────────────────────────────────────────

/// Walk `install_location` with jwalk parallel threads.
/// Every entry still present is a leftover — the uninstaller left it behind.
pub fn scan_install_residue(
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    if !install_location.exists() {
        // Directory gone — uninstaller cleaned up, nothing to flag
        return Ok(());
    }

    // WalkDir from jwalk — num_threads(0) = rayon global pool size
    for entry in WalkDir::new(install_location) {
        match entry {
            Ok(e) => {
                // Skip the root itself; only flag its contents
                if e.path() == install_location {
                    continue;
                }

                let item = if e.path().is_dir() {
                    LeftoverItem::directory(
                        e.path().to_string_lossy().to_string(),
                        ConfidenceLevel::High, // overridden later by assign_confidence
                        SOURCE_INSTALL_PATH.to_string(),
                    )
                } else {
                    LeftoverItem::file(
                        e.path().to_string_lossy().to_string(),
                        ConfidenceLevel::High,
                        SOURCE_INSTALL_PATH.to_string(),
                    )
                };

                if tx.send(item).is_err() {
                    // Receiver dropped — stop scanning
                    break;
                }
            }
            Err(e) => {
                warn!("fs_scanner: walk error in install residue: {}", e);
            }
        }
    }

    Ok(())
}

// ── Scan 2: AppData locations ─────────────────────────────────────────────────

/// Search appdata roots for subdirectories whose name matches the app or publisher.
/// Only goes one level deep — we don't want to scan everything in AppData.
pub fn scan_appdata_locations(
    metadata: &AppMetadata,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    let app_token = tokenize(&metadata.display_name);
    let pub_token = metadata.publisher.as_deref().map(tokenize);

    if app_token.is_empty() {
        return Ok(());
    }

    for root in appdata_roots() {
        if !root.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(&root) {
            Ok(e) => e,
            Err(err) => {
                warn!("fs_scanner: cannot read {:?}: {}", root, err);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            if name_matches(&dir_name_str, &app_token, pub_token.as_deref()) {
                // Flag the directory itself (cleaner will recurse)
                let item = LeftoverItem::directory(
                    path.to_string_lossy().to_string(),
                    ConfidenceLevel::Medium, // overridden later
                    SOURCE_APPDATA.to_string(),
                );
                if tx.send(item).is_err() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

// ── Scan 3: Shortcuts (.lnk) ─────────────────────────────────────────────────

/// Crawl Desktop + Start Menu for .lnk files whose IShellLink target path
/// starts with `install_location`.  Flag the shortcut as a leftover.
///
/// COM shell-link resolution uses:
///   CoInitialize → IShellLinkW::QueryInterface → IPersistFile::Load → GetPath
///
/// We use unsafe COM via the `windows` crate.  The scope of unsafe is minimal
/// and clearly delimited.
pub fn scan_shortcuts(
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    for root in shortcut_roots() {
        if !root.exists() {
            continue;
        }

        // Flat scan — only one level of nesting matters for shortcut folders
        for entry in WalkDir::new(&root) {
            match entry {
                Ok(e) if e.path().extension().and_then(|s| s.to_str()) == Some("lnk") => {
                    match resolve_lnk_target(&e.path()) {
                        Ok(Some(target)) => {
                            if target.starts_with(install_location) {
                                let item = LeftoverItem::file(
                                    e.path().to_string_lossy().to_string(),
                                    ConfidenceLevel::High,
                                    SOURCE_APPDATA.to_string(), // shortcuts = AppData category
                                );
                                if tx.send(item).is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        Ok(None) => {} // could not resolve, skip
                        Err(e) => warn!("fs_scanner: lnk resolve error: {}", e),
                    }
                }
                Ok(_) => {} // not a .lnk
                Err(e) => warn!("fs_scanner: walk error in shortcuts: {}", e),
            }
        }
    }

    Ok(())
}

/// Resolve the target path of a Windows .lnk file via COM IShellLinkW.
///
/// Returns Ok(Some(path)) when the target could be read,
///         Ok(None)       when the COM method reports an empty/unresolvable path,
///         Err(...)       only for hard failures worth logging.
fn resolve_lnk_target(lnk_path: &Path) -> Result<Option<PathBuf>, ScannerError> {
    use windows::{
        core::{Interface, PCWSTR},
        Win32::{
            System::Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile,
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM,
            },
            UI::Shell::{IShellLinkW, ShellLink, SLGP_RAWPATH},
        },
    };

    // Encode path to wide string
    let wide: Vec<u16> = lnk_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Buffer for the resolved target path
    let mut buf = [0u16; 1024];

    // Safety: standard COM init/uninit pair.  We call CoUninitialize at function exit.
    unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        // S_FALSE means already initialized on this thread — that's fine.
        if hr.is_err() && hr != windows::Win32::Foundation::S_FALSE {
            return Ok(None); // COM not available; skip
        }

        let result = (|| {
            // Create a ShellLink COM object
            let shell_link: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
                    .map_err(|e| ScannerError::FilesystemScan(format!("CoCreateInstance: {}", e)))?;

            // Cast to IPersistFile to load the .lnk
            let persist_file: IPersistFile = shell_link
                .cast()
                .map_err(|e| ScannerError::FilesystemScan(format!("cast IPersistFile: {}", e)))?;

            // Load the .lnk file
            persist_file
                .Load(PCWSTR(wide.as_ptr()), STGM(0))
                .map_err(|e| ScannerError::FilesystemScan(format!("IPersistFile::Load: {}", e)))?;

            // Retrieve the target path (no resolve attempt — SLGP_RAWPATH)
            shell_link
                .GetPath(&mut buf, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
                .map_err(|e| ScannerError::FilesystemScan(format!("GetPath: {}", e)))?;

            Ok::<(), ScannerError>(())
        })();

        CoUninitialize();
        result?;
    }

    // Convert the wide string buffer to a PathBuf
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if len == 0 {
        return Ok(None);
    }
    let path_str = String::from_utf16_lossy(&buf[..len]);
    Ok(Some(PathBuf::from(path_str)))
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all three filesystem scans in sequence, streaming results to `tx`.
/// Called from `scan_all()` on a rayon worker thread.
pub fn scan_filesystem(
    metadata: Arc<AppMetadata>,
    install_location: Option<Arc<PathBuf>>,
    tx: Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    // 1. Install residue (only when install location known)
    if let Some(ref loc) = install_location {
        scan_install_residue(loc, &tx)?;
        scan_shortcuts(loc, &tx)?;
    }

    // 2. AppData/ProgramData profile data
    scan_appdata_locations(&metadata, &tx)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use std::fs;
    use tempfile::TempDir;

    fn make_metadata(name: &str, publisher: Option<&str>) -> AppMetadata {
        let mut m = AppMetadata::new(name.to_string());
        m.publisher = publisher.map(str::to_string);
        m
    }

    // ── tokenize ──────────────────────────────────────────────────────────────

    #[test]
    fn tokenize_strips_version() {
        assert_eq!(tokenize("MyApp 2.0"), "myapp");
    }

    #[test]
    fn tokenize_strips_arch_suffix() {
        let t = tokenize("MyApp x64 Edition");
        assert!(t.contains("myapp"), "token: {t}");
        assert!(!t.contains("x64"), "token: {t}");
        assert!(!t.contains("edition"), "token: {t}");
    }

    // ── name_matches ──────────────────────────────────────────────────────────

    #[test]
    fn name_matches_app_token() {
        assert!(name_matches("testapp", "testapp", None));
        assert!(name_matches("TestApp Cache", "testapp", None));
        assert!(!name_matches("otherestapp", "testapp", None));
    }

    #[test]
    fn name_matches_publisher_token() {
        assert!(name_matches("ACME Corp", "acmex", Some("acme")));
        assert!(!name_matches("totally different", "acmex", Some("acme")));
    }

    // ── scan_install_residue ──────────────────────────────────────────────────

    #[test]
    fn scan_install_residue_nonexistent_dir_is_ok() {
        let (tx, _rx) = unbounded();
        let result = scan_install_residue(Path::new(r"C:\NonExistentApp12345"), &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn scan_install_residue_detects_files() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("sub");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("leftover.txt"), b"data").unwrap();
        fs::write(dir.path().join("root_file.exe"), b"exe").unwrap();

        let (tx, rx) = unbounded();
        scan_install_residue(dir.path(), &tx).unwrap();
        drop(tx);

        let items: Vec<LeftoverItem> = rx.iter().collect();
        // Expect subdir + root_file.exe + leftover.txt (order may vary)
        assert!(items.len() >= 3, "got {} items", items.len());
        assert!(items.iter().any(|i| i.path.ends_with("root_file.exe")));
        assert!(items.iter().any(|i| i.path.ends_with("leftover.txt")));
        assert!(items
            .iter()
            .any(|i| i.kind == crate::domain::leftover::LeftoverKind::Directory));
    }

    #[test]
    fn scan_install_residue_empty_dir_sends_nothing() {
        let dir = TempDir::new().unwrap();
        let (tx, rx) = unbounded();
        scan_install_residue(dir.path(), &tx).unwrap();
        drop(tx);
        assert_eq!(rx.iter().count(), 0);
    }

    // ── scan_appdata_locations ────────────────────────────────────────────────

    #[test]
    fn scan_appdata_matches_folder_by_name() {
        // Override APPDATA to a temp dir for this test
        let dir = TempDir::new().unwrap();
        let app_folder = dir.path().join("testapp");
        fs::create_dir(&app_folder).unwrap();

        // Temporarily override APPDATA
        std::env::set_var("APPDATA", dir.path());
        // Also clear LOCALAPPDATA to isolate
        let orig_local = std::env::var("LOCALAPPDATA").ok();
        std::env::remove_var("LOCALAPPDATA");
        let orig_prog = std::env::var("PROGRAMDATA").ok();
        std::env::remove_var("PROGRAMDATA");

        let (tx, rx) = unbounded();
        let meta = make_metadata("TestApp", None);
        let result = scan_appdata_locations(&meta, &tx);
        drop(tx);

        // Restore env vars
        if let Some(v) = orig_local {
            std::env::set_var("LOCALAPPDATA", v);
        }
        if let Some(v) = orig_prog {
            std::env::set_var("PROGRAMDATA", v);
        }

        assert!(result.is_ok());
        let items: Vec<LeftoverItem> = rx.iter().collect();
        assert!(
            items.iter().any(|i| i.path == app_folder.to_string_lossy()),
            "expected {:?} in items, got: {:?}",
            app_folder,
            items
        );
    }
}
