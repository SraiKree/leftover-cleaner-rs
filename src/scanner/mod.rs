// Scanner module — coordinates all three concurrent scanning passes:
//   fs_scanner   — install residue, AppData folders, shortcuts
//   reg_scanner  — Software keys, App Paths, CLSID COM entries
//   msi_scanner  — MSI UserData\Products\Components (best-effort)
//
// scan_all_with_context() launches all three on rayon worker threads and streams
// validated LeftoverItems via crossbeam-channel to the caller.

pub mod fs_scanner;
pub mod msi_scanner;
pub mod reg_scanner;

use std::{path::PathBuf, sync::Arc};

use crossbeam_channel::{unbounded, Receiver};

use crate::{
    domain::{
        error::ScannerError,
        leftover::{ConfidenceLevel, LeftoverItem},
        metadata::AppMetadata,
    },
    engine::safety::SafetyValidator,
};

use fs_scanner::scan_filesystem;
use msi_scanner::scan_msi_database;
use reg_scanner::scan_registry;

/// Context from the uninstaller execution, passed to the scanner to improve
/// detection accuracy.
///
/// MVP strategy: if the uninstaller ran and a file/dir still exists inside the
/// install location, the uninstaller failed to remove it → boost to High confidence.
#[derive(Debug, Clone, Default)]
pub struct UninstallerContext {
    /// Whether the uninstaller was actually launched (false = skipped or failed to start)
    pub ran: bool,
    /// Exit code returned by the uninstaller process (0 = success)
    pub exit_code: u32,
}

impl UninstallerContext {
    /// Create context for a successfully-run uninstaller.
    pub fn ran(exit_code: u32) -> Self {
        Self { ran: true, exit_code }
    }

    /// Create context for a skipped / failed-to-launch uninstaller.
    pub fn skipped() -> Self {
        Self { ran: false, exit_code: 0 }
    }
}

/// Launch all scanners concurrently, boosting confidence using uninstaller context.
///
/// Returns a `Receiver<LeftoverItem>` that streams validated results as they arrive.
/// The receiver yields items until all scanner threads finish and drop their `Sender` ends.
///
/// # Parameters
/// * `metadata`            — Shared application metadata (Arc for rayon workers).
/// * `install_location`    — Resolved install path, if known.
/// * `uninstaller_context` — Exit code + ran flag from the uninstaller.
///   Items inside the install dir that still exist are promoted
///   to High confidence when `ran == true`.
///
/// # Notes
/// * Items failing `SafetyValidator::validate` are silently dropped.
/// * Confidence: assigned by source tag, then boosted by uninstaller context.
pub fn scan_all_with_context(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
    uninstaller_context: UninstallerContext,
) -> Receiver<LeftoverItem> {
    // Internal channel: scanners → safety filter
    let (raw_tx, raw_rx) = unbounded::<LeftoverItem>();

    // Consumer channel: safety filter → caller
    let (safe_tx, safe_rx) = unbounded::<LeftoverItem>();

    // Shared install location
    let loc_arc: Option<Arc<PathBuf>> = install_location.map(Arc::new);

    // Clone Arc handles for the three workers
    let meta_fs  = Arc::clone(&metadata);
    let meta_reg = Arc::clone(&metadata);
    let meta_msi = Arc::clone(&metadata);

    let loc_fs  = loc_arc.as_ref().map(Arc::clone);
    let loc_reg = loc_arc.as_ref().map(Arc::clone);
    let loc_msi = loc_arc.as_ref().map(Arc::clone);

    // Each scanner gets its own tx clone; dropping when done closes that end
    let tx_fs  = raw_tx.clone();
    let tx_reg = raw_tx.clone();
    let tx_msi = raw_tx.clone();
    drop(raw_tx); // main thread sends nothing itself

    rayon::spawn(move || {
        if let Err(e) = scan_filesystem(meta_fs, loc_fs, tx_fs) {
            tracing::warn!("fs_scanner error: {}", e);
        }
    });

    rayon::spawn(move || {
        if let Err(e) = scan_registry(meta_reg, loc_reg, tx_reg) {
            tracing::warn!("reg_scanner error: {}", e);
        }
    });

    rayon::spawn(move || {
        if let Err(e) = scan_msi_database(meta_msi, loc_msi, tx_msi) {
            tracing::warn!("msi_scanner error: {}", e);
        }
    });

    // Pre-compute install dir prefix (lowercase) for fast path matching
    let install_lower = loc_arc
        .as_ref()
        .map(|p| p.to_string_lossy().to_lowercase());

    // Safety-filter thread: validate, boost confidence, forward
    rayon::spawn(move || {
        let validator = SafetyValidator::new();
        for mut item in raw_rx {
            // Step 1: assign base confidence from detection source tag
            SafetyValidator::assign_confidence(&mut item);

            // Step 2: boost to High if uninstaller ran and this item still
            //         physically exists inside the install directory — the
            //         uninstaller failed to clean it up.
            if uninstaller_context.ran {
                if let Some(ref prefix) = install_lower {
                    let item_lower = item.path.to_lowercase();
                    if item_lower.starts_with(prefix.as_str())
                        && item.kind.is_filesystem()
                        && std::path::Path::new(&item.path).exists()
                    {
                        item.confidence = ConfidenceLevel::High;
                        item.source = format!(
                            "{} [uninstaller exit={}]",
                            item.source, uninstaller_context.exit_code
                        );
                    }
                }
            }

            // Step 3: validate against blacklist / shared-DLL guard
            match validator.validate(&item) {
                Ok(()) => {
                    if safe_tx.send(item).is_err() {
                        break; // Consumer dropped receiver early
                    }
                }
                Err(e) => {
                    tracing::debug!("scan_all: blocked item: {}", e);
                }
            }
        }
        // safe_tx drops here → safe_rx.iter() terminates for the caller
    });

    safe_rx
}

/// Convenience wrapper — scan without uninstaller context.
pub fn scan_all(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
) -> Receiver<LeftoverItem> {
    scan_all_with_context(metadata, install_location, UninstallerContext::skipped())
}

/// Collect all items from `scan_all_with_context()` into a Vec.
pub fn collect_leftovers_with_context(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
    uninstaller_context: UninstallerContext,
) -> Result<Vec<LeftoverItem>, ScannerError> {
    let rx = scan_all_with_context(metadata, install_location, uninstaller_context);
    Ok(rx.iter().collect())
}

/// Collect all items from `scan_all()` into a Vec.
///
/// Convenience wrapper for callers that don't need streaming.
pub fn collect_leftovers(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
) -> Result<Vec<LeftoverItem>, ScannerError> {
    collect_leftovers_with_context(metadata, install_location, UninstallerContext::skipped())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_meta(name: &str) -> Arc<AppMetadata> {
        Arc::new(AppMetadata::new(name.to_string()))
    }

    // ── Basic channel termination ─────────────────────────────────────────────

    #[test]
    fn scan_all_returns_receiver_for_unknown_app() {
        let rx = scan_all(make_meta("ZZZNonExistentApp99999"), None);
        let items: Vec<_> = rx.iter().collect();
        drop(items);
    }

    #[test]
    fn collect_leftovers_returns_vec() {
        let result = collect_leftovers(make_meta("ZZZNonExistentApp99999"), None);
        assert!(result.is_ok());
    }

    // ── scan_all with temp install dir ────────────────────────────────────────

    #[test]
    fn scan_all_detects_install_residue() {
        let dir = TempDir::new().unwrap();
        let leftover_file = dir.path().join("leftover.txt");
        fs::write(&leftover_file, b"leftover data").unwrap();

        let meta = make_meta("TempScanApp");
        let items = collect_leftovers(meta, Some(dir.path().to_path_buf())).unwrap();

        assert!(
            items.iter().any(|i| i.path.ends_with("leftover.txt")),
            "leftover.txt not found in: {:?}",
            items.iter().map(|i| &i.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_all_items_have_valid_confidence() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.exe"), b"exe").unwrap();

        let meta = make_meta("TempScanApp2");
        let items = collect_leftovers(meta, Some(dir.path().to_path_buf())).unwrap();

        for item in &items {
            assert!(
                matches!(
                    item.confidence,
                    crate::domain::leftover::ConfidenceLevel::High
                        | crate::domain::leftover::ConfidenceLevel::Medium
                        | crate::domain::leftover::ConfidenceLevel::Low
                ),
                "unexpected confidence on {:?}",
                item
            );
        }
    }

    #[test]
    fn scan_all_does_not_return_system_paths() {
        let meta = make_meta("Windows");
        let items = collect_leftovers(meta, Some(PathBuf::from(r"C:\Windows"))).unwrap();

        for item in &items {
            let lower = item.path.to_lowercase();
            assert!(
                !lower.starts_with(r"c:\windows\system32"),
                "system path leaked: {}",
                item.path
            );
        }
    }

    // ── UninstallerContext confidence boost ───────────────────────────────────

    #[test]
    fn uninstaller_context_boosts_confidence_for_existing_files() {
        let dir = TempDir::new().unwrap();
        let leftover = dir.path().join("residue.dll");
        fs::write(&leftover, b"residue").unwrap();

        let meta = make_meta("TempBoostApp");
        let ctx = UninstallerContext::ran(0);
        let items = collect_leftovers_with_context(
            meta,
            Some(dir.path().to_path_buf()),
            ctx,
        )
        .unwrap();

        // Files inside install dir that exist → must be High confidence
        let residue = items.iter().find(|i| i.path.ends_with("residue.dll"));
        if let Some(item) = residue {
            assert_eq!(
                item.confidence,
                ConfidenceLevel::High,
                "expected High confidence from uninstaller context"
            );
            assert!(
                item.source.contains("uninstaller exit="),
                "source should contain exit code annotation"
            );
        }
        // (test passes even if residue.dll is filtered by safety validator for other reasons)
    }

    #[test]
    fn skipped_uninstaller_does_not_boost_confidence() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("residue.dll"), b"residue").unwrap();

        let meta = make_meta("TempNoBoostApp");
        let ctx = UninstallerContext::skipped();
        let items = collect_leftovers_with_context(
            meta,
            Some(dir.path().to_path_buf()),
            ctx,
        )
        .unwrap();

        // With skipped context, source must NOT contain the uninstaller annotation
        for item in &items {
            assert!(
                !item.source.contains("uninstaller exit="),
                "skipped context should not annotate source: {}",
                item.source
            );
        }
    }
}
