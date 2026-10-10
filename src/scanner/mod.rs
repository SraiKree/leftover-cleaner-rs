// Scanner module — coordinates all three concurrent scanning passes:
//   fs_scanner   — install residue, AppData folders, shortcuts
//   reg_scanner  — Software keys, App Paths, CLSID COM entries
//   msi_scanner  — MSI UserData\Products\Components (best-effort)
//
// scan_all() launches all three on rayon worker threads and streams
// validated LeftoverItems via crossbeam-channel to the caller.

pub mod fs_scanner;
pub mod msi_scanner;
pub mod reg_scanner;

use std::{path::PathBuf, sync::Arc};

use crossbeam_channel::{unbounded, Receiver};

use crate::{
    domain::{
        error::ScannerError,
        leftover::LeftoverItem,
        metadata::AppMetadata,
    },
    engine::safety::SafetyValidator,
};

use fs_scanner::scan_filesystem;
use msi_scanner::scan_msi_database;
use reg_scanner::scan_registry;

/// Launch all scanners concurrently.
///
/// Returns a `Receiver<LeftoverItem>` that streams validated results as they
/// arrive.  The receiver yields items until all three scanner threads finish
/// and drop their `Sender` ends.
///
/// # Parameters
/// * `metadata`         — Shared application metadata (Arc for rayon workers).
/// * `install_location` — Resolved install path, if known.
///
/// # Notes
/// * Items that fail `SafetyValidator::validate` are silently dropped.
/// * Confidence levels are updated by `SafetyValidator::assign_confidence`
///   before each item is forwarded to the consumer channel.
pub fn scan_all(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
) -> Receiver<LeftoverItem> {
    // Internal channel: scanners → safety filter
    let (raw_tx, raw_rx) = unbounded::<LeftoverItem>();

    // Consumer channel: safety filter → caller
    let (safe_tx, safe_rx) = unbounded::<LeftoverItem>();

    // Shared install location wrapped in Arc so all three workers can clone it
    let loc_arc: Option<Arc<PathBuf>> = install_location.map(Arc::new);

    // Clone Arc handles for the three workers
    let meta_fs  = Arc::clone(&metadata);
    let meta_reg = Arc::clone(&metadata);
    let meta_msi = Arc::clone(&metadata);

    let loc_fs  = loc_arc.as_ref().map(Arc::clone);
    let loc_reg = loc_arc.as_ref().map(Arc::clone);
    let loc_msi = loc_arc.as_ref().map(Arc::clone);

    // Clone tx handles — each scanner holds one, dropping when done
    let tx_fs  = raw_tx.clone();
    let tx_reg = raw_tx.clone();
    let tx_msi = raw_tx.clone();
    drop(raw_tx); // main thread doesn't send anything itself

    // Spawn all three scanners in parallel via rayon
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

    // Safety filter thread: validates and forwards items from raw_rx → safe_tx
    rayon::spawn(move || {
        let validator = SafetyValidator::new();
        for mut item in raw_rx {
            // Assign confidence based on item source tag
            SafetyValidator::assign_confidence(&mut item);

            // Validate against blacklist / shared-DLL guard
            match validator.validate(&item) {
                Ok(()) => {
                    if safe_tx.send(item).is_err() {
                        break; // Consumer dropped receiver
                    }
                }
                Err(e) => {
                    tracing::debug!("scan_all: blocked item: {}", e);
                }
            }
        }
        // safe_tx dropped here → safe_rx iter() terminates
    });

    safe_rx
}

/// Collect all items from `scan_all()` into a Vec.
///
/// Convenience wrapper for callers that don't need streaming.
pub fn collect_leftovers(
    metadata: Arc<AppMetadata>,
    install_location: Option<PathBuf>,
) -> Result<Vec<LeftoverItem>, ScannerError> {
    let rx = scan_all(metadata, install_location);
    // Blocking iteration — drains the channel until all senders are dropped
    Ok(rx.iter().collect())
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

    // ── scan_all returns a Receiver ───────────────────────────────────────────

    #[test]
    fn scan_all_returns_receiver_for_unknown_app() {
        // Unknown app — scanners find nothing, channel drains cleanly
        let rx = scan_all(make_meta("ZZZNonExistentApp99999"), None);
        let items: Vec<_> = rx.iter().collect();
        // No items expected — but channel must terminate (not hang)
        // This also verifies no panics in the scanner threads
        drop(items); // suppress unused warning
    }

    #[test]
    fn collect_leftovers_returns_vec() {
        let result = collect_leftovers(make_meta("ZZZNonExistentApp99999"), None);
        assert!(result.is_ok());
    }

    // ── scan_all with temp install dir ────────────────────────────────────────

    #[test]
    fn scan_all_detects_install_residue() {
        // Create a temp dir with leftover files
        let dir = TempDir::new().unwrap();
        let leftover_file = dir.path().join("leftover.txt");
        fs::write(&leftover_file, b"leftover data").unwrap();

        let meta = make_meta("TempScanApp");
        let items = collect_leftovers(meta, Some(dir.path().to_path_buf())).unwrap();

        // At minimum, leftover.txt must be in results
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

        // Every returned item must have a non-placeholder confidence
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
        // Even with a dummy meta, system paths must not appear
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
}
