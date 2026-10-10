// MSI database scanner — Phase 4C of the reconstruction plan.
//
// MSI tracking lives in:
//   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\<SID>\Products\<ProductCode>
//
// For each product whose DisplayName matches the target app:
//   • Flag the Products\<ProductCode>\InstallProperties key
//   • Flag the Components key if it references paths inside install_location
//
// Best-effort: Windows Installer product keys may be absent for non-MSI
// installers (NSIS, InnoSetup, ClickOnce).  All errors are treated as warnings,
// not hard failures, to avoid crashing the scan pipeline.
//
// All items tagged SOURCE_INSTALL_PATH; confidence assigned by SafetyValidator.

use std::{path::Path, sync::Arc};

use crossbeam_channel::Sender;
use tracing::warn;
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

use crate::{
    domain::{
        error::ScannerError,
        leftover::{ConfidenceLevel, LeftoverItem},
        metadata::AppMetadata,
    },
    engine::safety::SOURCE_INSTALL_PATH,
};

// Base path in the registry where Windows Installer tracks products per SID
const INSTALLER_USERDATA: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Case-insensitive substring check after stripping whitespace.
fn loose_name_match(haystack: &str, needle: &str) -> bool {
    !needle.is_empty()
        && haystack
            .to_lowercase()
            .contains(&needle.to_lowercase())
}

/// Expand environment variables in a path value string.
fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut result = s.to_string();
    for _ in 0..8 {
        if let Some(start) = result.find('%') {
            if let Some(end) = result[start + 1..].find('%') {
                let var_name = &result[start + 1..start + 1 + end];
                if let Ok(val) = std::env::var(var_name) {
                    result = format!("{}{}{}", &result[..start], val, &result[start + 2 + end..]);
                    continue;
                }
            }
        }
        break;
    }
    result
}

// ── Per-product scan ──────────────────────────────────────────────────────────

/// Inspect one MSI product key under `<UserData>\<SID>\Products\<ProductCode>`.
///
/// 1. Read DisplayName from InstallProperties — skip if it doesn't match `app_name`.
/// 2. Flag the InstallProperties key itself.
/// 3. Walk Components and flag any whose path starts with `install_location`.
fn scan_product(
    product_key: &RegKey,
    product_reg_path: &str,
    app_name: &str,
    install_location: Option<&Path>,
    tx: &Sender<LeftoverItem>,
) {
    // ── Check DisplayName ──────────────────────────────────────────────────
    let install_props = match product_key.open_subkey("InstallProperties") {
        Ok(k) => k,
        Err(_) => return, // Not a real product key
    };

    let display_name: String = match install_props.get_value("DisplayName") {
        Ok(v) => v,
        Err(_) => return, // No display name — skip
    };

    if !loose_name_match(&display_name, app_name) {
        return; // Different product
    }

    // ── Flag InstallProperties key ─────────────────────────────────────────
    let install_props_path = format!(r"{}\InstallProperties", product_reg_path);
    let item = LeftoverItem::registry_key(
        format!(r"HKEY_LOCAL_MACHINE\{}", install_props_path),
        ConfidenceLevel::High,
        SOURCE_INSTALL_PATH.to_string(),
    );
    let _ = tx.send(item);

    // ── Also flag the product root key ─────────────────────────────────────
    let product_root_item = LeftoverItem::registry_key(
        format!(r"HKEY_LOCAL_MACHINE\{}", product_reg_path),
        ConfidenceLevel::High,
        SOURCE_INSTALL_PATH.to_string(),
    );
    let _ = tx.send(product_root_item);

    // ── Walk Components (best-effort) ──────────────────────────────────────
    if let Some(loc) = install_location {
        scan_product_components(product_key, product_reg_path, loc, tx);
    }
}

/// Walk `Components` sub-keys of a product and flag those referencing `install_location`.
fn scan_product_components(
    product_key: &RegKey,
    product_reg_path: &str,
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) {
    let components_key = match product_key.open_subkey("Components") {
        Ok(k) => k,
        Err(_) => return, // Not present — ok
    };

    for comp_result in components_key.enum_keys() {
        let comp_name = match comp_result {
            Ok(n) => n,
            Err(_) => continue,
        };

        let comp_key = match components_key.open_subkey(&comp_name) {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Components store paths as named values keyed by SID or "00000000000000000000000000000000"
        for val_result in comp_key.enum_values() {
            let (_val_name, val_data) = match val_result {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            // Value data is typically a string path (possibly with env vars)
            if let winreg::RegValue {
                bytes,
                vtype: winreg::enums::REG_SZ | winreg::enums::REG_EXPAND_SZ,
            } = val_data
            {
                // Decode wide string from bytes
                if let Ok(path_str) = decode_reg_sz(&bytes) {
                    let expanded = expand_env(&path_str);
                    let p = Path::new(&expanded);
                    if p.starts_with(install_location) {
                        let reg_path = format!(
                            r"HKEY_LOCAL_MACHINE\{}\Components\{}",
                            product_reg_path, comp_name
                        );
                        let item = LeftoverItem::registry_key(
                            reg_path,
                            ConfidenceLevel::High,
                            SOURCE_INSTALL_PATH.to_string(),
                        );
                        let _ = tx.send(item);
                        break; // one match per component key is enough
                    }
                }
            }
        }
    }
}

/// Decode REG_SZ bytes (UTF-16 LE, null-terminated) to String.
fn decode_reg_sz(bytes: &[u8]) -> Result<String, ()> {
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let words: Vec<u16> = bytes
        .as_chunks::<2>().0.iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    // Strip null terminator
    let trimmed: Vec<u16> = words.into_iter().take_while(|&c| c != 0).collect();
    String::from_utf16(&trimmed).map_err(|_| ())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Best-effort MSI database scan.  Walks all SID buckets under UserData.
/// Called from `scan_all()` on a rayon worker thread.
pub fn scan_msi_database(
    metadata: Arc<AppMetadata>,
    install_location: Option<Arc<std::path::PathBuf>>,
    tx: Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let userdata_key = match hklm.open_subkey(INSTALLER_USERDATA) {
        Ok(k) => k,
        Err(e) => {
            warn!("msi_scanner: cannot open UserData key: {}", e);
            return Ok(()); // non-fatal — machine may have no MSI installs
        }
    };

    let loc = install_location.as_deref().map(|p| p.as_path());

    // Iterate over SID buckets (e.g. "S-1-5-18" for SYSTEM, user SIDs, etc.)
    for sid_result in userdata_key.enum_keys() {
        let sid = match sid_result {
            Ok(s) => s,
            Err(_) => continue,
        };

        let sid_key = match userdata_key.open_subkey(&sid) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let products_key = match sid_key.open_subkey("Products") {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Iterate over ProductCode GUIDs
        for product_result in products_key.enum_keys() {
            let product_code = match product_result {
                Ok(p) => p,
                Err(_) => continue,
            };

            let product_key = match products_key.open_subkey(&product_code) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let product_reg_path = format!(
                r"{}\{}\Products\{}",
                INSTALLER_USERDATA, sid, product_code
            );

            scan_product(
                &product_key,
                &product_reg_path,
                &metadata.display_name,
                loc,
                &tx,
            );
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_name_match_case_insensitive() {
        assert!(loose_name_match("My Application", "application"));
        assert!(loose_name_match("MyApp", "myapp"));
        assert!(!loose_name_match("OtherApp", "myapp"));
    }

    #[test]
    fn loose_name_match_empty_needle() {
        assert!(!loose_name_match("anything", ""));
    }

    #[test]
    fn decode_reg_sz_hello() {
        // "Hi" in UTF-16 LE with null terminator
        let bytes: Vec<u8> = "Hi\0"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(decode_reg_sz(&bytes).unwrap(), "Hi");
    }

    #[test]
    fn decode_reg_sz_empty() {
        // Just a null terminator
        let bytes: Vec<u8> = vec![0, 0];
        assert_eq!(decode_reg_sz(&bytes).unwrap(), "");
    }

    #[test]
    fn expand_env_no_vars() {
        assert_eq!(expand_env("plain"), "plain");
    }

    #[test]
    fn expand_env_system_root() {
        let result = expand_env("%SystemRoot%\\app");
        assert!(!result.starts_with('%'), "{result}");
        assert!(result.ends_with(r"\app"), "{result}");
    }

    #[test]
    fn scan_msi_database_does_not_crash() {
        use crossbeam_channel::unbounded;
        let (tx, _rx) = unbounded();
        let meta = Arc::new(AppMetadata::new("NonExistentApp12345".to_string()));
        // Should complete without panic — even if the registry key is absent
        let result = scan_msi_database(meta, None, tx);
        assert!(result.is_ok());
    }
}
