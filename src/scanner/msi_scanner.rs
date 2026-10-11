// MSI database scanner — verified against geek.exe (CScannerMSI::ScanMSITraces).
//
// How geek actually works (from Ghidra decompilation, FUN_00445eab):
//
//   1. The selected CUninstallItem has field +0x3c = MSI ProductCode GUID,
//      extracted from UninstallString ("MsiExec.exe /I{GUID}" or "/X{GUID}")
//      at harvest time. There is NO fuzzy name-matching against UserData.
//
//   2. For each SID bucket under HKLM\...\Installer\UserData, geek constructs
//      the exact path:
//        HKLM\...\UserData\<SID>\Products\<ProductCode>
//      and calls RegOpenKeyExW to test existence.
//
//   3. If the key exists, it enumerates ONLY the Components subkeys whose
//      path values start with the install_location. It does NOT flag the
//      Products\{GUID} root key or InstallProperties — only leaf Component
//      keys that reference files inside the install directory.
//
//   4. After the UserData scan, geek also checks
//        HKLM\...\Installer\Folders
//      for entries matching the install location.
//
// This is the approach we implement. Any name-based matching across all
// products was a previous bug and is not how geek works.

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

const INSTALLER_USERDATA: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";

const INSTALLER_FOLDERS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// Decode REG_SZ bytes (UTF-16 LE, null-terminated) to String.
fn decode_reg_sz(bytes: &[u8]) -> Result<String, ()> {
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let words: Vec<u16> = bytes
        .as_chunks::<2>().0.iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let trimmed: Vec<u16> = words.into_iter().take_while(|&c| c != 0).collect();
    String::from_utf16(&trimmed).map_err(|_| ())
}

// ── Per-SID scan ──────────────────────────────────────────────────────────────

/// Check one SID bucket for the given ProductCode GUID.
/// If `UserData\<sid>\Products\<product_code>` exists, scan its Components.
fn scan_sid_for_product(
    userdata_key: &RegKey,
    sid: &str,
    product_code: &str,
    install_location: Option<&Path>,
    tx: &Sender<LeftoverItem>,
) {
    let sid_key = match userdata_key.open_subkey(sid) {
        Ok(k) => k,
        Err(_) => return,
    };

    let products_key = match sid_key.open_subkey("Products") {
        Ok(k) => k,
        Err(_) => return,
    };

    // Test existence of the exact product key for this app.
    // geek does RegOpenKeyExW on HKLM\...\UserData\<sid>\Products\<GUID>
    let product_key = match products_key.open_subkey(product_code) {
        Ok(k) => k,
        Err(_) => return, // This SID doesn't have this product — skip
    };

    tracing::debug!(
        "msi_scanner: found product key for {} under SID {}",
        product_code, sid
    );

    // Only scan Components — we do NOT flag InstallProperties or the product
    // root key itself (deleting the root destroys Windows' record of the app).
    // geek only flags individual Component keys whose path values fall inside
    // the install location.
    if let Some(loc) = install_location {
        scan_product_components(&product_key, product_code, sid, loc, tx);
    }
}

/// Walk `Components` and flag those whose path value starts with `install_location`.
fn scan_product_components(
    product_key: &RegKey,
    product_code: &str,
    sid: &str,
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) {
    let components_key = match product_key.open_subkey("Components") {
        Ok(k) => k,
        Err(_) => return,
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

        // Each component key holds named values whose data is the installed path
        for val_result in comp_key.enum_values() {
            let (_val_name, val_data) = match val_result {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            if let winreg::RegValue {
                bytes,
                vtype: winreg::enums::REG_SZ | winreg::enums::REG_EXPAND_SZ,
            } = val_data
            {
                if let Ok(path_str) = decode_reg_sz(&bytes) {
                    let expanded = expand_env(&path_str);
                    let p = Path::new(&expanded);
                    if p.starts_with(install_location) {
                        // Flag only this specific Component key — leaf level, safe
                        let reg_path = format!(
                            r"HKEY_LOCAL_MACHINE\{}\{}\Products\{}\Components\{}",
                            INSTALLER_USERDATA, sid, product_code, comp_name
                        );
                        let item = LeftoverItem::registry_key(
                            reg_path,
                            ConfidenceLevel::High,
                            SOURCE_INSTALL_PATH.to_string(),
                        );
                        let _ = tx.send(item);
                        break; // one matching value per component key is enough
                    }
                }
            }
        }
    }
}

/// Scan HKLM\...\Installer\Folders for entries matching the install location.
/// geek checks this after UserData (verified in FUN_00445eab post-UserData block).
fn scan_installer_folders(
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let folders_key = match hklm.open_subkey(INSTALLER_FOLDERS) {
        Ok(k) => k,
        Err(_) => return,
    };

    let install_lower = install_location.to_string_lossy().to_lowercase();

    for val_result in folders_key.enum_values() {
        let (val_name, _) = match val_result {
            Ok(pair) => pair,
            Err(_) => continue,
        };

        // Value names ARE the folder paths in Installer\Folders
        let expanded = expand_env(&val_name);
        if expanded.to_lowercase().starts_with(&install_lower) {
            // This is a registry value, not a key
            let reg_path = format!(
                r"HKEY_LOCAL_MACHINE\{}\{}",
                INSTALLER_FOLDERS, val_name
            );
            let item = LeftoverItem::registry_value(
                reg_path,
                ConfidenceLevel::High,
                SOURCE_INSTALL_PATH.to_string(),
            );
            let _ = tx.send(item);
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// MSI database scan, matching geek.exe's CScannerMSI::ScanMSITraces approach.
///
/// Uses the app's MSI ProductCode GUID (from UninstallString) to directly
/// construct and probe `UserData\<SID>\Products\<GUID>` — no name matching.
/// Only flags leaf Component keys whose paths fall under install_location.
pub fn scan_msi_database(
    metadata: Arc<AppMetadata>,
    install_location: Option<Arc<std::path::PathBuf>>,
    tx: Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    // Without a ProductCode we cannot do MSI scanning.
    // Non-MSI installers (NSIS, InnoSetup) have no UserData entry.
    let product_code = match &metadata.msi_product_code {
        Some(code) => code.clone(),
        None => {
            tracing::debug!(
                "msi_scanner: '{}' has no MSI ProductCode, skipping",
                metadata.display_name
            );
            return Ok(());
        }
    };

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let userdata_key = match hklm.open_subkey(INSTALLER_USERDATA) {
        Ok(k) => k,
        Err(e) => {
            warn!("msi_scanner: cannot open UserData key: {}", e);
            return Ok(());
        }
    };

    let loc = install_location.as_deref().map(|p| p.as_path());

    // Enumerate SID buckets (S-1-5-18 for SYSTEM, user SIDs, etc.)
    for sid_result in userdata_key.enum_keys() {
        let sid = match sid_result {
            Ok(s) => s,
            Err(_) => continue,
        };
        scan_sid_for_product(&userdata_key, &sid, &product_code, loc, &tx);
    }

    // Also scan Installer\Folders for entries inside the install location
    if let Some(loc) = loc {
        scan_installer_folders(loc, &tx);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reg_sz_hello() {
        let bytes: Vec<u8> = "Hi\0"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(decode_reg_sz(&bytes).unwrap(), "Hi");
    }

    #[test]
    fn decode_reg_sz_empty() {
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
    fn scan_msi_skips_without_product_code() {
        use crossbeam_channel::unbounded;
        let (tx, rx) = unbounded();
        let meta = Arc::new(AppMetadata::new("NoMSIApp".to_string()));
        // No msi_product_code set → should return Ok and send nothing
        let result = scan_msi_database(meta, None, tx);
        drop(rx);
        assert!(result.is_ok());
    }

    #[test]
    fn scan_msi_does_not_crash_with_fake_guid() {
        use crossbeam_channel::unbounded;
        let (tx, _rx) = unbounded();
        let mut meta = AppMetadata::new("FakeApp".to_string());
        meta.msi_product_code = Some("{00000000-0000-0000-0000-000000000000}".to_string());
        let result = scan_msi_database(Arc::new(meta), None, tx);
        assert!(result.is_ok());
    }
}
