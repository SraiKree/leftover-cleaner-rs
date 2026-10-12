// Registry scanner — Phase 4B of the reconstruction plan.
//
// Three scan passes per the masterplan:
//
//   1. Software subkeys
//        HKCU\Software\<Publisher>\<App>
//        HKCU\Software\<App>
//        HKLM\Software\<Publisher>\<App>
//        HKLM\Software\<App>
//        HKLM\Software\WOW6432Node\<Publisher>\<App>
//        HKLM\Software\WOW6432Node\<App>
//
//   2. App Paths
//        HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<exe_name>
//        where exe_name is derived from UninstallString.
//
//   3. CLSID / COM shell extensions
//        HKCR\CLSID\{...}\InprocServer32 (default value)
//        HKCR\CLSID\{...}\LocalServer32 (default value)
//        Flag if value path starts with install_location.
//
// All items tagged SOURCE_INSTALL_PATH (App Paths / exact Software match)
// or SOURCE_CLSID (CLSID entries).
// SafetyValidator::assign_confidence sets the final ConfidenceLevel.

use std::{path::Path, sync::Arc};

use crossbeam_channel::Sender;
use tracing::warn;
use winreg::{
    enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
    RegKey,
};

use crate::{
    domain::{
        error::ScannerError,
        leftover::{LeftoverCategory, LeftoverItem},
        metadata::AppMetadata,
    },
    engine::safety::{SOURCE_CLSID, SOURCE_INSTALL_PATH},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Normalise a string for loose name comparison:
/// lowercase, strip spaces and common punctuation.
fn normalise(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Check whether `normalise(a)` contains `normalise(b)` as a substring.
fn name_contains(haystack: &str, needle: &str) -> bool {
    let h = normalise(haystack);
    let n = normalise(needle);
    !n.is_empty() && h.contains(n.as_str())
}

/// Extract the executable filename (without extension) from UninstallString.
/// `"C:\Program Files\App\unins000.exe" /SILENT` → `"unins000.exe"`
fn exe_from_uninstall_string(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // If the string starts with a quote, extract everything between the first pair of quotes
    let exe_path = if let Some(rest) = s.strip_prefix('"') {
        // Find the closing quote
        let end = rest.find('"').unwrap_or(rest.len());
        &rest[..end]
    } else {
        // Unquoted — take up to the first space (may be wrong for paths with spaces,
        // but that's the same heuristic geek uses for unquoted strings)
        s.split_whitespace().next().unwrap_or("")
    };

    Path::new(exe_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
}

// ── Scan 1: Software subkeys ──────────────────────────────────────────────────

/// Try to open `base\<segment>` and, if it exists, flag it as a registry-key leftover.
fn try_flag_software_key(
    base: &RegKey,
    subpath: &str,
    tx: &Sender<LeftoverItem>,
    hive_prefix: &str,
) {
    if base.open_subkey(subpath).is_ok() {
        let full = format!(r"{}\{}", hive_prefix, subpath);
        let item = LeftoverItem::registry_key(full, ConfidenceLevel::High, SOURCE_INSTALL_PATH.to_string());
        if tx.send(item).is_err() {
            // channel closed
        }
    }
}

/// Scan HKCU + HKLM + HKLM\WOW6432Node Software subkeys.
///
/// SAFETY NOTE: we only flag `<publisher>\<app>` or `<app>` subkeys, never
/// the bare publisher key.  Flagging `HKCU\Software\Valve` would wipe every
/// Valve title's registry data — we must require the app name to be present
/// in the subkey path.
pub fn scan_software_keys(
    metadata: &AppMetadata,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    let app = &metadata.display_name;
    let pub_opt = metadata.publisher.as_deref();

    // ── HKCU\Software ────────────────────────────────────────────────────────
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(sw) = hkcu.open_subkey(r"Software") {
        // <app> directly under Software
        try_flag_software_key(&sw, app, tx, r"HKEY_CURRENT_USER\Software");
        // <publisher>\<app> — app name must be the leaf, not the publisher alone
        if let Some(pub_name) = pub_opt {
            try_flag_software_key(
                &sw,
                &format!(r"{}\{}", pub_name, app),
                tx,
                r"HKEY_CURRENT_USER\Software",
            );
            // Do NOT flag bare pub_name — that would delete all apps by this publisher
        }
    }

    // ── HKLM\Software ────────────────────────────────────────────────────────
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(sw) = hklm.open_subkey(r"Software") {
        try_flag_software_key(&sw, app, tx, r"HKEY_LOCAL_MACHINE\Software");
        if let Some(pub_name) = pub_opt {
            try_flag_software_key(
                &sw,
                &format!(r"{}\{}", pub_name, app),
                tx,
                r"HKEY_LOCAL_MACHINE\Software",
            );
            // Do NOT flag bare pub_name
        }
    }

    // ── HKLM\Software\WOW6432Node ────────────────────────────────────────────
    if let Ok(wow) = hklm.open_subkey(r"Software\WOW6432Node") {
        try_flag_software_key(&wow, app, tx, r"HKEY_LOCAL_MACHINE\Software\WOW6432Node");
        if let Some(pub_name) = pub_opt {
            try_flag_software_key(
                &wow,
                &format!(r"{}\{}", pub_name, app),
                tx,
                r"HKEY_LOCAL_MACHINE\Software\WOW6432Node",
            );
            // Do NOT flag bare pub_name
        }
    }

    Ok(())
}

// ── Scan 2: App Paths ─────────────────────────────────────────────────────────

/// Check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<exe>.
/// If the key exists and its default value points into the install dir, flag both.
pub fn scan_app_paths(
    metadata: &AppMetadata,
    install_location: Option<&Path>,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    let uninstall_str = match &metadata.uninstall_string {
        Some(s) => s.clone(),
        None => return Ok(()),
    };

    let exe_name = match exe_from_uninstall_string(&uninstall_str) {
        Some(n) => n,
        None => return Ok(()),
    };

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let app_paths_root = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

    // Try exact exe name match
    let subkey_path = format!(r"{}\{}", app_paths_root, exe_name);
    if let Ok(key) = hklm.open_subkey(&subkey_path) {
        // Confirm the default value (executable path) is inside install_location
        let should_flag = if let Some(loc) = install_location {
            key.get_value::<String, _>("")
                .map(|val| Path::new(&val).starts_with(loc))
                .unwrap_or(true) // default: flag it
        } else {
            true
        };

        if should_flag {
            let full = format!(r"HKEY_LOCAL_MACHINE\{}", subkey_path);
            let item =
                LeftoverItem::registry_key(full, ConfidenceLevel::High, SOURCE_INSTALL_PATH.to_string());
            let _ = tx.send(item);
        }
    }

    // Also look for any key whose exe name contains the app display name (fuzzy fallback)
    if let Ok(root) = hklm.open_subkey(app_paths_root) {
        for name_result in root.enum_keys() {
            let name = match name_result {
                Ok(n) => n,
                Err(_) => continue,
            };
            if name_contains(&name, &metadata.display_name) {
                if let Ok(key) = root.open_subkey(&name) {
                    let should_flag = if let Some(loc) = install_location {
                        key.get_value::<String, _>("")
                            .map(|val| Path::new(&val).starts_with(loc))
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if should_flag {
                        let full = format!(r"HKEY_LOCAL_MACHINE\{}\{}", app_paths_root, name);
                        let item = LeftoverItem::registry_key(
                            full,
                            ConfidenceLevel::High,
                            SOURCE_INSTALL_PATH.to_string(),
                        );
                        let _ = tx.send(item);
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Scan 3: CLSID / COM ───────────────────────────────────────────────────────

/// Enumerate HKCR\CLSID\{...} and flag InprocServer32 / LocalServer32 entries
/// whose default value path starts with `install_location`.
///
/// HKCR is effectively HKLM\Software\Classes merged with HKCU\Software\Classes.
/// The winreg crate provides HKEY_CLASSES_ROOT for direct access.
///
/// Expensive — runs only when install_location is known.
pub fn scan_clsid(
    install_location: &Path,
    tx: &Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let clsid_root = match hkcr.open_subkey("CLSID") {
        Ok(k) => k,
        Err(e) => {
            warn!("reg_scanner: cannot open HKCR\\CLSID: {}", e);
            return Ok(());
        }
    };

    let server_subkeys = ["InprocServer32", "LocalServer32"];

    for guid_result in clsid_root.enum_keys() {
        let guid = match guid_result {
            Ok(g) => g,
            Err(_) => continue,
        };

        let guid_key = match clsid_root.open_subkey(&guid) {
            Ok(k) => k,
            Err(_) => continue,
        };

        for server_subkey in &server_subkeys {
            let server_key = match guid_key.open_subkey(server_subkey) {
                Ok(k) => k,
                Err(_) => continue,
            };

            // Default value = the DLL / EXE path
            let dll_path: String = match server_key.get_value("") {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Expand environment variables embedded in value (e.g. %SystemRoot%)
            let expanded = expand_env_string(&dll_path);
            let dll_path_obj = Path::new(&expanded);

            if dll_path_obj.starts_with(install_location) {
                let reg_path = format!(
                    r"HKEY_CLASSES_ROOT\CLSID\{}\{}",
                    guid, server_subkey
                );
                let item =
                    LeftoverItem::registry_key(reg_path, ConfidenceLevel::Low, SOURCE_CLSID.to_string());
                if tx.send(item).is_err() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Expand `%EnvVar%` tokens in a registry path value string.
/// Avoids pulling in extra crates — handles the common single-variable case.
fn expand_env_string(s: &str) -> String {
    // Fast path — no percent signs
    if !s.contains('%') {
        return s.to_string();
    }

    let mut result = s.to_string();
    // Expand up to 10 env vars to avoid infinite loops
    for _ in 0..10 {
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

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all registry scan passes and stream results to `tx`.
/// Called from `scan_all()` on a rayon worker thread.
pub fn scan_registry(
    metadata: Arc<AppMetadata>,
    install_location: Option<Arc<std::path::PathBuf>>,
    tx: Sender<LeftoverItem>,
) -> Result<(), ScannerError> {
    scan_software_keys(&metadata, &tx)?;

    let loc = install_location.as_deref().map(|p| p.as_path());
    scan_app_paths(&metadata, loc, &tx)?;

    if let Some(ref loc) = install_location {
        scan_clsid(loc, &tx)?;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_strips_case_and_punctuation() {
        assert_eq!(normalise("Hello World!"), "helloworld");
        assert_eq!(normalise("My-App_v2"), "myappv2");
    }

    #[test]
    fn name_contains_substring() {
        assert!(name_contains("MyAppCache", "myapp"));
        assert!(!name_contains("OtherApp", "myapp"));
        assert!(!name_contains("", "myapp"));
    }

    #[test]
    fn exe_from_uninstall_string_quoted() {
        let s = r#""C:\Program Files\App\unins000.exe" /SILENT"#;
        assert_eq!(
            exe_from_uninstall_string(s).as_deref(),
            Some("unins000.exe")
        );
    }

    #[test]
    fn exe_from_uninstall_string_unquoted() {
        // Unquoted path with no spaces — space-split works correctly
        let s = r"C:\Windows\App\unins000.exe /SILENT";
        assert_eq!(
            exe_from_uninstall_string(s).as_deref(),
            Some("unins000.exe")
        );
    }

    #[test]
    fn exe_from_uninstall_string_empty() {
        assert!(exe_from_uninstall_string("").is_none());
    }

    #[test]
    fn expand_env_string_no_vars() {
        assert_eq!(expand_env_string("plain string"), "plain string");
    }

    #[test]
    fn expand_env_string_with_system_root() {
        // SystemRoot is always set on Windows
        let result = expand_env_string("%SystemRoot%\\foo.dll");
        assert!(!result.starts_with('%'), "should expand: {result}");
        assert!(result.ends_with(r"\foo.dll"), "should keep suffix: {result}");
    }

    #[test]
    fn expand_env_string_unknown_var_left_intact() {
        let result = expand_env_string("%NONEXISTENT_XYZ_VAR%\\foo.dll");
        // Can't expand — leaves the string as-is
        assert!(result.contains("NONEXISTENT_XYZ_VAR"), "{result}");
    }

    // ── Software key scan — live registry read (HKCU\Software should always open) ──

    #[test]
    fn scan_software_keys_does_not_crash_on_common_names() {
        use crossbeam_channel::unbounded;
        let (tx, _rx) = unbounded();
        let meta = AppMetadata::new("SomeMadeUpAppXYZ123".to_string());
        // Should return Ok even when the key doesn't exist
        let result = scan_software_keys(&meta, &tx);
        assert!(result.is_ok());
    }
}
