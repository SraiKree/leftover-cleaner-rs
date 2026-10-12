// InstallLocationFinder — Reverse-engineered from Geek Uninstaller (geek.exe: CInstallLocationFinder)
//
// Key reverse-engineered mechanics:
// 1. If install_location exists in registry and passes is_safe_install_location, accept it.
// 2. FindByUninstallString:
//    - Strips command-line arguments and quotes.
//    - Expands 8.3 short paths via Windows API GetLongPathNameW.
//    - Tests LocalAppData\Programs.
//    - Trims parent path segments while computing normalized Levenshtein similarity
//      against DisplayName (GetInstallLocationFromPathLevinshtein / FUN_004347a3).
// 3. FindByDisplayIcon:
//    - Extracts executable/ico path, strips icon index (e.g. ",0"), resolves long path,
//      and performs Levenshtein parent path trimming.
// 4. FindByDisplayName:
//    - Searches standard roots (Program Files, Program Files (x86), LocalAppData\Programs, ProgramData).
//    - Evaluates subdirectories using Levenshtein distance (similarity >= 0.70).
// 5. All candidates must pass is_safe_install_location.

use std::path::{Path, PathBuf};
use strsim::normalized_levenshtein;
use tracing::{debug, info};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::GetLongPathNameW;

use crate::domain::metadata::AppMetadata;
use crate::engine::safety::is_safe_install_location;

/// Resolves the true application installation root directory using Geek Uninstaller algorithms.
pub struct InstallLocationFinder;

impl InstallLocationFinder {
    /// Find the confirmed install location for an application.
    pub fn find(metadata: &AppMetadata) -> Option<PathBuf> {
        // Step 1: Check metadata.install_location if present
        if let Some(ref loc) = metadata.install_location {
            let path = PathBuf::from(loc.trim().trim_matches('"'));
            let resolved = Self::resolve_long_path(&path);
            if is_safe_install_location(&resolved) {
                info!("InstallLocationFinder: accepted registry install_location: {:?}", resolved);
                return Some(resolved);
            }
        }

        // Step 2: FindByUninstallString
        if let Some(ref uninstall_str) = metadata.uninstall_string {
            if let Some(loc) = Self::find_by_uninstall_string(uninstall_str, metadata) {
                if is_safe_install_location(&loc) {
                    info!("InstallLocationFinder: found via uninstall string: {:?}", loc);
                    return Some(loc);
                }
            }
        }

        // Step 3: FindByDisplayIcon
        if let Some(ref icon_str) = metadata.display_icon {
            if let Some(loc) = Self::find_by_display_icon(icon_str, metadata) {
                if is_safe_install_location(&loc) {
                    info!("InstallLocationFinder: found via display icon: {:?}", loc);
                    return Some(loc);
                }
            }
        }

        // Step 4: FindByDisplayName
        if let Some(loc) = Self::find_by_display_name(metadata) {
            if is_safe_install_location(&loc) {
                info!("InstallLocationFinder: found via display name: {:?}", loc);
                return Some(loc);
            }
        }

        None
    }

    /// Extract install location from uninstall string.
    pub fn find_by_uninstall_string(uninstall_str: &str, metadata: &AppMetadata) -> Option<PathBuf> {
        let clean_exe_path = Self::extract_executable_path(uninstall_str)?;
        let long_path = Self::resolve_long_path(&clean_exe_path);

        Self::get_install_location_from_path_levenshtein(&long_path, &metadata.display_name)
    }

    /// Extract install location from display icon path.
    pub fn find_by_display_icon(icon_str: &str, metadata: &AppMetadata) -> Option<PathBuf> {
        let trimmed = icon_str.trim();
        // Remove icon resource index e.g. "C:\Path\app.exe,0" or "-1"
        let icon_path_str = if let Some((path_part, _)) = trimmed.split_once(',') {
            path_part.trim().trim_matches('"')
        } else {
            trimmed.trim_matches('"')
        };

        let path = PathBuf::from(icon_path_str);
        if !path.exists() {
            return None;
        }

        let long_path = Self::resolve_long_path(&path);
        Self::get_install_location_from_path_levenshtein(&long_path, &metadata.display_name)
    }

    /// Scan Program Files and LocalAppData for folder matching DisplayName.
    pub fn find_by_display_name(metadata: &AppMetadata) -> Option<PathBuf> {
        let clean_name = Self::sanitize_app_name(&metadata.display_name);
        if clean_name.is_empty() {
            return None;
        }

        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| format!(r"{}\Program Files", system_drive));
        let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| format!(r"{}\Program Files (x86)", system_drive));
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let program_data = std::env::var("PROGRAMDATA").unwrap_or_else(|_| format!(r"{}\ProgramData", system_drive));

        let mut roots = vec![
            PathBuf::from(program_files),
            PathBuf::from(program_files_x86),
            PathBuf::from(program_data),
        ];

        if !local_app_data.is_empty() {
            roots.push(PathBuf::from(local_app_data).join("Programs"));
        }

        let mut best_candidate: Option<(PathBuf, f64)> = None;

        for root in roots {
            if !root.exists() {
                continue;
            }

            let entries = match std::fs::read_dir(&root) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let candidate_path = entry.path();
                if !candidate_path.is_dir() {
                    continue;
                }

                let dir_name = candidate_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let sanitized_dir = Self::sanitize_app_name(dir_name);

                // Exact slug match or publisher matching
                let sim = normalized_levenshtein(&clean_name.to_lowercase(), &sanitized_dir.to_lowercase());
                if sim >= 0.70 {
                    if let Some((_, best_sim)) = best_candidate {
                        if sim > best_sim {
                            best_candidate = Some((candidate_path, sim));
                        }
                    } else {
                        best_candidate = Some((candidate_path, sim));
                    }
                }
            }
        }

        best_candidate.map(|(p, _)| p)
    }

    /// Reverse-engineered FUN_004347a3 (GetInstallLocationFromPathLevinshtein):
    /// Trims trailing segments of a file path, checking each ancestor directory against DisplayName.
    pub fn get_install_location_from_path_levenshtein(path: &Path, display_name: &str) -> Option<PathBuf> {
        let clean_display = Self::sanitize_app_name(display_name);
        let mut curr = if path.is_file() {
            path.parent()?.to_path_buf()
        } else {
            path.to_path_buf()
        };

        let mut best_match: Option<(PathBuf, f64)> = None;

        // Walk up ancestors
        while let Some(parent) = curr.parent() {
            // Do not consider root drives or empty paths
            if parent.parent().is_none() {
                break;
            }

            let seg_name = curr.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let sanitized_seg = Self::sanitize_app_name(seg_name);

            if !sanitized_seg.is_empty() && !clean_display.is_empty() {
                let sim = normalized_levenshtein(
                    &sanitized_seg.to_lowercase(),
                    &clean_display.to_lowercase(),
                );
                
                // If this segment has strong similarity (>= 0.60) or exact contains
                if sim >= 0.60 || sanitized_seg.to_lowercase().contains(&clean_display.to_lowercase()) {
                    if let Some((_, best_sim)) = best_match {
                        if sim >= best_sim {
                            best_match = Some((curr.clone(), sim));
                        }
                    } else {
                        best_match = Some((curr.clone(), sim));
                    }
                }
            }

            curr = parent.to_path_buf();
        }

        if let Some((matched_path, _)) = best_match {
            return Some(matched_path);
        }

        // If no ancestor reached the Levenshtein threshold, return the immediate parent of the binary
        if path.is_file() {
            path.parent().map(|p| p.to_path_buf())
        } else {
            Some(path.to_path_buf())
        }
    }

    /// Extract executable path from an uninstall command line string.
    pub fn extract_executable_path(cmd: &str) -> Option<PathBuf> {
        let trimmed = cmd.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Ignore MSI commands like MsiExec.exe /X{...}
        if trimmed.to_lowercase().contains("msiexec") {
            return None;
        }

        // 1. Quoted string: "C:\Program Files\App\unins000.exe" /SILENT
        if let Some(stripped) = trimmed.strip_prefix('"') {
            if let Some(end_quote) = stripped.find('"') {
                let path_str = &stripped[..end_quote];
                return Some(PathBuf::from(path_str));
            }
        }

        // 2. Unquoted string ending with .exe / .cmd / .bat
        for ext in &[".exe", ".cmd", ".bat"] {
            if let Some(idx) = trimmed.to_lowercase().find(ext) {
                let end = idx + ext.len();
                let path_str = trimmed[..end].trim();
                return Some(PathBuf::from(path_str));
            }
        }

        // 3. Fallback: split by whitespace
        trimmed.split_whitespace().next().map(PathBuf::from)
    }

    /// Convert short 8.3 paths (e.g. C:\PROGRA~1\...) to standard long paths via Windows API.
    pub fn resolve_long_path(path: &Path) -> PathBuf {
        let path_str = path.to_string_lossy();
        if !path_str.contains('~') {
            return path.to_path_buf();
        }

        let wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buffer: [u16; 1024] = [0; 1024];

        unsafe {
            let res = GetLongPathNameW(
                PCWSTR(wide.as_ptr()),
                Some(&mut buffer),
            );
            if res > 0 && (res as usize) < buffer.len() {
                let long_str = String::from_utf16_lossy(&buffer[..res as usize]);
                return PathBuf::from(long_str);
            }
        }

        path.to_path_buf()
    }

    /// Strip version, edition, architecture noise for matching.
    pub fn sanitize_app_name(name: &str) -> String {
        let stripped = regex::Regex::new(r"\(.*?\)|\b\d+(\.\d+)*\b|v\d+.*|Edition|Professional|Standard|Enterprise|x64|x86|64-bit|32-bit")
            .map(|re| re.replace_all(name, " ").to_string())
            .unwrap_or_else(|_| name.to_string());
        
        stripped.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_executable_path() {
        let cmd1 = r#""C:\Program Files\VLC\uninstall.exe" /S"#;
        assert_eq!(
            InstallLocationFinder::extract_executable_path(cmd1),
            Some(PathBuf::from(r"C:\Program Files\VLC\uninstall.exe"))
        );

        let cmd2 = r#"C:\Program Files\Sublime Text\unins000.exe /silent"#;
        assert_eq!(
            InstallLocationFinder::extract_executable_path(cmd2),
            Some(PathBuf::from(r"C:\Program Files\Sublime Text\unins000.exe"))
        );

        let cmd_msi = r#"MsiExec.exe /I{12345678-ABCD-1234-ABCD-1234567890AB}"#;
        assert_eq!(InstallLocationFinder::extract_executable_path(cmd_msi), None);
    }

    #[test]
    fn test_levenshtein_path_decomposition() {
        let deep_path = Path::new(r"C:\Program Files\Notepad++\bin\tools\uninstall.exe");
        let found = InstallLocationFinder::get_install_location_from_path_levenshtein(deep_path, "Notepad++ (64-bit x64)");
        assert_eq!(found, Some(PathBuf::from(r"C:\Program Files\Notepad++")));
    }
}
