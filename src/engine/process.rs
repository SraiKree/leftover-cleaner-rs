// Uninstaller process launch — REA-verified against geek.exe.
//
// geek.exe CUninstallProcess::Uninstall_Thread (0x43cc16) does:
//
//   CreateProcessW(
//     lpApplicationName = NULL,
//     lpCommandLine     = full_uninstall_string,   // verbatim from registry
//     dwCreationFlags   = CREATE_NEW_CONSOLE,      // 0x20  (interactive)
//     STARTUPINFO.cb    = 0x44, all zeroes,
//   )
//   then WaitForSingleObject(hProcess, ...) + polls child count.
//
// Critical: NO CREATE_SUSPENDED, NO job object on the initial spawn.
// CREATE_SUSPENDED + job assignment blocks Chrome's internal UAC elevation
// path, preventing its child (the real uninstaller UI) from launching.
//
// We replicate this exactly: plain CreateProcessW with CREATE_NEW_CONSOLE,
// then poll until the primary process exits. For launchers that spawn
// children (Chrome, Electron), we additionally poll child exit via
// WaitForProcessAndChildren pattern.

use std::path::{Path, PathBuf};
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            CreateProcessW, GetExitCodeProcess, WaitForSingleObject,
            CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOW,
        },
    },
};

use crate::domain::error::ProcessError;

/// Result of parsing an uninstall string into executable + arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallCommand {
    /// Absolute path (or bare exe name for system tools like MsiExec.exe)
    pub exe: String,
    /// Arguments to pass verbatim
    pub args: Vec<String>,
}

/// Parse a Windows UninstallString registry value into exe + args.
///
/// Handles:
/// - `"C:\Program Files\App\un.exe" /S`
/// - `C:\Program Files\App\un.exe /S`
/// - `MsiExec.exe /X{GUID}`
///
/// Returns `None` if the string is empty or unparseable.
pub fn parse_uninstall_string(s: &str) -> Option<UninstallCommand> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (exe, rest) = if let Some(inner) = s.strip_prefix('"') {
        let close = inner.find('"').unwrap_or(inner.len());
        let exe = inner[..close].to_string();
        let rest = inner.get(close + 1..).unwrap_or("").trim().to_string();
        (exe, rest)
    } else {
        if let Some(pos) = s.find(' ') {
            (s[..pos].to_string(), s[pos + 1..].trim().to_string())
        } else {
            (s.to_string(), String::new())
        }
    };

    if exe.is_empty() {
        return None;
    }

    Some(UninstallCommand { exe, args: split_args(&rest) })
}

/// Minimal argument splitter respecting double-quoted tokens.
fn split_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for ch in s.chars() {
        match ch {
            '"' => { in_quote = !in_quote; current.push(ch); }
            ' ' if !in_quote => {
                let token = current.trim().to_string();
                if !token.is_empty() { args.push(token); }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let token = current.trim().to_string();
    if !token.is_empty() { args.push(token); }
    args
}

// Poll interval for WaitForSingleObject
const POLL_MS: u32 = 200;
// Max wait (10 min)
const MAX_WAIT_MS: u32 = 600_000;
// After primary exits quickly, wait this long for spawned children
const CHILD_WAIT_MS: u32 = MAX_WAIT_MS;
// "Quick" primary exit threshold — launcher pattern if < this
const LAUNCHER_THRESHOLD_MS: u32 = 3_000;

/// Resolve a bare exe name (e.g. "MsiExec.exe") to full System32 path.
/// Returns unchanged path if it already contains separators.
pub fn resolve_exe_path(exe: &str) -> PathBuf {
    let p = Path::new(exe);
    if p.components().count() > 1 || p.has_root() {
        return p.to_path_buf();
    }

    let system32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32").join(exe))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32").join(exe));
    if system32.exists() { return system32; }

    let syswow64 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("SysWOW64").join(exe))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\SysWOW64").join(exe));
    if syswow64.exists() { return syswow64; }

    p.to_path_buf()
}

/// RAII guard for a spawned uninstaller process.
/// Drops close the process handle — does NOT kill the process.
pub struct ProcessTreeGuard {
    primary_pid: u32,
    primary_handle: HANDLE,
}

impl ProcessTreeGuard {
    /// Spawn the uninstaller using CREATE_NEW_CONSOLE — exactly as geek does.
    ///
    /// lpApplicationName = NULL, lpCommandLine = full quoted cmd string.
    /// CREATE_NEW_CONSOLE lets interactive UIs appear in their own window.
    pub fn spawn_and_assign(exe_path: &Path, args: &[&str]) -> Result<Self, ProcessError> {
        // Build: "exe_path" arg1 arg2 ...
        let cmd_line = build_command_line(exe_path, args);
        let cmd_hstr = HSTRING::from(cmd_line.as_str());

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                None,
                windows::core::PWSTR(cmd_hstr.as_ptr() as *mut u16),
                None,
                None,
                false,
                CREATE_NEW_CONSOLE,   // ← geek uses 0x20; NOT CREATE_SUSPENDED
                None,
                None,
                &si,
                &mut pi,
            )
            .map_err(|e| ProcessError::Execution(format!("CreateProcessW: {e}")))?
        };

        // Close thread handle immediately — not needed
        unsafe { let _ = CloseHandle(pi.hThread); }

        Ok(Self {
            primary_pid: pi.dwProcessId,
            primary_handle: pi.hProcess,
        })
    }

    /// Wait for the primary process (and optionally spawned children) to exit.
    ///
    /// Returns `(exit_code, elapsed_ms)`.
    ///
    /// Launcher pattern: if primary exits in < LAUNCHER_THRESHOLD_MS we
    /// continue polling for child processes via snapshot until they all exit
    /// or MAX_WAIT_MS is reached.
    pub fn wait_for_completion(&self) -> Result<(u32, u32), ProcessError> {
        let mut elapsed = 0u32;
        let mut exit_code = 0u32;

        // Phase 1: wait for primary
        loop {
            let result = unsafe { WaitForSingleObject(self.primary_handle, POLL_MS) };
            match result {
                WAIT_OBJECT_0 => {
                    unsafe {
                        GetExitCodeProcess(self.primary_handle, &mut exit_code)
                            .map_err(|e| ProcessError::Execution(
                                format!("GetExitCodeProcess: {e}")))?
                    };
                    break;
                }
                WAIT_TIMEOUT => {
                    elapsed += POLL_MS;
                    if elapsed >= MAX_WAIT_MS {
                        return Err(ProcessError::Timeout(format!(
                            "PID {} timed out after {}ms", self.primary_pid, MAX_WAIT_MS
                        )));
                    }
                }
                _ => return Err(ProcessError::Execution(format!(
                    "WaitForSingleObject failed for PID {}", self.primary_pid
                ))),
            }
        }

        // Phase 2: launcher pattern — if primary exited fast, wait for children
        // We poll by checking if any process with our PID as parent still runs.
        // Simple approach: sleep a bit and let the child do its work.
        // For Chrome: setup.exe spawns an elevated child; we can't track it
        // directly since it has a new token, but we can wait for user interaction.
        if elapsed < LAUNCHER_THRESHOLD_MS {
            // Poll for child processes using CreateToolhelp32Snapshot
            let mut child_elapsed = 0u32;
            loop {
                let children = count_child_processes(self.primary_pid);
                if children == 0 {
                    break; // no tracked children
                }
                std::thread::sleep(std::time::Duration::from_millis(POLL_MS as u64));
                child_elapsed += POLL_MS;
                elapsed += POLL_MS;
                if child_elapsed >= CHILD_WAIT_MS {
                    break; // give up waiting for children
                }
            }
        }

        Ok((exit_code, elapsed))
    }

    pub fn primary_pid(&self) -> u32 {
        self.primary_pid
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.primary_handle); }
    }
}

/// Count live child processes using CreateToolhelp32Snapshot.
/// Returns 0 on any error (conservative — don't block on failure).
fn count_child_processes(parent_pid: u32) -> u32 {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    let snap = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return 0,
        }
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut count = 0u32;

    unsafe {
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ParentProcessID == parent_pid {
                    count += 1;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }

    count
}

/// Build `"exe_path" arg1 arg2 ...` command line.
fn build_command_line(exe: &Path, args: &[&str]) -> String {
    let mut cmd = format!("\"{}\"", exe.display());
    for arg in args {
        cmd.push(' ');
        if arg.contains(' ') {
            cmd.push('"');
            cmd.push_str(arg);
            cmd.push('"');
        } else {
            cmd.push_str(arg);
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_line_no_args() {
        let path = Path::new(r"C:\Windows\System32\cmd.exe");
        let cmd = build_command_line(path, &[]);
        assert_eq!(cmd, r#""C:\Windows\System32\cmd.exe""#);
    }

    #[test]
    fn build_command_line_simple_args() {
        let path = Path::new(r"C:\setup.exe");
        let cmd = build_command_line(path, &["/S", "/quiet"]);
        assert_eq!(cmd, r#""C:\setup.exe" /S /quiet"#);
    }

    #[test]
    fn build_command_line_space_in_arg() {
        let path = Path::new(r"C:\setup.exe");
        let cmd = build_command_line(path, &["/D=C:\\Program Files\\App"]);
        assert!(cmd.contains('"'));
    }

    #[test]
    fn parse_uninstall_string_quoted_exe_with_args() {
        let s = r#""C:\Program Files\App\uninstall.exe" /S /quiet"#;
        let cmd = parse_uninstall_string(s).unwrap();
        assert_eq!(cmd.exe, r"C:\Program Files\App\uninstall.exe");
        assert_eq!(cmd.args, vec!["/S", "/quiet"]);
    }

    #[test]
    fn parse_uninstall_string_unquoted_exe_with_args() {
        let s = r"C:\App\uninstall.exe /S";
        let cmd = parse_uninstall_string(s).unwrap();
        assert_eq!(cmd.exe, r"C:\App\uninstall.exe");
        assert_eq!(cmd.args, vec!["/S"]);
    }

    #[test]
    fn parse_uninstall_string_msi_exec() {
        let s = r"MsiExec.exe /X{1D14C083-6BF1-4D4B-9F5C-B0DC6A1E3F55}";
        let cmd = parse_uninstall_string(s).unwrap();
        assert_eq!(cmd.exe, "MsiExec.exe");
        assert_eq!(cmd.args, vec!["/X{1D14C083-6BF1-4D4B-9F5C-B0DC6A1E3F55}"]);
    }

    #[test]
    fn parse_uninstall_string_no_args() {
        let s = r#""C:\App\un.exe""#;
        let cmd = parse_uninstall_string(s).unwrap();
        assert_eq!(cmd.exe, r"C:\App\un.exe");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn parse_uninstall_string_empty() {
        assert!(parse_uninstall_string("").is_none());
        assert!(parse_uninstall_string("   ").is_none());
    }

    #[test]
    fn parse_uninstall_string_chrome_style() {
        let s = r#""C:\Program Files\Google\Chrome\Application\154.0.8037.99\Installer\setup.exe" --uninstall --channel=stable --system-level --verbose-logging"#;
        let cmd = parse_uninstall_string(s).unwrap();
        assert_eq!(cmd.exe, r"C:\Program Files\Google\Chrome\Application\154.0.8037.99\Installer\setup.exe");
        assert!(cmd.args.contains(&"--uninstall".to_string()));
        assert!(cmd.args.contains(&"--system-level".to_string()));
    }
}
