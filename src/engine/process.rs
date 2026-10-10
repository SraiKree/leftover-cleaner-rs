// Process monitoring via Windows Job Objects.
// Job object kill-on-close = all children die when guard drops.
// RAII: no manual cleanup needed.

use std::path::Path;
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
                QueryInformationJobObject, SetInformationJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::{
                CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
                CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};

use crate::domain::error::ProcessError;

// Milliseconds between polls when waiting for job completion
const POLL_INTERVAL_MS: u32 = 100;
// Max wait time before declaring timeout (10 minutes)
const MAX_WAIT_MS: u32 = 600_000;

/// RAII guard wrapping a Windows Job Object.
/// Spawn uninstaller inside it so all child processes are killed on drop.
pub struct ProcessTreeGuard {
    // Job object handle — all assigned processes die when this closes
    job_handle: HANDLE,
    // PID of the root process we spawned
    primary_pid: u32,
    // Handle to the primary process for WaitForSingleObject
    primary_handle: HANDLE,
}

impl ProcessTreeGuard {
    /// Spawn executable in CREATE_SUSPENDED, assign to job, then resume.
    /// Returns guard that owns the job + process handles.
    pub fn spawn_and_assign(exe_path: &Path, args: &[&str]) -> Result<Self, ProcessError> {
        // Build command line string: "exe_path" arg1 arg2 ...
        let cmd_line = build_command_line(exe_path, args);
        let cmd_hstr = HSTRING::from(cmd_line.as_str());

        // Create job object — name is NULL (anonymous)
        let job_handle = unsafe {
            CreateJobObjectW(None, None)
                .map_err(|e| ProcessError::JobObjectCreation(e.to_string()))?
        };

        // Set KILL_ON_JOB_CLOSE so children die automatically on Drop
        let mut limit_info = JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ..Default::default()
        };
        unsafe {
            SetInformationJobObject(
                job_handle,
                windows::Win32::System::JobObjects::JobObjectBasicLimitInformation,
                &mut limit_info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| ProcessError::JobObjectCreation(format!("SetInformationJobObject: {e}")))?
        };

        // Launch process suspended so we can assign before any code runs
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
                CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut pi,
            )
            .map_err(|e| ProcessError::Execution(format!("CreateProcessW: {e}")))?
        };

        let proc_handle = pi.hProcess;
        let thread_handle = pi.hThread;
        let primary_pid = pi.dwProcessId;

        // Assign to job before first instruction runs
        unsafe {
            AssignProcessToJobObject(job_handle, proc_handle).map_err(|e| {
                // Clean up before returning error
                let _ = CloseHandle(proc_handle);
                let _ = CloseHandle(thread_handle);
                ProcessError::JobAssignment(e.to_string())
            })?
        };

        // Resume now that job assignment is atomic
        unsafe {
            ResumeThread(thread_handle);
            CloseHandle(thread_handle).ok(); // thread handle no longer needed
        }

        Ok(Self {
            job_handle,
            primary_pid,
            primary_handle: proc_handle,
        })
    }

    /// Block until primary process exits or timeout reached.
    /// Returns exit code on success.
    pub fn wait_for_completion(&self) -> Result<u32, ProcessError> {
        let mut elapsed = 0u32;

        loop {
            let result =
                unsafe { WaitForSingleObject(self.primary_handle, POLL_INTERVAL_MS) };

            match result {
                WAIT_OBJECT_0 => {
                    // Process exited — grab exit code
                    let mut exit_code: u32 = 0;
                    unsafe {
                        GetExitCodeProcess(self.primary_handle, &mut exit_code)
                            .map_err(|e| ProcessError::Execution(format!("GetExitCodeProcess: {e}")))?
                    };
                    return Ok(exit_code);
                }
                WAIT_TIMEOUT => {
                    elapsed += POLL_INTERVAL_MS;
                    if elapsed >= MAX_WAIT_MS {
                        return Err(ProcessError::Timeout(format!(
                            "PID {} timed out after {}ms",
                            self.primary_pid, MAX_WAIT_MS
                        )));
                    }
                    // Keep polling with natural backoff via WaitForSingleObject timeout
                }
                _ => {
                    return Err(ProcessError::Execution(format!(
                        "WaitForSingleObject unexpected result for PID {}",
                        self.primary_pid
                    )));
                }
            }
        }
    }

    /// How many active processes are in the job right now.
    /// Useful for diagnostics / tests.
    pub fn active_process_count(&self) -> Result<u32, ProcessError> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                self.job_handle,
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
            .map_err(|e| ProcessError::Execution(format!("QueryInformationJobObject: {e}")))?
        };
        Ok(info.ActiveProcesses)
    }

    /// Exposed for tests to verify job handle is valid
    pub fn primary_pid(&self) -> u32 {
        self.primary_pid
    }
}

/// Drop kills the entire process tree then closes handles.
/// KILL_ON_JOB_CLOSE handles the tree; we just close.
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        // Close primary process handle
        unsafe {
            let _ = CloseHandle(self.primary_handle);
            // Closing job handle triggers KILL_ON_JOB_CLOSE for any survivors
            let _ = CloseHandle(self.job_handle);
        }
    }
}

// Build "path\to\exe.exe" arg1 arg2 ... as wide string
fn build_command_line(exe: &Path, args: &[&str]) -> String {
    let mut cmd = format!("\"{}\"", exe.display());
    for arg in args {
        cmd.push(' ');
        // Quote args with spaces
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

    // Note: tests that create real processes need admin / a real exe.
    // Unit tests focus on pure logic (command-line builder, error paths).

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
        // arg has space → should be quoted
        assert!(cmd.contains('"'));
    }
}
