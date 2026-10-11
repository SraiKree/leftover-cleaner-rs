use clap::Parser;
use bucket_uninstaller::domain::app::{Application, Discovered};
use bucket_uninstaller::domain::leftover::LeftoverItem;
use bucket_uninstaller::engine::{
    cleaner::SafeDeletionEngine, harvester, process::parse_uninstall_string,
    process::resolve_exe_path, process::ProcessTreeGuard, resolver,
};
use bucket_uninstaller::scanner::{self, UninstallerContext};
use bucket_uninstaller::ui::tui;
use crossterm::{
    event::DisableMouseCapture,
    execute,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
};
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::sync::Arc;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt;

#[derive(Parser, Debug)]
#[command(name = "bucket-uninstaller")]
#[command(about = "Clean leftover files and registry entries after application uninstallation", long_about = None)]
struct Args {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Dry-run mode (don't actually delete anything)
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Skip uninstaller execution (scan for leftovers without running uninstaller)
    #[arg(short, long)]
    skip_uninstall: bool,
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original(info);
    }));
}

fn main() -> Result<(), Box<dyn Error>> {
    install_panic_hook();
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    fmt().with_max_level(log_level).init();

    info!(
        "Starting {} v{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    // Elevation check — registry writes and Program Files deletions require admin.
    if !is_elevated() {
        eprintln!(
            "\n  ⚠  Bucket Uninstaller must be run as Administrator.\n\n  \
             Right-click the terminal and choose \"Run as administrator\",\n  \
             then try again.\n"
        );
        std::process::exit(1);
    }

    // Phase 1: Harvest installed applications
    info!("Phase 1: Harvesting installed applications...");
    let metadata_list = harvester::harvest_installed_apps()?;
    info!("Found {} installed applications", metadata_list.len());

    if metadata_list.is_empty() {
        warn!("No applications found. Exiting.");
        return Ok(());
    }

    // Phase 2: Resolve install locations
    info!("Phase 2: Resolving install locations...");
    let apps: Vec<Application<Discovered>> = metadata_list
        .into_iter()
        .map(|mut metadata| {
            if metadata.install_location.is_none() {
                if let Ok(location) = resolver::resolve_install_location(&metadata) {
                    metadata.install_location = Some(location.to_string_lossy().to_string());
                }
            }
            Application::new(metadata)
        })
        .collect();

    info!("Resolved install locations for {} apps", apps.len());

    // Scan cache: keyed by display_name — re-selecting same app uses cached results
    let mut scan_cache: HashMap<String, Vec<LeftoverItem>> = HashMap::new();

    // Phase 3: Show TUI immediately — user picks an app
    info!("Phase 3: Launching TUI for application selection...");
    let selection = tui::run_app_selection_tui(apps)?;

    let (_app_idx, selected_app) = match selection {
        Some(s) => s,
        None => {
            info!("No application selected. Exiting.");
            return Ok(());
        }
    };

    info!("Selected: {}", selected_app.metadata.display_name);
        let app_name = selected_app.metadata.display_name.clone();

        // Phase 4: Check cache first
        let leftovers: Vec<LeftoverItem> = if let Some(cached) = scan_cache.get(&app_name) {
            info!(
                "Phase 4: Using cached scan results for '{}' ({} items).",
                app_name,
                cached.len()
            );
            cached.clone()
        } else {
            // Phase 4a: Run uninstaller through the TUI overlay (shows progress, allows cancel)
            let uninstaller_context = if args.skip_uninstall {
                info!("Phase 4: Skipping uninstaller (--skip-uninstall).");
                UninstallerContext::skipped()
            } else {
                // run_uninstall_tui spawns the uninstaller, shows a live "Uninstalling…"
                // screen with spinner + elapsed timer, and returns the context when done.
                // If the user cancels (Esc) the guard's Drop kills the process tree.
                match tui::run_uninstall_tui(&selected_app.metadata) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        warn!("Uninstall TUI error for '{}': {}. Continuing to scan.", app_name, e);
                        UninstallerContext::skipped()
                    }
                }
            };

            // Phase 4b: Launch scanners on background threads
            info!(
                "Phase 4: Scanning '{}' for leftovers (uninstaller ran={})...",
                app_name, uninstaller_context.ran
            );
            let metadata_arc = Arc::new(selected_app.metadata.clone());
            let install_location = selected_app
                .metadata
                .install_location
                .as_ref()
                .map(std::path::PathBuf::from);

            let scan_rx = scanner::scan_all_with_context(
                metadata_arc,
                install_location,
                uninstaller_context,
            );

            // Phase 4c: Show scanning overlay TUI — drains channel with spinner
            info!("Phase 4: Showing scanning overlay...");
            let found = tui::run_scanning_overlay(app_name.clone(), scan_rx)?;

            info!("Found {} leftover items for '{}'.", found.len(), app_name);

            // Cache the results
            scan_cache.insert(app_name.clone(), found.clone());
            found
        };

        if leftovers.is_empty() {
            info!("No leftovers found for '{}'. Nothing to clean up.", app_name);
            return Ok(());
        }

        // Phase 5: Populate scanned app and show leftover review TUI
        let uninstalling = selected_app.begin_uninstall();
        let mut scanned = uninstalling.complete_scan();
        for item in leftovers {
            scanned.add_leftover(item);
        }

        info!(
            "Phase 5: Launching leftover review TUI ({} items)...",
            scanned.leftover_count()
        );
        let selected_indices = tui::run_leftover_review_tui(scanned.clone())?;

        if selected_indices.is_empty() {
            info!("No selections made. Exiting.");
            return Ok(());
        }

        // Phase 6: Delete selected leftovers
        info!("Phase 6: Deleting selected leftovers for '{}'...", app_name);

        let selected_leftovers: Vec<_> = selected_indices
            .iter()
            .filter_map(|&idx| scanned.leftovers.get(idx).cloned())
            .collect();

        info!("Selected {} items for deletion.", selected_leftovers.len());

        if args.dry_run {
            info!("[DRY RUN] Would delete:");
            for item in &selected_leftovers {
                info!("  - {}", item.path);
            }
        } else {
            let mut engine = SafeDeletionEngine::new();
            match engine.delete_leftovers(selected_leftovers) {
                Ok(report) => {
                    report.print_summary();
                }
                Err(e) => {
                    error!("Failed to delete leftovers: {}", e);
                }
            }
            // Invalidate cache after deletion so re-scan picks up clean state
            scan_cache.remove(&app_name);
        }

    info!("Application shutdown complete");
    Ok(())
}

/// Returns true when the current process token has the Administrators group
/// enabled (i.e. the process is running elevated on Windows).
fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Launch the uninstaller for `metadata` without TUI (internal helper used
/// when the caller already handles the overlay separately, e.g. in tests).
///
/// Returns `UninstallerContext::ran(exit_code)` on success, or
/// `UninstallerContext::skipped()` if no string, parse fails, or launch fails.
pub fn run_uninstaller_headless(
    metadata: &bucket_uninstaller::domain::metadata::AppMetadata,
) -> UninstallerContext {
    let uninstall_str = match &metadata.uninstall_string {
        Some(s) => s.clone(),
        None => {
            warn!(
                "No uninstall string for '{}'. Skipping uninstaller.",
                metadata.display_name
            );
            return UninstallerContext::skipped();
        }
    };

    let cmd = match parse_uninstall_string(&uninstall_str) {
        Some(c) => c,
        None => {
            warn!(
                "Could not parse uninstall string '{}' for '{}'. Skipping.",
                uninstall_str, metadata.display_name
            );
            return UninstallerContext::skipped();
        }
    };

    info!(
        "Running uninstaller for '{}': {} {:?}",
        metadata.display_name, cmd.exe, cmd.args
    );

    // Resolve bare exe names (e.g. "MsiExec.exe") to full System32 path
    let resolved = resolve_exe_path(&cmd.exe);
    let args_refs: Vec<&str> = cmd.args.iter().map(String::as_str).collect();

    let guard = match ProcessTreeGuard::spawn_and_assign(&resolved, &args_refs) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                "Failed to launch uninstaller for '{}': {}. Continuing without uninstall.",
                metadata.display_name, e
            );
            return UninstallerContext::skipped();
        }
    };

    match guard.wait_for_completion() {
        Ok((exit_code, _elapsed)) => {
            info!(
                "Uninstaller for '{}' exited with code {}.",
                metadata.display_name, exit_code
            );
            if exit_code != 0 {
                warn!(
                    "Uninstaller returned non-zero exit code {}.",
                    exit_code
                );
            }
            UninstallerContext::ran(exit_code)
        }
        Err(e) => {
            warn!(
                "Error waiting for uninstaller of '{}': {}. Continuing to scan.",
                metadata.display_name, e
            );
            UninstallerContext::skipped()
        }
    }
}
