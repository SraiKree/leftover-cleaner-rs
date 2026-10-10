use clap::Parser;
use leftover_cleaner_rs::domain::app::{Application, Discovered};
use leftover_cleaner_rs::domain::leftover::LeftoverItem;
use leftover_cleaner_rs::engine::{
    cleaner::SafeDeletionEngine, harvester, process::parse_uninstall_string,
    process::ProcessTreeGuard, resolver,
};
use leftover_cleaner_rs::scanner::{self, UninstallerContext};
use leftover_cleaner_rs::ui::tui;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt;

#[derive(Parser, Debug)]
#[command(name = "leftover-cleaner")]
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

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    fmt().with_max_level(log_level).init();

    info!("Starting leftover-cleaner-rs v0.1.0");

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

    // Main loop: app selection → uninstall → scan → review → delete → back to selection
    let apps = apps;
    loop {
        // Phase 3: Show TUI immediately — user picks an app
        info!("Phase 3: Launching TUI for application selection...");
        let selection = tui::run_app_selection_tui(apps)?;

        let (_app_idx, selected_app) = match selection {
            Some(s) => s,
            None => {
                info!("No application selected. Exiting.");
                break;
            }
        };

        // Rebuild apps list after swap_remove for next iteration
        // (apps was consumed by run_app_selection_tui — re-harvest isn't needed
        //  for the cache use-case; we break after delete anyway)
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
            // Phase 4a: Run uninstaller (unless --skip-uninstall)
            let uninstaller_context = if args.skip_uninstall {
                info!("Phase 4: Skipping uninstaller (--skip-uninstall).");
                UninstallerContext::skipped()
            } else {
                run_uninstaller(&selected_app.metadata)
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
            info!("No leftovers found for '{}'. Returning to app selection.", app_name);
            // Rebuild apps from remaining discovered apps for next loop iteration.
            // Since we consumed `apps` above, we exit here for MVP.
            // (Full re-harvest loop would require cloning apps before TUI.)
            break;
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
            break;
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

        // After one round of deletion we exit; multi-app support is future work
        break;
    }

    info!("Application shutdown complete");
    Ok(())
}

/// Attempt to run the app's uninstaller via `ProcessTreeGuard`.
///
/// Returns `UninstallerContext::ran(exit_code)` on success, or
/// `UninstallerContext::skipped()` if no string, parse fails, or launch fails.
fn run_uninstaller(
    metadata: &leftover_cleaner_rs::domain::metadata::AppMetadata,
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
        "Phase 4: Running uninstaller for '{}': {} {:?}",
        metadata.display_name, cmd.exe, cmd.args
    );

    let exe_path = Path::new(&cmd.exe);
    let args_refs: Vec<&str> = cmd.args.iter().map(String::as_str).collect();

    let guard = match ProcessTreeGuard::spawn_and_assign(exe_path, &args_refs) {
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
        Ok(exit_code) => {
            info!(
                "Uninstaller for '{}' exited with code {}.",
                metadata.display_name, exit_code
            );
            if exit_code != 0 {
                warn!(
                    "Uninstaller returned non-zero exit code {}. Some files may not have been removed.",
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
            // guard drops here — KILL_ON_JOB_CLOSE cleans up any child processes
            UninstallerContext::skipped()
        }
    }
}
