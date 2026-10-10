use clap::Parser;
use leftover_cleaner_rs::domain::app::{Application, Discovered, Scanned};
use leftover_cleaner_rs::engine::{cleaner::SafeDeletionEngine, harvester, resolver};
use leftover_cleaner_rs::scanner;
use leftover_cleaner_rs::ui::tui;
use std::error::Error;
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

    /// Skip uninstaller execution (only scan for leftovers)
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

    // Phase 3: Select applications to clean (in real flow, user would uninstall first)
    // For now, we skip uninstall and go straight to scanning
    info!("Phase 3: Preparing applications for scanning...");
    let mut scanned_apps: Vec<Application<Scanned>> = Vec::new();

    for app in apps {
        info!("Processing: {}", app.metadata.display_name);

        if args.skip_uninstall {
            // Skip uninstall, directly transition to Scanned
            let uninstalling = app.begin_uninstall();
            let mut scanned = uninstalling.complete_scan();

            // Phase 4: Scan for leftovers
            info!("  Scanning for leftovers...");
            let metadata_arc = std::sync::Arc::new(scanned.metadata.clone());
            let install_location = scanned.metadata.install_location.as_ref().map(std::path::PathBuf::from);
            let leftover_rx = scanner::scan_all(metadata_arc, install_location);
            let leftovers: Vec<_> = leftover_rx.iter().collect();

            for leftover in leftovers {
                scanned.add_leftover(leftover);
            }

            info!(
                "  Found {} leftover items for {}",
                scanned.leftover_count(),
                scanned.metadata.display_name
            );

            if scanned.leftover_count() > 0 {
                scanned_apps.push(scanned);
            }
        }
    }

    if scanned_apps.is_empty() {
        info!("No leftovers found. Exiting.");
        return Ok(());
    }

    // Phase 5: Run TUI for user to review and select leftovers
    info!("Phase 5: Launching TUI for leftover review...");
    let selections = tui::run_tui(scanned_apps.clone())?;

    if selections.is_empty() {
        info!("No selections made. Exiting.");
        return Ok(());
    }

    // Phase 6: Delete selected leftovers
    info!("Phase 6: Deleting selected leftovers...");
    for (app_idx, leftover_indices) in selections {
        if let Some(app) = scanned_apps.get(app_idx) {
            info!("Cleaning: {}", app.metadata.display_name);

            let selected_leftovers: Vec<_> = leftover_indices
                .iter()
                .filter_map(|&idx| app.leftovers.get(idx).cloned())
                .collect();

            info!("  Selected {} items for deletion", selected_leftovers.len());

            if args.dry_run {
                info!("  [DRY RUN] Would delete:");
                for item in &selected_leftovers {
                    info!("    - {}", item.path);
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
            }
        }
    }

    info!("Application shutdown complete");
    Ok(())
}