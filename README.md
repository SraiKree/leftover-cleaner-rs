# Leftover Cleaner RS

**High-performance Windows leftover cleaner** — scans registry + filesystem for leftover files after uninstallation. Built in Rust, reverse-engineered from Geek Uninstaller.

## Features

✅ **Registry Harvesting** — Enumerates installed apps from HKLM/HKCU Uninstall keys  
✅ **Fuzzy Location Resolver** — Levenshtein matching (≥82% similarity) finds install paths  
✅ **Concurrent Scanning** — Parallel FS/registry/MSI scans via Rayon  
✅ **Type-Safe State Machine** — Compile-time lifecycle enforcement (Discovered → Uninstalling → Scanned → Purged)  
✅ **Safety Validator** — Blocks system paths (C:\Windows, C:\Program Files roots, etc.)  
✅ **TUI Interface** — ratatui terminal UI with confidence filtering  
✅ **Smart Deletion** — Bottom-up order (reg values → keys, files → dirs)  
✅ **Reboot Scheduling** — Locked files deleted via MoveFileExW on next boot

## System Requirements

- **OS:** Windows 10/11 64-bit
- **Privileges:** Administrator (required for registry/file deletion)
- **Rust:** 1.70+ (for building from source)

## Quick Start

### Build from Source
```powershell
cargo build --release
```
Binary: `target\release\leftover-cleaner-rs.exe`

### Run
```powershell
# Scan all apps and show TUI
.\leftover-cleaner-rs.exe --skip-uninstall

# Dry-run (no actual deletion)
.\leftover-cleaner-rs.exe --skip-uninstall --dry-run

# Verbose logging
.\leftover-cleaner-rs.exe --skip-uninstall --verbose
```

## Usage

### Command-Line Options
```
leftover-cleaner-rs [OPTIONS]

Options:
  -v, --verbose         Enable verbose logging
  -n, --dry-run         Don't actually delete anything (preview mode)
  -s, --skip-uninstall  Skip uninstaller execution (only scan for leftovers)
  -h, --help            Print help
```

### Workflow
1. **Harvest** — Reads Windows registry for installed apps
2. **Resolve** — Infers install paths via fuzzy matching or UninstallString parsing
3. **Scan** — Concurrent search for leftovers:
   - File system (install dir, AppData, shortcuts)
   - Registry (Software keys, App Paths, CLSID COM entries)
   - MSI database (UserData\Products\Components)
4. **Review** — TUI interface to select items for deletion
5. **Delete** — Safe removal with reboot scheduling for locked files

### TUI Controls
**Application Selection Screen:**
- `↑/↓` or `j/k` — Navigate list
- `Enter` — Select app
- `q` — Quit

**Leftover Review Screen:**
- `↑/↓` or `j/k` — Navigate table
- `Space` — Toggle selection
- `a` — Select all
- `d` — Deselect all
- `1` / `2` / `3` — Filter by High/Medium/Low confidence
- `0` — Show all (clear filter)
- `Enter` — Confirm deletion
- `q` — Cancel

## Architecture

```
src/
├── domain/          # Core types (Application<State>, LeftoverItem, errors)
├── engine/          # Business logic
│   ├── harvester    # Registry app enumeration
│   ├── resolver     # Install location inference
│   ├── process      # Job Object process monitor (for uninstallers)
│   ├── safety       # Blacklist validator + SharedDLLs checks
│   └── cleaner      # Safe deletion engine
├── scanner/         # Concurrent scanners
│   ├── fs_scanner   # Filesystem (jwalk)
│   ├── reg_scanner  # Registry Software keys + App Paths + CLSID
│   └── msi_scanner  # MSI database (UserData\Products)
└── ui/
    └── tui          # ratatui terminal interface
```

### Type-State Pattern
Compile-time enforcement prevents invalid operations:
```rust
Application<Discovered>   → begin_uninstall()  → Application<Uninstalling>
Application<Uninstalling> → complete_scan()    → Application<Scanned>
Application<Scanned>      → complete_purge()   → Application<Purged>
```

### Safety Features
- **Hardcoded Blacklist:** Blocks C:\, C:\Windows, C:\Windows\System32, C:\Program Files (root), C:\Users (root)
- **Canonicalization:** All paths normalized before validation
- **SharedDLLs Check:** .dll files checked against `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs`
- **Confidence Levels:**
  - **High:** Install path residue, exact registry match
  - **Medium:** AppData cache folders
  - **Low:** CLSID COM entries, generic Software keys

### Deletion Order
1. Registry values (leaf → root)
2. Registry keys (deepest → shallowest)
3. Files
4. Directories (deepest → shallowest, only if empty)

Locked files → scheduled for reboot deletion via `MoveFileExW(path, null, MOVEFILE_DELAY_UNTIL_REBOOT)`

## Development

### Run Tests
```powershell
cargo test          # 67 unit tests
cargo clippy        # Lint checks
cargo check         # Compilation
```

### Performance
- **Target:** <30s scan time for 1000+ items on 4-core machine
- **Parallelism:** Rayon worker threads + jwalk concurrent directory traversal
- **Streaming:** crossbeam-channel pipes results to TUI in real-time

## Known Limitations

- **Uninstaller Execution:** Not implemented (requires ProcessTreeGuard + Job Object wait logic)
- **Progress Overlay:** TUI shows final results only (no real-time scan progress)
- **Byte Counter:** DeletionReport.total_bytes_freed() not tracked (returns 0)
- **Integration Tests:** Dummy app test framework pending
- **SharedDLLs Enforcement:** Currently advisory only (warns but doesn't block)

## Safety Warnings

⚠️ **Run in Dry-Run Mode First** — Always use `--dry-run` to preview deletions  
⚠️ **Administrator Required** — Registry + Program Files access needs elevation  
⚠️ **Backup Critical Data** — No undo for deletion operations  
⚠️ **Review Selections Carefully** — False positives possible for generic folder names

## License

MIT
Built with: Rust, winreg, ratatui, rayon, crossterm, jwalk, strsim
