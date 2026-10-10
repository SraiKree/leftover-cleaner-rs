# Leftover Cleaner RS

**High-performance Windows leftover cleaner** — runs the app's uninstaller, then scans the registry and filesystem for whatever it left behind.

## Features

✅ **Registry Harvesting** — Enumerates installed apps from HKLM/HKCU Uninstall keys  
✅ **Uninstaller Execution** — Runs the app's own uninstaller via `ProcessTreeGuard` + Job Object  
✅ **Fuzzy Location Resolver** — Levenshtein matching (≥82% similarity) infers install paths  
✅ **Concurrent Scanning** — Parallel FS/registry/MSI scans via Rayon + jwalk  
✅ **Type-Safe State Machine** — Compile-time lifecycle enforcement (Discovered → Scanned → Purged)  
✅ **Safety Validator** — Blocks system paths (C:\Windows, C:\Program Files roots, C:\Users root)  
✅ **Cargo-Purge Style TUI** — Sidebar sections, alphabetical app list, real-time search, detail panel  
✅ **Smart Deletion** — Bottom-up order: registry values → keys, files → directories  
✅ **Reboot Scheduling** — Locked files queued for deletion via `MoveFileExW` on next boot  

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
# Normal workflow: pick an app, run its uninstaller, then scan and clean leftovers
.\leftover-cleaner-rs.exe

# Dry-run: preview what would be deleted, nothing is removed
.\leftover-cleaner-rs.exe --dry-run

# Skip the uninstaller step (scan-only, for already-uninstalled apps)
.\leftover-cleaner-rs.exe --skip-uninstall

# Verbose logging
.\leftover-cleaner-rs.exe --verbose
```

## Command-Line Options

```
leftover-cleaner-rs [OPTIONS]

Options:
  -v, --verbose         Enable verbose logging
  -n, --dry-run         Preview deletions only (no files/keys removed)
  -s, --skip-uninstall  Skip uninstaller execution (scan for leftovers only)
  -h, --help            Print help
```

## Workflow

1. **Harvest** — Reads Windows registry for installed apps
2. **Resolve** — Infers install paths via fuzzy string matching or `UninstallString` parsing
3. **Select** — TUI shows all apps sorted alphabetically; search/filter to find the target
4. **Uninstall** — Runs the app's own uninstaller (`--skip-uninstall` bypasses this)
5. **Scan** — Concurrent search for leftovers across:
   - File system (install dir, AppData, Desktop shortcuts)
   - Registry (Software keys, App Paths, CLSID COM entries)
   - MSI database (UserData\Products\Components)
6. **Review** — Leftover table with confidence levels; toggle items for deletion
7. **Delete** — Safe removal with reboot scheduling for locked files

## TUI — App Selection Screen

The first screen lets you find and pick the app to uninstall and clean.

```
┌─ header bar ─────────────────────────────────────────── ● READY ─┐
│ SECTIONS      │  🔍 Search apps...                  247 total    │
│  [1] Overview │ ┌── Apps & Packages ───────────────────────────┐ │
│  [2] Apps  247│ │ ☐ 7-Zip 23.01              Publisher  Size  │ │
│  [3] Deep Scan│ │ ☐ Adobe Acrobat Reader     Adobe Inc  412 MB│ │
│  [4] Caches   │ │ ▶ ☐ Google Chrome          Google     142 MB│ │  ← selected
│  [5] Daemons  │ └──────────────────────────────────────────────┘ │
│ ● 68% Healthy │      Selected App detail panel (right pane)      │
└── [Enter] Uninstall & Scan  [/] Search  [Tab] Switch Pane  [q] Quit ┘
```

### Key Bindings — App Selection

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move cursor through the (filtered) app list |
| `/` | Focus the search box |
| `Esc` | Clear search and restore full list (or exit search box) |
| `Backspace` | Delete last character in search query |
| `Tab` | Cycle keyboard focus: App List → Detail → Sidebar → … |
| `↑` / `↓` (Sidebar focused) | Navigate sidebar sections |
| `Space` | Toggle checkbox on the highlighted app |
| `Enter` | Confirm — runs uninstaller then scans for leftovers |
| `Ctrl+C` or `q` | Quit |

### Search behaviour

- Press `/` to jump into the search box.
- Type any substring — the list filters **in real-time** (case-insensitive).
- The search bar shows `N matches` when a query is active, or `N total` when empty.
- `Esc` clears the query and restores the full alphabetically-sorted list.
- Arrow keys always navigate the **filtered** list, not the full one.

## TUI — Scanning Overlay

After the uninstaller exits, a centred overlay shows scan progress:

```
╭──── Scanning for Leftovers ──────╮
│  ⠹  Google Chrome                │
│  Found  14 item(s)   Elapsed  3s │
│  [Esc] to cancel                 │
╰──────────────────────────────────╯
```

Press `Esc` or `q` to abort the scan. The overlay closes automatically when the scan finishes.

## TUI — Leftover Review Screen

After scanning, the full leftover list is shown for review and selective deletion.

```
┌─ header: leftover-cleaner v0.1.0 │ Reviewing leftovers for: Google Chrome ─┐
│ ☐ 📄 C:\Program Files\Google\Chrome\…\manifest.json         [H]            │
│ ☐ 📁 C:\Users\…\AppData\Local\Google\Chrome                 [M]            │
│ ▶ ☑ 🗝 HKCU\Software\Google\…                                [H]            │
├─── Item Details ──────────────────────────────────────────────────────────  │
│  Type:  RegistryKey   Confidence: High   Source: reg_scanner  Selected: Yes │
└─ [Enter] Delete Selected  [Space] Toggle  [a] All  [d] None  [1/2/3/0] Filter ┘
```

### Key Bindings — Leftover Review

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Navigate the leftover list |
| `Space` | Toggle selection on the highlighted item |
| `a` | Select all visible items |
| `d` | Deselect all visible items |
| `1` | Filter to **High** confidence items only |
| `2` | Filter to **Medium** confidence items only |
| `3` | Filter to **Low** confidence items only |
| `0` | Clear confidence filter (show all) |
| `Enter` | Delete all selected items (respects `--dry-run`) |
| `q` | Cancel (return to shell, no deletions) |

### Confidence levels

| Level | Colour | Meaning |
|---|---|---|
| **High** | 🟢 Green | Install-path residue or exact registry match — safe to remove |
| **Medium** | 🟡 Yellow | AppData cache/config folders — usually safe |
| **Low** | 🟠 Orange | CLSID COM entries, generic Software keys — review before deleting |

## Architecture

```
src/
├── domain/          # Core types: Application<State>, LeftoverItem, errors
├── engine/
│   ├── harvester    # Registry app enumeration (HKLM/HKCU Uninstall)
│   ├── resolver     # Install-location inference (fuzzy + UninstallString)
│   ├── process      # ProcessTreeGuard — Job Object uninstaller monitor
│   ├── safety       # Path blacklist validator + SharedDLLs checks
│   └── cleaner      # Safe, ordered deletion engine
├── scanner/
│   ├── fs_scanner   # Filesystem traversal (jwalk)
│   ├── reg_scanner  # Registry: Software keys, App Paths, CLSID
│   └── msi_scanner  # MSI UserData\Products components
└── ui/
    └── tui          # ratatui TUI (app selection + scanning overlay + leftover review)
```

### Type-State Pattern

Compile-time enforcement prevents calling operations out of order:

```rust
Application<Discovered>   → begin_uninstall()  → Application<Uninstalling>
Application<Uninstalling> → complete_scan()    → Application<Scanned>
Application<Scanned>      → complete_purge()   → Application<Purged>
```

### Safety

- **Hardcoded blacklist:** `C:\`, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files` (root only), `C:\Users` (root only)
- **Path canonicalization:** all paths normalized before blacklist checks
- **SharedDLLs advisory:** `.dll` files checked against `HKLM\…\SharedDLLs`; warns but does not block deletion
- **Dry-run mode:** `--dry-run` logs every planned action without touching disk or registry

### Deletion order

1. Registry values (leaf → root)
2. Registry keys (deepest → shallowest)
3. Files
4. Directories (deepest → shallowest; only if empty after file removal)

Locked files are scheduled for deletion on next boot via:
```rust
MoveFileExW(path, null, MOVEFILE_DELAY_UNTIL_REBOOT)
```

## Development

```powershell
cargo check          # Fast compile check
cargo clippy         # Lint
cargo test           # Unit tests
cargo build --release
```

### Performance targets
- Scan time: <30 s for 1 000+ items on a 4-core machine
- Parallelism: Rayon thread pool + jwalk concurrent directory traversal
- Streaming: crossbeam-channel pipes scan results to the TUI in real time

## Known Limitations

- **Bytes-freed counter** — `DeletionReport.total_bytes_freed()` always returns 0 (tracking not implemented)
- **SharedDLLs enforcement** — Advisory only; does not block deletion
- **Integration test suite** — Dummy app test framework pending
- **Multi-app sessions** — After one delete cycle the app exits; re-launching is required for a second app
- **Right-pane deep actions** — Detail panel is informational only; deeper actions deferred to a later feature

## Safety Warnings

⚠️ **Always dry-run first** — use `--dry-run` to preview before any real deletion  
⚠️ **Administrator required** — registry and Program Files access need elevation  
⚠️ **No undo** — deleted files and registry keys are gone immediately  
⚠️ **Review Low-confidence items carefully** — false positives are possible for generic folder names  

## License

MIT  
Built with: Rust · winreg · ratatui · rayon · crossterm · jwalk · strsim
