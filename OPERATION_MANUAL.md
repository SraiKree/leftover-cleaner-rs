# Operation Manual — Leftover Cleaner RS

**Quick reference for running leftover-cleaner-rs in production**

---

## Prerequisites

✅ **Administrator Privileges**  
→ Right-click PowerShell → "Run as Administrator"

✅ **Binary Location**  
→ `target\release\leftover-cleaner-rs.exe` (after `cargo build --release`)

---

## Command Quick Reference

```powershell
# Safe preview mode (recommended first run)
.\leftover-cleaner-rs.exe --skip-uninstall --dry-run --verbose

# Production scan + clean
.\leftover-cleaner-rs.exe --skip-uninstall

# Full workflow (uninstall → scan → clean) - NOT YET IMPLEMENTED
.\leftover-cleaner-rs.exe
```

---

## Step-by-Step Workflow

### Step 1: Dry-Run Scan (Safe Preview)
```powershell
.\leftover-cleaner-rs.exe --skip-uninstall --dry-run
```
**What happens:**
1. Harvests installed apps from registry (HKLM/HKCU Uninstall keys)
2. Resolves install locations via fuzzy matching
3. Scans for leftovers (registry + filesystem + MSI)
4. Launches TUI → select app → review leftovers
5. **NO DELETION** — only logs what *would* be deleted

**Output Example:**
```
[INFO] Starting leftover-cleaner-rs v0.1.0
[INFO] Phase 1: Harvesting installed applications...
[INFO] Found 247 installed applications
[INFO] Phase 2: Resolving install locations...
[INFO] Resolved install locations for 247 apps
[INFO] Phase 3: Preparing applications for scanning...
[INFO] Processing: Adobe Acrobat Reader DC
[INFO]   Scanning for leftovers...
[INFO]   Found 12 leftover items for Adobe Acrobat Reader DC
...
[INFO] Phase 5: Launching TUI for leftover review...
[INFO] Phase 6: Deleting selected leftovers...
[INFO] Cleaning: Adobe Acrobat Reader DC
[INFO]   Selected 8 items for deletion
[INFO]   [DRY RUN] Would delete:
[INFO]     - C:\ProgramData\Adobe\ARM\leftover.log
[INFO]     - HKCU\Software\Adobe\Acrobat Reader\DC
...
```

---

### Step 2: TUI Navigation

#### **App Selection Screen**
```
┌─ Select Application to Clean ──────────────────────────────────┐
│                                                                 │
│ ┌─ Applications ─────────────────────────────────────────────┐ │
│ │ ▶ Adobe Acrobat Reader DC (12 leftovers)                   │ │
│ │   Google Chrome (5 leftovers)                              │ │
│ │   Steam (143 leftovers)                                     │ │
│ │   ...                                                       │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ ↑/↓ Navigate | Enter Select | q Quit                          │
└─────────────────────────────────────────────────────────────────┘
```
**Controls:**
- `↑` / `↓` or `j` / `k` → Navigate
- `Enter` → Select app
- `q` → Quit

---

#### **Leftover Review Screen**
```
┌─ Review Leftovers: Adobe Acrobat Reader DC ───────────────────┐
│                                                                │
│ ┌─ Leftovers (12) ─────────────────────────────────────────┐  │
│ │ Sel   Kind              Path                 Confidence  │  │
│ │ ───────────────────────────────────────────────────────   │  │
│ │ [X]   File              C:\ProgramData\...   High        │  │
│ │ [ ]   RegistryKey       HKCU\Software\...    Medium      │  │
│ │ [X]   Directory         C:\Users\...\...     High        │  │
│ │ ...                                                       │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                │
│ ↑/↓ Navigate | Space Toggle | a Select All | d Deselect All  │
│ 1/2/3/0 Filter | Enter Confirm (8 selected) | q Cancel        │
└────────────────────────────────────────────────────────────────┘
```
**Controls:**
- `↑` / `↓` or `j` / `k` → Navigate rows
- `Space` → Toggle checkbox
- `a` → Select all visible items
- `d` → Deselect all
- `1` → Show only High confidence
- `2` → Show only Medium confidence
- `3` → Show only Low confidence
- `0` → Show all (clear filter)
- `Enter` → Confirm deletion
- `q` → Cancel

**Confidence Guide:**
- **High** — Install path residue, exact registry match (safe to delete)
- **Medium** — AppData cache folders (usually safe)
- **Low** — Generic COM entries, shared keys (review carefully)

---

### Step 3: Production Deletion
```powershell
.\leftover-cleaner-rs.exe --skip-uninstall
```
**Same as dry-run, but actually deletes selected items.**

**Deletion Summary:**
```
[INFO] === Deletion Summary ===
[INFO] Successfully deleted: 8 items
[INFO] Scheduled for reboot deletion: 2 items
[WARN] Failed to delete: 1 items
[WARN]   - C:\Program Files\Adobe\locked.dll: Access denied
```

**Reboot Required?**  
If any files scheduled for reboot deletion → restart Windows to complete cleanup.

---

## Safety Checklist

Before production deletion:

☑ **Backup Critical Data**  
☑ **Run Dry-Run First** (`--dry-run` flag)  
☑ **Review Low-Confidence Items** (filter with `3` key in TUI)  
☑ **Check Shared DLLs** (warnings logged if SharedDLLs ref count > 0)  
☑ **Admin Privileges Active** (registry ops require elevation)  
☑ **No Running Applications** (uninstalled app should be fully closed)

---

## Troubleshooting

### **"Access Denied" Errors**
→ **Cause:** Insufficient privileges or file locked  
→ **Fix:**  
1. Run PowerShell as Administrator
2. Close any running processes using the file
3. Files will be scheduled for reboot deletion if locked

### **"No Applications Found"**
→ **Cause:** Registry read error or no apps installed  
→ **Fix:**  
1. Verify admin privileges
2. Check verbose logs (`--verbose`)
3. Manually verify `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` exists

### **TUI Doesn't Launch**
→ **Cause:** Terminal compatibility issue  
→ **Fix:**  
1. Use Windows Terminal (not cmd.exe)
2. Update PowerShell to 7+
3. Check for conflicting keyboard shortcuts

### **False Positives (Wrong Items Selected)**
→ **Cause:** Generic folder name matching  
→ **Fix:**  
1. Filter by High confidence only (`1` key)
2. Manually deselect items with `Space`
3. Review paths carefully before confirming

### **Reboot Deletion Not Working**
→ **Cause:** `MoveFileExW` registry entry corruption  
→ **Fix:**  
1. Check `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
2. Manually restart Windows
3. If still present, delete registry entry and try manual deletion

---

## Logging

### **Enable Verbose Logs**
```powershell
.\leftover-cleaner-rs.exe --skip-uninstall --verbose
```
**Shows:**
- Registry key enumeration
- Path resolution logic
- Fuzzy matching scores
- Safety validator decisions
- Deletion operations (file-by-file)

### **Log Levels**
- `INFO` — Normal operations (default)
- `DEBUG` — Verbose diagnostics (`--verbose` flag)
- `WARN` — Non-fatal errors (permission denied, missing keys)
- `ERROR` — Fatal errors (crash/abort)

---

## Performance Notes

**Typical Scan Times:**
- 100 apps → ~5-10 seconds
- 500 apps → ~20-30 seconds
- 1000+ apps → ~30-60 seconds

**Factors:**
- Disk I/O speed (SSD vs HDD)
- Number of registry keys
- Install path complexity
- Concurrent worker threads (Rayon auto-detects CPU cores)

---

## Known Limitations

❌ **Uninstaller Execution** — Not implemented (use `--skip-uninstall` always)  
❌ **Real-Time Progress** — TUI shows final results only (no streaming scan updates)  
❌ **Byte Counter** — Total space freed not tracked (shows 0)  
❌ **SharedDLLs Enforcement** — Advisory only (warns but doesn't block)  
❌ **Integration Tests** — Dummy app test framework pending

---

## Emergency Recovery

### **Undo Deletion (IMPOSSIBLE)**
Deletion is **permanent**. No undo. Use dry-run mode first.

### **Restore from Backup**
If critical files deleted:
1. Check Windows Restore Points (`rstrui.exe`)
2. Use File History (if enabled)
3. Third-party backup tools (Veeam, Acronis, etc.)

### **Cancel Reboot Deletion**
Before restarting Windows:
```powershell
# Delete registry key (requires admin)
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations"
```

---

## Best Practices

✅ **Always Dry-Run First** → Preview before deletion  
✅ **Filter by High Confidence** → Reduce false positives  
✅ **Review Generic Names** → "Common Files", "Shared", etc. likely shared  
✅ **Backup Registry** → `regedit → File → Export` before deletion  
✅ **Close All Apps** → Prevent file locks  
✅ **Restart After** → Complete reboot deletions  
✅ **Test with Non-Critical Apps** → Learn tool behavior safely

---

## Example Session

```powershell
PS C:\> cd leftover-cleaner-rs
PS C:\leftover-cleaner-rs> .\target\release\leftover-cleaner-rs.exe --skip-uninstall --dry-run

[INFO] Starting leftover-cleaner-rs v0.1.0
[INFO] Phase 1: Harvesting installed applications...
[INFO] Found 247 installed applications
[INFO] Phase 2: Resolving install locations...
[INFO] Resolved install locations for 247 apps
[INFO] Phase 3: Preparing applications for scanning...
[INFO] Processing: Steam
[INFO]   Scanning for leftovers...
[INFO]   Found 143 leftover items for Steam
...
# TUI launches → select Steam → review 143 items → select 87 high-confidence items → press Enter
[INFO] Phase 6: Deleting selected leftovers...
[INFO] Cleaning: Steam
[INFO]   Selected 87 items for deletion
[INFO]   [DRY RUN] Would delete:
[INFO]     - C:\Program Files (x86)\Steam\leftover.log
[INFO]     - C:\ProgramData\Steam\cache\...
[INFO]     - HKCU\Software\Valve\Steam\leftover_key
...
[INFO] Application shutdown complete

PS C:\leftover-cleaner-rs> # Review output, looks good
PS C:\leftover-cleaner-rs> .\target\release\leftover-cleaner-rs.exe --skip-uninstall

# Same workflow, but deletes for real
[INFO] === Deletion Summary ===
[INFO] Successfully deleted: 85 items
[INFO] Scheduled for reboot deletion: 2 items
[WARN] Failed to delete: 0 items

PS C:\leftover-cleaner-rs> Restart-Computer  # Complete reboot deletions
```

---

## Support

**Issues:** GitHub Issues (if open-source)  
**Logs:** Always include `--verbose` output when reporting bugs  
**System Info:** Windows version, admin status, disk type (SSD/HDD)

---

**End of Operation Manual**
