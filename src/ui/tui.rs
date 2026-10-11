// TUI module — three screens + one overlay:
//
//   run_app_selection_tui   — Phase 1: pick which installed app to clean
//   run_uninstall_tui       — Phase 2: launch uninstaller, show live progress (NEW)
//   run_scanning_overlay    — Phase 3: spinner while background scan runs
//   run_leftover_review_tui — Phase 4: choose which leftovers to delete
//
// All screens share the same dark palette and ratatui 0.30 APIs.

use crate::domain::app::{Discovered, Scanned};
use crate::domain::leftover::{ConfidenceLevel, LeftoverItem, LeftoverKind};
use crate::domain::metadata::AppMetadata;
use crate::engine::process::{parse_uninstall_string, resolve_exe_path, ProcessTreeGuard};
use crate::scanner::UninstallerContext;
use crossbeam_channel::Receiver;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

// ─── Palette ──────────────────────────────────────────────────────────────────
const CYAN: Color = Color::Rgb(56, 189, 248);
const _CYAN_DIM: Color = Color::Rgb(30, 110, 150);
const GREEN: Color = Color::Rgb(34, 197, 94);
const YELLOW: Color = Color::Rgb(250, 204, 21);
const ORANGE: Color = Color::Rgb(251, 146, 60);
const RED: Color = Color::Rgb(248, 113, 113);
const BG: Color = Color::Rgb(9, 13, 18);
const BG_PANEL: Color = Color::Rgb(13, 18, 26);
const BG_SELECTED: Color = Color::Rgb(22, 30, 42);
const BG_HEADER: Color = Color::Rgb(16, 22, 32);
const FG_PRIMARY: Color = Color::Rgb(224, 235, 245);
const FG_DIM: Color = Color::Rgb(100, 116, 130);
const FG_MED: Color = Color::Rgb(148, 163, 175);
const BORDER: Color = Color::Rgb(30, 42, 58);
const BORDER_ACTIVE: Color = Color::Rgb(56, 189, 248);

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const APP_TITLE: &str = "Bucket Uninstaller";
const BUCKET_TICK: Duration = Duration::from_millis(120);

/// Four-frame ASCII bucket (~9 cols). Tilt left / upright / lid / tilt right.
const BUCKET_FRAMES: [&[&str]; 4] = [
    &[
        r"   .-.   ",
        r"  /   \  ",
        r" |  ~  | ",
        r" |_____| ",
        r"/_______\",
    ],
    &[
        r"  .-.    ",
        r" /   \   ",
        r"|  ~  |  ",
        r" \_____\ ",
        r" /______\",
    ],
    &[
        r"   ___   ",
        r"  /   \  ",
        r" |  ~  | ",
        r" |_____| ",
        r"/_______\",
    ],
    &[
        r"    .-.  ",
        r"   /   \ ",
        r"  |  ~  |",
        r"  /_____/",
        r" /______\",
    ],
];

// ─── Focus pane ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    AppList,
    Detail,
}

// ─── App list item ────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct AppListItem {
    display_name: String,
    publisher: String,
    size_bytes: u64,
}

impl AppListItem {
    fn from_app(app: &crate::domain::app::Application<Discovered>) -> Self {
        Self {
            display_name: app.metadata.display_name.clone(),
            publisher: app.metadata.publisher.clone().unwrap_or_else(|| "Unknown".to_string()),
            size_bytes: app.metadata.estimated_size.unwrap_or(0),
        }
    }

    fn size_label(&self) -> String {
        format_size(self.size_bytes)
    }
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 { return "? MB".to_string(); }
    if bytes >= 1_073_741_824 { format!("{:.2} GB", bytes as f64 / 1_073_741_824.0) }
    else if bytes >= 1_048_576 { format!("{} MB", bytes / 1_048_576) }
    else if bytes >= 1024 { format!("{} KB", bytes / 1024) }
    else { format!("{} B", bytes) }
}

// ─── App selection state ──────────────────────────────────────────────────────
pub struct AppSelectionState {
    apps: Vec<crate::domain::app::Application<Discovered>>,
    items: Vec<AppListItem>,
    filtered_indices: Vec<usize>,
    selected_filtered: usize,
    search_input: String,
    search_focused: bool,
    focus: FocusPane,
    bucket_frame: usize,
    last_bucket_tick: Instant,
    disk_health: u8,
    disk_free_gb: f64,
    disk_total_gb: f64,
}

impl AppSelectionState {
    pub fn new(mut apps: Vec<crate::domain::app::Application<Discovered>>) -> Self {
        apps.sort_by(|a, b| {
            a.metadata.display_name.to_lowercase().cmp(&b.metadata.display_name.to_lowercase())
        });
        let items: Vec<AppListItem> = apps.iter().map(AppListItem::from_app).collect();
        let count = items.len();
        Self {
            apps,
            items,
            filtered_indices: (0..count).collect(),
            selected_filtered: 0,
            search_input: String::new(),
            search_focused: false,
            focus: FocusPane::AppList,
            bucket_frame: 0,
            last_bucket_tick: Instant::now(),
            disk_health: 68,
            disk_free_gb: 142.6,
            disk_total_gb: 512.0,
        }
    }

    fn update_filter(&mut self) {
        let query = self.search_input.to_lowercase();
        self.filtered_indices = if query.is_empty() {
            (0..self.items.len()).collect()
        } else {
            self.items.iter().enumerate()
                .filter(|(_, item)| item.display_name.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect()
        };
        if self.filtered_indices.is_empty() {
            self.selected_filtered = 0;
        } else {
            self.selected_filtered = self.selected_filtered.min(self.filtered_indices.len() - 1);
        }
    }

    fn push_char(&mut self, c: char) { self.search_input.push(c); self.update_filter(); }
    fn pop_char(&mut self) { self.search_input.pop(); self.update_filter(); }
    fn clear_search(&mut self) { self.search_input.clear(); self.update_filter(); }

    fn next_app(&mut self) {
        if self.filtered_indices.is_empty() { return; }
        self.selected_filtered = (self.selected_filtered + 1) % self.filtered_indices.len();
    }

    fn prev_app(&mut self) {
        if self.filtered_indices.is_empty() { return; }
        self.selected_filtered = if self.selected_filtered == 0 {
            self.filtered_indices.len() - 1
        } else {
            self.selected_filtered - 1
        };
    }

    fn selected_app_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.selected_filtered).copied()
    }

    fn selected_item(&self) -> Option<&AppListItem> {
        self.selected_app_index().and_then(|i| self.items.get(i))
    }

    fn matches_label(&self) -> String {
        let total = self.items.len();
        let shown = self.filtered_indices.len();
        if self.search_input.is_empty() { format!("{} total", total) }
        else { format!("{} match{}", shown, if shown == 1 { "" } else { "es" }) }
    }

    fn tick_bucket(&mut self) {
        if self.last_bucket_tick.elapsed() >= BUCKET_TICK {
            self.bucket_frame = (self.bucket_frame + 1) % BUCKET_FRAMES.len();
            self.last_bucket_tick = Instant::now();
        }
    }
}

// ─── Phase 1 public entry point ───────────────────────────────────────────────
pub fn run_app_selection_tui(
    apps: Vec<crate::domain::app::Application<Discovered>>,
) -> Result<Option<(usize, crate::domain::app::Application<Discovered>)>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppSelectionState::new(apps);
    let result = run_selection_loop(&mut terminal, &mut state)?;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    match result {
        Some(item_idx) => {
            let app = state.apps.swap_remove(item_idx);
            Ok(Some((item_idx, app)))
        }
        None => Ok(None),
    }
}

fn run_selection_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppSelectionState,
) -> Result<Option<usize>, io::Error> {
    loop {
        state.tick_bucket();
        terminal.draw(|f| draw_main_screen(f, state))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }

        let Event::Key(key) = event::read()? else { continue };
        if key.kind != KeyEventKind::Press { continue; }

        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return Ok(None);
        }

        if state.search_focused {
            match key.code {
                KeyCode::Esc => { state.clear_search(); state.search_focused = false; }
                KeyCode::Backspace => state.pop_char(),
                KeyCode::Char(c) => state.push_char(c),
                KeyCode::Down | KeyCode::Enter => {
                    state.search_focused = false;
                    state.focus = FocusPane::AppList;
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Char('q') => return Ok(None),
                KeyCode::Char('/') => { state.search_focused = true; state.focus = FocusPane::AppList; }
                KeyCode::Tab => {
                    state.focus = match state.focus {
                        FocusPane::AppList => FocusPane::Detail,
                        FocusPane::Detail => FocusPane::AppList,
                    };
                }
                KeyCode::Down | KeyCode::Char('j') => state.next_app(),
                KeyCode::Up | KeyCode::Char('k') => state.prev_app(),
                KeyCode::Esc => state.clear_search(),
                KeyCode::Enter => {
                    if let Some(idx) = state.selected_app_index() {
                        return Ok(Some(idx));
                    }
                }
                _ => {}
            }
        }
    }
}

// ─── Main screen layout ───────────────────────────────────────────────────────
fn draw_main_screen(f: &mut Frame, state: &mut AppSelectionState) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let [header_area, body_area, cmd_area, status_area] = split_v(area, &[
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(3),
        Constraint::Length(1),
    ]);

    draw_header(f, header_area, state);
    draw_body(f, body_area, state);
    draw_command_bar(f, cmd_area, state);
    draw_status_bar(f, status_area);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    f.render_widget(Block::default().style(Style::default().bg(BG_HEADER)), area);

    let [brand_area, stats_area, ready_area] = split_h(area, &[
        Constraint::Length(44), Constraint::Min(0), Constraint::Length(18),
    ]);

    let brand = Line::from(vec![
        format!(" ✦ {APP_TITLE}").bold().fg(FG_PRIMARY),
        Span::raw(" "),
        format!("v{}", env!("CARGO_PKG_VERSION")).bold().fg(CYAN).bg(Color::Rgb(10, 30, 48)),
    ]);
    f.render_widget(Paragraph::new(brand), brand_area);

    let stats = Line::from(vec![
        Span::styled("  APPS ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{}", state.items.len()), Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("   FREE ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{:.1} GB", state.disk_free_gb), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Span::styled("   TOTAL ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{:.0} GB", state.disk_total_gb), Style::default().fg(FG_MED).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(stats), stats_area);

    let ready = Line::from("● READY ".bold().fg(GREEN));
    f.render_widget(Paragraph::new(ready).alignment(Alignment::Right), ready_area);
}

fn draw_body(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    let [sidebar_area, content_area] = split_h(area, &[Constraint::Length(22), Constraint::Min(0)]);
    draw_sidebar(f, sidebar_area, state);
    draw_content(f, content_area, state);
}

fn draw_sidebar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let [bucket_area, disk_area] = split_v(area, &[Constraint::Min(0), Constraint::Length(6)]);

    let bucket_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(" BUCKET ", Style::default().fg(FG_DIM)))
        .style(Style::default().bg(BG_PANEL));

    let inner = bucket_block.inner(bucket_area);
    f.render_widget(bucket_block, bucket_area);

    let frame = BUCKET_FRAMES[state.bucket_frame];
    let art: Vec<Line> = frame
        .iter()
        .map(|line| Line::from(line.cyan()))
        .collect();
    f.render_widget(
        Paragraph::new(art).alignment(Alignment::Center),
        inner,
    );

    draw_disk_health(f, disk_area, state);
}

fn draw_disk_health(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(" DISK HEALTH ", Style::default().fg(FG_DIM)))
        .style(Style::default().bg(BG_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let [gauge_area, info_area] = split_v(inner, &[Constraint::Length(2), Constraint::Length(1)]);

    let pct = state.disk_health as u16;
    let color = if pct >= 70 { GREEN } else if pct >= 40 { YELLOW } else { RED };
    f.render_widget(
        Gauge::default()
            .gauge_style(Style::default().fg(color).bg(Color::Rgb(20, 28, 38)))
            .percent(pct)
            .label(Span::styled(format!("{}% Healthy", pct), Style::default().fg(color).add_modifier(Modifier::BOLD))),
        gauge_area,
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("Free: {:.1} GB", state.disk_free_gb), Style::default().fg(FG_MED)),
            Span::styled(format!("  Total: {:.0} GB", state.disk_total_gb), Style::default().fg(FG_DIM)),
        ])),
        info_area,
    );
}

fn draw_content(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    let [search_area, panes_area] = split_v(area, &[Constraint::Length(3), Constraint::Min(0)]);
    draw_search_bar(f, search_area, state);
    draw_split_panes(f, panes_area, state);
}

fn draw_search_bar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let focused = state.search_focused;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { BORDER_ACTIVE } else { BORDER }))
        .style(Style::default().bg(BG_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let [icon_area, count_area] = split_h(inner, &[Constraint::Min(0), Constraint::Length(16)]);

    let cursor = if focused { "█" } else { "" };
    let line = if state.search_input.is_empty() && !focused {
        Line::from(vec![
            Span::styled("  🔍 ", Style::default().fg(FG_DIM)),
            Span::styled("Search apps... (press / to focus)", Style::default().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  🔍 ", Style::default().fg(CYAN)),
            Span::styled(&state.search_input, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
            Span::styled(cursor, Style::default().fg(CYAN).add_modifier(Modifier::SLOW_BLINK)),
        ])
    };
    f.render_widget(Paragraph::new(line), icon_area);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(state.matches_label(), Style::default().fg(FG_DIM)),
            Span::raw("  "),
        ])).alignment(Alignment::Right),
        count_area,
    );
}

fn draw_split_panes(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    let [list_area, detail_area] = split_h(area, &[Constraint::Percentage(55), Constraint::Percentage(45)]);
    draw_app_list(f, list_area, state);
    draw_detail_panel(f, detail_area, state);
}

fn draw_app_list(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    let focused = state.focus == FocusPane::AppList;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if focused { BORDER_ACTIVE } else { BORDER }))
        .title(Line::from(vec![
            Span::styled(" Apps & Packages ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{} ", state.matches_label()), Style::default().fg(FG_DIM)),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let list_width = inner.width as usize;

    let items: Vec<ListItem> = state.filtered_indices.iter().enumerate().map(|(fi, &item_idx)| {
        let item = &state.items[item_idx];
        let selected = fi == state.selected_filtered;
        let size_str = item.size_label();
        let pub_str = if item.publisher.len() > 20 {
            format!("{}…", &item.publisher[..19])
        } else {
            item.publisher.clone()
        };

        let row_bg = if selected { BG_SELECTED } else { BG_PANEL };
        let name_style = if selected {
            Style::default().fg(CYAN).bg(row_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(FG_PRIMARY).bg(row_bg)
        };

        let used = 2 + item.display_name.len();
        let right_used = size_str.len() + 2;
        let pad = list_width.saturating_sub(used + right_used);

        let row = Line::from(vec![
            Span::styled(" ", Style::default().bg(row_bg)),
            Span::styled(item.display_name.clone(), name_style),
            Span::styled(" ".repeat(pad), Style::default().bg(row_bg)),
            Span::styled(format!(" {} ", size_str), Style::default().fg(FG_MED).bg(row_bg)),
        ]);

        let pub_row = Line::from(vec![
            Span::styled("  ", Style::default().bg(row_bg)),
            Span::styled(pub_str, Style::default().fg(FG_DIM).bg(row_bg)),
        ]);

        ListItem::new(vec![row, pub_row])
    }).collect();

    let mut list_state = ListState::default();
    if !state.filtered_indices.is_empty() {
        list_state.select(Some(state.selected_filtered));
    }
    f.render_stateful_widget(List::new(items).highlight_symbol(""), inner, &mut list_state);
}

fn draw_detail_panel(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let focused = state.focus == FocusPane::Detail;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { BORDER_ACTIVE } else { BORDER }))
        .title(Span::styled(" Selected App ", Style::default().fg(FG_DIM)))
        .style(Style::default().bg(BG_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(item) = state.selected_item() {
        let app_idx = state.selected_app_index().unwrap_or(0);
        let app = &state.apps[app_idx];
        let meta = &app.metadata;

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("  {}", meta.display_name),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());

        if let Some(pub_name) = &meta.publisher {
            lines.push(Line::from(vec![
                Span::styled("  Publisher  ", Style::default().fg(FG_DIM)),
                Span::styled(pub_name, Style::default().fg(FG_MED)),
            ]));
        }
        if let Some(ver) = &meta.version {
            lines.push(Line::from(vec![
                Span::styled("  Version    ", Style::default().fg(FG_DIM)),
                Span::styled(ver, Style::default().fg(FG_MED)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  Size       ", Style::default().fg(FG_DIM)),
            Span::styled(item.size_label(), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        ]));
        if let Some(loc) = &meta.install_location {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("  Install Location", Style::default().fg(FG_DIM))));
            lines.push(Line::from(Span::styled(format!("  {}", loc), Style::default().fg(FG_MED))));
        }
        if let Some(date) = &meta.install_date {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("  Installed  ", Style::default().fg(FG_DIM)),
                Span::styled(date, Style::default().fg(FG_MED)),
            ]));
        }

        // Uninstaller availability badge
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "  ─────────────────────────────────",
            Style::default().fg(BORDER),
        )));
        lines.push(Line::default());

        if meta.uninstall_string.is_some() {
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
                Span::styled("Uninstaller available", Style::default().fg(FG_MED)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("  ✗ ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                Span::styled("No uninstaller found", Style::default().fg(FG_DIM)),
            ]));
        }

        if meta.msi_product_code.is_some() {
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
                Span::styled("MSI package", Style::default().fg(FG_MED)),
            ]));
        }

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("  Press ", Style::default().fg(FG_DIM)),
            Span::styled("[Enter]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" to uninstall & scan", Style::default().fg(FG_DIM)),
        ]));

        if meta.system_component {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  ⚠ System Component",
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
            )));
        }

        f.render_widget(Paragraph::new(lines).wrap(Wrap::default()), inner);
    } else {
        f.render_widget(
            Paragraph::new(Span::styled("  No app selected", Style::default().fg(FG_DIM))),
            inner,
        );
    }
}

fn draw_command_bar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let [left_area, right_area] = split_h(inner, &[Constraint::Min(0), Constraint::Length(52)]);

    let name = state.selected_item().map(|i| i.display_name.as_str()).unwrap_or("—");
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("  › {APP_TITLE}  "), Style::default().fg(FG_DIM)),
            Span::styled(name, Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("  Ready to uninstall & scan", Style::default().fg(FG_DIM)),
        ])),
        left_area,
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [Enter] ", Style::default().fg(BG).bg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" Uninstall & Scan ", Style::default().fg(CYAN)),
            Span::raw("  "),
            Span::styled("[/] Search", Style::default().fg(FG_DIM)),
            Span::raw("  "),
            Span::styled("[Tab] Pane", Style::default().fg(FG_DIM)),
            Span::raw("  "),
            Span::styled("[q] Quit", Style::default().fg(FG_DIM)),
        ])).alignment(Alignment::Right),
        right_area,
    );
}

fn draw_status_bar(f: &mut Frame, area: Rect) {
    f.render_widget(Block::default().style(Style::default().bg(BG_HEADER)), area);

    let [left_area, right_area] = split_h(area, &[Constraint::Min(0), Constraint::Length(26)]);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("[Enter]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" Uninstall+Scan  ", Style::default().fg(FG_DIM)),
            Span::styled("[Tab]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" Pane  ", Style::default().fg(FG_DIM)),
            Span::styled("[q]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" Quit", Style::default().fg(FG_DIM)),
        ])),
        left_area,
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("● ratatui 0.30", Style::default().fg(GREEN)),
            Span::styled("  Ready", Style::default().fg(FG_DIM)),
        ])).alignment(Alignment::Right),
        right_area,
    );
}

// ─── Phase 2: Uninstall TUI ───────────────────────────────────────────────────
//
// Shows a live "Uninstalling <app>…" overlay while the uninstaller process
// runs in a background thread.  The user can press Esc to cancel (the Job
// Object guard's Drop kills the process tree automatically).
//
// Design:
//   - Spawns the uninstaller in a background OS thread (not tokio — we need
//     blocking wait on the Windows Job Object handle).
//   - Shares an `Arc<Mutex<Option<UninstallerResult>>>` so the TUI thread can
//     poll for completion without blocking the render loop.
//   - The ProcessTreeGuard lives in the background thread; its Drop kills
//     leftover children when the thread exits.

/// Result type shared between the background thread and the TUI.
#[derive(Debug)]
enum UninstallerResult {
    Completed(u32),                         // primary exit code
    SkippedNoString,                        // no uninstall string in registry
    #[allow(dead_code)]
    SkippedSpawnFailed(String),             // couldn't launch the exe
    #[allow(dead_code)]
    SkippedWaitError(String),               // wait failed (timeout etc.)
}

/// State shared between background thread and render loop.
struct UninstallShared {
    result: Option<UninstallerResult>,
    /// Live status line shown in the TUI (updated by bg thread)
    status: String,
}

/// Phase 2 TUI: show "Uninstalling…" screen while the uninstaller runs.
///
/// Returns `UninstallerContext::ran(code)` on normal completion,
/// `UninstallerContext::skipped()` if the user cancelled or no uninstaller exists.
pub fn run_uninstall_tui(metadata: &AppMetadata) -> Result<UninstallerContext, io::Error> {
    // Parse the uninstall command before touching the TUI.
    let cmd_opt = build_uninstall_cmd(metadata);

    // Shared state between bg thread and render loop
    let shared: Arc<Mutex<UninstallShared>> = Arc::new(Mutex::new(UninstallShared {
        result: None,
        status: String::new(),
    }));

    match cmd_opt {
        None => {
            // No uninstall string — skip straight to scanning but tell the user
            shared.lock().unwrap().result = Some(UninstallerResult::SkippedNoString);
        }
        Some((resolved_exe, args)) => {
            let shared_bg = Arc::clone(&shared);
            let exe_display = resolved_exe.display().to_string();

            shared.lock().unwrap().status =
                format!("Launching: {}", resolved_exe.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| exe_display.clone()));

            std::thread::spawn(move || {
                let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

                let guard = match ProcessTreeGuard::spawn_and_assign(&resolved_exe, &args_refs) {
                    Ok(g) => {
                        shared_bg.lock().unwrap().status =
                            format!("Running uninstaller (PID {})", g.primary_pid());
                        g
                    }
                    Err(e) => {
                        warn!("uninstall_tui: failed to spawn '{}': {}", exe_display, e);
                        shared_bg.lock().unwrap().result =
                            Some(UninstallerResult::SkippedSpawnFailed(e.to_string()));
                        return;
                    }
                };

                match guard.wait_for_completion() {
                    Ok((code, elapsed_ms)) => {
                        info!("uninstall_tui: exited code={} elapsed={}ms", code, elapsed_ms);
                        shared_bg.lock().unwrap().status =
                            format!("Finished (exit code {})", code);
                        shared_bg.lock().unwrap().result =
                            Some(UninstallerResult::Completed(code));
                    }
                    Err(e) => {
                        warn!("uninstall_tui: wait error: {}", e);
                        shared_bg.lock().unwrap().result =
                            Some(UninstallerResult::SkippedWaitError(e.to_string()));
                    }
                }
            });
        }
    }

    // Render loop
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app_name = metadata.display_name.clone();
    let uninstall_str_display = metadata.uninstall_string.clone()
        .unwrap_or_else(|| "— no uninstall string —".to_string());
    let mut spinner_idx: usize = 0;
    let start = Instant::now();
    let frame_ms = Duration::from_millis(100);
    let mut last_frame = Instant::now();
    let mut user_cancelled = false;

    let ctx = loop {
        // Snapshot shared state
        let (maybe_result, status_line) = {
            let lock = shared.lock().unwrap();
            (lock.result.as_ref().map(|r| match r {
                UninstallerResult::Completed(code) => UninstallerContext::ran(*code),
                _ => UninstallerContext::skipped(),
            }), lock.status.clone())
        };

        if let Some(ctx) = maybe_result {
            terminal.draw(|f| draw_uninstall_overlay(f, &UninstallOverlayParams {
                app_name: &app_name, uninstall_str: &uninstall_str_display,
                status_line: &status_line, spinner_idx,
                elapsed: start.elapsed(), done: true, cancelled: false,
            }))?;
            std::thread::sleep(Duration::from_millis(600));
            break ctx;
        }

        if user_cancelled {
            break UninstallerContext::skipped();
        }

        if last_frame.elapsed() >= frame_ms {
            spinner_idx = (spinner_idx + 1) % SPINNER_FRAMES.len();
            terminal.draw(|f| draw_uninstall_overlay(f, &UninstallOverlayParams {
                app_name: &app_name, uninstall_str: &uninstall_str_display,
                status_line: &status_line, spinner_idx,
                elapsed: start.elapsed(), done: false, cancelled: false,
            }))?;
            last_frame = Instant::now();
        }

        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc {
                    user_cancelled = true;
                    terminal.draw(|f| draw_uninstall_overlay(f, &UninstallOverlayParams {
                        app_name: &app_name, uninstall_str: &uninstall_str_display,
                        status_line: &status_line, spinner_idx,
                        elapsed: start.elapsed(), done: false, cancelled: true,
                    }))?;
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(ctx)
}

/// Parse and resolve the uninstall command from AppMetadata.
/// Returns `Some((exe_path, args))` or `None` when no uninstaller is available.
fn build_uninstall_cmd(metadata: &AppMetadata) -> Option<(std::path::PathBuf, Vec<String>)> {
    let uninstall_str = metadata.uninstall_string.as_ref()?;
    let cmd = parse_uninstall_string(uninstall_str)?;
    let resolved = resolve_exe_path(&cmd.exe);
    Some((resolved, cmd.args))
}

/// Parameters for draw_uninstall_overlay — avoids clippy::too_many_arguments.
struct UninstallOverlayParams<'a> {
    app_name: &'a str,
    uninstall_str: &'a str,
    status_line: &'a str,
    spinner_idx: usize,
    elapsed: Duration,
    done: bool,
    cancelled: bool,
}

/// Draw the "Uninstalling…" overlay card.
fn draw_uninstall_overlay(f: &mut Frame, p: &UninstallOverlayParams<'_>) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let card = centered_rect(70, 50, area);
    let status_col = if p.cancelled { RED } else if p.done { GREEN } else { CYAN };
    let title_text = if p.cancelled {
        "✗ Cancelling…"
    } else if p.done {
        "✓ Uninstall Complete — scanning for leftovers…"
    } else {
        "Uninstalling…"
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(status_col))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(title_text, Style::default().fg(status_col).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(card);
    f.render_widget(Clear, card);
    f.render_widget(block, card);

    let [spin_area, app_area, cmd_area, status_area, elapsed_area, hint_area] = split_v(inner, &[
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Min(1),
    ]);

    // Spinner + phase label
    let spinner = if p.done { "✓" } else if p.cancelled { "✗" } else { SPINNER_FRAMES[p.spinner_idx] };
    let phase = if p.done {
        "  Uninstaller finished — scanning…"
    } else if p.cancelled {
        "  Cancelling (killing process tree)…"
    } else if p.status_line.is_empty() {
        "  Starting…"
    } else {
        ""
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(spinner, Style::default().fg(status_col).add_modifier(Modifier::BOLD)),
            Span::styled(phase, Style::default().fg(FG_DIM)),
        ])),
        spin_area,
    );

    // App name
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  App       ", Style::default().fg(FG_DIM)),
            Span::styled(p.app_name, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
        ])),
        app_area,
    );

    // Uninstall command (truncated)
    let cmd_display = if p.uninstall_str.len() > (card.width as usize).saturating_sub(16) {
        format!("{}…", &p.uninstall_str[..(card.width as usize).saturating_sub(17)])
    } else {
        p.uninstall_str.to_string()
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Command   ", Style::default().fg(FG_DIM)),
            Span::styled(cmd_display, Style::default().fg(FG_MED)),
        ])),
        cmd_area,
    );

    // Live status from background thread
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Status    ", Style::default().fg(FG_DIM)),
            Span::styled(
                if !p.status_line.is_empty() { p.status_line } else { "Waiting…" },
                Style::default().fg(if p.done { GREEN } else { YELLOW }),
            ),
        ])),
        status_area,
    );

    // Elapsed timer
    let secs = p.elapsed.as_secs();
    let elapsed_str = if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Elapsed   ", Style::default().fg(FG_DIM)),
            Span::styled(elapsed_str, Style::default().fg(FG_MED)),
            Span::styled("   (timeout 10 min)", Style::default().fg(FG_DIM)),
        ])),
        elapsed_area,
    );

    // Hint
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            if p.done || p.cancelled {
                "  Proceeding to leftover scan…"
            } else {
                "  [Esc] cancel & skip uninstaller — will still scan for leftovers"
            },
            Style::default().fg(FG_DIM),
        ))),
        hint_area,
    );
}

// ─── Phase 3: Leftover Review TUI ─────────────────────────────────────────────

#[derive(Debug)]
struct LeftoverReviewState {
    app: crate::domain::app::Application<Scanned>,
    selected_indices: Vec<bool>,
    list_state: ListState,
    filter_confidence: Option<ConfidenceLevel>,
}

impl LeftoverReviewState {
    fn new(app: crate::domain::app::Application<Scanned>) -> Self {
        let count = app.leftovers.len();
        let mut list_state = ListState::default();
        if count > 0 { list_state.select(Some(0)); }
        Self { app, selected_indices: vec![false; count], list_state, filter_confidence: None }
    }

    fn visible_leftovers(&self) -> Vec<(usize, &LeftoverItem)> {
        self.app.leftovers.iter().enumerate()
            .filter(|(_, item)| self.filter_confidence.is_none_or(|f| item.confidence == f))
            .collect()
    }

    fn visible_leftover_count(&self) -> usize { self.visible_leftovers().len() }

    fn current_actual_index(&self) -> Option<usize> {
        let vi = self.list_state.selected()?;
        self.visible_leftovers().get(vi).map(|(idx, _)| *idx)
    }

    fn next(&mut self) {
        let count = self.visible_leftover_count();
        if count == 0 { return; }
        let i = self.list_state.selected().map_or(0, |i| if i >= count - 1 { 0 } else { i + 1 });
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let count = self.visible_leftover_count();
        if count == 0 { return; }
        let i = self.list_state.selected().map_or(0, |i| if i == 0 { count - 1 } else { i - 1 });
        self.list_state.select(Some(i));
    }

    fn toggle_current(&mut self) {
        if let Some(idx) = self.current_actual_index() {
            self.selected_indices[idx] = !self.selected_indices[idx];
        }
    }

    fn select_all(&mut self) { self.selected_indices.fill(true); }
    fn deselect_all(&mut self) { self.selected_indices.fill(false); }
    fn set_filter(&mut self, f: Option<ConfidenceLevel>) { self.filter_confidence = f; self.list_state.select(Some(0)); }

    fn selected_leftover_indices(&self) -> Vec<usize> {
        self.selected_indices.iter().enumerate()
            .filter_map(|(i, &sel)| if sel { Some(i) } else { None })
            .collect()
    }
}

pub fn run_leftover_review_tui(
    app: crate::domain::app::Application<Scanned>,
) -> Result<Vec<usize>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut review_state = LeftoverReviewState::new(app);
    let confirmed = run_leftover_review_loop(&mut terminal, &mut review_state)?;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if confirmed { Ok(review_state.selected_leftover_indices()) } else { Ok(Vec::new()) }
}

fn run_leftover_review_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut LeftoverReviewState,
) -> Result<bool, io::Error> {
    loop {
        terminal.draw(|f| draw_leftover_review(f, state))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') => return Ok(false),
                    KeyCode::Down | KeyCode::Char('j') => state.next(),
                    KeyCode::Up | KeyCode::Char('k') => state.previous(),
                    KeyCode::Char(' ') => state.toggle_current(),
                    KeyCode::Char('a') => state.select_all(),
                    KeyCode::Char('d') => state.deselect_all(),
                    KeyCode::Char('1') => state.set_filter(Some(ConfidenceLevel::High)),
                    KeyCode::Char('2') => state.set_filter(Some(ConfidenceLevel::Medium)),
                    KeyCode::Char('3') => state.set_filter(Some(ConfidenceLevel::Low)),
                    KeyCode::Char('0') => state.set_filter(None),
                    KeyCode::Enter => return Ok(true),
                    _ => {}
                }
            }
        }
    }
}

fn draw_leftover_review(f: &mut Frame, state: &mut LeftoverReviewState) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let [header_area, body_area, footer_area] = split_v(area, &[
        Constraint::Length(1), Constraint::Min(0), Constraint::Length(3),
    ]);

    f.render_widget(Block::default().style(Style::default().bg(BG_HEADER)), header_area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" ✦ {APP_TITLE}  "), Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
            Span::styled(format!("v{}  ", env!("CARGO_PKG_VERSION")), Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("│ Reviewing leftovers for: ", Style::default().fg(FG_DIM)),
            Span::styled(
                &state.app.metadata.display_name,
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
        ])),
        header_area,
    );

    let [list_area, detail_area] = split_h(body_area, &[Constraint::Percentage(60), Constraint::Percentage(40)]);
    draw_leftover_list(f, list_area, state);
    draw_leftover_detail(f, detail_area, state);

    let sel_count = state.selected_leftover_indices().len();
    let footer_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));
    let footer_inner = footer_block.inner(footer_area);
    f.render_widget(footer_block, footer_area);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("[Enter] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Delete Selected  ", Style::default().fg(FG_DIM)),
            Span::styled("[Space] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Toggle  ", Style::default().fg(FG_DIM)),
            Span::styled("[a] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("All  ", Style::default().fg(FG_DIM)),
            Span::styled("[d] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("None  ", Style::default().fg(FG_DIM)),
            Span::styled("[1/2/3/0] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Filter  ", Style::default().fg(FG_DIM)),
            Span::styled(format!("[{} selected]", sel_count), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled("  [q] Cancel", Style::default().fg(FG_DIM)),
        ])),
        footer_inner,
    );
}

fn draw_leftover_list(f: &mut Frame, area: Rect, state: &mut LeftoverReviewState) {
    let visible = state.visible_leftovers();
    let count = visible.len();
    let filter_label = match state.filter_confidence {
        Some(ConfidenceLevel::High) => "  High only",
        Some(ConfidenceLevel::Medium) => "  Med only",
        Some(ConfidenceLevel::Low) => "  Low only",
        None => "",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Line::from(vec![
            Span::styled(" Leftovers ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(format!("({}){}  ", count, filter_label), Style::default().fg(FG_DIM)),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let items: Vec<ListItem> = visible.iter().map(|(idx, item)| {
        let checked = state.selected_indices[*idx];
        let check_col = if checked { GREEN } else { FG_DIM };
        let kind_icon = match item.kind {
            LeftoverKind::File => "📄",
            LeftoverKind::Directory => "📁",
            LeftoverKind::RegistryKey | LeftoverKind::RegistryValue => "🗝",
        };
        let conf_col = match item.confidence {
            ConfidenceLevel::High => GREEN,
            ConfidenceLevel::Medium => YELLOW,
            ConfidenceLevel::Low => ORANGE,
        };
        let conf_label = match item.confidence {
            ConfidenceLevel::High => "H",
            ConfidenceLevel::Medium => "M",
            ConfidenceLevel::Low => "L",
        };
        let path_display = if item.path.len() > 52 {
            format!("…{}", &item.path[item.path.len() - 51..])
        } else {
            item.path.clone()
        };

        ListItem::new(Line::from(vec![
            Span::styled(format!(" {} ", if checked { "☑" } else { "☐" }), Style::default().fg(check_col)),
            Span::styled(format!("{} ", kind_icon), Style::default().fg(FG_DIM)),
            Span::styled(path_display, Style::default().fg(FG_PRIMARY)),
            Span::raw(" "),
            Span::styled(format!("[{}]", conf_label), Style::default().fg(conf_col).add_modifier(Modifier::BOLD)),
        ]))
    }).collect();

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().bg(BG_SELECTED).fg(CYAN).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ "),
        inner,
        &mut state.list_state,
    );
}

fn draw_leftover_detail(f: &mut Frame, area: Rect, state: &LeftoverReviewState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(" Item Details ", Style::default().fg(FG_DIM)))
        .style(Style::default().bg(BG_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = state.visible_leftovers();
    if let Some(vi) = state.list_state.selected() {
        if let Some((idx, item)) = visible.get(vi) {
            let checked = state.selected_indices[*idx];
            let mut lines: Vec<Line> = vec![Line::default()];
            lines.push(Line::from(vec![
                Span::styled("  Type       ", Style::default().fg(FG_DIM)),
                Span::styled(format!("{:?}", item.kind), Style::default().fg(FG_MED)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Confidence ", Style::default().fg(FG_DIM)),
                Span::styled(item.confidence.description(), Style::default().fg(match item.confidence {
                    ConfidenceLevel::High => GREEN,
                    ConfidenceLevel::Medium => YELLOW,
                    ConfidenceLevel::Low => ORANGE,
                }).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Source     ", Style::default().fg(FG_DIM)),
                Span::styled(&item.source, Style::default().fg(FG_MED)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Selected   ", Style::default().fg(FG_DIM)),
                Span::styled(
                    if checked { "Yes" } else { "No" },
                    Style::default().fg(if checked { GREEN } else { FG_DIM }),
                ),
            ]));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("  Path", Style::default().fg(FG_DIM))));
            lines.push(Line::default());
            for chunk in item.path.as_bytes().chunks(inner.width.saturating_sub(4) as usize) {
                let s = String::from_utf8_lossy(chunk).into_owned();
                lines.push(Line::from(Span::styled(format!("  {}", s), Style::default().fg(FG_PRIMARY))));
            }
            f.render_widget(Paragraph::new(lines).wrap(Wrap::default()), inner);
        }
    } else {
        f.render_widget(
            Paragraph::new(Span::styled("  No item selected", Style::default().fg(FG_DIM))),
            inner,
        );
    }
}

// ─── Phase 4: Scanning overlay ────────────────────────────────────────────────

struct ScanOverlayState {
    app_name: String,
    items: Vec<LeftoverItem>,
    spinner_idx: usize,
    start: Instant,
}

impl ScanOverlayState {
    fn new(app_name: String) -> Self {
        Self { app_name, items: Vec::new(), spinner_idx: 0, start: Instant::now() }
    }
    fn tick(&mut self) { self.spinner_idx = (self.spinner_idx + 1) % SPINNER_FRAMES.len(); }
}

pub fn run_scanning_overlay(
    app_name: String,
    scan_rx: Receiver<LeftoverItem>,
) -> Result<Vec<LeftoverItem>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = ScanOverlayState::new(app_name);
    let frame_interval = Duration::from_millis(100);
    let mut last_frame = Instant::now();

    let user_cancelled: bool = 'outer: loop {
        // Drain the channel
        loop {
            match scan_rx.try_recv() {
                Ok(item) => state.items.push(item),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    terminal.draw(|f| draw_scan_overlay(f, &state, true))?;
                    std::thread::sleep(Duration::from_millis(400));
                    disable_raw_mode()?;
                    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                    terminal.show_cursor()?;
                    return Ok(state.items);
                }
            }
        }

        if last_frame.elapsed() >= frame_interval {
            state.tick();
            terminal.draw(|f| draw_scan_overlay(f, &state, false))?;
            last_frame = Instant::now();
        }

        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                {
                    break 'outer true;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if user_cancelled { Ok(Vec::new()) } else { Ok(state.items) }
}

fn draw_scan_overlay(f: &mut Frame, state: &ScanOverlayState, done: bool) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let card = centered_rect(60, 40, area);
    let status_col = if done { GREEN } else { CYAN };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                if done { "✓ Scan Complete" } else { "Scanning for Leftovers" },
                Style::default().fg(status_col).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(card);
    f.render_widget(Clear, card);
    f.render_widget(block, card);

    let [spin_area, stats_area, hint_area] = split_v(inner, &[
        Constraint::Length(2), Constraint::Length(2), Constraint::Length(1),
    ]);

    let spinner = if done { "✓" } else { SPINNER_FRAMES[state.spinner_idx] };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(spinner, Style::default().fg(status_col).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(&state.app_name, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
        ])),
        spin_area,
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Found  ", Style::default().fg(FG_DIM)),
            Span::styled(format!("{} item(s)", state.items.len()), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled("   Elapsed  ", Style::default().fg(FG_DIM)),
            Span::styled(format!("{}s", state.start.elapsed().as_secs()), Style::default().fg(FG_MED)),
        ])),
        stats_area,
    );

    f.render_widget(
        Paragraph::new(if done {
            Line::from(Span::styled("  Press any key to continue…", Style::default().fg(FG_DIM)))
        } else {
            Line::from(Span::styled("  [Esc] to cancel", Style::default().fg(FG_DIM)))
        }),
        hint_area,
    );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn split_v<const N: usize>(area: Rect, constraints: &[Constraint]) -> [Rect; N] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.to_vec())
        .split(area);
    std::array::from_fn(|i| chunks[i])
}

fn split_h<const N: usize>(area: Rect, constraints: &[Constraint]) -> [Rect; N] {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints.to_vec())
        .split(area);
    std::array::from_fn(|i| chunks[i])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(v[1])[1]
}
