use crate::domain::app::{Discovered, Scanned};
use crate::domain::leftover::{ConfidenceLevel, LeftoverItem, LeftoverKind};
use crossbeam_channel::Receiver;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

// ─── Palette ──────────────────────────────────────────────────────────────────
const CYAN: Color = Color::Rgb(56, 189, 248);      // Electric cyan accent
const _CYAN_DIM: Color = Color::Rgb(30, 110, 150);
const GREEN: Color = Color::Rgb(34, 197, 94);
const YELLOW: Color = Color::Rgb(250, 204, 21);
const ORANGE: Color = Color::Rgb(251, 146, 60);
const RED: Color = Color::Rgb(248, 113, 113);
const _MAGENTA: Color = Color::Rgb(192, 132, 252);
const BG: Color = Color::Rgb(9, 13, 18);
const BG_PANEL: Color = Color::Rgb(13, 18, 26);
const BG_SELECTED: Color = Color::Rgb(22, 30, 42);
const BG_HEADER: Color = Color::Rgb(16, 22, 32);
const FG_PRIMARY: Color = Color::Rgb(224, 235, 245);
const FG_DIM: Color = Color::Rgb(100, 116, 130);
const FG_MED: Color = Color::Rgb(148, 163, 175);
const BORDER: Color = Color::Rgb(30, 42, 58);
const BORDER_ACTIVE: Color = Color::Rgb(56, 189, 248);

// ─── Section tabs (left sidebar) ──────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    OverviewHealth,
    AppsPackages,
    DeepScanLeftovers,
    BuildCaches,
    DaemonsAndTasks,
}

impl Section {
    const ALL: &'static [Section] = &[
        Section::OverviewHealth,
        Section::AppsPackages,
        Section::DeepScanLeftovers,
        Section::BuildCaches,
        Section::DaemonsAndTasks,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::OverviewHealth => "Overview & Health",
            Section::AppsPackages => "Apps & Packages",
            Section::DeepScanLeftovers => "Deep Scan Leftovers",
            Section::BuildCaches => "Target & Build Caches",
            Section::DaemonsAndTasks => "Daemons & Tasks",
        }
    }

    fn badge(self, apps_count: usize) -> Option<String> {
        match self {
            Section::AppsPackages => Some(format!("{}", apps_count)),
            Section::DeepScanLeftovers => Some("3.46".to_string()),
            Section::BuildCaches => Some("12".to_string()),
            Section::DaemonsAndTasks => Some("3".to_string()),
            _ => None,
        }
    }
}

// ─── Focus pane ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    Sidebar,
    AppList,
    Detail,
}

// ─── App list item state ───────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct AppListItem {
    display_name: String,
    publisher: String,
    size_bytes: u64,
    tag: Option<String>,
    tag_color: Option<Color>,
    checked: bool,
}

impl AppListItem {
    fn from_app(app: &crate::domain::app::Application<Discovered>) -> Self {
        let size_bytes = app.metadata.estimated_size.unwrap_or(0);
        let publisher = app.metadata.publisher.clone().unwrap_or_else(|| "Unknown".to_string());
        Self {
            display_name: app.metadata.display_name.clone(),
            publisher,
            size_bytes,
            tag: None,
            tag_color: None,
            checked: false,
        }
    }

    fn size_label(&self) -> String {
        format_size(self.size_bytes)
    }
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 {
        return "? MB".to_string();
    }
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{} MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

// ─── AppListState ─────────────────────────────────────────────────────────────
/// All state for the FEAT-006 redesigned app-selection screen.
pub struct AppSelectionState {
    /// Original apps (sorted alphabetically, immutable order)
    apps: Vec<crate::domain::app::Application<Discovered>>,
    /// Derived display items (sorted alphabetically once at construction)
    items: Vec<AppListItem>,
    /// Indices into `items` that pass the current search filter
    filtered_indices: Vec<usize>,
    /// Cursor into `filtered_indices`
    selected_filtered: usize,
    /// Current search query
    search_input: String,
    /// Whether the search box is focused
    search_focused: bool,
    /// Which pane has keyboard focus
    focus: FocusPane,
    /// Which sidebar section is active
    active_section: usize,
    /// Disk health % (mock)
    disk_health: u8,
    /// Free disk bytes (mock)
    disk_free_gb: f64,
    /// Total disk bytes (mock)
    disk_total_gb: f64,
}

impl AppSelectionState {
    pub fn new(mut apps: Vec<crate::domain::app::Application<Discovered>>) -> Self {
        // Sort alphabetically (case-insensitive)
        apps.sort_by(|a, b| {
            a.metadata
                .display_name
                .to_lowercase()
                .cmp(&b.metadata.display_name.to_lowercase())
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
            active_section: 1, // "Apps & Packages"
            disk_health: 68,
            disk_free_gb: 142.6,
            disk_total_gb: 512.0,
        }
    }

    // ── Search / filter ──────────────────────────────────────────────────────

    fn update_filter(&mut self) {
        let query = self.search_input.to_lowercase();
        if query.is_empty() {
            self.filtered_indices = (0..self.items.len()).collect();
        } else {
            self.filtered_indices = self
                .items
                .iter()
                .enumerate()
                .filter(|(_, item)| item.display_name.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect();
        }
        // Clamp cursor
        if self.filtered_indices.is_empty() {
            self.selected_filtered = 0;
        } else {
            self.selected_filtered = self.selected_filtered.min(self.filtered_indices.len() - 1);
        }
    }

    fn push_char(&mut self, c: char) {
        self.search_input.push(c);
        self.update_filter();
    }

    fn pop_char(&mut self) {
        self.search_input.pop();
        self.update_filter();
    }

    fn clear_search(&mut self) {
        self.search_input.clear();
        self.update_filter();
    }

    // ── Navigation ───────────────────────────────────────────────────────────

    fn next_app(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        self.selected_filtered =
            (self.selected_filtered + 1) % self.filtered_indices.len();
    }

    fn prev_app(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        if self.selected_filtered == 0 {
            self.selected_filtered = self.filtered_indices.len() - 1;
        } else {
            self.selected_filtered -= 1;
        }
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
        if self.search_input.is_empty() {
            format!("{} total", total)
        } else {
            format!("{} match{}", shown, if shown == 1 { "" } else { "es" })
        }
    }
}

// ─── Phase 1 public entry point ───────────────────────────────────────────────

/// Phase 1 TUI: show discovered apps with cargo-purge style layout.
/// Returns the selected `Application<Discovered>` or `None` if user quits.
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
        terminal.draw(|f| draw_main_screen(f, state))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // Global: Ctrl+C / q (when not typing) to quit
            if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                return Ok(None);
            }

            if state.search_focused {
                // ── Search box captures keys ──────────────────────────────
                match key.code {
                    KeyCode::Esc => {
                        state.clear_search();
                        state.search_focused = false;
                    }
                    KeyCode::Backspace => state.pop_char(),
                    KeyCode::Char(c) => state.push_char(c),
                    KeyCode::Down => {
                        state.search_focused = false;
                        state.focus = FocusPane::AppList;
                    }
                    KeyCode::Enter => {
                        state.search_focused = false;
                        state.focus = FocusPane::AppList;
                    }
                    _ => {}
                }
            } else {
                // ── Normal navigation ─────────────────────────────────────
                match key.code {
                    KeyCode::Char('q') => return Ok(None),
                    KeyCode::Char('/') => {
                        state.search_focused = true;
                        state.focus = FocusPane::AppList;
                    }
                    KeyCode::Tab => {
                        state.focus = match state.focus {
                            FocusPane::Sidebar => FocusPane::AppList,
                            FocusPane::AppList => FocusPane::Detail,
                            FocusPane::Detail => FocusPane::Sidebar,
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if state.focus == FocusPane::Sidebar {
                            state.active_section =
                                (state.active_section + 1) % Section::ALL.len();
                        } else {
                            state.next_app();
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if state.focus == FocusPane::Sidebar {
                            if state.active_section == 0 {
                                state.active_section = Section::ALL.len() - 1;
                            } else {
                                state.active_section -= 1;
                            }
                        } else {
                            state.prev_app();
                        }
                    }
                    KeyCode::Char(' ') => {
                        if let Some(idx) = state.selected_app_index() {
                            state.items[idx].checked = !state.items[idx].checked;
                        }
                    }
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
}

// ─── Main screen layout ───────────────────────────────────────────────────────
//
//  ┌──────────────────── header (1 line) ─────────────────────────────────────┐
//  │ sidebar (30%) │           center pane (70%)                               │
//  │               │  search bar (3)                                           │
//  │               │  app list (fill) │  detail panel (fill)                  │
//  │ disk health   │                                                           │
//  ├──────────────────── command bar (3) ─────────────────────────────────────┤
//  └──────────────────── status bar (1) ──────────────────────────────────────┘

fn draw_main_screen(f: &mut Frame, state: &mut AppSelectionState) {
    let area = f.size();

    // Background fill
    f.render_widget(
        Block::default().style(Style::default().bg(BG)),
        area,
    );

    // Outer vertical split: header | body | cmd | status
    let [header_area, body_area, cmd_area, status_area] = split_v(
        area,
        &[
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(3),
            Constraint::Length(1),
        ],
    );

    draw_header(f, header_area, state);
    draw_body(f, body_area, state);
    draw_command_bar(f, cmd_area, state);
    draw_status_bar(f, status_area);
}

// ─── Header ───────────────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    // bg for header
    f.render_widget(
        Block::default().style(Style::default().bg(BG_HEADER)),
        area,
    );

    // Split: left brand | center stats | right status
    let [brand_area, stats_area, ready_area] = split_h(
        area,
        &[
            Constraint::Length(38),
            Constraint::Min(0),
            Constraint::Length(18),
        ],
    );

    // Brand: "leftover-cleaner  v0.1.0"
    let brand = Line::from(vec![
        Span::styled(" ✦ leftover-cleaner", Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled("v0.1.0", Style::default().fg(CYAN).bg(Color::Rgb(10, 30, 48)).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(brand), brand_area);

    // Stats
    let apps_total = state.items.len();
    let free_gb = state.disk_free_gb;
    let total_gb = state.disk_total_gb;
    let stats = Line::from(vec![
        Span::styled("  APPS ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{}", apps_total), Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("   FREE ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{:.1} GB", free_gb), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
        Span::styled("   TOTAL ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{:.0} GB", total_gb), Style::default().fg(FG_MED).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(stats), stats_area);

    // Ready indicator
    let ready = Line::from(vec![
        Span::styled("● READY ", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(
        Paragraph::new(ready).alignment(Alignment::Right),
        ready_area,
    );
}

// ─── Body split ───────────────────────────────────────────────────────────────

fn draw_body(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    // Horizontal: sidebar | main content
    let [sidebar_area, content_area] = split_h(
        area,
        &[Constraint::Length(22), Constraint::Min(0)],
    );

    // Sidebar: sections list + disk health at bottom
    draw_sidebar(f, sidebar_area, state);

    // Content: search + split (list | detail)
    draw_content(f, content_area, state);
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

fn draw_sidebar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let [sections_area, disk_area] = split_v(
        area,
        &[Constraint::Min(0), Constraint::Length(6)],
    );

    // Sections panel
    let sections_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if state.focus == FocusPane::Sidebar { BORDER_ACTIVE } else { BORDER }))
        .title(Span::styled(" SECTIONS ", Style::default().fg(FG_DIM)))
        .title_alignment(Alignment::Left)
        .style(Style::default().bg(BG_PANEL));

    let inner = sections_block.inner(sections_area);
    f.render_widget(sections_block, sections_area);

    let items: Vec<ListItem> = Section::ALL
        .iter()
        .enumerate()
        .map(|(i, sec)| {
            let active = i == state.active_section;
            let badge = sec.badge(state.items.len());
            let label = sec.label();
            let num = format!("[{}] ", i + 1);

            if active {
                let mut spans = vec![
                    Span::styled(num, Style::default().fg(FG_DIM)),
                    Span::styled(label, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
                ];
                if let Some(b) = badge {
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(
                        b,
                        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                    ));
                }
                ListItem::new(Line::from(spans))
                    .style(Style::default().bg(BG_SELECTED).fg(FG_PRIMARY))
            } else {
                let mut spans = vec![
                    Span::styled(num, Style::default().fg(FG_DIM)),
                    Span::styled(label, Style::default().fg(FG_MED)),
                ];
                if let Some(b) = badge {
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(b, Style::default().fg(FG_DIM)));
                }
                ListItem::new(Line::from(spans))
            }
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.active_section));

    let list = List::new(items)
        .highlight_style(Style::default().bg(BG_SELECTED))
        .highlight_symbol("▌ ");

    f.render_stateful_widget(list, inner, &mut list_state);

    // Disk health panel
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
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(color).bg(Color::Rgb(20, 28, 38)))
        .percent(pct)
        .label(Span::styled(
            format!("{}% Healthy", pct),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(gauge, gauge_area);

    let info = Line::from(vec![
        Span::styled(format!("Free: {:.1} GB", state.disk_free_gb), Style::default().fg(FG_MED)),
        Span::styled(format!("  Total: {:.0} GB", state.disk_total_gb), Style::default().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(info), info_area);
}

// ─── Content pane (search + list + detail) ────────────────────────────────────

fn draw_content(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    // Vertical: search bar | split pane
    let [search_area, panes_area] = split_v(
        area,
        &[Constraint::Length(3), Constraint::Min(0)],
    );

    draw_search_bar(f, search_area, state);
    draw_split_panes(f, panes_area, state);
}

fn draw_search_bar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let focused = state.search_focused;
    let border_color = if focused { BORDER_ACTIVE } else { BORDER };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split inner: icon + input | match count
    let [icon_area, count_area] = split_h(inner, &[Constraint::Min(0), Constraint::Length(16)]);

    let cursor = if focused { "█" } else { "" };
    let query_display = if state.search_input.is_empty() && !focused {
        Line::from(vec![
            Span::styled("  ", Style::default().fg(FG_DIM)),
            Span::styled("🔍 ", Style::default().fg(FG_DIM)),
            Span::styled("Search apps... (press / to focus)", Style::default().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  ", Style::default().fg(FG_DIM)),
            Span::styled("🔍 ", Style::default().fg(CYAN)),
            Span::styled(&state.search_input, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
            Span::styled(cursor, Style::default().fg(CYAN).add_modifier(Modifier::SLOW_BLINK)),
        ])
    };

    f.render_widget(Paragraph::new(query_display), icon_area);

    let count = Line::from(vec![
        Span::styled(state.matches_label(), Style::default().fg(FG_DIM)),
        Span::raw("  "),
    ]);
    f.render_widget(
        Paragraph::new(count).alignment(Alignment::Right),
        count_area,
    );
}

fn draw_split_panes(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    // Horizontal: app list (55%) | detail panel (45%)
    let [list_area, detail_area] = split_h(
        area,
        &[Constraint::Percentage(55), Constraint::Percentage(45)],
    );

    draw_app_list(f, list_area, state);
    draw_detail_panel(f, detail_area, state);
}

// ─── App list panel ───────────────────────────────────────────────────────────

fn draw_app_list(f: &mut Frame, area: Rect, state: &mut AppSelectionState) {
    let focused = state.focus == FocusPane::AppList;
    let _title_label = format!(" Apps & Packages  {} ", state.matches_label());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if focused { BORDER_ACTIVE } else { BORDER }))
        .title(Line::from(vec![
            Span::styled(" Apps & Packages ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{} ", state.matches_label()),
                Style::default().fg(FG_DIM),
            ),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let list_width = inner.width as usize;

    // Build list items from filtered indices
    let items: Vec<ListItem> = state
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(fi, &item_idx)| {
            let item = &state.items[item_idx];
            let selected = fi == state.selected_filtered;
            let check = if item.checked { "☑" } else { "☐" };
            let name = &item.display_name;
            let pub_str = if item.publisher.len() > 20 {
                format!("{}…", &item.publisher[..19])
            } else {
                item.publisher.clone()
            };
            let size_str = item.size_label();

            // Tag badge
            let tag_span: Option<Span> = item.tag.as_ref().map(|t| {
                let col = item.tag_color.unwrap_or(FG_DIM);
                Span::styled(format!(" {} ", t), Style::default().fg(BG).bg(col).add_modifier(Modifier::BOLD))
            });

            // Build row spans
            let row_bg = if selected { BG_SELECTED } else { BG_PANEL };
            let name_style = if selected {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(FG_PRIMARY)
            };

            let mut spans = vec![
                Span::styled(format!(" {} ", check), Style::default().fg(if item.checked { GREEN } else { FG_DIM }).bg(row_bg)),
                Span::styled(format!("{}", name), name_style.bg(row_bg)),
            ];

            // Pad + size
            let used = 4 + name.len();
            let right_used = size_str.len() + 2 + tag_span.as_ref().map(|t| t.content.len()).unwrap_or(0) + 2;
            let pad = (list_width as usize).saturating_sub(used + right_used);
            spans.push(Span::styled(" ".repeat(pad), Style::default().bg(row_bg)));

            spans.push(Span::styled(
                format!(" {} ", size_str),
                Style::default().fg(FG_MED).bg(row_bg),
            ));

            if let Some(ts) = tag_span {
                let ts_with_bg = Span::styled(
                    ts.content.clone(),
                    ts.style.bg(row_bg),
                );
                // render the tag badge inline
                spans.push(Span::styled(" ", Style::default().bg(row_bg)));
                spans.push(ts_with_bg);
            }

            // Publisher sub-line
            let pub_spans = vec![
                Span::styled("    ", Style::default().bg(row_bg)),
                Span::styled(pub_str, Style::default().fg(FG_DIM).bg(row_bg)),
            ];

            // Ratatui 0.25 ListItem only takes a single Text (Vec<Line>)
            ListItem::new(vec![
                Line::from(spans),
                Line::from(pub_spans),
            ])
        })
        .collect();

    let mut list_state = ListState::default();
    if !state.filtered_indices.is_empty() {
        list_state.select(Some(state.selected_filtered));
    }

    let list = List::new(items)
        .highlight_style(Style::default().bg(BG_SELECTED))
        .highlight_symbol("");

    f.render_stateful_widget(list, inner, &mut list_state);

    // Bottom footer inside panel: selected item summary
    // (rendered in detail panel below)
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

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

        // App name (large)
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}", meta.display_name),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::raw("")));

        // Publisher
        if let Some(pub_name) = &meta.publisher {
            lines.push(Line::from(vec![
                Span::styled("  Publisher  ", Style::default().fg(FG_DIM)),
                Span::styled(pub_name, Style::default().fg(FG_MED)),
            ]));
        }

        // Version
        if let Some(ver) = &meta.version {
            lines.push(Line::from(vec![
                Span::styled("  Version    ", Style::default().fg(FG_DIM)),
                Span::styled(ver, Style::default().fg(FG_MED)),
            ]));
        }

        // Size
        lines.push(Line::from(vec![
            Span::styled("  Size       ", Style::default().fg(FG_DIM)),
            Span::styled(item.size_label(), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        ]));

        // Install location
        if let Some(loc) = &meta.install_location {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled("  Install Location", Style::default().fg(FG_DIM))));
            lines.push(Line::from(Span::styled(
                format!("  {}", loc),
                Style::default().fg(FG_MED),
            )));
        }

        // Install date
        if let Some(date) = &meta.install_date {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(vec![
                Span::styled("  Installed  ", Style::default().fg(FG_DIM)),
                Span::styled(date, Style::default().fg(FG_MED)),
            ]));
        }

        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "  ─────────────────────────────────",
            Style::default().fg(BORDER),
        )));
        lines.push(Line::from(Span::raw("")));

        // Action hint
        lines.push(Line::from(vec![
            Span::styled("  Press ", Style::default().fg(FG_DIM)),
            Span::styled("[Enter]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" to scan for leftovers", Style::default().fg(FG_DIM)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Press ", Style::default().fg(FG_DIM)),
            Span::styled("[Space]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" to toggle selection", Style::default().fg(FG_DIM)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Press ", Style::default().fg(FG_DIM)),
            Span::styled("[/]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" to search", Style::default().fg(FG_DIM)),
        ]));

        // System component badge
        if meta.system_component {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled(
                "  ⚠ System Component",
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
            )));
        }

        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            inner,
        );
    } else {
        let placeholder = Paragraph::new(Line::from(Span::styled(
            "  No app selected",
            Style::default().fg(FG_DIM),
        )));
        f.render_widget(placeholder, inner);
    }
}

// ─── Command bar ──────────────────────────────────────────────────────────────

fn draw_command_bar(f: &mut Frame, area: Rect, state: &AppSelectionState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Left: selected app name | Right: action buttons
    let [left_area, right_area] = split_h(
        inner,
        &[Constraint::Min(0), Constraint::Length(52)],
    );

    // Selected name
    let name = state
        .selected_item()
        .map(|i| i.display_name.as_str())
        .unwrap_or("—");

    let selected_spans = Line::from(vec![
        Span::styled("  › leftover-cleaner  ", Style::default().fg(FG_DIM)),
        Span::styled(
            name,
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  Ready to scan for leftovers"),
            Style::default().fg(FG_DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(selected_spans), left_area);

    // Buttons
    let btns = Line::from(vec![
        Span::styled(" [Enter] ", Style::default().fg(BG).bg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" Scan App ", Style::default().fg(CYAN)),
        Span::raw("  "),
        Span::styled("[/] Search", Style::default().fg(FG_DIM)),
        Span::raw("  "),
        Span::styled("[Tab] Switch Pane", Style::default().fg(FG_DIM)),
        Span::raw("  "),
        Span::styled("[q] Quit", Style::default().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(btns).alignment(Alignment::Right), right_area);
}

// ─── Status bar ───────────────────────────────────────────────────────────────

fn draw_status_bar(f: &mut Frame, area: Rect) {
    f.render_widget(
        Block::default().style(Style::default().bg(BG_HEADER)),
        area,
    );

    let [left_area, right_area] = split_h(
        area,
        &[Constraint::Min(0), Constraint::Length(26)],
    );

    let keybinds = Line::from(vec![
        Span::styled("[Enter]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" Scan  ", Style::default().fg(FG_DIM)),
        Span::styled("[Space]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" Select  ", Style::default().fg(FG_DIM)),
        Span::styled("[Tab]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" Switch Pane  ", Style::default().fg(FG_DIM)),
        Span::styled("[q]", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" Quit", Style::default().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(keybinds), left_area);

    let ver = Line::from(vec![
        Span::styled("● ratatui 0.25", Style::default().fg(GREEN)),
        Span::styled("  Ready", Style::default().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(ver).alignment(Alignment::Right), right_area);
}

// ─── Phase 2: Leftover Review TUI ─────────────────────────────────────────────
//  (kept and adapted to cargo-purge style)

/// TUI state for leftover review (Scanned app — scanning already done)
#[derive(Debug)]
struct LeftoverReviewState {
    app: crate::domain::app::Application<Scanned>,
    selected_indices: Vec<bool>,
    list_state: ListState,
    filter_confidence: Option<ConfidenceLevel>,
}

impl LeftoverReviewState {
    fn new(app: crate::domain::app::Application<Scanned>) -> Self {
        let selected_indices = vec![false; app.leftovers.len()];
        let mut list_state = ListState::default();
        if !app.leftovers.is_empty() {
            list_state.select(Some(0));
        }
        Self { app, selected_indices, list_state, filter_confidence: None }
    }

    fn next(&mut self) {
        let count = self.visible_leftover_count();
        if count == 0 { return; }
        let i = match self.list_state.selected() {
            Some(i) => if i >= count - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let count = self.visible_leftover_count();
        if count == 0 { return; }
        let i = match self.list_state.selected() {
            Some(i) => if i == 0 { count - 1 } else { i - 1 },
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn toggle_current(&mut self) {
        if let Some(idx) = self.current_actual_index() {
            self.selected_indices[idx] = !self.selected_indices[idx];
        }
    }

    fn select_all(&mut self) { self.selected_indices.fill(true); }
    fn deselect_all(&mut self) { self.selected_indices.fill(false); }

    fn set_filter(&mut self, confidence: Option<ConfidenceLevel>) {
        self.filter_confidence = confidence;
        self.list_state.select(Some(0));
    }

    fn visible_leftovers(&self) -> Vec<(usize, &LeftoverItem)> {
        self.app.leftovers.iter().enumerate()
            .filter(|(_, item)| {
                if let Some(filter) = self.filter_confidence { item.confidence == filter } else { true }
            })
            .collect()
    }

    fn visible_leftover_count(&self) -> usize { self.visible_leftovers().len() }

    fn current_actual_index(&self) -> Option<usize> {
        let vi = self.list_state.selected()?;
        self.visible_leftovers().get(vi).map(|(idx, _)| *idx)
    }

    fn selected_leftover_indices(&self) -> Vec<usize> {
        self.selected_indices.iter().enumerate()
            .filter_map(|(i, &sel)| if sel { Some(i) } else { None })
            .collect()
    }
}

/// Phase 2 TUI: show scanned leftovers. Returns selected leftover indices.
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
    let area = f.size();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let [header_area, body_area, footer_area] = split_v(
        area,
        &[Constraint::Length(1), Constraint::Min(0), Constraint::Length(3)],
    );

    // Header
    f.render_widget(Block::default().style(Style::default().bg(BG_HEADER)), header_area);
    let htitle = Line::from(vec![
        Span::styled(" ✦ leftover-cleaner  ", Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
        Span::styled("v0.1.0  ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("│ Reviewing leftovers for: ", Style::default().fg(FG_DIM)),
        Span::styled(
            &state.app.metadata.display_name,
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ),
    ]);
    f.render_widget(Paragraph::new(htitle), header_area);

    // Body: list | detail
    let [list_area, detail_area] = split_h(
        body_area,
        &[Constraint::Percentage(60), Constraint::Percentage(40)],
    );

    draw_leftover_list(f, list_area, state);
    draw_leftover_detail(f, detail_area, state);

    // Footer
    let sel_count = state.selected_leftover_indices().len();
    let footer_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));
    let footer_inner = footer_block.inner(footer_area);
    f.render_widget(footer_block, footer_area);

    let footer = Line::from(vec![
        Span::styled("[Enter] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("Delete Selected  ", Style::default().fg(FG_DIM)),
        Span::styled("[Space] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("Toggle  ", Style::default().fg(FG_DIM)),
        Span::styled("[a] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("All  ", Style::default().fg(FG_DIM)),
        Span::styled("[d] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("None  ", Style::default().fg(FG_DIM)),
        Span::styled("[1/2/3/0] ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("Filter confidence  ", Style::default().fg(FG_DIM)),
        Span::styled(format!("[{} selected]", sel_count), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled("  [q] Cancel", Style::default().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(footer), footer_inner);
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

    let items: Vec<ListItem> = visible
        .iter()
        .map(|(idx, item)| {
            let checked = state.selected_indices[*idx];
            let check_sym = if checked { "☑" } else { "☐" };
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

            // Truncate path for display
            let path_display = if item.path.len() > 52 {
                format!("…{}", &item.path[item.path.len() - 51..])
            } else {
                item.path.clone()
            };

            let spans = Line::from(vec![
                Span::styled(format!(" {} ", check_sym), Style::default().fg(check_col)),
                Span::styled(format!("{} ", kind_icon), Style::default().fg(FG_DIM)),
                Span::styled(path_display, Style::default().fg(FG_PRIMARY)),
                Span::raw(" "),
                Span::styled(
                    format!("[{}]", conf_label),
                    Style::default().fg(conf_col).add_modifier(Modifier::BOLD),
                ),
            ]);
            ListItem::new(spans)
        })
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default().bg(BG_SELECTED).fg(CYAN).add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, inner, &mut state.list_state);
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
            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(vec![
                Span::styled("  Type       ", Style::default().fg(FG_DIM)),
                Span::styled(format!("{:?}", item.kind), Style::default().fg(FG_MED)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Confidence ", Style::default().fg(FG_DIM)),
                Span::styled(
                    item.confidence.description(),
                    Style::default().fg(match item.confidence {
                        ConfidenceLevel::High => GREEN,
                        ConfidenceLevel::Medium => YELLOW,
                        ConfidenceLevel::Low => ORANGE,
                    }).add_modifier(Modifier::BOLD),
                ),
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
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled("  Path", Style::default().fg(FG_DIM))));
            lines.push(Line::from(Span::raw("")));
            // Word-wrap path
            for chunk in item.path.as_bytes().chunks(inner.width.saturating_sub(4) as usize) {
                let s = String::from_utf8_lossy(chunk).into_owned();
                lines.push(Line::from(Span::styled(format!("  {}", s), Style::default().fg(FG_PRIMARY))));
            }
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
    } else {
        f.render_widget(
            Paragraph::new(Span::styled("  No item selected", Style::default().fg(FG_DIM))),
            inner,
        );
    }
}

// ─── Scanning overlay ─────────────────────────────────────────────────────────

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

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
    fn tick_spinner(&mut self) { self.spinner_idx = (self.spinner_idx + 1) % SPINNER_FRAMES.len(); }
    fn spinner(&self) -> &str { SPINNER_FRAMES[self.spinner_idx] }
    fn elapsed_secs(&self) -> u64 { self.start.elapsed().as_secs() }
}

/// Show a scanning overlay while draining `scan_rx`.
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
    let frame_interval = Duration::from_millis(125);
    let mut last_frame = Instant::now();

    let user_cancelled = 'outer: loop {
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
            state.tick_spinner();
            terminal.draw(|f| draw_scan_overlay(f, &state, false))?;
            last_frame = Instant::now();
        }

        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => break 'outer true,
                        _ => {}
                    }
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
    let area = f.size();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    // Centered card
    let card = centered_rect(60, 40, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                if done { "✓ Scan Complete" } else { "Scanning for Leftovers" },
                Style::default().fg(if done { GREEN } else { CYAN }).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(card);
    f.render_widget(Clear, card);
    f.render_widget(block, card);

    let [spin_area, stats_area, hint_area] = split_v(
        inner,
        &[Constraint::Length(2), Constraint::Length(2), Constraint::Length(1)],
    );

    // Spinner + app name
    let spinner = if done { "✓" } else { state.spinner() };
    let spin_line = Line::from(vec![
        Span::raw("  "),
        Span::styled(spinner, Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(&state.app_name, Style::default().fg(FG_PRIMARY).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(Paragraph::new(spin_line), spin_area);

    // Stats
    let stats = Line::from(vec![
        Span::styled("  Found  ", Style::default().fg(FG_DIM)),
        Span::styled(
            format!("{} item(s)", state.items.len()),
            Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   Elapsed  ", Style::default().fg(FG_DIM)),
        Span::styled(
            format!("{}s", state.elapsed_secs()),
            Style::default().fg(FG_MED),
        ),
    ]);
    f.render_widget(Paragraph::new(stats), stats_area);

    // Hint
    let hint = if done {
        Line::from(Span::styled("  Press any key to continue…", Style::default().fg(FG_DIM)))
    } else {
        Line::from(Span::styled("  [Esc] to cancel", Style::default().fg(FG_DIM)))
    };
    f.render_widget(Paragraph::new(hint), hint_area);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Split a `Rect` vertically with given constraints; returns array of areas.
fn split_v<const N: usize>(area: Rect, constraints: &[Constraint]) -> [Rect; N] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.to_vec())
        .split(area);
    std::array::from_fn(|i| chunks[i])
}

/// Split a `Rect` horizontally with given constraints; returns array of areas.
fn split_h<const N: usize>(area: Rect, constraints: &[Constraint]) -> [Rect; N] {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints.to_vec())
        .split(area);
    std::array::from_fn(|i| chunks[i])
}

/// Centered rect helper (percent_x × percent_y of parent).
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
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
        .split(vertical[1])[1]
}
