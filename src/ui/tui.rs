use crate::domain::leftover::{ConfidenceLevel, LeftoverItem};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::io;

/// TUI state for application selection
#[derive(Debug)]
pub struct AppSelectionState {
    apps: Vec<crate::domain::app::Application<crate::domain::app::Scanned>>,
    list_state: ListState,
}

impl AppSelectionState {
    fn new(apps: Vec<crate::domain::app::Application<crate::domain::app::Scanned>>) -> Self {
        let mut state = ListState::default();
        if !apps.is_empty() {
            state.select(Some(0));
        }
        Self { apps, list_state: state }
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.apps.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.apps.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }
}

/// TUI state for leftover review
#[derive(Debug)]
struct LeftoverReviewState {
    app: crate::domain::app::Application<crate::domain::app::Scanned>,
    selected_indices: Vec<bool>, // true = selected for deletion
    table_state: TableState,
    filter_confidence: Option<ConfidenceLevel>,
}

impl LeftoverReviewState {
    fn new(app: crate::domain::app::Application<crate::domain::app::Scanned>) -> Self {
        let selected_indices = vec![false; app.leftovers.len()];
        let mut table_state = TableState::default();
        if !app.leftovers.is_empty() {
            table_state.select(Some(0));
        }
        
        Self {
            app,
            selected_indices,
            table_state,
            filter_confidence: None,
        }
    }

    fn next(&mut self) {
        let visible_count = self.visible_leftover_count();
        if visible_count == 0 {
            return;
        }
        
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= visible_count - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        let visible_count = self.visible_leftover_count();
        if visible_count == 0 {
            return;
        }
        
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    visible_count - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn toggle_current(&mut self) {
        if let Some(idx) = self.current_actual_index() {
            self.selected_indices[idx] = !self.selected_indices[idx];
        }
    }

    fn select_all(&mut self) {
        self.selected_indices.fill(true);
    }

    fn deselect_all(&mut self) {
        self.selected_indices.fill(false);
    }

    fn set_filter(&mut self, confidence: Option<ConfidenceLevel>) {
        self.filter_confidence = confidence;
        self.table_state.select(Some(0));
    }

    fn visible_leftovers(&self) -> Vec<(usize, &LeftoverItem)> {
        self.app
            .leftovers
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                if let Some(filter) = self.filter_confidence {
                    item.confidence == filter
                } else {
                    true
                }
            })
            .collect()
    }

    fn visible_leftover_count(&self) -> usize {
        self.visible_leftovers().len()
    }

    fn current_actual_index(&self) -> Option<usize> {
        let visible_idx = self.table_state.selected()?;
        self.visible_leftovers().get(visible_idx).map(|(idx, _)| *idx)
    }

    fn selected_leftover_indices(&self) -> Vec<usize> {
        self.selected_indices
            .iter()
            .enumerate()
            .filter_map(|(i, &selected)| if selected { Some(i) } else { None })
            .collect()
    }
}

/// Main TUI entry point - returns selected leftover indices for each app
pub fn run_tui(
    apps: Vec<crate::domain::app::Application<crate::domain::app::Scanned>>,
) -> Result<Vec<(usize, Vec<usize>)>, io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run app selection
    let mut app_state = AppSelectionState::new(apps);
    let selected_app_idx = run_app_selection(&mut terminal, &mut app_state)?;

    let mut results = Vec::new();

    if let Some(app_idx) = selected_app_idx {
        // Clone the selected app for review
        let app = app_state.apps.swap_remove(app_idx);
        
        // Run leftover review
        let mut review_state = LeftoverReviewState::new(app);
        let confirmed = run_leftover_review(&mut terminal, &mut review_state)?;

        if confirmed {
            let selected_indices = review_state.selected_leftover_indices();
            results.push((app_idx, selected_indices));
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(results)
}

/// Run application selection screen
fn run_app_selection(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppSelectionState,
) -> Result<Option<usize>, io::Error> {
    loop {
        terminal.draw(|f| draw_app_selection(f, state))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') => return Ok(None),
                    KeyCode::Down | KeyCode::Char('j') => state.next(),
                    KeyCode::Up | KeyCode::Char('k') => state.previous(),
                    KeyCode::Enter => {
                        return Ok(state.list_state.selected());
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Draw application selection screen
fn draw_app_selection(f: &mut Frame, state: &mut AppSelectionState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Header
    let header = Paragraph::new("Select Application to Clean")
        .style(Style::default().fg(Color::Rgb(142, 213, 255)).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(56, 189, 248))));
    f.render_widget(header, chunks[0]);

    // Application list
    let items: Vec<ListItem> = state
        .apps
        .iter()
        .map(|app| {
            let line = format!(
                "{} ({} leftovers)",
                app.metadata.display_name,
                app.leftovers.len()
            );
            ListItem::new(line).style(Style::default().fg(Color::Rgb(224, 226, 234)))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Applications ")
                .border_style(Style::default().fg(Color::Rgb(135, 146, 154))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(56, 189, 248))
                .fg(Color::Rgb(9, 13, 18))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, chunks[1], &mut state.list_state);

    // Footer
    let footer = Paragraph::new("↑/↓ Navigate | Enter Select | q Quit")
        .style(Style::default().fg(Color::Rgb(189, 200, 209)))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(135, 146, 154))));
    f.render_widget(footer, chunks[2]);
}

/// Run leftover review screen
fn run_leftover_review(
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

/// Draw leftover review screen
fn draw_leftover_review(f: &mut Frame, state: &mut LeftoverReviewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(4),
        ])
        .split(f.size());

    // Header
    let title = format!("Review Leftovers: {}", state.app.metadata.display_name);
    let header = Paragraph::new(title)
        .style(Style::default().fg(Color::Rgb(142, 213, 255)).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(56, 189, 248))));
    f.render_widget(header, chunks[0]);

    // Table
    let visible = state.visible_leftovers();
    let rows: Vec<Row> = visible
        .iter()
        .map(|(idx, item)| {
            let check = if state.selected_indices[*idx] { "[X]" } else { "[ ]" };
            let kind_str = format!("{:?}", item.kind);
            let confidence_str = format!("{:?}", item.confidence);
            
            Row::new(vec![
                check.to_string(),
                kind_str,
                item.path.clone(),
                confidence_str,
            ])
            .style(Style::default().fg(Color::Rgb(224, 226, 234)))
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Length(15),
        Constraint::Min(40),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Sel", "Kind", "Path", "Confidence"])
                .style(Style::default().fg(Color::Rgb(142, 213, 255)).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Leftovers ({}) ", visible.len()))
                .border_style(Style::default().fg(Color::Rgb(135, 146, 154))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(28, 32, 37))
                .fg(Color::Rgb(142, 213, 255))
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(table, chunks[1], &mut state.table_state);

    // Footer
    let selected_count = state.selected_leftover_indices().len();
    let footer_text = format!(
        "↑/↓ Navigate | Space Toggle | a Select All | d Deselect All | 1/2/3/0 Filter | Enter Confirm ({} selected) | q Cancel",
        selected_count
    );
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Rgb(189, 200, 209)))
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(135, 146, 154))));
    f.render_widget(footer, chunks[2]);
}

