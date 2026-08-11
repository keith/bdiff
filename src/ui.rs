use std::collections::{HashMap, VecDeque};
use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};

use crate::artifact::{Analysis, Comparison};
use crate::diff::{DiffView, LineKind};
use crate::passes::{PassRegistry, PassSpec, run_comparison};

type CacheKey = (usize, usize);

struct Job {
    key: CacheKey,
    comparison: Comparison,
    pass: PassSpec,
    tool_timeout: Duration,
}

struct JobResult {
    key: CacheKey,
    view: DiffView,
}

struct Worker {
    queue: Arc<(Mutex<JobQueue>, Condvar)>,
    receiver: Receiver<JobResult>,
    handle: Option<JoinHandle<()>>,
    cancellation: Arc<AtomicBool>,
}

#[derive(Default)]
struct JobQueue {
    jobs: VecDeque<Job>,
    shutdown: bool,
}

impl Worker {
    fn new() -> Self {
        let (result_sender, result_receiver) = mpsc::channel::<JobResult>();
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = cancellation.clone();
        let queue = Arc::new((Mutex::new(JobQueue::default()), Condvar::new()));
        let worker_queue = queue.clone();
        let handle = thread::spawn(move || {
            loop {
                let job = {
                    let (mutex, available) = &*worker_queue;
                    let mut state = mutex
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    while state.jobs.is_empty() && !state.shutdown {
                        state = available
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    if state.shutdown {
                        break;
                    }
                    state
                        .jobs
                        .pop_front()
                        .expect("queue was checked as non-empty")
                };
                if worker_cancellation.load(Ordering::Relaxed) {
                    break;
                }
                let view = run_comparison(
                    &job.comparison,
                    &job.pass,
                    job.tool_timeout,
                    Some(&worker_cancellation),
                )
                .diff();
                if result_sender
                    .send(JobResult { key: job.key, view })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            queue,
            receiver: result_receiver,
            handle: Some(handle),
            cancellation,
        }
    }

    fn submit(&self, job: Job, priority: bool) {
        let (mutex, available) = &*self.queue;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.shutdown {
            return;
        }
        if priority {
            state.jobs.push_front(job);
        } else {
            state.jobs.push_back(job);
        }
        available.notify_one();
    }

    fn prioritize(&self, key: CacheKey) {
        let (mutex, available) = &*self.queue;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(position) = state.jobs.iter().position(|job| job.key == key) {
            let job = state
                .jobs
                .remove(position)
                .expect("position came from queue");
            state.jobs.push_front(job);
            available.notify_one();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Relaxed);
        let (mutex, available) = &*self.queue;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.shutdown = true;
        state.jobs.clear();
        available.notify_one();
        drop(state);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

enum LoadState {
    Loading,
    Ready(DiffView),
}

struct App {
    // Drop the worker before Analysis removes extracted member paths.
    worker: Worker,
    analysis: Analysis,
    registry: PassRegistry,
    tool_timeout: Duration,
    current_node: usize,
    selected_pass: usize,
    vertical_scroll: usize,
    horizontal_scroll: usize,
    change_cursor: Option<(CacheKey, usize)>,
    pending_auto_jump: Option<CacheKey>,
    body_height: usize,
    browser_open: bool,
    browser_cursor: usize,
    help_open: bool,
    cache: HashMap<CacheKey, LoadState>,
}

impl App {
    fn new(analysis: Analysis, registry: PassRegistry, tool_timeout: Duration) -> Self {
        let selected_pass = registry
            .applicable_indices(&analysis.comparisons[0])
            .first()
            .copied()
            .unwrap_or(0);
        let mut app = Self {
            worker: Worker::new(),
            analysis,
            registry,
            tool_timeout,
            current_node: 0,
            selected_pass,
            vertical_scroll: 0,
            horizontal_scroll: 0,
            change_cursor: None,
            pending_auto_jump: None,
            body_height: 1,
            browser_open: false,
            browser_cursor: 0,
            help_open: false,
            cache: HashMap::new(),
        };
        app.schedule_eager_passes();
        app
    }

    fn comparison(&self) -> &Comparison {
        &self.analysis.comparisons[self.current_node]
    }

    fn applicable(&self) -> Vec<usize> {
        self.registry.applicable_indices(self.comparison())
    }

    fn displayed_passes(&self) -> Vec<usize> {
        self.applicable()
    }

    fn current_pass_index(&self) -> Option<usize> {
        let applicable = self.applicable();
        applicable
            .contains(&self.selected_pass)
            .then_some(self.selected_pass)
            .or_else(|| applicable.first().copied())
    }

    fn current_key(&self) -> Option<CacheKey> {
        self.current_pass_index()
            .map(|pass| (self.comparison().id, pass))
    }

    fn current_view(&self) -> Option<&DiffView> {
        match self.current_key().and_then(|key| self.cache.get(&key)) {
            Some(LoadState::Ready(view)) => Some(view),
            _ => None,
        }
    }

    fn request_pass(&mut self, pass_index: usize, priority: bool) {
        let key = (self.comparison().id, pass_index);
        if self.cache.contains_key(&key) {
            if priority {
                self.worker.prioritize(key);
            }
            return;
        }
        self.cache.insert(key, LoadState::Loading);
        self.worker.submit(
            Job {
                key,
                comparison: self.comparison().clone(),
                pass: self.registry.passes[pass_index].clone(),
                tool_timeout: self.tool_timeout,
            },
            priority,
        );
    }

    fn request_current(&mut self) {
        if let Some(pass_index) = self.current_pass_index() {
            self.request_pass(pass_index, true);
        }
    }

    fn schedule_eager_passes(&mut self) {
        for pass_index in self.applicable() {
            if !self.registry.passes[pass_index].is_lazy() {
                self.request_pass(pass_index, false);
            }
        }
        // This matters when a future default or restored selection is lazy.
        self.request_current();
    }

    fn receive_results(&mut self) {
        while let Ok(result) = self.worker.receiver.try_recv() {
            self.cache.insert(result.key, LoadState::Ready(result.view));
        }
        self.apply_pending_auto_jump();
        self.clamp_scroll();
    }

    fn switch_tab(&mut self, amount: isize) {
        let passes = self.displayed_passes();
        let count = passes.len();
        if count == 0 {
            return;
        }
        let current = passes
            .iter()
            .position(|pass| *pass == self.selected_pass)
            .unwrap_or(0);
        self.selected_pass = passes[wrapping_index(current, count, amount)];
        self.vertical_scroll = 0;
        self.horizontal_scroll = 0;
        self.change_cursor = None;
        self.pending_auto_jump = self.current_key();
        self.request_current();
        self.apply_pending_auto_jump();
    }

    fn select_browser_node(&mut self) {
        self.current_node = self.browser_cursor;
        self.selected_pass = self.applicable().first().copied().unwrap_or(0);
        self.vertical_scroll = 0;
        self.horizontal_scroll = 0;
        self.change_cursor = None;
        self.browser_open = false;
        self.pending_auto_jump = self.current_key();
        self.schedule_eager_passes();
        self.apply_pending_auto_jump();
    }

    fn scroll_vertical(&mut self, amount: isize) {
        self.change_cursor = None;
        self.pending_auto_jump = None;
        self.vertical_scroll = saturating_add_signed(self.vertical_scroll, amount);
        self.clamp_scroll();
    }

    fn clamp_scroll(&mut self) {
        let line_count = self.current_view().map_or(1, |view| view.lines.len());
        let maximum = line_count.saturating_sub(self.body_height.max(1));
        self.vertical_scroll = self.vertical_scroll.min(maximum);
    }

    fn jump_change(&mut self, forward: bool) {
        self.pending_auto_jump = None;
        let Some(key) = self.current_key() else {
            return;
        };
        let Some(view) = self.current_view() else {
            return;
        };
        if view.changed_lines.is_empty() {
            return;
        }
        let previous = self
            .change_cursor
            .filter(|(cursor_key, _)| *cursor_key == key)
            .map(|(_, index)| index);
        let index =
            wrapped_change_index(previous, &view.changed_lines, self.vertical_scroll, forward)
                .expect("changed lines were checked as non-empty");
        self.vertical_scroll = change_scroll_offset(view.changed_lines[index]);
        self.change_cursor = Some((key, index));
        self.clamp_scroll();
    }

    fn apply_pending_auto_jump(&mut self) {
        let Some(key) = self.pending_auto_jump else {
            return;
        };
        if self.current_key() != Some(key) {
            self.pending_auto_jump = None;
            return;
        }
        let Some(LoadState::Ready(view)) = self.cache.get(&key) else {
            return;
        };
        let first_change = view.changed_lines.first().copied();
        self.pending_auto_jump = None;
        if let Some(first_change) = first_change {
            self.vertical_scroll = change_scroll_offset(first_change);
            self.change_cursor = Some((key, 0));
        } else {
            self.vertical_scroll = 0;
            self.change_cursor = None;
        }
        self.clamp_scroll();
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return true;
        }
        if self.help_open {
            self.help_open = false;
            return false;
        }
        if self.browser_open {
            match key.code {
                KeyCode::Esc | KeyCode::Char('b') => self.browser_open = false,
                KeyCode::Char('q') => return true,
                KeyCode::Enter => self.select_browser_node(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.browser_cursor = (self.browser_cursor + 1)
                        .min(self.analysis.comparisons.len().saturating_sub(1));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.browser_cursor = self.browser_cursor.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.browser_cursor = (self.browser_cursor + self.body_height)
                        .min(self.analysis.comparisons.len().saturating_sub(1));
                }
                KeyCode::PageUp => {
                    self.browser_cursor = self.browser_cursor.saturating_sub(self.body_height);
                }
                KeyCode::Home | KeyCode::Char('g') => self.browser_cursor = 0,
                KeyCode::End | KeyCode::Char('G') => {
                    self.browser_cursor = self.analysis.comparisons.len().saturating_sub(1);
                }
                _ => {}
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => self.help_open = true,
            KeyCode::Char('b') => {
                self.browser_cursor = self.current_node;
                self.browser_open = true;
            }
            KeyCode::Char(']') | KeyCode::Char('}') => self.switch_tab(1),
            KeyCode::Char('[') | KeyCode::Char('{') => self.switch_tab(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_vertical(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_vertical(-1),
            KeyCode::PageDown => self.scroll_vertical(self.body_height as isize),
            KeyCode::PageUp => self.scroll_vertical(-(self.body_height as isize)),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.scroll_vertical((self.body_height / 2) as isize)
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.scroll_vertical(-((self.body_height / 2) as isize))
            }
            KeyCode::Char('g') => {
                self.change_cursor = None;
                self.pending_auto_jump = None;
                self.vertical_scroll = 0;
            }
            KeyCode::Char('G') => {
                self.change_cursor = None;
                self.pending_auto_jump = None;
                self.vertical_scroll = usize::MAX;
                self.clamp_scroll();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.horizontal_scroll = self.horizontal_scroll.saturating_sub(4)
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.horizontal_scroll = self.horizontal_scroll.saturating_add(4)
            }
            KeyCode::Char('n') => self.jump_change(true),
            KeyCode::Char('N') => self.jump_change(false),
            _ => {}
        }
        false
    }
}

pub fn run(analysis: Analysis, registry: PassRegistry, timeout_seconds: u64) -> Result<()> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("the interactive UI needs a terminal; use --report for plain output");
    }

    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let _cleanup = TerminalCleanup;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    let mut app = App::new(analysis, registry, Duration::from_secs(timeout_seconds));

    loop {
        app.receive_results();
        terminal.draw(|frame| draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(75))?
            && let Event::Key(key) = event::read()?
            && app.handle_key(key)
        {
            break;
        }
    }
    Ok(())
}

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let area = frame.area();
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area);

    draw_tabs(frame, sections[0], app);
    draw_diff(frame, sections[1], app);
    draw_footer(frame, sections[2], app);

    if app.browser_open {
        draw_browser(frame, area, app);
    } else if app.help_open {
        draw_help(frame, area);
    }
}

fn draw_tabs(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let applicable = app.displayed_passes();
    if applicable.is_empty() {
        frame.render_widget(
            Block::default()
                .title(" No applicable passes ")
                .borders(Borders::ALL),
            area,
        );
        return;
    }

    let selected_position = applicable
        .iter()
        .position(|pass| *pass == app.selected_pass)
        .unwrap_or(0);
    let (start, end) = visible_tab_range(
        app,
        &applicable,
        selected_position,
        area.width.saturating_sub(4) as usize,
    );
    let titles = applicable[start..end]
        .iter()
        .map(|index| tab_title(app, *index))
        .collect::<Vec<_>>();
    let title = format!(
        " Passes  [ / ] switch{}{} ",
        if start > 0 { "  ‹" } else { "" },
        if end < applicable.len() { "  ›" } else { "" }
    );
    let tabs = Tabs::new(titles)
        .block(Block::default().title(title).borders(Borders::ALL))
        .select(selected_position - start)
        .divider(" │ ")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn tab_title(app: &App, pass_index: usize) -> Line<'static> {
    let pass = &app.registry.passes[pass_index];
    let state = app.cache.get(&(app.comparison().id, pass_index));
    let (marker, style) = match state {
        Some(LoadState::Ready(view)) if !view.identical => (
            if view.incomplete {
                "[diff?] "
            } else {
                "[diff] "
            },
            Style::default().fg(Color::LightRed),
        ),
        Some(LoadState::Ready(view)) if view.incomplete => {
            ("[?] ", Style::default().fg(Color::Yellow))
        }
        Some(LoadState::Ready(_)) => ("[same] ", Style::default().fg(Color::Green)),
        Some(LoadState::Loading) => ("[run] ", Style::default().fg(Color::Yellow)),
        None if pass.is_lazy() => ("[lazy] ", Style::default().fg(Color::DarkGray)),
        None => ("[wait] ", Style::default().fg(Color::DarkGray)),
    };
    Line::from(vec![
        Span::styled(marker, style.add_modifier(Modifier::BOLD)),
        Span::raw(pass.title.clone()),
    ])
}

fn visible_tab_range(
    app: &App,
    applicable: &[usize],
    selected_position: usize,
    width: usize,
) -> (usize, usize) {
    let mut start = selected_position.saturating_sub(1);
    let mut used = 0;
    let mut end = start;
    while end < applicable.len() {
        let pass_width = app.registry.passes[applicable[end]].title.chars().count() + 10;
        if end > start && used + pass_width > width.max(12) {
            break;
        }
        used += pass_width;
        end += 1;
    }
    while selected_position >= end && start < selected_position {
        start += 1;
        used = 0;
        end = start;
        while end < applicable.len() {
            let pass_width = app.registry.passes[applicable[end]].title.chars().count() + 10;
            if end > start && used + pass_width > width.max(12) {
                break;
            }
            used += pass_width;
            end += 1;
        }
    }
    (start, end.max(start + 1).min(applicable.len()))
}

fn draw_diff(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    app.body_height = panes[0].height.saturating_sub(2) as usize;
    app.clamp_scroll();

    let comparison = app.comparison();
    let left_title = side_title(comparison.left.as_deref(), "Left");
    let right_title = side_title(comparison.right.as_deref(), "Right");
    let (left_lines, right_lines) = match app.current_view() {
        Some(view) => render_lines(
            view,
            app.vertical_scroll,
            app.horizontal_scroll,
            app.body_height,
            panes[0].width.saturating_sub(2) as usize,
        ),
        None => (
            vec![Line::from(Span::styled(
                " Running pass…",
                Style::default().fg(Color::Yellow),
            ))],
            vec![Line::from(Span::styled(
                " Running pass…",
                Style::default().fg(Color::Yellow),
            ))],
        ),
    };
    frame.render_widget(
        Paragraph::new(left_lines).block(Block::default().title(left_title).borders(Borders::ALL)),
        panes[0],
    );
    frame.render_widget(
        Paragraph::new(right_lines)
            .block(Block::default().title(right_title).borders(Borders::ALL)),
        panes[1],
    );
}

fn side_title(artifact: Option<&crate::artifact::Artifact>, side: &str) -> String {
    artifact.map_or_else(
        || format!(" {side}: missing "),
        |artifact| format!(" {side}: {} [{}] ", artifact.label, artifact.kind.name()),
    )
}

fn render_lines(
    view: &DiffView,
    vertical: usize,
    horizontal: usize,
    height: usize,
    width: usize,
) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    let mut left_lines = Vec::new();
    let mut right_lines = Vec::new();
    let text_width = width.saturating_sub(10);
    for (index, line) in view.lines.iter().enumerate().skip(vertical).take(height) {
        let (left_marker, right_marker, style) = match line.kind {
            LineKind::Equal => (' ', ' ', Style::default()),
            LineKind::Delete => ('-', ' ', Style::default().fg(Color::Red)),
            LineKind::Insert => (' ', '+', Style::default().fg(Color::Green)),
            LineKind::Replace => ('!', '!', Style::default().fg(Color::Yellow)),
        };
        let left_text = crop(&line.left, horizontal, text_width);
        let right_text = crop(&line.right, horizontal, text_width);
        left_lines.push(Line::from(Span::styled(
            format!("{:>7} {} {}", index + 1, left_marker, left_text),
            style,
        )));
        right_lines.push(Line::from(Span::styled(
            format!("{:>7} {} {}", index + 1, right_marker, right_text),
            style,
        )));
    }
    (left_lines, right_lines)
}

fn crop(value: &str, offset: usize, width: usize) -> String {
    value.chars().skip(offset).take(width).collect()
}

fn draw_footer(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let pass = app
        .current_pass_index()
        .and_then(|index| app.registry.passes.get(index));
    let state = match app.current_view() {
        Some(view) if view.incomplete && view.identical => {
            "incomplete · captured output identical".to_owned()
        }
        Some(view) if view.incomplete => {
            format!("incomplete · {} changed rows", view.changed_lines.len())
        }
        Some(view) if view.identical => "identical".to_owned(),
        Some(view) => format!("{} changed rows", view.changed_lines.len()),
        None => "running".to_owned(),
    };
    let description = pass.map_or("", |pass| pass.description.as_str());
    let first = Line::from(vec![
        Span::styled(
            format!(" {} ", state),
            Style::default()
                .fg(Color::Black)
                .bg(
                    if app
                        .current_view()
                        .is_some_and(|view| view.identical && !view.incomplete)
                    {
                        Color::Green
                    } else {
                        Color::Yellow
                    },
                )
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {description}")),
    ]);
    let second = Line::from(
        " b files  [/] pass  j/k scroll  h/l pan  n forward  N back  g/G ends  ? help  q quit",
    );
    frame.render_widget(Paragraph::new(vec![first, second]), area);
}

fn draw_browser(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let popup = centered_rect(76, 78, area);
    frame.render_widget(Clear, popup);
    let items = app
        .analysis
        .comparisons
        .iter()
        .map(|comparison| {
            let left_kind = comparison
                .left
                .as_ref()
                .map_or("missing", |artifact| artifact.kind.name());
            let right_kind = comparison
                .right
                .as_ref()
                .map_or("missing", |artifact| artifact.kind.name());
            ListItem::new(format!(
                "{}{} {}  [{} ↔ {}]",
                "  ".repeat(comparison.depth),
                comparison.side_marker(),
                comparison.label,
                left_kind,
                right_kind
            ))
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Files and container members  Enter select · b/Esc close ")
                .borders(Borders::ALL),
        )
        .highlight_symbol("› ")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default().with_selected(Some(app.browser_cursor));
    frame.render_stateful_widget(list, popup, &mut state);
}

fn draw_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(68, 88, area);
    frame.render_widget(Clear, popup);
    let text = vec![
        Line::from("Passes"),
        Line::from("  [ / ]     previous / next pass (kept separate from text movement)"),
        Line::from("  [diff]    output differs; tab order always remains stable"),
        Line::from("  [same]    output is identical"),
        Line::from("  [run]     scheduled; [lazy] runs only when selected"),
        Line::from("  [?]       output was incomplete, unavailable, or truncated"),
        Line::from(""),
        Line::from("Diff navigation"),
        Line::from("  j / k     down / up"),
        Line::from("  h / l     pan left / right"),
        Line::from("  PgUp/Dn   one page; Ctrl-u/d half a page"),
        Line::from("  g / G     start / end"),
        Line::from("  n / N     next / previous change, with 3 context lines above"),
        Line::from(""),
        Line::from("Containers"),
        Line::from("  b         browse archive members and fat Mach-O slices"),
        Line::from("  Enter     compare the selected member/slice"),
        Line::from(""),
        Line::from("Press any key to close help."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::default().title(" Help ").borders(Borders::ALL)),
        popup,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let width = area.width.saturating_mul(percent_x).saturating_div(100);
    let height = area.height.saturating_mul(percent_y).saturating_div(100);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn wrapping_index(current: usize, length: usize, amount: isize) -> usize {
    (current as isize + amount).rem_euclid(length as isize) as usize
}

fn change_scroll_offset(changed_line: usize) -> usize {
    changed_line.saturating_sub(3)
}

fn wrapped_change_index(
    current: Option<usize>,
    changed_lines: &[usize],
    vertical_scroll: usize,
    forward: bool,
) -> Option<usize> {
    if changed_lines.is_empty() {
        return None;
    }
    if let Some(current) = current {
        return Some(if forward {
            (current + 1) % changed_lines.len()
        } else {
            current.checked_sub(1).unwrap_or(changed_lines.len() - 1)
        });
    }
    if forward {
        Some(
            changed_lines
                .iter()
                .position(|line| *line >= vertical_scroll)
                .unwrap_or(0),
        )
    } else {
        Some(
            changed_lines
                .iter()
                .rposition(|line| *line < vertical_scroll)
                .unwrap_or(changed_lines.len() - 1),
        )
    }
}

fn saturating_add_signed(value: usize, amount: isize) -> usize {
    if amount >= 0 {
        value.saturating_add(amount as usize)
    } else {
        value.saturating_sub(amount.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_navigation_wraps() {
        assert_eq!(wrapping_index(0, 4, -1), 3);
        assert_eq!(wrapping_index(3, 4, 1), 0);
    }

    #[test]
    fn cropping_is_unicode_safe() {
        assert_eq!(crop("aλbc", 1, 2), "λb");
    }

    #[test]
    fn change_navigation_wraps_in_both_directions() {
        let changes = [2, 8, 20];
        assert_eq!(wrapped_change_index(Some(2), &changes, 18, true), Some(0));
        assert_eq!(wrapped_change_index(Some(0), &changes, 2, false), Some(2));
        assert_eq!(wrapped_change_index(None, &changes, 8, true), Some(1));
        assert_eq!(wrapped_change_index(None, &changes, 8, false), Some(0));
    }

    #[test]
    fn change_jumps_leave_three_lines_of_context() {
        assert_eq!(change_scroll_offset(10), 7);
        assert_eq!(change_scroll_offset(2), 0);
    }
}
