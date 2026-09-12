//! Rendering. Colors come from the active `cybercore` theme, same
//! approach as CyberVault's TUI (respects `CYBERGRID_THEME`).

use super::app::{App, Mode, Tab};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

struct Theme {
    purple: Color,
    cyan: Color,
    acid_green: Color,
    red: Color,
    orange: Color,
    muted: Color,
    line: Color,
    white: Color,
}

fn hex_to_color(hex: &str) -> Color {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(hex.get(0..2).unwrap_or("ff"), 16).unwrap_or(255);
    let g = u8::from_str_radix(hex.get(2..4).unwrap_or("ff"), 16).unwrap_or(255);
    let b = u8::from_str_radix(hex.get(4..6).unwrap_or("ff"), 16).unwrap_or(255);
    Color::Rgb(r, g, b)
}

impl Theme {
    fn load() -> Self {
        let p = &cybercore::schema::load().palette;
        Self {
            purple: hex_to_color(&p.purple),
            cyan: hex_to_color(&p.cyan),
            acid_green: hex_to_color(&p.acid_green),
            red: hex_to_color(&p.red),
            orange: hex_to_color(&p.orange),
            muted: hex_to_color(&p.muted),
            line: hex_to_color(&p.line),
            white: hex_to_color(&p.white),
        }
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let theme = Theme::load();
    let has_input = matches!(app.mode, Mode::AddLinkId | Mode::AddLinkMode | Mode::AddLinkAddress);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(if has_input { 3 } else { 0 }), Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    draw_tabs(frame, &theme, app, chunks[0]);
    if has_input {
        draw_input_line(frame, &theme, app, chunks[1]);
    }

    match app.tab {
        Tab::Status => draw_status(frame, &theme, app, chunks[2]),
        Tab::Links => draw_links(frame, &theme, app, chunks[2]),
        Tab::Service => draw_service(frame, &theme, app, chunks[2]),
    }

    draw_footer(frame, &theme, app, chunks[3]);
}

fn draw_tabs(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let tab_style = |t: Tab| if app.tab == t { Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.muted) };
    let title = Line::from(vec![
        Span::styled(" GHOSTPORT ", Style::default().fg(theme.purple).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled("[1] status", tab_style(Tab::Status)),
        Span::raw("  "),
        Span::styled("[2] links", tab_style(Tab::Links)),
        Span::raw("  "),
        Span::styled("[3] service", tab_style(Tab::Service)),
    ]);
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line));
    frame.render_widget(Paragraph::new(title).block(block), area);
}

fn draw_input_line(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let label = match app.mode {
        Mode::AddLinkId => "link id".to_string(),
        Mode::AddLinkMode => "mode — press f (forward) or r (reverse)".to_string(),
        Mode::AddLinkAddress => match app.pending_link_needs_listen() {
            Some(true) => "listen address (host:port)".to_string(),
            Some(false) => "target address (host:port)".to_string(),
            None => "address".to_string(),
        },
        _ => String::new(),
    };
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.cyan)).title(Span::styled(format!(" {label} "), Style::default().fg(theme.cyan)));
    let text = if app.mode == Mode::AddLinkMode { String::new() } else { format!("{}_", app.input_buffer) };
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_status(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(" live status ", Style::default().fg(theme.muted)));

    let Some(snap) = &app.status_snapshot else {
        let msg = app.status_error.as_deref().unwrap_or("no data yet");
        let lines = vec![Line::from(Span::styled(format!("daemon not reachable: {msg}"), Style::default().fg(theme.red))), Line::from(Span::styled("(is it running? see the Service tab)", Style::default().fg(theme.muted)))];
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    };

    let inner = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(0)]).split(block.inner(area));
    frame.render_widget(block, area);

    let control = if snap.control_connected { Span::styled("connected", Style::default().fg(theme.acid_green)) } else { Span::styled("disconnected", Style::default().fg(theme.red)) };
    let mut header = vec![Span::styled("role ", Style::default().fg(theme.muted)), Span::raw(&snap.role), Span::raw("   "), Span::styled("uptime ", Style::default().fg(theme.muted)), Span::raw(format!("{}s", snap.uptime_secs)), Span::raw("   "), Span::styled("control ", Style::default().fg(theme.muted)), control];
    if let (Some(addr), Some(since)) = (&snap.control_peer_addr, snap.control_connected_since_secs_ago) {
        header.push(Span::raw(format!("  ({addr}, {since}s ago)")));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), inner[0]);

    let rows: Vec<Row> = snap
        .links
        .iter()
        .map(|l| Row::new(vec![Cell::from(l.id.clone()), Cell::from(l.mode.clone()), Cell::from(l.active_streams.to_string()), Cell::from(l.total_streams.to_string()), Cell::from(l.bytes_forward.to_string()), Cell::from(l.bytes_back.to_string())]))
        .collect();
    let widths = [Constraint::Length(16), Constraint::Length(10), Constraint::Length(8), Constraint::Length(8), Constraint::Length(12), Constraint::Length(12)];
    let table = Table::new(rows, widths)
        .header(Row::new(vec!["link", "mode", "active", "total", "bytes-fwd", "bytes-back"]).style(Style::default().fg(theme.cyan)))
        .column_spacing(2);
    frame.render_widget(table, inner[1]);
}

fn draw_links(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let title = if app.dirty { " links (unsaved changes) " } else { " links " };
    let title_style = if app.dirty { Style::default().fg(theme.orange) } else { Style::default().fg(theme.muted) };
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(title, title_style));

    let rows: Vec<Row> = app
        .config
        .links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let style = if i == app.links_selected { Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.white) };
            let addr = l.listen.as_deref().or(l.target.as_deref()).unwrap_or("");
            let field = if l.listen.is_some() { "listen" } else { "target" };
            Row::new(vec![Cell::from(l.id.clone()), Cell::from(format!("{:?}", l.mode).to_lowercase()), Cell::from(field), Cell::from(addr.to_string())]).style(style)
        })
        .collect();
    let widths = [Constraint::Length(16), Constraint::Length(10), Constraint::Length(8), Constraint::Length(28)];
    let table = Table::new(rows, widths).header(Row::new(vec!["id", "mode", "field", "address"]).style(Style::default().fg(theme.cyan))).column_spacing(2).block(block);
    frame.render_widget(table, area);
}

fn draw_service(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(" ghostport.service ", Style::default().fg(theme.muted)));

    let state_line = match &app.service_state {
        Some(s) if s == "active" => Line::from(Span::styled(format!("state: {s}"), Style::default().fg(theme.acid_green))),
        Some(s) => Line::from(Span::styled(format!("state: {s}"), Style::default().fg(theme.red))),
        None => Line::from(Span::styled("state: unknown", Style::default().fg(theme.muted))),
    };

    let mut lines = vec![state_line, Line::from("")];
    if app.mode == Mode::ConfirmServiceAction {
        if let Some(action) = app.pending_service_action {
            lines.push(Line::from(Span::styled(format!("{} ghostport.service? this needs sudo — y/n", action.systemctl_verb()), Style::default().fg(theme.orange))));
        }
    } else {
        lines.push(Line::from("s = start   x = stop   r = restart"));
        lines.push(Line::from(Span::styled("(each suspends this TUI briefly for the sudo prompt, then returns)", Style::default().fg(theme.muted))));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let text = if let Some(msg) = &app.message {
        Line::from(Span::styled(msg.clone(), Style::default().fg(theme.acid_green)))
    } else {
        match (app.tab, &app.mode) {
            (_, Mode::AddLinkId | Mode::AddLinkAddress) => Line::from(Span::styled("enter confirm  esc cancel", Style::default().fg(theme.muted))),
            (_, Mode::AddLinkMode) => Line::from(Span::styled("f forward   r reverse   esc cancel", Style::default().fg(theme.muted))),
            (_, Mode::ConfirmRemoveLink) => Line::from(Span::styled("remove this link? y/n", Style::default().fg(theme.red))),
            (Tab::Status, Mode::Normal) => Line::from(Span::styled("tab/1-3 switch  q quit", Style::default().fg(theme.muted))),
            (Tab::Links, Mode::Normal) => Line::from(Span::styled("j/k move  a add  d delete  s save  tab/1-3 switch  q quit", Style::default().fg(theme.muted))),
            (Tab::Service, Mode::Normal) => Line::from(Span::styled("s start  x stop  r restart  tab/1-3 switch  q quit", Style::default().fg(theme.muted))),
            _ => Line::from(""),
        }
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), area);
}
