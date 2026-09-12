//! Rendering. Colors come from the active `cybercore` theme, same
//! approach as CyberVault's TUI (respects `CYBERGRID_THEME`) — used
//! liberally throughout, not just a couple of accents.

use super::app::{App, Mode, ServiceAction, Tab, SERVICE_MENU};
use super::{format, templates};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table};
use ratatui::Frame;

struct Theme {
    purple: Color,
    cyan: Color,
    acid_green: Color,
    hot_pink: Color,
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
            hot_pink: hex_to_color(&p.hot_pink),
            red: hex_to_color(&p.red),
            orange: hex_to_color(&p.orange),
            muted: hex_to_color(&p.muted),
            line: hex_to_color(&p.line),
            white: hex_to_color(&p.white),
        }
    }

    /// Forward and reverse get distinct colors everywhere they're shown
    /// so the two are visually distinguishable at a glance, not just by
    /// text.
    fn mode_color(&self, mode_is_forward: bool) -> Color {
        if mode_is_forward {
            self.cyan
        } else {
            self.hot_pink
        }
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let theme = Theme::load();
    let input_height: u16 = match app.mode {
        Mode::ChooseTemplate => templates::menu_len() as u16 + 2,
        Mode::AddLinkMode => 6, // room for the forward/reverse explanation lines
        Mode::AddLinkId | Mode::AddLinkAddress => 3,
        _ => 0,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(input_height), Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    draw_tabs(frame, &theme, app, chunks[0]);
    if input_height > 0 {
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
    match app.mode {
        Mode::ChooseTemplate => draw_template_menu(frame, theme, app, area),
        Mode::AddLinkId => {
            let verb = if app.is_editing() { "edit" } else { "new" };
            draw_text_step(frame, theme, area, &format!("{verb} encrypted port — id"), app, None);
        }
        Mode::AddLinkAddress => {
            let field_label = match app.pending_link_needs_listen() {
                Some(true) => "listen address",
                Some(false) => "target address",
                None => "address",
            };
            let hint = match app.link_address_input_status() {
                None => None,
                Some(true) => Some(Span::styled("  ✓ valid", Style::default().fg(theme.acid_green))),
                Some(false) => Some(Span::styled("  ✗ needs host:port, e.g. 127.0.0.1:5432", Style::default().fg(theme.red))),
            };
            let verb = if app.is_editing() { "edit" } else { "new" };
            draw_text_step(frame, theme, area, &format!("{verb} encrypted port — {field_label} (host:port)"), app, hint);
        }
        Mode::AddLinkMode => draw_mode_step(frame, theme, area, app),
        _ => {}
    }
}

/// The template chooser — a real selectable list (`List` + `ListState`),
/// not single-letter keys, per the "needs little drop down options"
/// request. "Custom" is always the last row.
fn draw_template_menu(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let mut items: Vec<ListItem> = templates::TEMPLATES
        .iter()
        .map(|t| {
            let mode_color = theme.mode_color(t.mode == crate::config::LinkMode::Forward);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<28}", t.name), Style::default().fg(theme.white)),
                Span::styled(format!("{:?}", t.mode).to_lowercase(), Style::default().fg(mode_color)),
                Span::styled(format!("  default port {}", t.default_port), Style::default().fg(theme.muted)),
            ]))
        })
        .collect();
    items.push(ListItem::new(Line::from(Span::styled("Custom (type everything yourself)", Style::default().fg(theme.muted)))));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.cyan))
        .title(Span::styled(" new encrypted port — choose a template ", Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)));
    let list = List::new(items).block(block).highlight_style(Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD)).highlight_symbol("> ");
    let mut state = ListState::default().with_selected(Some(app.template_selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_text_step(frame: &mut Frame, theme: &Theme, area: Rect, title: &str, app: &App, trailing_hint: Option<Span<'static>>) {
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.cyan)).title(Span::styled(format!(" {title} "), Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)));
    let mut spans = vec![Span::styled(app.input_buffer.clone(), Style::default().fg(theme.white)), Span::styled("_", Style::default().fg(theme.acid_green))];
    if let Some(hint) = trailing_hint {
        spans.push(hint);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_mode_step(frame: &mut Frame, theme: &Theme, area: Rect, app: &App) {
    let verb = if app.is_editing() { "edit" } else { "new" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.cyan))
        .title(Span::styled(format!(" {verb} encrypted port — direction "), Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)));
    let lines = vec![
        Line::from(vec![
            Span::styled("f", Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" forward  "),
            Span::styled("— reach a service near the peer, from a port here", Style::default().fg(theme.muted)),
        ]),
        Line::from(vec![
            Span::styled("r", Style::default().fg(theme.hot_pink).add_modifier(Modifier::BOLD)),
            Span::raw(" reverse  "),
            Span::styled("— expose a service near here, via a port on the peer", Style::default().fg(theme.muted)),
        ]),
        Line::from(Span::styled("esc cancel", Style::default().fg(theme.muted))),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_status(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(" live status ", Style::default().fg(theme.purple).add_modifier(Modifier::BOLD)));

    let Some(snap) = &app.status_snapshot else {
        let msg = app.status_error.as_deref().unwrap_or("no data yet");
        let lines = vec![Line::from(Span::styled(format!("daemon not reachable: {msg}"), Style::default().fg(theme.red))), Line::from(Span::styled("(is it running? see the Service tab)", Style::default().fg(theme.muted)))];
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    };

    let inner = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(0)]).split(block.inner(area));
    frame.render_widget(block, area);

    let control =
        if snap.control_connected { Span::styled("connected", Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD)) } else { Span::styled("disconnected", Style::default().fg(theme.red).add_modifier(Modifier::BOLD)) };
    let mut header = vec![
        Span::styled("role ", Style::default().fg(theme.muted)),
        Span::styled(snap.role.clone(), Style::default().fg(theme.purple)),
        Span::raw("   "),
        Span::styled("uptime ", Style::default().fg(theme.muted)),
        Span::styled(format::duration(snap.uptime_secs), Style::default().fg(theme.cyan)),
        Span::raw("   "),
        Span::styled("control ", Style::default().fg(theme.muted)),
        control,
    ];
    if let (Some(addr), Some(since)) = (&snap.control_peer_addr, snap.control_connected_since_secs_ago) {
        header.push(Span::styled(format!("  ({addr}, up {})", format::duration(since)), Style::default().fg(theme.muted)));
    }
    frame.render_widget(Paragraph::new(Line::from(header)), inner[0]);

    let mut total_active = 0u64;
    let mut total_streams = 0u64;
    let mut total_fwd = 0u64;
    let mut total_back = 0u64;

    let mut rows: Vec<Row> = snap
        .links
        .iter()
        .map(|l| {
            total_active += l.active_streams;
            total_streams += l.total_streams;
            total_fwd += l.bytes_forward;
            total_back += l.bytes_back;

            let mode_color = theme.mode_color(l.mode == "forward");
            let active_style = if l.active_streams > 0 { Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.white) };
            let rate_text = match app.link_rate(&l.id) {
                Some((fwd, back)) if fwd > 0.0 || back > 0.0 => format!("{} / {}", format::rate(fwd), format::rate(back)),
                Some(_) => "idle".to_string(),
                None => "—".to_string(),
            };
            Row::new(vec![
                Cell::from(l.id.clone()).style(Style::default().fg(theme.white)),
                Cell::from(l.mode.clone()).style(Style::default().fg(mode_color)),
                Cell::from(l.active_streams.to_string()).style(active_style),
                Cell::from(l.total_streams.to_string()).style(Style::default().fg(theme.white)),
                Cell::from(format::bytes(l.bytes_forward)).style(Style::default().fg(theme.orange)),
                Cell::from(format::bytes(l.bytes_back)).style(Style::default().fg(theme.orange)),
                Cell::from(rate_text).style(Style::default().fg(theme.muted)),
            ])
        })
        .collect();

    if !snap.links.is_empty() {
        rows.push(Row::new(vec![
            Cell::from("TOTAL").style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Cell::from(""),
            Cell::from(total_active.to_string()).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Cell::from(total_streams.to_string()).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Cell::from(format::bytes(total_fwd)).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Cell::from(format::bytes(total_back)).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)),
            Cell::from(""),
        ]));
    }

    let widths = [Constraint::Length(14), Constraint::Length(9), Constraint::Length(7), Constraint::Length(7), Constraint::Length(10), Constraint::Length(10), Constraint::Length(20)];
    let table = Table::new(rows, widths)
        .header(Row::new(vec!["link", "mode", "active", "total", "bytes-fwd", "bytes-back", "rate (fwd/back)"]).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD)))
        .column_spacing(2);
    frame.render_widget(table, inner[1]);
}

fn draw_links(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let title = if app.dirty { " links (unsaved changes) " } else { " links " };
    let title_style = if app.dirty { Style::default().fg(theme.orange).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.purple).add_modifier(Modifier::BOLD) };
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(title, title_style));

    let rows: Vec<Row> = app
        .config
        .links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let selected = i == app.links_selected;
            let mode_color = theme.mode_color(l.mode == crate::config::LinkMode::Forward);
            let id_style = if selected { Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.white) };
            let mode_style = if selected { Style::default().fg(mode_color).add_modifier(Modifier::BOLD) } else { Style::default().fg(mode_color) };
            let addr = l.listen.as_deref().or(l.target.as_deref()).unwrap_or("");
            let field = if l.listen.is_some() { "listen" } else { "target" };
            Row::new(vec![
                Cell::from(l.id.clone()).style(id_style),
                Cell::from(format!("{:?}", l.mode).to_lowercase()).style(mode_style),
                Cell::from(field).style(Style::default().fg(theme.muted)),
                Cell::from(addr.to_string()).style(Style::default().fg(theme.white)),
            ])
        })
        .collect();
    let widths = [Constraint::Length(16), Constraint::Length(10), Constraint::Length(8), Constraint::Length(28)];
    let table = Table::new(rows, widths).header(Row::new(vec!["id", "mode", "field", "address"]).style(Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD))).column_spacing(2).block(block);
    frame.render_widget(table, area);

    if app.config.links.is_empty() {
        let hint = Paragraph::new(Line::from(Span::styled("no encrypted ports yet — press 'a' to add one", Style::default().fg(theme.muted))));
        let inner = Rect { y: area.y + 2, height: 1, ..area };
        frame.render_widget(hint, inner);
    }
}

fn service_action_color(theme: &Theme, action: ServiceAction) -> Color {
    match action {
        ServiceAction::Start | ServiceAction::Enable => theme.acid_green,
        ServiceAction::Stop | ServiceAction::Disable => theme.red,
        ServiceAction::Restart => theme.orange,
        ServiceAction::InstallUnit => theme.purple,
        ServiceAction::ViewLogs => theme.cyan,
    }
}

fn draw_service(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line)).title(Span::styled(" ghostport.service ", Style::default().fg(theme.purple).add_modifier(Modifier::BOLD)));
    let inner = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(2), Constraint::Min(0)]).split(block.inner(area));
    frame.render_widget(block, area);

    let active_span = match &app.service_state {
        Some(s) if s == "active" => Span::styled(s.clone(), Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD)),
        Some(s) => Span::styled(s.clone(), Style::default().fg(theme.red).add_modifier(Modifier::BOLD)),
        None => Span::styled("unknown", Style::default().fg(theme.muted)),
    };
    let enabled_span = match &app.enabled_state {
        Some(s) if s == "enabled" => Span::styled(s.clone(), Style::default().fg(theme.acid_green)),
        Some(s) => Span::styled(s.clone(), Style::default().fg(theme.muted)),
        None => Span::styled("unknown", Style::default().fg(theme.muted)),
    };
    let header = Line::from(vec![
        Span::styled("state ", Style::default().fg(theme.muted)),
        active_span,
        Span::raw("   "),
        Span::styled("boot ", Style::default().fg(theme.muted)),
        enabled_span,
    ]);
    frame.render_widget(Paragraph::new(header), inner[0]);

    if app.mode == Mode::ConfirmServiceAction {
        if let Some(action) = app.pending_service_action {
            let text = Line::from(Span::styled(format!("{}? this needs sudo — y/n", action.label()), Style::default().fg(theme.orange).add_modifier(Modifier::BOLD)));
            frame.render_widget(Paragraph::new(text), inner[1]);
            return;
        }
    }

    // The service action menu itself — a real dropdown-style list
    // (arrow keys + enter), not a wall of single-letter keys, per the
    // "needs little drop down options" request.
    let items: Vec<ListItem> = SERVICE_MENU
        .iter()
        .map(|&action| {
            let color = service_action_color(theme, action);
            ListItem::new(Line::from(Span::styled(action.label(), Style::default().fg(color))))
        })
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(theme.line)).highlight_symbol("> ");
    let mut state = ListState::default().with_selected(Some(app.service_menu_selected));
    frame.render_stateful_widget(list, inner[1], &mut state);
}

fn draw_footer(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let text = if let Some(msg) = &app.message {
        Line::from(Span::styled(msg.clone(), Style::default().fg(theme.acid_green)))
    } else {
        match (app.tab, &app.mode) {
            (_, Mode::ChooseTemplate) => key_hints(theme, &[("j/k", "move"), ("enter", "select"), ("esc", "cancel")]),
            (_, Mode::AddLinkId | Mode::AddLinkAddress) => key_hints(theme, &[("enter", "confirm"), ("esc", "cancel")]),
            (_, Mode::AddLinkMode) => key_hints(theme, &[("f", "forward"), ("r", "reverse"), ("esc", "cancel")]),
            (_, Mode::ConfirmRemoveLink) => Line::from(Span::styled("remove this port? y/n", Style::default().fg(theme.red).add_modifier(Modifier::BOLD))),
            (_, Mode::ConfirmServiceAction) => Line::from(Span::styled("confirm? y/n", Style::default().fg(theme.orange).add_modifier(Modifier::BOLD))),
            (Tab::Status, Mode::Normal) => key_hints(theme, &[("r", "refresh"), ("tab/1-3", "switch"), ("q", "quit")]),
            (Tab::Links, Mode::Normal) => key_hints(theme, &[("j/k", "move"), ("a", "add port"), ("e", "edit"), ("d", "delete"), ("s", "save"), ("tab/1-3", "switch"), ("q", "quit")]),
            (Tab::Service, Mode::Normal) => key_hints(theme, &[("j/k", "move"), ("enter", "select"), ("tab/1-3", "switch"), ("q", "quit")]),
        }
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), area);
}

/// Renders `key  label   key  label ...` with each key colored to stand
/// out against the muted label text — used throughout instead of one
/// flat-colored hint string.
fn key_hints(theme: &Theme, pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (key, label)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(key.to_string(), Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD)));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(label.to_string(), Style::default().fg(theme.muted)));
    }
    Line::from(spans)
}
