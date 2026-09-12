mod app;
mod ui;

pub use app::App;
use app::{Mode, ServiceAction, Tab};

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const SERVICE_NAME: &str = "ghostport";

pub fn run(config_path: PathBuf, socket_path: PathBuf) -> ExitCode {
    let mut app = match App::new(config_path, socket_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    app.service_state = query_service_state();
    app.apply_status(runtime.block_on(crate::ipc::query_status(&app.socket_path)));

    let setup = (|| -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Terminal::new(CrosstermBackend::new(stdout))
    })();

    let mut terminal = match setup {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ghostport: failed to start TUI: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = run_event_loop(&mut terminal, &mut app, &runtime);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghostport: TUI error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                app.message = None;
                handle_key(app, key.code, terminal, runtime)?;
            }
        } else {
            // Idle tick: refresh whatever the current tab needs live data
            // for. Cheap and infrequent enough that a blocking query
            // here doesn't hurt responsiveness.
            match app.tab {
                app::Tab::Status => app.apply_status(runtime.block_on(crate::ipc::query_status(&app.socket_path))),
                app::Tab::Service => app.service_state = query_service_state(),
                app::Tab::Links => {}
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    match app.mode {
        Mode::Normal => handle_normal(app, code, terminal),
        Mode::AddLinkId | Mode::AddLinkAddress => handle_link_text_input(app, code),
        Mode::AddLinkMode => handle_link_mode_choice(app, code),
        Mode::ConfirmRemoveLink => handle_confirm_remove_link(app, code),
        Mode::ConfirmServiceAction => handle_confirm_service_action(app, code, terminal, runtime),
    }
}

fn handle_normal(app: &mut App, code: KeyCode, _terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Tab => app.next_tab(),
        KeyCode::Char('1') => app.tab = Tab::Status,
        KeyCode::Char('2') => app.tab = Tab::Links,
        KeyCode::Char('3') => app.tab = Tab::Service,
        _ => match app.tab {
            Tab::Links => match code {
                KeyCode::Char('j') | KeyCode::Down => app.move_link_selection(1),
                KeyCode::Char('k') | KeyCode::Up => app.move_link_selection(-1),
                KeyCode::Char('a') => app.begin_add_link(),
                KeyCode::Char('d') => {
                    if app.selected_link().is_some() {
                        app.mode = Mode::ConfirmRemoveLink;
                    }
                }
                KeyCode::Char('s') => app.save_config(),
                _ => {}
            },
            Tab::Service => match code {
                KeyCode::Char('s') => app.request_service_action(ServiceAction::Start),
                KeyCode::Char('x') => app.request_service_action(ServiceAction::Stop),
                KeyCode::Char('r') => app.request_service_action(ServiceAction::Restart),
                _ => {}
            },
            Tab::Status => {}
        },
    }
    Ok(())
}

fn handle_link_text_input(app: &mut App, code: KeyCode) -> io::Result<()> {
    match code {
        KeyCode::Esc => app.cancel_link_wizard(),
        KeyCode::Enter => match app.mode {
            Mode::AddLinkId => app.confirm_link_id(),
            Mode::AddLinkAddress => app.confirm_link_address(),
            _ => {}
        },
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Char(c) => app.input_buffer.push(c),
        _ => {}
    }
    Ok(())
}

fn handle_link_mode_choice(app: &mut App, code: KeyCode) -> io::Result<()> {
    match code {
        KeyCode::Esc => app.cancel_link_wizard(),
        KeyCode::Char('f') | KeyCode::Char('F') => app.choose_link_mode(crate::config::LinkMode::Forward),
        KeyCode::Char('r') | KeyCode::Char('R') => app.choose_link_mode(crate::config::LinkMode::Reverse),
        _ => {}
    }
    Ok(())
}

fn handle_confirm_remove_link(app: &mut App, code: KeyCode) -> io::Result<()> {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.remove_selected_link(),
        _ => app.mode = Mode::Normal,
    }
    Ok(())
}

fn handle_confirm_service_action(app: &mut App, code: KeyCode, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let Some(action) = app.pending_service_action.take() else {
                app.mode = Mode::Normal;
                return Ok(());
            };
            app.mode = Mode::Normal;
            run_service_action_suspended(terminal, action)?;
            app.service_state = query_service_state();
            app.apply_status(runtime.block_on(crate::ipc::query_status(&app.socket_path)));
        }
        _ => app.cancel_service_action(),
    }
    Ok(())
}

/// Leaves the alternate screen / raw mode, runs `sudo systemctl <action>
/// ghostport` inheriting this process's stdio (so the sudo password
/// prompt appears exactly as if typed directly — same convention as
/// WraithFlow's `--admin`), waits for it, then restores the TUI. Same
/// "suspend for an interactive subprocess" pattern cyberfleet uses for
/// `git fetch` (an SSH passphrase prompt hangs otherwise).
fn run_service_action_suspended(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, action: ServiceAction) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    let verb = action.systemctl_verb();
    println!("[ghostport] running: sudo systemctl {verb} {SERVICE_NAME}");
    io::stdout().flush()?;
    let status = std::process::Command::new("sudo").args(["systemctl", verb, SERVICE_NAME]).status();
    match status {
        Ok(s) if s.success() => println!("[ghostport] {verb} succeeded"),
        Ok(s) => println!("[ghostport] {verb} exited with {s}"),
        Err(e) => println!("[ghostport] failed to run systemctl: {e}"),
    }
    println!("Press Enter to return to the TUI...");
    io::stdout().flush()?;
    let mut discard = String::new();
    let _ = io::stdin().read_line(&mut discard);

    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()
}

/// Read-only, no sudo needed — same reasoning as WraithFlow's
/// `--admin --status` not requiring privilege.
fn query_service_state() -> Option<String> {
    let output = std::process::Command::new("systemctl").args(["is-active", SERVICE_NAME]).output().ok()?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if state.is_empty() {
        None
    } else {
        Some(state)
    }
}
