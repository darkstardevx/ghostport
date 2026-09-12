mod app;
mod format;
mod templates;
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
/// Embedded at compile time so "install unit" doesn't need to know
/// where the source repo lives at runtime — the installed binary
/// carries its own copy of the template regardless of where it ends up
/// (e.g. symlinked into ~/.local/bin, run from a completely different
/// working directory).
const UNIT_FILE: &str = include_str!("../../systemd/ghostport.service");

pub fn run(config_path: PathBuf, socket_path: PathBuf) -> ExitCode {
    let mut app = match App::new(config_path, socket_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    refresh_service_info(&mut app);
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

fn refresh_service_info(app: &mut App) {
    app.service_state = query_systemctl_field("is-active");
    app.enabled_state = query_systemctl_field("is-enabled");
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
                app::Tab::Service => refresh_service_info(app),
                app::Tab::Links => {}
            }
        }

        // Activating a service action (from Normal-mode Enter on
        // ViewLogs, or a confirmed y/n) is handled right after the key
        // that set it, via `pending_service_action` — see below.
        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    match app.mode {
        Mode::Normal => handle_normal(app, code, terminal, runtime),
        Mode::ChooseTemplate => handle_choose_template(app, code),
        Mode::AddLinkId | Mode::AddLinkAddress => handle_link_text_input(app, code),
        Mode::AddLinkMode => handle_link_mode_choice(app, code),
        Mode::ConfirmRemoveLink => handle_confirm_remove_link(app, code),
        Mode::ConfirmServiceAction => handle_confirm_service_action(app, code, terminal, runtime),
    }
}

fn handle_normal(app: &mut App, code: KeyCode, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
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
                KeyCode::Char('e') => {
                    if app.selected_link().is_some() {
                        app.begin_edit_link();
                    }
                }
                KeyCode::Char('d') => {
                    if app.selected_link().is_some() {
                        app.mode = Mode::ConfirmRemoveLink;
                    }
                }
                KeyCode::Char('s') => app.save_config(),
                _ => {}
            },
            Tab::Service => match code {
                KeyCode::Char('j') | KeyCode::Down => app.move_service_selection(1),
                KeyCode::Char('k') | KeyCode::Up => app.move_service_selection(-1),
                KeyCode::Enter => {
                    app.activate_selected_service_action();
                    // ViewLogs (and anything else that skips the y/n
                    // confirm) needs to actually run right away.
                    if app.mode == Mode::Normal {
                        run_pending_service_action(app, terminal, runtime);
                    }
                }
                _ => {}
            },
            Tab::Status => {
                if code == KeyCode::Char('r') {
                    app.apply_status(runtime.block_on(crate::ipc::query_status(&app.socket_path)));
                }
            }
        },
    }
    Ok(())
}

fn handle_choose_template(app: &mut App, code: KeyCode) -> io::Result<()> {
    match code {
        KeyCode::Esc => app.cancel_link_wizard(),
        KeyCode::Char('j') | KeyCode::Down => app.move_template_selection(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_template_selection(-1),
        KeyCode::Enter => app.confirm_template_choice(),
        _ => {}
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
            app.mode = Mode::Normal;
            run_pending_service_action(app, terminal, runtime);
        }
        _ => app.cancel_service_action(),
    }
    Ok(())
}

fn run_pending_service_action(app: &mut App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, runtime: &tokio::runtime::Runtime) {
    let Some(action) = app.pending_service_action.take() else { return };
    let _ = run_service_action_suspended(terminal, action);
    refresh_service_info(app);
    app.apply_status(runtime.block_on(crate::ipc::query_status(&app.socket_path)));
}

/// Leaves the alternate screen / raw mode, runs the action inheriting
/// this process's stdio (so an interactive sudo password prompt appears
/// exactly as if typed directly — same convention as WraithFlow's
/// `--admin`), waits for it, then restores the TUI. Same "suspend for an
/// interactive subprocess" pattern cyberfleet uses for `git fetch` (an
/// SSH passphrase prompt hangs otherwise).
fn run_service_action_suspended(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, action: ServiceAction) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    match action {
        ServiceAction::Start | ServiceAction::Stop | ServiceAction::Restart | ServiceAction::Enable | ServiceAction::Disable => {
            let verb = action.systemctl_verb();
            println!("[ghostport] running: sudo systemctl {verb} {SERVICE_NAME}");
            io::stdout().flush()?;
            match std::process::Command::new("sudo").args(["systemctl", verb, SERVICE_NAME]).status() {
                Ok(s) if s.success() => println!("[ghostport] {verb} succeeded"),
                Ok(s) => println!("[ghostport] {verb} exited with {s}"),
                Err(e) => println!("[ghostport] failed to run systemctl: {e}"),
            }
        }
        ServiceAction::InstallUnit => install_unit()?,
        ServiceAction::ViewLogs => {
            println!("[ghostport] running: journalctl -u {SERVICE_NAME} -n 50 --no-pager");
            io::stdout().flush()?;
            // Deliberately no sudo — same "read-only status doesn't need
            // privilege" reasoning as `systemctl is-active`. If the local
            // journal ACL denies it, the error prints directly; that's
            // more honest than silently retrying with sudo.
            match std::process::Command::new("journalctl").args(["-u", SERVICE_NAME, "-n", "50", "--no-pager"]).status() {
                Ok(_) => {}
                Err(e) => println!("[ghostport] failed to run journalctl: {e}"),
            }
        }
    }

    println!("Press Enter to return to the TUI...");
    io::stdout().flush()?;
    let mut discard = String::new();
    let _ = io::stdin().read_line(&mut discard);

    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()
}

/// Writes the embedded unit file to `/etc/systemd/system/ghostport.service`
/// via `sudo tee` (no temp file needed — the content is piped straight
/// into the privileged write) and reloads systemd's unit cache. Doesn't
/// overwrite silently: the confirm prompt before this runs is the same
/// y/n every other Service action gets.
fn install_unit() -> io::Result<()> {
    println!("[ghostport] installing systemd/ghostport.service to /etc/systemd/system/ (sudo tee)");
    io::stdout().flush()?;

    let mut tee = std::process::Command::new("sudo")
        .args(["tee", "/etc/systemd/system/ghostport.service"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null()) // tee would otherwise echo the file back to our own stdout
        .spawn()?;
    tee.stdin.take().expect("stdin was piped").write_all(UNIT_FILE.as_bytes())?;
    match tee.wait() {
        Ok(s) if s.success() => println!("[ghostport] unit file installed"),
        Ok(s) => {
            println!("[ghostport] install failed (sudo tee exited with {s})");
            return Ok(());
        }
        Err(e) => {
            println!("[ghostport] failed to run sudo tee: {e}");
            return Ok(());
        }
    }

    println!("[ghostport] running: sudo systemctl daemon-reload");
    io::stdout().flush()?;
    match std::process::Command::new("sudo").args(["systemctl", "daemon-reload"]).status() {
        Ok(s) if s.success() => println!("[ghostport] daemon-reload succeeded"),
        Ok(s) => println!("[ghostport] daemon-reload exited with {s}"),
        Err(e) => println!("[ghostport] failed to run systemctl daemon-reload: {e}"),
    }
    Ok(())
}

/// Read-only, no sudo needed — same reasoning as WraithFlow's
/// `--admin --status` not requiring privilege. `field` is `is-active` or
/// `is-enabled`.
fn query_systemctl_field(field: &str) -> Option<String> {
    let output = std::process::Command::new("systemctl").args([field, SERVICE_NAME]).output().ok()?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if state.is_empty() {
        None
    } else {
        Some(state)
    }
}
