//! TUI application state. Three tabs: live Status (reads the running
//! daemon's IPC socket — the daemon may or may not actually be running,
//! that's a normal state to render, not an error), Links (add/remove
//! link entries, validated via `Config::validate` before every save —
//! never writes something the daemon would refuse to start with), and
//! Service (systemctl start/stop/restart, same `sudo systemctl`
//! invocation convention as WraithFlow's `--admin` flags).
//!
//! Editing here never affects an already-running daemon (no live
//! reload) — it prepares the config file for the *next* start, which is
//! why the Service tab lives next to the Links tab: the natural
//! workflow is edit -> save -> restart.

use crate::config::{Config, LinkConfig, LinkMode};
use crate::stats::StatusSnapshot;
use std::path::PathBuf;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Tab {
    Status,
    Links,
    Service,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    pub fn systemctl_verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    AddLinkId,
    AddLinkMode,
    AddLinkAddress,
    ConfirmRemoveLink,
    ConfirmServiceAction,
}

pub struct App {
    pub config_path: PathBuf,
    pub socket_path: PathBuf,
    pub config: Config,
    pub dirty: bool,

    pub tab: Tab,
    pub mode: Mode,
    pub input_buffer: String,
    pub links_selected: usize,

    pub status_snapshot: Option<StatusSnapshot>,
    pub status_error: Option<String>,
    pub service_state: Option<String>,
    pub pending_service_action: Option<ServiceAction>,

    pub message: Option<String>,
    pub should_quit: bool,

    pending_link_id: Option<String>,
    pending_link_mode: Option<LinkMode>,
}

impl App {
    pub fn new(config_path: PathBuf, socket_path: PathBuf) -> Result<Self, String> {
        let config = Config::load(&config_path)?;
        Ok(Self {
            config_path,
            socket_path,
            config,
            dirty: false,
            tab: Tab::Status,
            mode: Mode::Normal,
            input_buffer: String::new(),
            links_selected: 0,
            status_snapshot: None,
            status_error: None,
            service_state: None,
            pending_service_action: None,
            message: None,
            should_quit: false,
            pending_link_id: None,
            pending_link_mode: None,
        })
    }

    pub fn apply_status(&mut self, result: Result<StatusSnapshot, String>) {
        match result {
            Ok(snap) => {
                self.status_snapshot = Some(snap);
                self.status_error = None;
            }
            Err(e) => {
                self.status_snapshot = None;
                self.status_error = Some(e);
            }
        }
    }

    pub fn next_tab(&mut self) {
        self.tab = match self.tab {
            Tab::Status => Tab::Links,
            Tab::Links => Tab::Service,
            Tab::Service => Tab::Status,
        };
    }

    // --- Links tab ---

    pub fn selected_link(&self) -> Option<&LinkConfig> {
        self.config.links.get(self.links_selected)
    }

    pub fn move_link_selection(&mut self, delta: isize) {
        if self.config.links.is_empty() {
            return;
        }
        let len = self.config.links.len() as isize;
        let new = (self.links_selected as isize + delta).rem_euclid(len);
        self.links_selected = new as usize;
    }

    pub fn begin_add_link(&mut self) {
        self.pending_link_id = None;
        self.pending_link_mode = None;
        self.input_buffer.clear();
        self.mode = Mode::AddLinkId;
    }

    pub fn confirm_link_id(&mut self) {
        let id = self.input_buffer.trim().to_string();
        if id.is_empty() {
            self.cancel_link_wizard();
            return;
        }
        self.pending_link_id = Some(id);
        self.input_buffer.clear();
        self.mode = Mode::AddLinkMode;
    }

    /// Called on 'f'/'r' while in `AddLinkMode` — a single keypress
    /// picks the mode directly rather than needing a typed value for a
    /// two-option enum.
    pub fn choose_link_mode(&mut self, mode: LinkMode) {
        self.pending_link_mode = Some(mode);
        self.input_buffer.clear();
        self.mode = Mode::AddLinkAddress;
    }

    /// Which field this side needs for the in-progress link, per the
    /// same (role, mode) rule the daemon itself enforces — exposed so
    /// the UI can label the prompt correctly ("listen address:" vs
    /// "target address:").
    pub fn pending_link_needs_listen(&self) -> Option<bool> {
        self.pending_link_mode.map(|m| self.config.link_needs_listen(m))
    }

    /// Live feedback while typing an address in `AddLinkAddress` —
    /// `None` while the field is empty (nothing to judge yet), `Some`
    /// afterward. Lets the UI show "not a valid host:port" as you type,
    /// not just when Enter is pressed or the config is saved.
    pub fn link_address_input_status(&self) -> Option<bool> {
        let trimmed = self.input_buffer.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.parse::<std::net::SocketAddr>().is_ok())
        }
    }

    pub fn confirm_link_address(&mut self) {
        let (Some(id), Some(mode)) = (self.pending_link_id.take(), self.pending_link_mode.take()) else {
            self.mode = Mode::Normal;
            return;
        };
        let addr = self.input_buffer.trim().to_string();
        if addr.is_empty() {
            self.input_buffer.clear();
            self.mode = Mode::Normal;
            self.message = Some("add cancelled: address can't be empty".to_string());
            return;
        }
        if addr.parse::<std::net::SocketAddr>().is_err() {
            // Put the pending state back so the wizard stays right where
            // it was — fix the typo and press enter again, no need to
            // restart the whole add from the id step.
            self.pending_link_id = Some(id);
            self.pending_link_mode = Some(mode);
            self.message = Some(format!("\"{addr}\" isn't a valid host:port (e.g. 127.0.0.1:5432) — fix it and press enter"));
            return;
        }
        self.input_buffer.clear();
        self.mode = Mode::Normal;

        let needs_listen = self.config.link_needs_listen(mode);
        let link = if needs_listen {
            LinkConfig { id: id.clone(), mode, listen: Some(addr), target: None }
        } else {
            LinkConfig { id: id.clone(), mode, listen: None, target: Some(addr) }
        };

        self.config.links.retain(|l| l.id != id); // replace if the id already existed
        self.config.links.push(link);
        self.dirty = true;
        self.links_selected = self.config.links.len() - 1;
        self.message = Some(format!("added \"{id}\" (unsaved — press s to write, or the daemon won't see it until restart)"));
    }

    pub fn cancel_link_wizard(&mut self) {
        self.pending_link_id = None;
        self.pending_link_mode = None;
        self.input_buffer.clear();
        self.mode = Mode::Normal;
    }

    pub fn remove_selected_link(&mut self) {
        if self.links_selected < self.config.links.len() {
            let removed = self.config.links.remove(self.links_selected);
            self.links_selected = self.links_selected.saturating_sub(1);
            self.dirty = true;
            self.message = Some(format!("removed \"{}\" (unsaved — press s to write)", removed.id));
        }
        self.mode = Mode::Normal;
    }

    pub fn save_config(&mut self) {
        match self.config.save(&self.config_path) {
            Ok(()) => {
                self.dirty = false;
                self.message = Some(format!("saved {}", self.config_path.display()));
            }
            Err(errors) => {
                self.message = Some(format!("refused to save — {} problem(s): {}", errors.len(), errors.join("; ")));
            }
        }
    }

    // --- Service tab ---

    pub fn request_service_action(&mut self, action: ServiceAction) {
        self.pending_service_action = Some(action);
        self.mode = Mode::ConfirmServiceAction;
    }

    pub fn cancel_service_action(&mut self) {
        self.pending_service_action = None;
        self.mode = Mode::Normal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Role;

    fn scratch_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ghostport-tui-app-test-{name}-{}.toml", std::process::id()))
    }

    fn write_sample_config(path: &PathBuf) {
        let cfg = Config {
            role: Role::Client,
            private_key_path: PathBuf::from("/tmp/identity.key"),
            peer_public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
            listen_control: None,
            listen_data: None,
            server_control_addr: Some("example.com:9000".to_string()),
            server_data_addr: Some("example.com:9001".to_string()),
            links: vec![],
        };
        std::fs::write(path, toml::to_string(&cfg).unwrap()).unwrap();
    }

    #[test]
    fn add_link_wizard_produces_a_correctly_shaped_forward_link() {
        let path = scratch_config_path("add-forward");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.input_buffer = "db".to_string();
        app.confirm_link_id();
        assert_eq!(app.mode, Mode::AddLinkMode);

        app.choose_link_mode(LinkMode::Forward); // client + forward -> needs `listen`
        assert_eq!(app.mode, Mode::AddLinkAddress);
        assert_eq!(app.pending_link_needs_listen(), Some(true));

        app.input_buffer = "127.0.0.1:5432".to_string();
        app.confirm_link_address();

        assert!(app.dirty);
        let link = app.config.links.iter().find(|l| l.id == "db").unwrap();
        assert_eq!(link.listen.as_deref(), Some("127.0.0.1:5432"));
        assert!(link.target.is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn adding_a_link_with_an_existing_id_replaces_it() {
        let path = scratch_config_path("replace");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.config.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Reverse, listen: None, target: Some("old".to_string()) });

        app.begin_add_link();
        app.input_buffer = "db".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Forward);
        app.input_buffer = "127.0.0.1:5432".to_string();
        app.confirm_link_address();

        assert_eq!(app.config.links.iter().filter(|l| l.id == "db").count(), 1);
        assert_eq!(app.config.links.iter().find(|l| l.id == "db").unwrap().mode, LinkMode::Forward);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_writes_a_valid_config_and_clears_dirty() {
        let path = scratch_config_path("save");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.input_buffer = "dev".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Reverse); // client + reverse -> needs `target`
        assert_eq!(app.pending_link_needs_listen(), Some(false));
        app.input_buffer = "127.0.0.1:3000".to_string();
        app.confirm_link_address();
        assert!(app.dirty);

        app.save_config();
        assert!(!app.dirty);

        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.links.len(), 1);
        assert_eq!(reloaded.links[0].target.as_deref(), Some("127.0.0.1:3000"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_selected_link_marks_dirty_and_removes_it() {
        let path = scratch_config_path("remove");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        app.config.links.push(LinkConfig { id: "a".to_string(), mode: LinkMode::Forward, listen: Some("x".to_string()), target: None });
        app.config.links.push(LinkConfig { id: "b".to_string(), mode: LinkMode::Forward, listen: Some("y".to_string()), target: None });
        app.links_selected = 0;

        app.remove_selected_link();

        assert!(app.dirty);
        assert_eq!(app.config.links.len(), 1);
        assert_eq!(app.config.links[0].id, "b");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_link_id_cancels_without_creating_anything() {
        let path = scratch_config_path("empty-id");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.input_buffer.clear();
        app.confirm_link_id();

        assert_eq!(app.mode, Mode::Normal);
        assert!(app.config.links.is_empty());
        assert!(!app.dirty);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn invalid_address_is_rejected_without_losing_the_wizard_progress() {
        let path = scratch_config_path("invalid-addr");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.input_buffer = "dev".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Reverse);

        app.input_buffer = "not-a-real-address".to_string();
        app.confirm_link_address();

        // Stays in AddLinkAddress (not bounced back to Normal) so the
        // user can just fix the typo and press enter again.
        assert_eq!(app.mode, Mode::AddLinkAddress);
        assert!(app.message.as_deref().unwrap_or_default().contains("isn't a valid host:port"));
        assert!(app.config.links.is_empty());

        // Fixing it and confirming again should now succeed.
        app.input_buffer = "127.0.0.1:3000".to_string();
        app.confirm_link_address();
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.config.links.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn link_address_input_status_reflects_validity_live() {
        let path = scratch_config_path("live-validation");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        app.begin_add_link();
        app.input_buffer = "dev".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Reverse);

        assert_eq!(app.link_address_input_status(), None); // nothing typed yet

        app.input_buffer = "not-valid".to_string();
        assert_eq!(app.link_address_input_status(), Some(false));

        app.input_buffer = "127.0.0.1:3000".to_string();
        assert_eq!(app.link_address_input_status(), Some(true));
        std::fs::remove_file(&path).ok();
    }
}
