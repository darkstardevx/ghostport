//! TUI application state. Three tabs: live Status (reads the running
//! daemon's IPC socket — the daemon may or may not actually be running,
//! that's a normal state to render, not an error), Links (add via
//! templates or from scratch, fully edit, remove — validated via
//! `Config::validate` before every save, never writes something the
//! daemon would refuse to start with), and Service (a navigable menu:
//! start/stop/restart/enable/disable/install-unit/view-logs, same
//! `sudo systemctl` invocation convention as WraithFlow's `--admin`
//! flags).
//!
//! Editing here never affects an already-running daemon (no live
//! reload) — it prepares the config file for the *next* start, which is
//! why the Service tab lives next to the Links tab: the natural
//! workflow is edit -> save -> restart.

use crate::tui::templates;
use ghostport_core::config::{Config, LinkConfig, LinkMode, PeerConfig, Role};
use ghostport_core::keys;
use ghostport_core::stats::StatusSnapshot;
use std::path::PathBuf;
use std::time::Instant;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Tab {
    Status,
    Links,
    Service,
    Peers,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    InstallUnit,
    ViewLogs,
}

pub const SERVICE_MENU: &[ServiceAction] = &[
    ServiceAction::Start,
    ServiceAction::Stop,
    ServiceAction::Restart,
    ServiceAction::Enable,
    ServiceAction::Disable,
    ServiceAction::InstallUnit,
    ServiceAction::ViewLogs,
];

impl ServiceAction {
    pub fn systemctl_verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Enable => "enable",
            ServiceAction::Disable => "disable",
            ServiceAction::InstallUnit | ServiceAction::ViewLogs => "",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ServiceAction::Start => "Start",
            ServiceAction::Stop => "Stop",
            ServiceAction::Restart => "Restart",
            ServiceAction::Enable => "Enable at boot",
            ServiceAction::Disable => "Disable at boot",
            ServiceAction::InstallUnit => "Install systemd unit",
            ServiceAction::ViewLogs => "View recent logs",
        }
    }

    /// Only viewing logs is a harmless, non-privileged read — everything
    /// else changes system state and gets a confirm prompt.
    pub fn needs_confirm(self) -> bool {
        !matches!(self, ServiceAction::ViewLogs)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    ChooseTemplate,
    AddLinkId,
    AddLinkDirection,
    AddLinkAddress,
    ConfirmRemoveLink,
    ConfirmServiceAction,
    AddPeerName,
    AddPeerPublicKey,
    AddPeerLinks,
    ConfirmRemovePeer,
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
    pub template_selected: usize,
    pub service_menu_selected: usize,

    pub status_snapshot: Option<StatusSnapshot>,
    pub status_error: Option<String>,
    previous_snapshot: Option<(Instant, StatusSnapshot)>,
    status_captured_at: Option<Instant>,

    pub service_state: Option<String>,
    pub enabled_state: Option<String>,
    pub pending_service_action: Option<ServiceAction>,

    pub message: Option<String>,
    pub should_quit: bool,

    pending_link_id: Option<String>,
    pending_link_mode: Option<LinkMode>,
    /// Pre-fill for the address step — a template's suggested
    /// `127.0.0.1:<port>`, or the current value when editing an existing
    /// link. `None` for a from-scratch "Custom" add, which starts empty.
    pending_default_address: Option<String>,
    /// Set while editing an existing link, holding its original id —
    /// lets `confirm_link_address` remove the *old* entry if the id
    /// itself was changed, instead of just deduping the new id.
    editing_original_id: Option<String>,

    pub peers_selected: usize,
    pending_peer_name: Option<String>,
    pending_peer_public_key: Option<String>,
    /// Pre-fill for the public-key step when editing an existing peer
    /// (so re-confirming an unchanged 44-char key is just pressing
    /// enter, not retyping it) — same role as `pending_default_address`
    /// for links. `None` for a from-scratch add, which starts empty.
    pending_default_peer_public_key: Option<String>,
    /// The in-progress peer's checked link ids, built up as the
    /// checklist step is toggled — not committed to `config.peers`
    /// until `confirm_peer_links` confirms the whole wizard.
    pending_peer_links: Vec<String>,
    /// Cursor over `config.links` during the checklist step — distinct
    /// from `peers_selected` (the outer Peers-tab list cursor).
    pub peer_links_cursor: usize,
    /// Set while editing an existing peer, holding its original name —
    /// lets `confirm_peer_links` remove the *old* entry if the name
    /// itself was changed, instead of just deduping the new name.
    editing_original_peer_name: Option<String>,
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
            template_selected: 0,
            service_menu_selected: 0,
            status_snapshot: None,
            status_error: None,
            previous_snapshot: None,
            status_captured_at: None,
            service_state: None,
            enabled_state: None,
            pending_service_action: None,
            message: None,
            should_quit: false,
            pending_link_id: None,
            pending_link_mode: None,
            pending_default_address: None,
            editing_original_id: None,
            peers_selected: 0,
            pending_peer_name: None,
            pending_peer_public_key: None,
            pending_default_peer_public_key: None,
            pending_peer_links: Vec::new(),
            peer_links_cursor: 0,
            editing_original_peer_name: None,
        })
    }

    pub fn apply_status(&mut self, result: Result<StatusSnapshot, String>) {
        let now = Instant::now();
        match result {
            Ok(snap) => {
                if let Some(current) = self.status_snapshot.take() {
                    self.previous_snapshot =
                        Some((self.status_captured_at.unwrap_or(now), current));
                }
                self.status_captured_at = Some(now);
                self.status_snapshot = Some(snap);
                self.status_error = None;
            }
            Err(e) => {
                self.status_snapshot = None;
                self.status_error = Some(e);
            }
        }
    }

    /// (bytes/sec forward, bytes/sec back) for a link, from the two most
    /// recent snapshots. `None` until at least two samples have arrived
    /// (or the link is new since the last one) — the UI shows a dash
    /// rather than a misleading 0 in that case.
    pub fn link_rate(&self, link_id: &str) -> Option<(f64, f64)> {
        let (prev_at, prev_snap) = self.previous_snapshot.as_ref()?;
        let cur_snap = self.status_snapshot.as_ref()?;
        let cur_at = self.status_captured_at?;
        let elapsed = cur_at.duration_since(*prev_at).as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        let prev_link = prev_snap.links.iter().find(|l| l.id == link_id)?;
        let cur_link = cur_snap.links.iter().find(|l| l.id == link_id)?;
        let fwd = cur_link
            .bytes_forward
            .saturating_sub(prev_link.bytes_forward) as f64
            / elapsed;
        let back = cur_link.bytes_back.saturating_sub(prev_link.bytes_back) as f64 / elapsed;
        Some((fwd, back))
    }

    pub fn next_tab(&mut self) {
        self.tab = match self.tab {
            Tab::Status => Tab::Links,
            Tab::Links => Tab::Service,
            Tab::Service => Tab::Peers,
            Tab::Peers => Tab::Status,
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

    /// 'a': opens the template chooser (step 1 of adding a new port).
    pub fn begin_add_link(&mut self) {
        self.editing_original_id = None;
        self.pending_link_id = None;
        self.pending_link_mode = None;
        self.pending_default_address = None;
        self.template_selected = 0;
        self.input_buffer.clear();
        self.mode = Mode::ChooseTemplate;
    }

    /// 'e': edit the selected link — same wizard as adding, but every
    /// step starts pre-filled with the link's current values, and the
    /// original entry gets replaced (or removed, if the id changed)
    /// rather than a duplicate being created.
    pub fn begin_edit_link(&mut self) {
        let Some(link) = self.selected_link().cloned() else {
            return;
        };
        self.editing_original_id = Some(link.id.clone());
        self.pending_link_id = None;
        self.pending_link_mode = None;
        self.pending_default_address = Some(link.listen.or(link.target).unwrap_or_default());
        self.input_buffer = link.id;
        self.mode = Mode::AddLinkId;
    }

    pub fn move_template_selection(&mut self, delta: isize) {
        let len = templates::menu_len() as isize;
        self.template_selected = (self.template_selected as isize + delta).rem_euclid(len) as usize;
    }

    /// Enter on the template chooser: a real template pre-fills its
    /// default id/mode and skips straight to confirming the address (its
    /// mode is fixed by the template) — "Custom" instead goes through
    /// the full id -> mode -> address wizard with nothing pre-filled.
    pub fn confirm_template_choice(&mut self) {
        if self.template_selected == templates::custom_index() {
            self.input_buffer.clear();
        } else if let Some(t) = templates::TEMPLATES.get(self.template_selected) {
            self.pending_link_mode = Some(t.mode);
            self.pending_default_address = Some(format!("127.0.0.1:{}", t.default_port));
            self.input_buffer = t.default_id.to_string();
        }
        self.mode = Mode::AddLinkId;
    }

    pub fn confirm_link_id(&mut self) {
        let id = self.input_buffer.trim().to_string();
        if id.is_empty() {
            self.cancel_link_wizard();
            return;
        }
        self.pending_link_id = Some(id);
        if self.pending_link_mode.is_some() {
            // A template already fixed the mode — skip straight to the
            // address step, pre-filled with the template's suggestion.
            self.input_buffer = self.pending_default_address.clone().unwrap_or_default();
            self.mode = Mode::AddLinkAddress;
        } else {
            self.input_buffer.clear();
            self.mode = Mode::AddLinkDirection;
        }
    }

    /// Called on 'f'/'r' while in `AddLinkDirection` — a single keypress
    /// picks the mode directly rather than needing a typed value for a
    /// two-option enum.
    pub fn choose_link_mode(&mut self, mode: LinkMode) {
        self.pending_link_mode = Some(mode);
        self.input_buffer = self.pending_default_address.clone().unwrap_or_default();
        self.mode = Mode::AddLinkAddress;
    }

    /// Which field this side needs for the in-progress link, per the
    /// same (role, mode) rule the daemon itself enforces — exposed so
    /// the UI can label the prompt correctly ("listen address:" vs
    /// "target address:").
    pub fn pending_link_needs_listen(&self) -> Option<bool> {
        self.pending_link_mode
            .map(|m| self.config.link_needs_listen(m))
    }

    pub fn is_editing(&self) -> bool {
        self.editing_original_id.is_some()
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
        let (Some(id), Some(mode)) = (self.pending_link_id.take(), self.pending_link_mode.take())
        else {
            self.mode = Mode::Normal;
            return;
        };
        let addr = self.input_buffer.trim().to_string();
        if addr.is_empty() {
            self.input_buffer.clear();
            self.mode = Mode::Normal;
            self.editing_original_id = None;
            self.pending_default_address = None;
            self.message = Some("cancelled: address can't be empty".to_string());
            return;
        }
        if addr.parse::<std::net::SocketAddr>().is_err() {
            // Put the pending state back so the wizard stays right where
            // it was — fix the typo and press enter again, no need to
            // restart the whole add/edit from the id step.
            self.pending_link_id = Some(id);
            self.pending_link_mode = Some(mode);
            self.message = Some(format!(
                "\"{addr}\" isn't a valid host:port (e.g. 127.0.0.1:5432) — fix it and press enter"
            ));
            return;
        }
        self.input_buffer.clear();
        self.mode = Mode::Normal;

        let needs_listen = self.config.link_needs_listen(mode);
        let link = if needs_listen {
            LinkConfig {
                id: id.clone(),
                mode,
                listen: Some(addr),
                target: None,
            }
        } else {
            LinkConfig {
                id: id.clone(),
                mode,
                listen: None,
                target: Some(addr),
            }
        };

        let was_editing = self.editing_original_id.is_some();
        if let Some(old_id) = self.editing_original_id.take() {
            if old_id != id {
                self.config.links.retain(|l| l.id != old_id);
            }
        }
        self.config.links.retain(|l| l.id != id); // replace if this id already existed
        self.config.links.push(link);
        self.dirty = true;
        self.links_selected = self
            .config
            .links
            .iter()
            .position(|l| l.id == id)
            .unwrap_or(0);
        self.pending_default_address = None;
        let verb = if was_editing { "updated" } else { "added" };
        self.message = Some(format!("{verb} \"{id}\" (unsaved — press s to write, or the daemon won't see it until restart)"));
    }

    pub fn cancel_link_wizard(&mut self) {
        self.pending_link_id = None;
        self.pending_link_mode = None;
        self.pending_default_address = None;
        self.editing_original_id = None;
        self.input_buffer.clear();
        self.mode = Mode::Normal;
    }

    pub fn remove_selected_link(&mut self) {
        if self.links_selected < self.config.links.len() {
            let removed = self.config.links.remove(self.links_selected);
            self.links_selected = self.links_selected.saturating_sub(1);
            self.dirty = true;
            self.message = Some(format!(
                "removed \"{}\" (unsaved — press s to write)",
                removed.id
            ));
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
                self.message = Some(format!(
                    "refused to save — {} problem(s): {}",
                    errors.len(),
                    errors.join("; ")
                ));
            }
        }
    }

    // --- Peers tab ---

    pub fn selected_peer(&self) -> Option<&PeerConfig> {
        self.config.peers.get(self.peers_selected)
    }

    pub fn move_peer_selection(&mut self, delta: isize) {
        if self.config.peers.is_empty() {
            return;
        }
        let len = self.config.peers.len() as isize;
        let new = (self.peers_selected as isize + delta).rem_euclid(len);
        self.peers_selected = new as usize;
    }

    /// 'a' on the Peers tab: peers only exist for a server-role config
    /// (the client side pins exactly one server via `peer_public_key`,
    /// nothing to manage here) — checked here too, not just left to the
    /// UI layer to avoid offering the key in the first place.
    pub fn begin_add_peer(&mut self) {
        if self.config.role != Role::Server {
            self.message =
                Some("peers are a server-role feature — this config's role is client".to_string());
            return;
        }
        self.editing_original_peer_name = None;
        self.pending_peer_name = None;
        self.pending_peer_public_key = None;
        self.pending_default_peer_public_key = None;
        self.pending_peer_links = Vec::new();
        self.peer_links_cursor = 0;
        self.input_buffer.clear();
        self.mode = Mode::AddPeerName;
    }

    /// 'e': edit the selected peer — same wizard as adding, pre-filled
    /// with its current name/key/links, replacing (or renaming) the
    /// original entry rather than creating a duplicate.
    pub fn begin_edit_peer(&mut self) {
        if self.config.role != Role::Server {
            return;
        }
        let Some(peer) = self.selected_peer().cloned() else {
            return;
        };
        self.editing_original_peer_name = Some(peer.name.clone());
        self.pending_peer_name = None;
        self.pending_peer_public_key = None;
        self.pending_default_peer_public_key = Some(peer.public_key);
        self.pending_peer_links = peer.links;
        self.peer_links_cursor = 0;
        self.input_buffer = peer.name;
        self.mode = Mode::AddPeerName;
    }

    pub fn is_editing_peer(&self) -> bool {
        self.editing_original_peer_name.is_some()
    }

    pub fn confirm_peer_name(&mut self) {
        let name = self.input_buffer.trim().to_string();
        if name.is_empty() {
            self.cancel_peer_wizard();
            return;
        }
        self.pending_peer_name = Some(name);
        self.input_buffer = self
            .pending_default_peer_public_key
            .clone()
            .unwrap_or_default();
        self.mode = Mode::AddPeerPublicKey;
    }

    /// Live feedback while typing a public key, same idea as
    /// `link_address_input_status` — `None` while empty, `Some`
    /// afterward, using the exact validation `config.rs::validate_peers`
    /// (and the daemon) actually uses, so the wizard can't approve
    /// something the daemon would later refuse.
    pub fn peer_public_key_input_status(&self) -> Option<bool> {
        let trimmed = self.input_buffer.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(keys::decode_public_key(trimmed).is_ok())
        }
    }

    pub fn confirm_peer_public_key(&mut self) {
        if self.pending_peer_name.is_none() {
            self.mode = Mode::Normal;
            return;
        }
        let key = self.input_buffer.trim().to_string();
        if key.is_empty() {
            self.input_buffer.clear();
            self.mode = Mode::Normal;
            self.editing_original_peer_name = None;
            self.pending_peer_name = None;
            self.pending_default_peer_public_key = None;
            self.message = Some("cancelled: public key can't be empty".to_string());
            return;
        }
        if keys::decode_public_key(&key).is_err() {
            // Stays on this step, same "fix the typo and press enter
            // again" UX as an invalid link address — doesn't discard
            // the name already entered.
            self.message =
                Some("not a valid base64-encoded 32-byte key — fix it and press enter".to_string());
            return;
        }
        self.pending_peer_public_key = Some(key);
        self.peer_links_cursor = 0;
        self.mode = Mode::AddPeerLinks;
    }

    pub fn move_peer_links_cursor(&mut self, delta: isize) {
        if self.config.links.is_empty() {
            return;
        }
        let len = self.config.links.len() as isize;
        let new = (self.peer_links_cursor as isize + delta).rem_euclid(len);
        self.peer_links_cursor = new as usize;
    }

    /// Space on the checklist step: toggles the link currently under
    /// the cursor in/out of the in-progress peer's selected set.
    pub fn toggle_peer_link(&mut self) {
        let Some(link) = self.config.links.get(self.peer_links_cursor) else {
            return;
        };
        let id = link.id.clone();
        if let Some(pos) = self.pending_peer_links.iter().position(|l| *l == id) {
            self.pending_peer_links.remove(pos);
        } else {
            self.pending_peer_links.push(id);
        }
    }

    pub fn peer_link_is_checked(&self, link_id: &str) -> bool {
        self.pending_peer_links.iter().any(|l| l == link_id)
    }

    /// Enter on the checklist step: an empty selection is a legitimate,
    /// valid outcome (a peer provisioned but not yet granted access to
    /// anything) — `config.rs::validate_peers` doesn't require a peer to
    /// have any links, so this doesn't either.
    pub fn confirm_peer_links(&mut self) {
        let (Some(name), Some(public_key)) = (
            self.pending_peer_name.take(),
            self.pending_peer_public_key.take(),
        ) else {
            self.mode = Mode::Normal;
            return;
        };
        let links = std::mem::take(&mut self.pending_peer_links);
        self.pending_default_peer_public_key = None;
        self.input_buffer.clear();
        self.mode = Mode::Normal;

        let peer = PeerConfig {
            name: name.clone(),
            public_key,
            links,
        };

        let was_editing = self.editing_original_peer_name.is_some();
        if let Some(old_name) = self.editing_original_peer_name.take() {
            if old_name != name {
                self.config.peers.retain(|p| p.name != old_name);
            }
        }
        self.config.peers.retain(|p| p.name != name); // replace if this name already existed
        self.config.peers.push(peer);
        self.dirty = true;
        self.peers_selected = self
            .config
            .peers
            .iter()
            .position(|p| p.name == name)
            .unwrap_or(0);
        let verb = if was_editing { "updated" } else { "added" };
        self.message = Some(format!(
            "{verb} peer \"{name}\" (unsaved — press s to write, or the daemon won't see it until restart)"
        ));
    }

    pub fn cancel_peer_wizard(&mut self) {
        self.pending_peer_name = None;
        self.pending_peer_public_key = None;
        self.pending_default_peer_public_key = None;
        self.pending_peer_links = Vec::new();
        self.editing_original_peer_name = None;
        self.input_buffer.clear();
        self.mode = Mode::Normal;
    }

    pub fn remove_selected_peer(&mut self) {
        if self.peers_selected < self.config.peers.len() {
            let removed = self.config.peers.remove(self.peers_selected);
            self.peers_selected = self.peers_selected.saturating_sub(1);
            self.dirty = true;
            self.message = Some(format!(
                "removed peer \"{}\" (unsaved — press s to write)",
                removed.name
            ));
        }
        self.mode = Mode::Normal;
    }

    // --- Service tab ---

    pub fn move_service_selection(&mut self, delta: isize) {
        let len = SERVICE_MENU.len() as isize;
        self.service_menu_selected =
            (self.service_menu_selected as isize + delta).rem_euclid(len) as usize;
    }

    pub fn selected_service_action(&self) -> ServiceAction {
        SERVICE_MENU[self.service_menu_selected]
    }

    /// Enter on the service menu: harmless read-only actions (just
    /// viewing logs) run immediately, everything else — which changes
    /// system state — asks for confirmation first.
    pub fn activate_selected_service_action(&mut self) {
        let action = self.selected_service_action();
        if action.needs_confirm() {
            self.pending_service_action = Some(action);
            self.mode = Mode::ConfirmServiceAction;
        } else {
            self.pending_service_action = Some(action);
        }
    }

    pub fn cancel_service_action(&mut self) {
        self.pending_service_action = None;
        self.mode = Mode::Normal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostport_core::config::Role;

    fn scratch_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghostport-tui-app-test-{name}-{}.toml",
            std::process::id()
        ))
    }

    fn write_sample_config(path: &PathBuf) {
        let cfg = Config {
            role: Role::Client,
            private_key_path: PathBuf::from("/tmp/identity.key"),
            peer_public_key: Some(ghostport_core::keys::encode_public_key(
                &ghostport_core::keys::generate().public,
            )),
            peers: vec![],
            listen_control: None,
            listen_data: None,
            server_control_addr: Some("example.com:9000".to_string()),
            server_data_addr: Some("example.com:9001".to_string()),
            links: vec![],
        };
        std::fs::write(path, toml::to_string(&cfg).unwrap()).unwrap();
    }

    /// Server-role fixture, needed for peer tests — `write_sample_config`
    /// above is client-role only. Comes with two pre-defined links for
    /// the checklist tests to toggle against.
    fn write_sample_server_config(path: &PathBuf) {
        let cfg = Config {
            role: Role::Server,
            private_key_path: PathBuf::from("/tmp/identity.key"),
            peer_public_key: None,
            peers: vec![],
            listen_control: Some("0.0.0.0:9000".to_string()),
            listen_data: Some("0.0.0.0:9001".to_string()),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![
                LinkConfig {
                    id: "db".to_string(),
                    mode: LinkMode::Forward,
                    listen: None,
                    target: Some("127.0.0.1:5432".to_string()),
                },
                LinkConfig {
                    id: "dev".to_string(),
                    mode: LinkMode::Reverse,
                    listen: Some("0.0.0.0:8080".to_string()),
                    target: None,
                },
            ],
        };
        std::fs::write(path, toml::to_string(&cfg).unwrap()).unwrap();
    }

    #[test]
    fn add_link_wizard_produces_a_correctly_shaped_forward_link() {
        let path = scratch_config_path("add-forward");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        assert_eq!(app.mode, Mode::ChooseTemplate);
        app.template_selected = templates::custom_index(); // "Custom"
        app.confirm_template_choice();
        assert_eq!(app.mode, Mode::AddLinkId);

        app.input_buffer = "db".to_string();
        app.confirm_link_id();
        assert_eq!(app.mode, Mode::AddLinkDirection);

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
    fn template_choice_prefills_id_and_skips_the_mode_step() {
        let path = scratch_config_path("template");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.template_selected = 0; // SSH: forward, port 22
        app.confirm_template_choice();

        assert_eq!(app.mode, Mode::AddLinkId);
        assert_eq!(app.input_buffer, "ssh");

        app.confirm_link_id(); // mode already fixed by the template -> jumps straight to address
        assert_eq!(app.mode, Mode::AddLinkAddress);
        assert_eq!(app.input_buffer, "127.0.0.1:22");
        assert_eq!(app.pending_link_needs_listen(), Some(true)); // client + forward

        app.confirm_link_address(); // accept the default as-is
        let link = app.config.links.iter().find(|l| l.id == "ssh").unwrap();
        assert_eq!(link.mode, LinkMode::Forward);
        assert_eq!(link.listen.as_deref(), Some("127.0.0.1:22"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn adding_a_link_with_an_existing_id_replaces_it() {
        let path = scratch_config_path("replace");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.config.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Reverse,
            listen: None,
            target: Some("old".to_string()),
        });

        app.begin_add_link();
        app.template_selected = templates::custom_index();
        app.confirm_template_choice();
        app.input_buffer = "db".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Forward);
        app.input_buffer = "127.0.0.1:5432".to_string();
        app.confirm_link_address();

        assert_eq!(app.config.links.iter().filter(|l| l.id == "db").count(), 1);
        assert_eq!(
            app.config.links.iter().find(|l| l.id == "db").unwrap().mode,
            LinkMode::Forward
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn edit_prefills_current_values_and_updates_in_place() {
        let path = scratch_config_path("edit");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        app.config.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: Some("127.0.0.1:5432".to_string()),
            target: None,
        });
        app.links_selected = 0;

        app.begin_edit_link();
        assert_eq!(app.mode, Mode::AddLinkId);
        assert_eq!(app.input_buffer, "db"); // prefilled with current id
        assert!(app.is_editing());

        app.confirm_link_id(); // id unchanged, mode not yet re-chosen -> normal mode step
        assert_eq!(app.mode, Mode::AddLinkDirection);

        app.choose_link_mode(LinkMode::Forward);
        assert_eq!(app.input_buffer, "127.0.0.1:5432"); // prefilled with the CURRENT address

        app.input_buffer = "127.0.0.1:2222".to_string(); // actually change it
        app.confirm_link_address();

        assert_eq!(
            app.config.links.len(),
            1,
            "must update in place, not create a second entry"
        );
        assert_eq!(
            app.config.links[0].listen.as_deref(),
            Some("127.0.0.1:2222")
        );
        assert!(app
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("updated"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn editing_and_changing_the_id_removes_the_old_entry() {
        let path = scratch_config_path("edit-rename");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        app.config.links.push(LinkConfig {
            id: "old-name".to_string(),
            mode: LinkMode::Forward,
            listen: Some("127.0.0.1:1".to_string()),
            target: None,
        });
        app.links_selected = 0;

        app.begin_edit_link();
        app.input_buffer = "new-name".to_string(); // rename it
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Forward);
        app.input_buffer = "127.0.0.1:1".to_string();
        app.confirm_link_address();

        assert_eq!(app.config.links.len(), 1);
        assert_eq!(app.config.links[0].id, "new-name");
        assert!(!app.config.links.iter().any(|l| l.id == "old-name"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_writes_a_valid_config_and_clears_dirty() {
        let path = scratch_config_path("save");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_link();
        app.template_selected = templates::custom_index();
        app.confirm_template_choice();
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
        app.config.links.push(LinkConfig {
            id: "a".to_string(),
            mode: LinkMode::Forward,
            listen: Some("x".to_string()),
            target: None,
        });
        app.config.links.push(LinkConfig {
            id: "b".to_string(),
            mode: LinkMode::Forward,
            listen: Some("y".to_string()),
            target: None,
        });
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
        app.template_selected = templates::custom_index();
        app.confirm_template_choice();
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
        app.template_selected = templates::custom_index();
        app.confirm_template_choice();
        app.input_buffer = "dev".to_string();
        app.confirm_link_id();
        app.choose_link_mode(LinkMode::Reverse);

        app.input_buffer = "not-a-real-address".to_string();
        app.confirm_link_address();

        // Stays in AddLinkAddress (not bounced back to Normal) so the
        // user can just fix the typo and press enter again.
        assert_eq!(app.mode, Mode::AddLinkAddress);
        assert!(app
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("isn't a valid host:port"));
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
        app.template_selected = templates::custom_index();
        app.confirm_template_choice();
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

    #[test]
    fn service_menu_navigation_wraps_around() {
        let path = scratch_config_path("service-nav");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        assert_eq!(app.service_menu_selected, 0);
        app.move_service_selection(-1); // wrap to the last item
        assert_eq!(app.service_menu_selected, SERVICE_MENU.len() - 1);
        app.move_service_selection(1);
        assert_eq!(app.service_menu_selected, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn view_logs_activates_without_a_confirm_prompt() {
        let path = scratch_config_path("view-logs");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        let logs_index = SERVICE_MENU
            .iter()
            .position(|a| *a == ServiceAction::ViewLogs)
            .unwrap();
        app.service_menu_selected = logs_index;
        app.activate_selected_service_action();

        assert_eq!(
            app.mode,
            Mode::Normal,
            "view-logs shouldn't need a y/n confirm"
        );
        assert_eq!(app.pending_service_action, Some(ServiceAction::ViewLogs));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn start_action_requires_confirmation() {
        let path = scratch_config_path("start-confirm");
        write_sample_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.service_menu_selected = SERVICE_MENU
            .iter()
            .position(|a| *a == ServiceAction::Start)
            .unwrap();
        app.activate_selected_service_action();

        assert_eq!(app.mode, Mode::ConfirmServiceAction);
        assert_eq!(app.pending_service_action, Some(ServiceAction::Start));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn link_rate_is_none_until_two_samples_exist() {
        let path = scratch_config_path("rate-none");
        write_sample_config(&path);
        let app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        assert_eq!(app.link_rate("anything"), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn add_peer_wizard_produces_a_correctly_shaped_peer() {
        let path = scratch_config_path("add-peer");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        let peer_key_b64 =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);

        app.begin_add_peer();
        assert_eq!(app.mode, Mode::AddPeerName);

        app.input_buffer = "alice".to_string();
        app.confirm_peer_name();
        assert_eq!(app.mode, Mode::AddPeerPublicKey);

        app.input_buffer = peer_key_b64.clone();
        app.confirm_peer_public_key();
        assert_eq!(app.mode, Mode::AddPeerLinks);

        app.toggle_peer_link(); // cursor starts at 0 -> "db"
        app.confirm_peer_links();

        assert!(app.dirty);
        let peer = app.config.peers.iter().find(|p| p.name == "alice").unwrap();
        assert_eq!(peer.public_key, peer_key_b64);
        assert_eq!(peer.links, vec!["db".to_string()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn peer_links_checklist_toggles_selection() {
        let path = scratch_config_path("peer-toggle");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        let peer_key_b64 =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);

        app.begin_add_peer();
        app.input_buffer = "bob".to_string();
        app.confirm_peer_name();
        app.input_buffer = peer_key_b64;
        app.confirm_peer_public_key();

        assert!(!app.peer_link_is_checked("db"));
        app.toggle_peer_link(); // cursor 0 -> "db"
        assert!(app.peer_link_is_checked("db"));
        app.toggle_peer_link(); // toggled back off
        assert!(!app.peer_link_is_checked("db"));

        app.move_peer_links_cursor(1); // cursor -> "dev"
        app.toggle_peer_link();
        assert!(app.peer_link_is_checked("dev"));
        assert!(!app.peer_link_is_checked("db"));

        app.confirm_peer_links();
        let peer = app.config.peers.iter().find(|p| p.name == "bob").unwrap();
        assert_eq!(peer.links, vec!["dev".to_string()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn adding_a_peer_with_an_existing_name_replaces_it() {
        let path = scratch_config_path("peer-replace");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        let old_key =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.config.peers.push(PeerConfig {
            name: "alice".to_string(),
            public_key: old_key,
            links: vec![],
        });

        let new_key =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.begin_add_peer();
        app.input_buffer = "alice".to_string();
        app.confirm_peer_name();
        app.input_buffer = new_key.clone();
        app.confirm_peer_public_key();
        app.toggle_peer_link();
        app.confirm_peer_links();

        assert_eq!(
            app.config
                .peers
                .iter()
                .filter(|p| p.name == "alice")
                .count(),
            1
        );
        assert_eq!(
            app.config
                .peers
                .iter()
                .find(|p| p.name == "alice")
                .unwrap()
                .public_key,
            new_key
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn edit_peer_prefills_current_values_and_updates_in_place() {
        let path = scratch_config_path("peer-edit");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        let key = ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.config.peers.push(PeerConfig {
            name: "alice".to_string(),
            public_key: key.clone(),
            links: vec!["db".to_string()],
        });
        app.peers_selected = 0;

        app.begin_edit_peer();
        assert_eq!(app.mode, Mode::AddPeerName);
        assert_eq!(app.input_buffer, "alice"); // prefilled with current name
        assert!(app.is_editing_peer());

        app.confirm_peer_name(); // name unchanged
        assert_eq!(app.mode, Mode::AddPeerPublicKey);
        assert_eq!(app.input_buffer, key); // prefilled with the CURRENT key

        app.confirm_peer_public_key(); // accept the prefilled key as-is
        assert_eq!(app.mode, Mode::AddPeerLinks);
        assert!(app.peer_link_is_checked("db")); // prefilled with current links

        app.toggle_peer_link(); // cursor 0 -> "db", turn it off
        app.move_peer_links_cursor(1); // -> "dev"
        app.toggle_peer_link(); // turn "dev" on
        app.confirm_peer_links();

        assert_eq!(
            app.config.peers.len(),
            1,
            "must update in place, not create a second entry"
        );
        assert_eq!(app.config.peers[0].links, vec!["dev".to_string()]);
        assert!(app
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("updated"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn editing_and_renaming_a_peer_removes_the_old_entry() {
        let path = scratch_config_path("peer-rename");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        let key = ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.config.peers.push(PeerConfig {
            name: "old-name".to_string(),
            public_key: key,
            links: vec![],
        });
        app.peers_selected = 0;

        app.begin_edit_peer();
        app.input_buffer = "new-name".to_string(); // rename it
        app.confirm_peer_name();
        app.confirm_peer_public_key(); // key prefilled, accept as-is
        app.confirm_peer_links(); // links prefilled empty, accept

        assert_eq!(app.config.peers.len(), 1);
        assert_eq!(app.config.peers[0].name, "new-name");
        assert!(!app.config.peers.iter().any(|p| p.name == "old-name"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn invalid_peer_public_key_is_rejected_without_losing_wizard_progress() {
        let path = scratch_config_path("peer-invalid-key");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_peer();
        app.input_buffer = "alice".to_string();
        app.confirm_peer_name();

        app.input_buffer = "not-a-real-key".to_string();
        app.confirm_peer_public_key();

        // Stays in AddPeerPublicKey (not bounced back to Normal) so the
        // user can just fix it and press enter again.
        assert_eq!(app.mode, Mode::AddPeerPublicKey);
        assert!(app
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("not a valid"));
        assert!(app.config.peers.is_empty());

        let real_key =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.input_buffer = real_key.clone();
        app.confirm_peer_public_key();
        assert_eq!(app.mode, Mode::AddPeerLinks);
        app.confirm_peer_links();
        assert_eq!(app.config.peers.len(), 1);
        assert_eq!(app.config.peers[0].public_key, real_key);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_selected_peer_marks_dirty_and_removes_it() {
        let path = scratch_config_path("peer-remove");
        write_sample_server_config(&path);
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();
        app.config.peers.push(PeerConfig {
            name: "a".to_string(),
            public_key: ghostport_core::keys::encode_public_key(
                &ghostport_core::keys::generate().public,
            ),
            links: vec![],
        });
        app.config.peers.push(PeerConfig {
            name: "b".to_string(),
            public_key: ghostport_core::keys::encode_public_key(
                &ghostport_core::keys::generate().public,
            ),
            links: vec![],
        });
        app.peers_selected = 0;

        app.remove_selected_peer();

        assert!(app.dirty);
        assert_eq!(app.config.peers.len(), 1);
        assert_eq!(app.config.peers[0].name, "b");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn begin_add_peer_is_a_noop_for_client_role_config() {
        let path = scratch_config_path("peer-client-role");
        write_sample_config(&path); // client role
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_peer();

        assert_eq!(
            app.mode,
            Mode::Normal,
            "must not enter the peer wizard for a client-role config"
        );
        assert!(app
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("server-role"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn peer_checklist_confirms_with_zero_links_when_none_are_configured() {
        let path = scratch_config_path("peer-no-links");
        let cfg = Config {
            role: Role::Server,
            private_key_path: PathBuf::from("/tmp/identity.key"),
            peer_public_key: None,
            peers: vec![],
            listen_control: Some("0.0.0.0:9000".to_string()),
            listen_data: Some("0.0.0.0:9001".to_string()),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![], // no links defined at all
        };
        std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
        let mut app = App::new(path.clone(), PathBuf::from("/tmp/nonexistent.sock")).unwrap();

        app.begin_add_peer();
        app.input_buffer = "alice".to_string();
        app.confirm_peer_name();
        app.input_buffer =
            ghostport_core::keys::encode_public_key(&ghostport_core::keys::generate().public);
        app.confirm_peer_public_key();
        assert_eq!(app.mode, Mode::AddPeerLinks);

        // No links to toggle -- confirming directly should still
        // succeed with an empty set, not get stuck.
        app.confirm_peer_links();
        assert_eq!(app.mode, Mode::Normal);
        let peer = app.config.peers.iter().find(|p| p.name == "alice").unwrap();
        assert!(peer.links.is_empty());
        std::fs::remove_file(&path).ok();
    }
}
