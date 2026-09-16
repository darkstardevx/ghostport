//! Live runtime state, shared across every task in the daemon via
//! `Arc`. Counters are individual atomics rather than one big
//! `Mutex<Struct>` deliberately — `relay::relay` updates these on the
//! hot path (every proxied connection), and a lock there would mean
//! every stream contends with the IPC status query. The per-link map
//! itself (`SharedState::links`) is built once at startup from the
//! config and never mutated afterward, only the atomics inside each
//! `LinkStats` are — so reading it needs no lock either.

use crate::config::{Config, Role};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Live per-link counters, updated on the hot path by [`crate::relay::relay`].
#[derive(Default)]
pub struct LinkStats {
    /// Streams currently being relayed on this link.
    pub active_streams: AtomicU64,
    /// Total streams ever opened on this link since the daemon started.
    pub total_streams: AtomicU64,
    /// Bytes relayed client-to-target (or, for a reverse link,
    /// initiator-to-target) since the daemon started.
    pub bytes_forward: AtomicU64,
    /// Bytes relayed in the opposite direction of [`Self::bytes_forward`].
    pub bytes_back: AtomicU64,
}

impl LinkStats {
    fn snapshot(&self, id: &str, mode: &str) -> LinkSnapshot {
        LinkSnapshot {
            id: id.to_string(),
            mode: mode.to_string(),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            total_streams: self.total_streams.load(Ordering::Relaxed),
            bytes_forward: self.bytes_forward.load(Ordering::Relaxed),
            bytes_back: self.bytes_back.load(Ordering::Relaxed),
        }
    }
}

/// Live status of the single control connection (connected/not, since
/// when, and which peer).
#[derive(Default)]
pub struct ControlStatus {
    connected: AtomicBool,
    /// Unix timestamp (seconds) of the current/most recent connect —
    /// plain `Mutex` is fine here, this changes on the order of
    /// "occasionally", not per-stream.
    connected_since: Mutex<Option<u64>>,
    peer_addr: Mutex<Option<String>>,
    /// Which configured peer this connection matched, server-role only
    /// (`None` on the client side — a client only ever has one server
    /// to name, so there's nothing to disambiguate). Meaningful now
    /// that a server can have more than one allowed peer.
    peer_name: Mutex<Option<String>>,
}

impl ControlStatus {
    /// Records a fresh control connection: marks connected, timestamps
    /// it, and remembers the peer's address and (server-role only)
    /// matched name.
    pub fn set_connected(&self, peer_addr: String, peer_name: Option<String>) {
        self.connected.store(true, Ordering::Relaxed);
        *self.connected_since.lock().expect("not poisoned") = Some(now_unix());
        *self.peer_addr.lock().expect("not poisoned") = Some(peer_addr);
        *self.peer_name.lock().expect("not poisoned") = peer_name;
    }

    /// Marks the control connection as no longer connected. Leaves the
    /// last-known peer address/name in place (only `connected` and
    /// `connected_since`-reporting change) so status output can still
    /// say who it was.
    pub fn set_disconnected(&self) {
        self.connected.store(false, Ordering::Relaxed);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// All live runtime state for one daemon instance, shared via `Arc`
/// across every task and queried by the status IPC socket.
pub struct SharedState {
    /// Which role this instance is running as.
    pub role: Role,
    started_at: u64,
    /// Live control-connection status.
    pub control: ControlStatus,
    /// Per-link counters, keyed by link ID. Built once at startup from
    /// config and never mutated afterward — only the atomics inside
    /// each [`LinkStats`] change, so reading this map needs no lock.
    pub links: HashMap<String, LinkStats>,
}

impl SharedState {
    /// Builds fresh, zeroed state for every link in `config`.
    pub fn new(config: &Config) -> Self {
        let links = config
            .links
            .iter()
            .map(|l| (l.id.clone(), LinkStats::default()))
            .collect();
        Self {
            role: config.role,
            started_at: now_unix(),
            control: ControlStatus::default(),
            links,
        }
    }

    /// Takes a point-in-time, JSON-serializable snapshot of this state
    /// for the status IPC socket / TUI to consume. `config` supplies
    /// each link's mode (not stored in `LinkStats` itself) and the
    /// authoritative link ordering.
    pub fn snapshot(&self, config: &Config) -> StatusSnapshot {
        let control_connected = self.control.connected.load(Ordering::Relaxed);
        StatusSnapshot {
            role: format!("{:?}", self.role).to_lowercase(),
            uptime_secs: now_unix().saturating_sub(self.started_at),
            control_connected,
            control_connected_since_secs_ago: self
                .control
                .connected_since
                .lock()
                .expect("not poisoned")
                .filter(|_| control_connected)
                .map(|t| now_unix().saturating_sub(t)),
            control_peer_addr: self.control.peer_addr.lock().expect("not poisoned").clone(),
            control_peer_name: self.control.peer_name.lock().expect("not poisoned").clone(),
            links: config
                .links
                .iter()
                .filter_map(|l| {
                    self.links
                        .get(&l.id)
                        .map(|stats| stats.snapshot(&l.id, &format!("{:?}", l.mode).to_lowercase()))
                })
                .collect(),
        }
    }
}

/// One link's counters at snapshot time — the JSON-serializable form
/// of [`LinkStats`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkSnapshot {
    /// The link's configured ID.
    pub id: String,
    /// `"forward"` or `"reverse"`, lowercased from [`crate::config::LinkMode`].
    pub mode: String,
    /// Streams currently being relayed.
    pub active_streams: u64,
    /// Total streams ever opened on this link.
    pub total_streams: u64,
    /// Bytes relayed in the forward direction — see [`LinkStats::bytes_forward`].
    pub bytes_forward: u64,
    /// Bytes relayed in the opposite direction.
    pub bytes_back: u64,
}

/// The full point-in-time daemon status, as served over the status IPC
/// socket and consumed by `ghostport status`/the TUI.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatusSnapshot {
    /// `"server"` or `"client"`, lowercased from [`Role`].
    pub role: String,
    /// Seconds since this daemon instance started.
    pub uptime_secs: u64,
    /// Whether the control connection is currently up.
    pub control_connected: bool,
    /// Seconds since the current control connection was established;
    /// `None` when not connected.
    pub control_connected_since_secs_ago: Option<u64>,
    /// The control peer's socket address, if ever connected.
    pub control_peer_addr: Option<String>,
    /// The control peer's matched config name (server role only).
    pub control_peer_name: Option<String>,
    /// Per-link snapshots, in config order.
    pub links: Vec<LinkSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LinkConfig, LinkMode};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering::Relaxed;

    fn sample_config() -> Config {
        Config {
            role: Role::Server,
            private_key_path: PathBuf::new(),
            peer_public_key: None,
            peers: vec![],
            listen_control: Some("0.0.0.0:9000".to_string()),
            listen_data: Some("0.0.0.0:9001".to_string()),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![LinkConfig {
                id: "fwd".to_string(),
                mode: LinkMode::Forward,
                listen: None,
                target: Some("127.0.0.1:1".to_string()),
            }],
        }
    }

    #[test]
    fn snapshot_reflects_zeroed_counters_at_start() {
        let cfg = sample_config();
        let state = SharedState::new(&cfg);
        let snap = state.snapshot(&cfg);

        assert_eq!(snap.role, "server");
        assert!(!snap.control_connected);
        assert_eq!(snap.links.len(), 1);
        assert_eq!(snap.links[0].id, "fwd");
        assert_eq!(snap.links[0].active_streams, 0);
        assert_eq!(snap.links[0].bytes_forward, 0);
    }

    #[test]
    fn snapshot_reflects_updated_counters() {
        let cfg = sample_config();
        let state = SharedState::new(&cfg);
        let stats = state.links.get("fwd").unwrap();
        stats.active_streams.fetch_add(1, Relaxed);
        stats.total_streams.fetch_add(3, Relaxed);
        stats.bytes_forward.fetch_add(1024, Relaxed);

        let snap = state.snapshot(&cfg);
        assert_eq!(snap.links[0].active_streams, 1);
        assert_eq!(snap.links[0].total_streams, 3);
        assert_eq!(snap.links[0].bytes_forward, 1024);
    }

    #[test]
    fn control_connect_disconnect_reflected_in_snapshot() {
        let cfg = sample_config();
        let state = SharedState::new(&cfg);

        state
            .control
            .set_connected("1.2.3.4:5678".to_string(), Some("alice".to_string()));
        let snap = state.snapshot(&cfg);
        assert!(snap.control_connected);
        assert_eq!(snap.control_peer_addr.as_deref(), Some("1.2.3.4:5678"));
        assert_eq!(snap.control_peer_name.as_deref(), Some("alice"));
        assert!(snap.control_connected_since_secs_ago.is_some());

        state.control.set_disconnected();
        let snap = state.snapshot(&cfg);
        assert!(!snap.control_connected);
        // "since" is only meaningful while connected; not reported once
        // disconnected rather than showing a stale timestamp.
        assert!(snap.control_connected_since_secs_ago.is_none());
    }

    #[test]
    fn unknown_link_ids_in_config_are_skipped_gracefully() {
        // Defensive: if config and state's link map ever disagree (shouldn't
        // happen in practice since both are built from the same config),
        // snapshot must not panic.
        let mut cfg = sample_config();
        cfg.links.push(LinkConfig {
            id: "not-in-state".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:2".to_string()),
        });
        let state = SharedState::new(&sample_config()); // state built from the config WITHOUT the extra link
        let snap = state.snapshot(&cfg);
        assert_eq!(snap.links.len(), 1);
    }
}
