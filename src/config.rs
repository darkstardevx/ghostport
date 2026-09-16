//! TOML config schema + validation. Validation runs both at `run` time
//! (refuse to start on a broken config) and via the standalone `check`
//! subcommand (catch mistakes before ever starting the daemon) — same
//! "validate before it can cause a runtime failure" principle as
//! CyberVault's TUI pre-save checks, just at the CLI layer here since
//! there's no TUI for this tool yet.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    /// A service near the server is exposed on a port the client listens
    /// on locally — like `ssh -L`.
    Forward,
    /// A service near the client is exposed on a port the server listens
    /// on — like `ssh -R`. Needs the control channel's signaling, since
    /// the client is the side that can't accept unsolicited connections
    /// (it's the one assumed to be behind NAT/unpredictable networks).
    Reverse,
}

/// A single allowed client identity, server-role only. Multiple peers
/// can be pinned at once; each is independently restricted to its own
/// subset of `links` rather than trusted for everything the server
/// defines.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: String,
    pub links: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LinkConfig {
    pub id: String,
    pub mode: LinkMode,
    /// Present on whichever side accepts the "real" connections for this
    /// link (local apps for `forward`, external clients for `reverse`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Present on whichever side dials the real destination for this
    /// link once a stream arrives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub role: Role,
    pub private_key_path: PathBuf,

    // Client-role field: the one server this client trusts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_public_key: Option<String>,

    // Server-role fields.
    /// Every client identity this server accepts, each independently
    /// restricted to its own `links`. Noise_KK requires the responder
    /// to already have the correct remote static key loaded before a
    /// handshake message can even be processed — with more than one
    /// allowed peer, the server tries each one's key against the
    /// incoming handshake in turn (see `peermatch.rs`) rather than
    /// switching to a pattern that learns the identity mid-handshake,
    /// preserving KK's "an unrecognized key simply can't complete the
    /// handshake" guarantee for the whole allowed set, not just one key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_data: Option<String>,

    // Client-role fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_control_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_data_addr: Option<String>,

    #[serde(default)]
    pub links: Vec<LinkConfig>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }

    /// Used by the TUI's link editor: writes only if this config passes
    /// `validate()` first — never save something the daemon would refuse
    /// to start with. Returns the validation errors instead of writing
    /// when invalid, same "full list, not just the first" shape as
    /// `validate()` itself.
    pub fn save(&self, path: &std::path::Path) -> Result<(), Vec<String>> {
        let errors = self.validate();
        if !errors.is_empty() {
            return Err(errors);
        }
        let text = toml::to_string_pretty(self).map_err(|e| vec![e.to_string()])?;
        std::fs::write(path, text)
            .map_err(|e| vec![format!("failed to write {}: {e}", path.display())])
    }

    /// Whether a link of `mode` needs `listen` (vs `target`) on *this*
    /// side, given `self.role` — the same rule `validate_link` enforces,
    /// exposed for the TUI's link editor to know which field to prompt
    /// for and how to label it.
    pub fn link_needs_listen(&self, mode: LinkMode) -> bool {
        matches!(
            (self.role, mode),
            (Role::Client, LinkMode::Forward) | (Role::Server, LinkMode::Reverse)
        )
    }

    /// All problems found, not just the first — a config editor (or a
    /// human squinting at error output) wants the full list in one pass,
    /// not a fix-one-rerun-find-the-next loop.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        match self.role {
            Role::Server => {
                require_present(
                    &mut errors,
                    "listen_control",
                    &self.listen_control,
                    "role = \"server\"",
                );
                require_present(
                    &mut errors,
                    "listen_data",
                    &self.listen_data,
                    "role = \"server\"",
                );
                require_absent(
                    &mut errors,
                    "server_control_addr",
                    &self.server_control_addr,
                    "role = \"server\"",
                );
                require_absent(
                    &mut errors,
                    "server_data_addr",
                    &self.server_data_addr,
                    "role = \"server\"",
                );
                if self.peer_public_key.is_some() {
                    errors.push("`peer_public_key` must not be set when role = \"server\" (use `peers` instead)".to_string());
                }
                if self.peers.is_empty() {
                    errors.push(
                        "`peers` must have at least one entry when role = \"server\"".to_string(),
                    );
                }
                self.validate_peers(&mut errors);
            }
            Role::Client => {
                require_present(
                    &mut errors,
                    "server_control_addr",
                    &self.server_control_addr,
                    "role = \"client\"",
                );
                require_present(
                    &mut errors,
                    "server_data_addr",
                    &self.server_data_addr,
                    "role = \"client\"",
                );
                require_absent(
                    &mut errors,
                    "listen_control",
                    &self.listen_control,
                    "role = \"client\"",
                );
                require_absent(
                    &mut errors,
                    "listen_data",
                    &self.listen_data,
                    "role = \"client\"",
                );
                match &self.peer_public_key {
                    None => errors
                        .push("`peer_public_key` is required when role = \"client\"".to_string()),
                    Some(key) => {
                        if keys_module_decode(key).is_err() {
                            errors.push(
                                "peer_public_key is not a valid base64-encoded 32-byte key"
                                    .to_string(),
                            );
                        }
                    }
                }
                if !self.peers.is_empty() {
                    errors.push("`peers` must not be set when role = \"client\" (use `peer_public_key` instead)".to_string());
                }
            }
        }

        let mut seen_ids = std::collections::HashSet::new();
        for link in &self.links {
            if !seen_ids.insert(link.id.clone()) {
                errors.push(format!("link \"{}\": duplicate id", link.id));
            }
            self.validate_link(link, &mut errors);
        }

        errors
    }

    /// Each peer's own fields, plus cross-peer checks (duplicate name/
    /// key) that only make sense with the full list in view.
    fn validate_peers(&self, errors: &mut Vec<String>) {
        let mut seen_names = std::collections::HashSet::new();
        let mut seen_keys = std::collections::HashSet::new();
        let link_ids: std::collections::HashSet<&str> =
            self.links.iter().map(|l| l.id.as_str()).collect();

        for peer in &self.peers {
            if !seen_names.insert(peer.name.clone()) {
                errors.push(format!("peer \"{}\": duplicate name", peer.name));
            }
            match keys_module_decode(&peer.public_key) {
                Ok(key) => {
                    if !seen_keys.insert(key) {
                        errors.push(format!(
                            "peer \"{}\": public_key is already used by another peer",
                            peer.name
                        ));
                    }
                }
                Err(_) => errors.push(format!(
                    "peer \"{}\": public_key is not a valid base64-encoded 32-byte key",
                    peer.name
                )),
            }
            for link_id in &peer.links {
                if !link_ids.contains(link_id.as_str()) {
                    errors.push(format!("peer \"{}\": link id \"{link_id}\" is not defined in this config's `links`", peer.name));
                }
            }
        }
    }

    /// Exactly one of `listen`/`target` must be set on this side, and
    /// which one is required depends on both `role` and `mode` — see the
    /// module doc table in README for the full (role, mode) -> field
    /// matrix; this mirrors it directly.
    fn validate_link(&self, link: &LinkConfig, errors: &mut Vec<String>) {
        let needs_listen = self.link_needs_listen(link.mode);
        let (required_field, forbidden_field, required_value, forbidden_value) = if needs_listen {
            ("listen", "target", &link.listen, &link.target)
        } else {
            ("target", "listen", &link.target, &link.listen)
        };

        if required_value.is_none() {
            errors.push(format!(
                "link \"{}\": {:?} on this side ({:?}) requires `{required_field}`",
                link.id, link.mode, self.role
            ));
        }
        if forbidden_value.is_some() {
            errors.push(format!("link \"{}\": {:?} on this side ({:?}) must not set `{forbidden_field}` (that belongs on the peer's config)", link.id, link.mode, self.role));
        }
        if let Some(addr) = required_value.as_deref() {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                errors.push(format!(
                    "link \"{}\": `{required_field}` = \"{addr}\" is not a valid host:port address",
                    link.id
                ));
            }
        }
    }
}

fn require_present(errors: &mut Vec<String>, field: &str, value: &Option<String>, because: &str) {
    if value.is_none() {
        errors.push(format!("`{field}` is required when {because}"));
    }
}

fn require_absent(errors: &mut Vec<String>, field: &str, value: &Option<String>, because: &str) {
    if value.is_some() {
        errors.push(format!("`{field}` must not be set when {because}"));
    }
}

/// Thin indirection so this module doesn't need `keys` as a hard
/// dependency just for one validation check — kept trivial on purpose.
fn keys_module_decode(s: &str) -> Result<Vec<u8>, String> {
    crate::keys::decode_public_key(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_server() -> Config {
        Config {
            role: Role::Server,
            private_key_path: PathBuf::from("/tmp/server.key"),
            peer_public_key: None,
            peers: vec![PeerConfig {
                name: "client".to_string(),
                public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
                links: Vec::new(),
            }],
            listen_control: Some("0.0.0.0:9000".to_string()),
            listen_data: Some("0.0.0.0:9001".to_string()),
            server_control_addr: None,
            server_data_addr: None,
            links: Vec::new(),
        }
    }

    fn base_client() -> Config {
        Config {
            role: Role::Client,
            private_key_path: PathBuf::from("/tmp/client.key"),
            peer_public_key: Some(crate::keys::encode_public_key(
                &crate::keys::generate().public,
            )),
            peers: Vec::new(),
            listen_control: None,
            listen_data: None,
            server_control_addr: Some("example.com:9000".to_string()),
            server_data_addr: Some("example.com:9001".to_string()),
            links: Vec::new(),
        }
    }

    #[test]
    fn minimal_valid_server_and_client_configs_pass() {
        assert!(base_server().validate().is_empty());
        assert!(base_client().validate().is_empty());
    }

    #[test]
    fn server_missing_listen_fields_is_rejected() {
        let mut cfg = base_server();
        cfg.listen_data = None;
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("listen_data")),
            "{errors:?}"
        );
    }

    #[test]
    fn client_with_server_only_fields_is_rejected() {
        let mut cfg = base_client();
        cfg.listen_control = Some("0.0.0.0:9000".to_string());
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("listen_control")),
            "{errors:?}"
        );
    }

    #[test]
    fn invalid_client_peer_public_key_is_rejected() {
        let mut cfg = base_client();
        cfg.peer_public_key = Some("not-base64!!".to_string());
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("peer_public_key")),
            "{errors:?}"
        );
    }

    #[test]
    fn client_missing_peer_public_key_is_rejected() {
        let mut cfg = base_client();
        cfg.peer_public_key = None;
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("peer_public_key")),
            "{errors:?}"
        );
    }

    #[test]
    fn server_with_peer_public_key_set_is_rejected() {
        let mut cfg = base_server();
        cfg.peer_public_key = Some(crate::keys::encode_public_key(
            &crate::keys::generate().public,
        ));
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("peer_public_key") && e.contains("must not be set")),
            "{errors:?}"
        );
    }

    #[test]
    fn client_with_peers_set_is_rejected() {
        let mut cfg = base_client();
        cfg.peers = vec![PeerConfig {
            name: "x".to_string(),
            public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
            links: Vec::new(),
        }];
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("`peers`") && e.contains("must not be set")),
            "{errors:?}"
        );
    }

    #[test]
    fn server_with_no_peers_is_rejected() {
        let mut cfg = base_server();
        cfg.peers.clear();
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("`peers`") && e.contains("at least one")),
            "{errors:?}"
        );
    }

    #[test]
    fn peer_with_invalid_public_key_is_rejected() {
        let mut cfg = base_server();
        cfg.peers[0].public_key = "not-base64!!".to_string();
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("public_key")),
            "{errors:?}"
        );
    }

    #[test]
    fn peer_link_id_not_defined_in_links_is_rejected() {
        let mut cfg = base_server();
        cfg.peers[0].links.push("nonexistent".to_string());
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("nonexistent") && e.contains("is not defined")),
            "{errors:?}"
        );
    }

    #[test]
    fn peer_link_id_that_exists_is_accepted() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:5432".to_string()),
        });
        cfg.peers[0].links.push("db".to_string());
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
    }

    #[test]
    fn duplicate_peer_public_keys_are_rejected() {
        let mut cfg = base_server();
        let shared_key = cfg.peers[0].public_key.clone();
        cfg.peers.push(PeerConfig {
            name: "second".to_string(),
            public_key: shared_key,
            links: Vec::new(),
        });
        let errors = cfg.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("already used by another peer")),
            "{errors:?}"
        );
    }

    #[test]
    fn duplicate_peer_names_are_rejected() {
        let mut cfg = base_server();
        let name = cfg.peers[0].name.clone();
        cfg.peers.push(PeerConfig {
            name,
            public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
            links: Vec::new(),
        });
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("duplicate name")),
            "{errors:?}"
        );
    }

    #[test]
    fn forward_link_on_client_needs_listen_not_target() {
        let mut cfg = base_client();
        cfg.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:5432".to_string()),
        });
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("requires `listen`")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("must not set `target`")),
            "{errors:?}"
        );
    }

    #[test]
    fn forward_link_on_server_needs_target_not_listen() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: Some("0.0.0.0:5432".to_string()),
            target: None,
        });
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("requires `target`")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("must not set `listen`")),
            "{errors:?}"
        );
    }

    #[test]
    fn reverse_link_on_server_needs_listen_client_needs_target() {
        let mut server = base_server();
        server.links.push(LinkConfig {
            id: "dev".to_string(),
            mode: LinkMode::Reverse,
            listen: Some("0.0.0.0:8080".to_string()),
            target: None,
        });
        assert!(server.validate().is_empty());

        let mut client = base_client();
        client.links.push(LinkConfig {
            id: "dev".to_string(),
            mode: LinkMode::Reverse,
            listen: None,
            target: Some("127.0.0.1:3000".to_string()),
        });
        assert!(client.validate().is_empty());
    }

    #[test]
    fn correctly_configured_forward_link_passes_on_both_sides() {
        let mut server = base_server();
        server.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:5432".to_string()),
        });
        assert!(server.validate().is_empty(), "{:?}", server.validate());

        let mut client = base_client();
        client.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: Some("127.0.0.1:5432".to_string()),
            target: None,
        });
        assert!(client.validate().is_empty(), "{:?}", client.validate());
    }

    #[test]
    fn duplicate_link_ids_are_rejected() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "dup".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:1".to_string()),
        });
        cfg.links.push(LinkConfig {
            id: "dup".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:2".to_string()),
        });
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("duplicate id")),
            "{errors:?}"
        );
    }

    #[test]
    fn non_socket_addr_target_is_rejected() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "bad".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("not-an-address".to_string()),
        });
        let errors = cfg.validate();
        assert!(
            errors.iter().any(|e| e.contains("not a valid host:port")),
            "{errors:?}"
        );
    }

    #[test]
    fn round_trips_through_toml() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:5432".to_string()),
        });
        let text = toml::to_string(&cfg).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert_eq!(parsed.links[0].id, "db");
    }

    fn scratch_toml_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ghostport-config-test-{name}-{}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn save_writes_a_valid_config_and_it_reloads_identically() {
        let path = scratch_toml_path("save-valid");
        let mut cfg = base_server();
        cfg.links.push(LinkConfig {
            id: "db".to_string(),
            mode: LinkMode::Forward,
            listen: None,
            target: Some("127.0.0.1:5432".to_string()),
        });

        cfg.save(&path).unwrap();
        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.links.len(), 1);
        assert_eq!(reloaded.links[0].id, "db");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_refuses_to_write_an_invalid_config() {
        let path = scratch_toml_path("save-invalid");
        let mut cfg = base_server();
        cfg.listen_data = None; // now invalid

        let result = cfg.save(&path);
        assert!(result.is_err());
        assert!(
            !path.exists(),
            "an invalid config must never be written to disk"
        );
    }

    #[test]
    fn link_needs_listen_matches_the_role_mode_matrix() {
        let client = base_client();
        let server = base_server();
        assert!(client.link_needs_listen(LinkMode::Forward)); // client + forward -> listen
        assert!(!client.link_needs_listen(LinkMode::Reverse)); // client + reverse -> target
        assert!(!server.link_needs_listen(LinkMode::Forward)); // server + forward -> target
        assert!(server.link_needs_listen(LinkMode::Reverse)); // server + reverse -> listen
    }
}
