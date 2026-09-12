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
    pub peer_public_key: String,

    // Server-role fields.
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
        let text = std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }

    /// All problems found, not just the first — a config editor (or a
    /// human squinting at error output) wants the full list in one pass,
    /// not a fix-one-rerun-find-the-next loop.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if keys_module_decode(&self.peer_public_key).is_err() {
            errors.push("peer_public_key is not a valid base64-encoded 32-byte key".to_string());
        }

        match self.role {
            Role::Server => {
                require_present(&mut errors, "listen_control", &self.listen_control, "role = \"server\"");
                require_present(&mut errors, "listen_data", &self.listen_data, "role = \"server\"");
                require_absent(&mut errors, "server_control_addr", &self.server_control_addr, "role = \"server\"");
                require_absent(&mut errors, "server_data_addr", &self.server_data_addr, "role = \"server\"");
            }
            Role::Client => {
                require_present(&mut errors, "server_control_addr", &self.server_control_addr, "role = \"client\"");
                require_present(&mut errors, "server_data_addr", &self.server_data_addr, "role = \"client\"");
                require_absent(&mut errors, "listen_control", &self.listen_control, "role = \"client\"");
                require_absent(&mut errors, "listen_data", &self.listen_data, "role = \"client\"");
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

    /// Exactly one of `listen`/`target` must be set on this side, and
    /// which one is required depends on both `role` and `mode` — see the
    /// module doc table in README for the full (role, mode) -> field
    /// matrix; this mirrors it directly.
    fn validate_link(&self, link: &LinkConfig, errors: &mut Vec<String>) {
        let needs_listen = matches!((self.role, link.mode), (Role::Client, LinkMode::Forward) | (Role::Server, LinkMode::Reverse));
        let (required_field, forbidden_field, required_value, forbidden_value) =
            if needs_listen { ("listen", "target", &link.listen, &link.target) } else { ("target", "listen", &link.target, &link.listen) };

        if required_value.is_none() {
            errors.push(format!("link \"{}\": {:?} on this side ({:?}) requires `{required_field}`", link.id, link.mode, self.role));
        }
        if forbidden_value.is_some() {
            errors.push(format!("link \"{}\": {:?} on this side ({:?}) must not set `{forbidden_field}` (that belongs on the peer's config)", link.id, link.mode, self.role));
        }
        if let Some(addr) = required_value.as_deref() {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                errors.push(format!("link \"{}\": `{required_field}` = \"{addr}\" is not a valid host:port address", link.id));
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
            peer_public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
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
            peer_public_key: crate::keys::encode_public_key(&crate::keys::generate().public),
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
        assert!(errors.iter().any(|e| e.contains("listen_data")), "{errors:?}");
    }

    #[test]
    fn client_with_server_only_fields_is_rejected() {
        let mut cfg = base_client();
        cfg.listen_control = Some("0.0.0.0:9000".to_string());
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("listen_control")), "{errors:?}");
    }

    #[test]
    fn invalid_peer_public_key_is_rejected() {
        let mut cfg = base_server();
        cfg.peer_public_key = "not-base64!!".to_string();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("peer_public_key")), "{errors:?}");
    }

    #[test]
    fn forward_link_on_client_needs_listen_not_target() {
        let mut cfg = base_client();
        cfg.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Forward, listen: None, target: Some("127.0.0.1:5432".to_string()) });
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("requires `listen`")), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("must not set `target`")), "{errors:?}");
    }

    #[test]
    fn forward_link_on_server_needs_target_not_listen() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Forward, listen: Some("0.0.0.0:5432".to_string()), target: None });
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("requires `target`")), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("must not set `listen`")), "{errors:?}");
    }

    #[test]
    fn reverse_link_on_server_needs_listen_client_needs_target() {
        let mut server = base_server();
        server.links.push(LinkConfig { id: "dev".to_string(), mode: LinkMode::Reverse, listen: Some("0.0.0.0:8080".to_string()), target: None });
        assert!(server.validate().is_empty());

        let mut client = base_client();
        client.links.push(LinkConfig { id: "dev".to_string(), mode: LinkMode::Reverse, listen: None, target: Some("127.0.0.1:3000".to_string()) });
        assert!(client.validate().is_empty());
    }

    #[test]
    fn correctly_configured_forward_link_passes_on_both_sides() {
        let mut server = base_server();
        server.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Forward, listen: None, target: Some("127.0.0.1:5432".to_string()) });
        assert!(server.validate().is_empty(), "{:?}", server.validate());

        let mut client = base_client();
        client.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Forward, listen: Some("127.0.0.1:5432".to_string()), target: None });
        assert!(client.validate().is_empty(), "{:?}", client.validate());
    }

    #[test]
    fn duplicate_link_ids_are_rejected() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig { id: "dup".to_string(), mode: LinkMode::Forward, listen: None, target: Some("127.0.0.1:1".to_string()) });
        cfg.links.push(LinkConfig { id: "dup".to_string(), mode: LinkMode::Forward, listen: None, target: Some("127.0.0.1:2".to_string()) });
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("duplicate id")), "{errors:?}");
    }

    #[test]
    fn non_socket_addr_target_is_rejected() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig { id: "bad".to_string(), mode: LinkMode::Forward, listen: None, target: Some("not-an-address".to_string()) });
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("not a valid host:port")), "{errors:?}");
    }

    #[test]
    fn round_trips_through_toml() {
        let mut cfg = base_server();
        cfg.links.push(LinkConfig { id: "db".to_string(), mode: LinkMode::Forward, listen: None, target: Some("127.0.0.1:5432".to_string()) });
        let text = toml::to_string(&cfg).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert_eq!(parsed.links[0].id, "db");
    }
}
