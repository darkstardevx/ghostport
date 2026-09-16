//! TOML config schema — same shape as [[VortexWall]]'s own `config.rs`,
//! since the tuning knobs (threshold, window, ban duration, allowlist)
//! mean exactly the same thing here.

use serde::Deserialize;
use std::path::PathBuf;

fn default_threshold() -> usize {
    5
}
fn default_window_secs() -> u64 {
    600
}
fn default_ban_secs() -> u64 {
    3600
}
fn default_service() -> String {
    "ghostport".to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    /// [`crate::detector::Offense::HandshakeFailed`] occurrences within
    /// `window_secs` before an IP gets banned.
    /// [`crate::detector::Offense::RateLimited`] bypasses this entirely
    /// and bans on the first occurrence — see `detector` module docs.
    #[serde(default = "default_threshold")]
    pub threshold: usize,
    /// The sliding window, in seconds, `HandshakeFailed` occurrences
    /// are counted over.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// How long a ban lasts, in seconds, before nftables auto-expires
    /// it.
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    /// Extra IPs to never ban, on top of the hardcoded loopback and
    /// private-range exclusion (`detector::is_never_bannable`, which
    /// this can't override either way). CIDR ranges aren't supported
    /// yet — plain IPs only.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// The systemd unit to tail via `journalctl -f -u <service>`.
    #[serde(default = "default_service")]
    pub service: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            window_secs: default_window_secs(),
            ban_secs: default_ban_secs(),
            allowlist: Vec::new(),
            service: default_service(),
        }
    }
}

/// `$XDG_CONFIG_HOME/ghostport-firewall/config.toml`, falling back to
/// `~/.config/ghostport-firewall/config.toml`, then `./config.toml` —
/// same search order as VortexWall's own `default_config_path`.
pub fn default_config_path() -> Option<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok()?;
    let candidates = [
        config_home.join("ghostport-firewall").join("config.toml"),
        PathBuf::from("config.toml"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub fn load(path: &std::path::Path) -> Result<AppConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_vortexwall_convention() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.window_secs, 600);
        assert_eq!(cfg.ban_secs, 3600);
        assert!(cfg.allowlist.is_empty());
        assert_eq!(cfg.service, "ghostport");
    }

    #[test]
    fn parses_a_minimal_toml_with_all_defaults() {
        let cfg: AppConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.service, "ghostport");
    }

    #[test]
    fn parses_a_fully_specified_toml() {
        let toml_text = r#"
threshold = 3
window_secs = 300
ban_secs = 7200
allowlist = ["198.51.100.1"]
service = "ghostport-server"
"#;
        let cfg: AppConfig = toml::from_str(toml_text).unwrap();
        assert_eq!(cfg.threshold, 3);
        assert_eq!(cfg.window_secs, 300);
        assert_eq!(cfg.ban_secs, 7200);
        assert_eq!(cfg.allowlist, vec!["198.51.100.1".to_string()]);
        assert_eq!(cfg.service, "ghostport-server");
    }
}
