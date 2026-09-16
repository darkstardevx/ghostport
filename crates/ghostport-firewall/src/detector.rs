//! Turns raw `journalctl` lines from a running `ghostport` (or
//! `ghostport-udp`) daemon into ban decisions. No I/O here — `nft`
//! shell-outs and journal tailing live in their own places so this
//! stays trivially unit-testable, the same split VortexWall's own
//! `detector.rs` already uses.
//!
//! Patterns below are copied verbatim from the real, current log-line
//! text in `ghostport-core/src/server.rs` and `ghostport-udp/src/server.rs`
//! (grepped directly, not remembered) — only lines that both indicate a
//! real, unambiguous misbehavior *and* actually print the peer's
//! address qualify. Several real rejection lines print only the
//! peer's *name*, not its address (e.g. "is not authorized for link"),
//! and are correctly left out — they're not extractable at all, not
//! just deprioritized.
//!
//! Deliberately excluded: handshake *timeouts*. GhostPort's own client
//! model is "a laptop that roams between neighbors' WiFi and the
//! library" — a timeout there is much more likely to be real network
//! flakiness than an attack, unlike VortexWall's SSH case where the
//! admin's own IP is usually stable. Only a cryptographically-wrong
//! completed handshake, or a rejection the app's own rate limiter
//! already decided was abusive, count here.

use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// What kind of real misbehavior a log line indicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offense {
    /// The app's own `ratelimit::HandshakeLimiter` already decided
    /// this source IP was abusive before this line was ever printed —
    /// ban immediately, no further threshold needed.
    RateLimited,
    /// A handshake completed but was cryptographically wrong (an
    /// unrecognized or mismatched key). Can't happen to a real
    /// key-holder from network conditions alone, but a single instance
    /// could be an honest first-time-setup typo — tracked via
    /// [`FailureTracker`], not banned on the first occurrence.
    HandshakeFailed,
}

/// One capture-group pattern per real log line shape, paired with the
/// [`Offense`] it represents.
fn patterns() -> &'static [(Regex, Offense)] {
    static PATTERNS: OnceLock<Vec<(Regex, Offense)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // `SocketAddr`'s own Display: `ip:port` for v4, `[ip]:port`
        // for v6 — matches either shape.
        const ADDR: &str = r"\[?(?P<ip>[0-9a-fA-F:.]+)\]?:\d+";
        [
            (
                format!(r"control: rejected {ADDR} \(too many recent handshake attempts\)"),
                Offense::RateLimited,
            ),
            (
                format!(r"data: rejected {ADDR} \(too many recent handshake attempts\)"),
                Offense::RateLimited,
            ),
            (
                format!(r"control: handshake with {ADDR} failed:"),
                Offense::HandshakeFailed,
            ),
            (
                format!(r#"ghostport-udp: handshake with {ADDR} \("#),
                Offense::HandshakeFailed,
            ),
        ]
        .into_iter()
        .map(|(pattern, offense)| {
            (
                Regex::new(&pattern).expect("hardcoded regex must compile"),
                offense,
            )
        })
        .collect()
    })
}

/// Strips ANSI SGR escape sequences (`\x1b[...m`) — GhostPort's own
/// `theme::err`/`theme::warn` wrap these log lines in color codes, and
/// whether a downstream consumer sees them un-stripped under a
/// non-TTY systemd journal depends on `cybercore::palette`'s own TTY
/// detection, which isn't something to assume without checking.
/// Stripping unconditionally is cheap and correct either way.
fn strip_ansi(line: &str) -> String {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    let re = ANSI.get_or_init(|| Regex::new("\x1b\\[[0-9;]*m").expect("hardcoded regex"));
    re.replace_all(line, "").into_owned()
}

/// Extracts an offending IP and what it did from one journal line, if
/// it matches a known real misbehavior pattern. `None` for every other
/// line (successful connections, informational output, timeouts,
/// anything without an extractable address).
pub fn extract_offense(line: &str) -> Option<(IpAddr, Offense)> {
    let clean = strip_ansi(line);
    for (re, offense) in patterns() {
        if let Some(caps) = re.captures(&clean) {
            if let Some(ip_str) = caps.name("ip") {
                if let Ok(ip) = ip_str.as_str().parse::<IpAddr>() {
                    return Some((ip, *offense));
                }
            }
        }
    }
    None
}

/// True for loopback and every RFC1918/RFC4193 private range — ported
/// verbatim from VortexWall's `detector::is_never_bannable`. These can
/// never be banned, full stop, regardless of what's in the config:
/// they're the ranges every LAN this box has ever been on (home, a
/// neighbor's, a library) uses, so banning one is banning a network
/// you're physically on right now.
pub fn is_never_bannable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00, // fc00::/7 (ULA)
    }
}

/// Sliding-window per-IP failure tracker for [`Offense::HandshakeFailed`]
/// — ported verbatim from VortexWall's, which is already
/// transport/service-agnostic. `RateLimited` offenses bypass this
/// entirely (see module docs) and ban immediately instead.
pub struct FailureTracker {
    window: Duration,
    threshold: usize,
    history: HashMap<IpAddr, VecDeque<Instant>>,
}

impl FailureTracker {
    /// Builds a tracker that bans an IP once it accumulates `threshold`
    /// failures within `window`.
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            window,
            threshold,
            history: HashMap::new(),
        }
    }

    /// Records one failure for `ip` at `now`. Returns `true` exactly
    /// once per ban-worthy streak — the transition from "under
    /// threshold" to "at or over threshold" within the window.
    pub fn record(&mut self, ip: IpAddr, now: Instant) -> bool {
        let entry = self.history.entry(ip).or_default();
        entry.push_back(now);
        while let Some(&front) = entry.front() {
            if now.duration_since(front) > self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.len() == self.threshold
    }

    /// Drops tracking state for an IP — call this once it's actually
    /// been banned, so a stale count doesn't linger after the ban
    /// itself expires in nftables.
    pub fn forget(&mut self, ip: &IpAddr) {
        self.history.remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: &str = "\x1b[38;2;255;59;82m";
    const RESET: &str = "\x1b[0m";

    #[test]
    fn extracts_ip_from_control_rate_limit_rejection() {
        let line = format!(
            "{RED}control: rejected 198.51.100.7:51422 (too many recent handshake attempts){RESET}"
        );
        assert_eq!(
            extract_offense(&line),
            Some(("198.51.100.7".parse().unwrap(), Offense::RateLimited))
        );
    }

    #[test]
    fn extracts_ip_from_data_rate_limit_rejection() {
        let line = "data: rejected 203.0.113.9:9000 (too many recent handshake attempts)";
        assert_eq!(
            extract_offense(line),
            Some(("203.0.113.9".parse().unwrap(), Offense::RateLimited))
        );
    }

    #[test]
    fn extracts_ip_from_tcp_handshake_failed() {
        let line = format!(
            "{RED}control: handshake with 198.51.100.7:51422 failed: decryption failed{RESET}"
        );
        assert_eq!(
            extract_offense(&line),
            Some(("198.51.100.7".parse().unwrap(), Offense::HandshakeFailed))
        );
    }

    #[test]
    fn extracts_ip_from_udp_handshake_failed() {
        let line = r#"ghostport-udp: handshake with 203.0.113.9:33000 ("client") failed: decryption failed"#;
        assert_eq!(
            extract_offense(line),
            Some(("203.0.113.9".parse().unwrap(), Offense::HandshakeFailed))
        );
    }

    #[test]
    fn extracts_ipv6_from_bracketed_socketaddr_format() {
        let line = "control: rejected [2001:db8::1]:5678 (too many recent handshake attempts)";
        assert_eq!(
            extract_offense(line),
            Some(("2001:db8::1".parse().unwrap(), Offense::RateLimited))
        );
    }

    #[test]
    fn ignores_handshake_timeouts() {
        let line = "control: handshake with 198.51.100.7:51422 timed out";
        assert_eq!(extract_offense(line), None);
    }

    #[test]
    fn ignores_address_less_authorization_failures() {
        // Real current line -- prints only the peer's name, never its
        // address, so there is nothing extractable here on purpose.
        let line = r#"peer "alice" is not authorized for link "db""#;
        assert_eq!(extract_offense(line), None);
    }

    #[test]
    fn ignores_unrelated_lines() {
        let line = "ghostport: control channel connected from 198.51.100.7:51422 (peer \"alice\")";
        assert_eq!(extract_offense(line), None);
    }

    #[test]
    fn loopback_and_private_ranges_never_bannable() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.50",
            "169.254.1.1",
            "::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_never_bannable(&ip), "{ip} should be protected");
        }
        for ip in ["198.51.100.7", "203.0.113.9", "8.8.8.8"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_never_bannable(&ip), "{ip} should NOT be protected");
        }
    }

    #[test]
    fn tracker_fires_exactly_once_at_threshold() {
        let mut tracker = FailureTracker::new(Duration::from_secs(600), 3);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0));
        assert!(!tracker.record(ip, t0));
        assert!(tracker.record(ip, t0)); // 3rd failure crosses threshold=3
        assert!(!tracker.record(ip, t0)); // 4th: already over, no re-fire
    }

    #[test]
    fn tracker_prunes_outside_window() {
        let mut tracker = FailureTracker::new(Duration::from_secs(10), 2);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0));
        let t1 = t0 + Duration::from_secs(30);
        assert!(!tracker.record(ip, t1));
    }

    #[test]
    fn forget_resets_the_count() {
        let mut tracker = FailureTracker::new(Duration::from_secs(600), 2);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0));
        assert!(tracker.record(ip, t0));
        tracker.forget(&ip);
        assert!(!tracker.record(ip, t0));
    }
}
