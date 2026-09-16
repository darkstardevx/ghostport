//! All the actual firewall interaction — shells out to `nft`, ported
//! from [[VortexWall]]'s own `nft.rs` (`~/tools/daemons/vortexwall`),
//! the real, working nftables-blackholing tool this plugin's whole
//! approach is based on. Everything lives in its own `inet
//! ghostport-firewall` table, kept deliberately separate from
//! VortexWall's own `inet vortexwall` table (and `ufw`'s) — all three
//! ultimately run on the same nftables kernel subsystem, but as
//! independent tables none of them need to know about each other.
//!
//! Needs real `CAP_NET_ADMIN` to do anything — every function here
//! shells out to a real `nft` invocation, which this development
//! sandbox cannot privilege-test (confirmed directly: a bare `nft list
//! tables` here fails with "Operation not permitted, perhaps you must
//! be root?"). Verified by code review and by handing the exact
//! command sequence to the user to run for real, not by fabricated
//! test coverage — VortexWall's own `nft.rs` has zero unit tests for
//! the identical reason.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Output};
use std::time::Duration;

const TABLE: &str = "inet ghostport-firewall";

/// Idempotent — safe to call on every startup. `add` (not `create`)
/// throughout, which `nft` treats as a no-op if the thing already
/// exists.
///
/// The chain hooks `prerouting` at priority `-300` (the "raw" tier) —
/// before connection tracking, before any other firewall tool's
/// filter-tier rules run. Banned traffic is dropped as early and
/// cheaply as nftables allows.
pub fn setup() -> io::Result<()> {
    run_script(&format!(
        r#"
add table {table}
add set {table} blackhole {{ type ipv4_addr; flags timeout; }}
add set {table} blackhole6 {{ type ipv6_addr; flags timeout; }}
add chain {table} drop_blackholed {{ type filter hook prerouting priority -300; policy accept; }}
flush chain {table} drop_blackholed
add rule {table} drop_blackholed ip saddr @blackhole drop
add rule {table} drop_blackholed ip6 saddr @blackhole6 drop
"#,
        table = TABLE
    ))
}

/// Removes the entire table — every rule, every currently-banned IP,
/// gone. Not an error if it doesn't exist (nothing to tear down).
pub fn teardown() -> io::Result<()> {
    let output = Command::new("nft")
        .args(["delete", "table"])
        .args(TABLE.split_whitespace())
        .output()?;
    if output.status.success() || stderr_of(&output).contains("No such file or directory") {
        Ok(())
    } else {
        Err(nft_error("delete table", &output))
    }
}

fn set_name(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "blackhole",
        IpAddr::V6(_) => "blackhole6",
    }
}

/// Bans `ip` for `duration` — nftables' own `timeout` flag on the set
/// auto-expires the entry at the kernel level, so nothing here needs
/// to track/unban it later.
pub fn ban(ip: IpAddr, duration: Duration) -> io::Result<()> {
    let secs = duration.as_secs().max(1);
    run_script(&format!(
        "add element {table} {set} {{ {ip} timeout {secs}s }}",
        table = TABLE,
        set = set_name(&ip)
    ))
}

/// Removes a ban immediately, before its timeout would have expired
/// it naturally.
pub fn unban(ip: IpAddr) -> io::Result<()> {
    run_script(&format!(
        "delete element {table} {set} {{ {ip} }}",
        table = TABLE,
        set = set_name(&ip)
    ))
}

/// Every currently-banned IP, parsed from `nft`'s plain-text set
/// listing. Good enough for a status display — not parsed as
/// structured JSON since nothing safety-relevant depends on this being
/// bulletproof.
pub fn list_banned() -> io::Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for set in ["blackhole", "blackhole6"] {
        let output = Command::new("nft")
            .args(["list", "set"])
            .args(TABLE.split_whitespace())
            .arg(set)
            .output()?;
        if !output.status.success() {
            continue; // table/set not set up yet -- treat as empty, not an error
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for token in text.split(|c: char| c == ',' || c == '{' || c == '}' || c.is_whitespace()) {
            if let Ok(ip) = token.parse::<IpAddr>() {
                ips.push(ip);
            }
        }
    }
    Ok(ips)
}

/// Runs an nft script via `nft -f -`, fed over stdin.
fn run_script(script: &str) -> io::Result<()> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(nft_error(script, &output))
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn nft_error(what: &str, output: &Output) -> io::Error {
    io::Error::other(format!("nft failed on `{what}`: {}", stderr_of(output)))
}
