//! `ghostport-firewall` — GhostPort's third plugin. Watches a running
//! server-role daemon's journal for rejected/failed handshake attempts
//! and actively blackholes the offending IP via `nftables`. Ported
//! from [[VortexWall]]'s own real, working approach
//! (`~/tools/daemons/vortexwall`) against GhostPort's own log output
//! instead of sshd's. See [`detector`] for exactly which log lines
//! count and why, and [`nft`] for the firewall interaction itself.
//!
//! A separate sidecar process, same shape as `ghostport-metrics` — it
//! never touches `ghostport-core`'s handshake/relay path, and the
//! `ghostport` binary never links this crate in. Unlike the first two
//! plugins, this one actively blocks network traffic and needs real
//! `CAP_NET_ADMIN` to do it — always start with `--dry-run`.

mod config;
mod detector;
mod nft;

use clap::Parser;
use detector::Offense;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Watches a running ghostport daemon's journal and actively blackholes offending IPs via nftables"
)]
struct Args {
    /// Path to this tool's own config.toml (threshold/window/ban
    /// duration/allowlist/service). Defaults to
    /// $XDG_CONFIG_HOME/ghostport-firewall/config.toml, then
    /// ~/.config/ghostport-firewall/config.toml, then ./config.toml.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Path to the *target* ghostport daemon's own config.toml. When
    /// given, refuses to start unless that config's role is "server"
    /// -- a client never accepts inbound connections, so there is
    /// nothing here to protect on a client machine. Optional: without
    /// it, this check is simply skipped.
    #[arg(long)]
    ghostport_config: Option<std::path::PathBuf>,

    /// Detect and log what *would* be banned without ever touching
    /// nftables. Always start here on a new box or after changing
    /// thresholds.
    #[arg(long)]
    dry_run: bool,

    // --- systemd service control ---
    #[arg(long)]
    admin: bool,
    #[arg(long, requires = "admin")]
    start: bool,
    #[arg(long, requires = "admin")]
    stop: bool,
    #[arg(long, requires = "admin")]
    restart: bool,
    #[arg(long, requires = "admin")]
    status: bool,

    // --- nftables management, independent of the systemd service ---
    /// List currently banned IPs and exit.
    #[arg(long)]
    bans: bool,
    /// Remove one IP's ban immediately and exit.
    #[arg(long, value_name = "IP")]
    unban: Option<String>,
    /// Remove the entire ghostport-firewall nftables table -- every
    /// rule, every ban, gone -- and exit.
    #[arg(long)]
    teardown: bool,
    /// Create the nftables table/set/chain (idempotent) and exit,
    /// without starting the log-watching loop.
    #[arg(long)]
    setup: bool,
    /// Ban one IP immediately and exit, bypassing log detection
    /// entirely. Refuses anything in `detector::is_never_bannable`
    /// (loopback/private).
    #[arg(long, value_name = "IP")]
    test_ban: Option<String>,
}

fn run_admin(args: &Args) -> std::io::Result<i32> {
    let action = match (args.start, args.stop, args.restart, args.status) {
        (true, false, false, false) => "start",
        (false, true, false, false) => "stop",
        (false, false, true, false) => "restart",
        (false, false, false, true) => "status",
        (false, false, false, false) => {
            eprintln!("--admin needs exactly one of --start, --stop, --restart, --status");
            return Ok(1);
        }
        _ => {
            eprintln!(
                "--admin takes exactly one of --start, --stop, --restart, --status, not several at once"
            );
            return Ok(1);
        }
    };

    let mut cmd = if action == "status" {
        let mut c = std::process::Command::new("systemctl");
        c.arg("status");
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.args(["systemctl", action]);
        c
    };
    cmd.arg("ghostport-firewall");

    use std::io::Write;
    let prefix = if action == "status" { "" } else { "sudo " };
    println!("[admin] running: {prefix}systemctl {action} ghostport-firewall");
    std::io::stdout().flush()?;
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

/// Tails one systemd unit's journal, sending each detected offense
/// down `tx`. Runs until the journalctl process itself exits (which
/// shouldn't happen under `-f` short of the process being killed).
async fn watch_service(service: String, tx: mpsc::Sender<(IpAddr, Offense)>) {
    loop {
        println!("[watch] tailing journal for {service}");
        let child = TokioCommand::new("journalctl")
            .args(["-f", "-u", &service, "-o", "cat", "--since", "now"])
            .stdout(std::process::Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[watch] failed to spawn journalctl for {service}: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("journalctl stdout was piped");
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(offense) = detector::extract_offense(&line) {
                let _ = tx.send(offense).await;
            }
        }

        eprintln!("[watch] journalctl for {service} exited -- restarting in 10s");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Loads the target ghostport daemon's own config (if given) and
/// confirms it's server-role -- a client never accepts inbound
/// connections, so there's nothing for this tool to protect there.
fn check_target_is_server_role(path: &std::path::Path) -> Result<(), String> {
    let cfg = ghostport_core::config::Config::load(path)?;
    if cfg.role != ghostport_core::config::Role::Server {
        return Err(format!(
            "{} is a client-role config -- a client never accepts inbound \
             connections, so there is nothing here for ghostport-firewall to protect",
            path.display()
        ));
    }
    Ok(())
}

async fn run_daemon(args: Args) -> std::io::Result<()> {
    if let Some(path) = &args.ghostport_config {
        check_target_is_server_role(path).map_err(std::io::Error::other)?;
        println!(
            "[config] confirmed {} is a server-role config",
            path.display()
        );
    }

    let config_path = args.config.or_else(config::default_config_path);
    let cfg = match config_path {
        Some(path) => config::load(&path).map_err(std::io::Error::other)?,
        None => {
            println!("[config] no config file found -- running with built-in defaults");
            config::AppConfig::default()
        }
    };

    println!(
        "[config] threshold={} window={}s ban_duration={}s dry_run={} watching={}",
        cfg.threshold, cfg.window_secs, cfg.ban_secs, args.dry_run, cfg.service
    );

    if args.dry_run {
        println!("[nftables] dry-run -- skipping table setup, nothing will be touched");
    } else {
        nft::setup()?;
        println!("[nftables] table ready (inet ghostport-firewall)");
    }

    let allowlist: Vec<IpAddr> = cfg
        .allowlist
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if allowlist.len() != cfg.allowlist.len() {
        eprintln!(
            "[config] warning: some allowlist entries didn't parse as plain IPs (CIDR ranges aren't supported yet) and were ignored"
        );
    }

    let (tx, mut rx) = mpsc::channel::<(IpAddr, Offense)>(256);
    tokio::spawn(watch_service(cfg.service.clone(), tx.clone()));
    drop(tx); // the loop below exits if the watcher dies and drops its sender

    let mut tracker =
        detector::FailureTracker::new(Duration::from_secs(cfg.window_secs), cfg.threshold);
    let ban_duration = Duration::from_secs(cfg.ban_secs);

    while let Some((ip, offense)) = rx.recv().await {
        if detector::is_never_bannable(&ip) {
            println!("[protected] {ip} triggered {offense:?} but is loopback/private -- never a ban candidate");
            continue;
        }
        if allowlist.contains(&ip) {
            continue;
        }

        let should_ban = match offense {
            // Already rate-limited by the app itself -- ban on the
            // first occurrence, no additional threshold.
            Offense::RateLimited => true,
            // A single wrong-key attempt could be an honest first-time
            // setup typo -- only ban once it's a sustained pattern.
            Offense::HandshakeFailed => tracker.record(ip, Instant::now()),
        };

        if should_ban {
            if args.dry_run {
                println!(
                    "[DRY-RUN] would ban {ip} for {}s ({offense:?})",
                    cfg.ban_secs
                );
            } else {
                match nft::ban(ip, ban_duration) {
                    Ok(()) => println!("[BANNED] {ip} for {}s ({offense:?})", cfg.ban_secs),
                    Err(e) => eprintln!("[ERROR] failed to ban {ip}: {e}"),
                }
            }
            tracker.forget(&ip);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if args.admin {
        return match run_admin(&args) {
            Ok(code) => ExitCode::from(code as u8),
            Err(e) => {
                eprintln!("[admin] error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.teardown {
        return match nft::teardown() {
            Ok(()) => {
                println!(
                    "[teardown] inet ghostport-firewall table removed -- every rule and ban is gone"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[teardown] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.setup {
        return match nft::setup() {
            Ok(()) => {
                println!("[setup] inet ghostport-firewall table ready");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[setup] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(ip_str) = &args.test_ban {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[test-ban] not a valid IP address: {ip_str}");
                return ExitCode::FAILURE;
            }
        };
        if detector::is_never_bannable(&ip) {
            eprintln!("[test-ban] refusing -- {ip} is loopback or a private range, never bannable");
            return ExitCode::FAILURE;
        }
        return match nft::ban(ip, Duration::from_secs(60)) {
            Ok(()) => {
                println!(
                    "[test-ban] {ip} banned for 60s -- check with --bans, or \
                     `nft list set inet ghostport-firewall blackhole`"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[test-ban] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.bans {
        return match nft::list_banned() {
            Ok(ips) if ips.is_empty() => {
                println!("No IPs currently banned.");
                ExitCode::SUCCESS
            }
            Ok(ips) => {
                for ip in ips {
                    println!("{ip}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[bans] failed to list: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(ip_str) = &args.unban {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[unban] not a valid IP address: {ip_str}");
                return ExitCode::FAILURE;
            }
        };
        return match nft::unban(ip) {
            Ok(()) => {
                println!("[unban] {ip} removed");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[unban] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run_daemon(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[Critical Failure] {e}");
            ExitCode::FAILURE
        }
    }
}
