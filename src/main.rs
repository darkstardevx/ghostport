mod tui;

use clap::{Parser, Subcommand};
use ghostport_core::config::{Config, Role};
use ghostport_core::{client, ipc, keys, peermatch, server, stats, theme};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "ghostport",
    version = "0.1.0",
    about = "Encrypted, NAT-traversing port forwarder"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new static Noise keypair. Prints the public key to
    /// stdout — copy it into the peer's `peer_public_key` config field.
    Keygen {
        /// Where to save the private key (a `.pub` sibling file is also
        /// written alongside it).
        #[arg(long, default_value = "~/.config/ghostport/identity.key")]
        out: String,
    },
    /// Validate a config file without starting the daemon.
    Check { config: PathBuf },
    /// Start the daemon (server or client role, per the config file).
    Run {
        config: PathBuf,
        /// Status IPC socket path. Defaults to
        /// ~/.local/state/ghostport/ghostport.sock — override when
        /// running more than one instance on the same machine (they
        /// can't share a socket file).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Query a running daemon's live status over its Unix socket.
    Status {
        /// Path to the status socket. Defaults to
        /// ~/.local/state/ghostport/ghostport.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Re-query and reprint every second instead of once.
        #[arg(long)]
        watch: bool,
        /// Print the raw JSON snapshot instead of a formatted table.
        #[arg(long)]
        json: bool,
    },
    /// Interactive TUI: live status, link editing, service control.
    Tui {
        config: PathBuf,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

fn banner() {
    let c = cybercore::palette::purple();
    let r = cybercore::palette::RESET;
    println!(
        "{c}
   ____ _               _   ____            _
  / ___| |__   ___  ___| |_|  _ \\ ___  _ __| |_
 | |  _| '_ \\ / _ \\/ __| __| |_) / _ \\| '__| __|
 | |_| | | | | (_) \\__ \\ |_|  __/ (_) | |  | |_
  \\____|_| |_|\\___/|___/\\__|_|   \\___/|_|   \\__|{r}"
    );
    println!("  » Encrypted, NAT-traversing port forwarder\n");
}

fn run_keygen(out: &str) -> ExitCode {
    let path = expand_tilde(out);
    let kp = keys::generate();

    if let Err(e) = keys::save_private_key(&path, &kp.private) {
        eprintln!("ghostport: failed to save private key: {e}");
        return ExitCode::FAILURE;
    }
    let pub_path = keys::public_key_path(&path);
    if let Err(e) = keys::save_public_key(&pub_path, &kp.public) {
        eprintln!("ghostport: failed to save public key: {e}");
        return ExitCode::FAILURE;
    }

    println!(
        "Private key saved to {} (0600)",
        theme::accent(&path.display().to_string())
    );
    println!(
        "Public key saved to  {}",
        theme::accent(&pub_path.display().to_string())
    );
    println!();
    println!("Give this public key to the peer, for their config's `peer_public_key`:");
    println!(
        "  {}",
        theme::emphasis(&keys::encode_public_key(&kp.public))
    );
    println!();
    println!("Fingerprint (read this aloud / compare side-by-side with the peer");
    println!("to catch a transcription error in the key above):");
    println!("  {}", theme::accent(&keys::fingerprint(&kp.public)));
    ExitCode::SUCCESS
}

fn run_check(config_path: &Path) -> ExitCode {
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ghostport: {}", theme::err(&e));
            return ExitCode::FAILURE;
        }
    };
    let errors = cfg.validate();
    if errors.is_empty() {
        println!(
            "ghostport: {} is {} ({:?} role, {} link{})",
            config_path.display(),
            theme::ok("valid"),
            cfg.role,
            cfg.links.len(),
            if cfg.links.len() == 1 { "" } else { "s" }
        );
        println!();
        print_fingerprints_for_check(&cfg);
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "ghostport: {} has {} {}:",
            config_path.display(),
            errors.len(),
            theme::err(if errors.len() == 1 {
                "problem"
            } else {
                "problems"
            })
        );
        for e in &errors {
            eprintln!("  - {}", theme::warn(e));
        }
        ExitCode::FAILURE
    }
}

/// Prints whatever key fingerprints are available for a valid config —
/// same verification ritual as an SSH host key, read aloud or compared
/// side-by-side with the peer over an out-of-band channel. Best-effort:
/// a config can be structurally valid before `ghostport keygen` has
/// ever been run for this identity, so a missing/unreadable local
/// public key file just means that line is skipped, not a `check`
/// failure.
fn print_fingerprints_for_check(cfg: &Config) {
    match cfg.role {
        Role::Client => {
            if let Some(peer_key_b64) = &cfg.peer_public_key {
                if let Ok(peer_key) = keys::decode_public_key(peer_key_b64) {
                    println!(
                        "  peer_public_key fingerprint: {}",
                        theme::accent(&keys::fingerprint(&peer_key))
                    );
                }
            }
        }
        Role::Server => {
            for peer in &cfg.peers {
                if let Ok(peer_key) = keys::decode_public_key(&peer.public_key) {
                    println!(
                        "  peer \"{}\" fingerprint: {} (links: {})",
                        peer.name,
                        theme::accent(&keys::fingerprint(&peer_key)),
                        peer.links.join(", ")
                    );
                }
            }
        }
    }

    let local_pub_path = keys::public_key_path(&cfg.private_key_path);
    if let Ok(text) = std::fs::read_to_string(&local_pub_path) {
        if let Ok(local_key) = keys::decode_public_key(text.trim()) {
            println!(
                "  local identity fingerprint:  {}",
                theme::accent(&keys::fingerprint(&local_key))
            );
        }
    }
}

async fn run_status(socket: PathBuf, watch: bool, json: bool) -> ExitCode {
    loop {
        match ipc::query_status(&socket).await {
            Ok(snapshot) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snapshot).unwrap_or_default()
                    );
                } else {
                    if watch {
                        print!("\x1b[2J\x1b[H"); // clear screen, home cursor — plain redraw, no ratatui needed for a one-shot/poll view
                    }
                    print_status(&snapshot);
                }
            }
            Err(e) => {
                eprintln!("ghostport: {e}");
                if !watch {
                    return ExitCode::FAILURE;
                }
            }
        }
        if !watch {
            return ExitCode::SUCCESS;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn print_status(snapshot: &stats::StatusSnapshot) {
    let purple = cybercore::palette::purple();
    let hot_pink = cybercore::palette::hot_pink();
    let cyan = cybercore::palette::cyan();
    let orange = cybercore::palette::orange();
    let r = cybercore::palette::RESET;

    let control = if snapshot.control_connected {
        theme::ok("connected")
    } else {
        theme::err("disconnected")
    };
    println!(
        "role: {purple}{}{r}   uptime: {cyan}{}s{r}   control channel: {control}",
        snapshot.role, snapshot.uptime_secs
    );
    if snapshot.control_connected {
        if let (Some(addr), Some(since)) = (
            &snapshot.control_peer_addr,
            snapshot.control_connected_since_secs_ago,
        ) {
            println!("  peer: {addr}  (connected {since}s ago)");
        }
    }
    println!();
    println!(
        "{cyan}{:<14} {:<9} {:>7} {:>7} {:>12} {:>12}{r}",
        "link", "mode", "active", "total", "bytes-fwd", "bytes-back"
    );
    if snapshot.links.is_empty() {
        println!("(no links configured)");
    }
    for link in &snapshot.links {
        let mode_color = if link.mode == "forward" {
            &cyan
        } else {
            &hot_pink
        };
        // Pad the plain number to width first, then color the whole
        // already-padded string — coloring first and padding second
        // would count the ANSI escape bytes toward the width and throw
        // off alignment.
        let active_padded = format!("{:>7}", link.active_streams);
        let active = if link.active_streams > 0 {
            theme::ok(&active_padded)
        } else {
            active_padded
        };
        println!(
            "{:<14} {mode_color}{:<9}{r} {active} {:>7} {orange}{:>12}{r} {orange}{:>12}{r}",
            link.id, link.mode, link.total_streams, link.bytes_forward, link.bytes_back
        );
    }
}

async fn run_daemon(config_path: &Path, socket_path: PathBuf) -> ExitCode {
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let errors = cfg.validate();
    if !errors.is_empty() {
        eprintln!(
            "ghostport: refusing to start — {} has {} problem(s):",
            config_path.display(),
            errors.len()
        );
        for e in &errors {
            eprintln!("  - {e}");
        }
        eprintln!(
            "(run `ghostport check {}` for details)",
            config_path.display()
        );
        return ExitCode::FAILURE;
    }

    let private_key = match keys::load_private_key(&cfg.private_key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };

    let role = cfg.role;
    let state = Arc::new(stats::SharedState::new(&cfg));
    let private_key = Arc::new(private_key);

    let result = match role {
        Role::Server => {
            let mut peers = Vec::with_capacity(cfg.peers.len());
            for peer in &cfg.peers {
                let public_key = match keys::decode_public_key(&peer.public_key) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("ghostport: peer \"{}\": {e}", peer.name);
                        return ExitCode::FAILURE;
                    }
                };
                peers.push(peermatch::ResolvedPeer {
                    name: peer.name.clone(),
                    public_key,
                    links: peer.links.iter().cloned().collect(),
                });
            }
            let config = Arc::new(cfg);
            server::run(server::Context {
                config,
                private_key,
                peers: Arc::new(peers),
                state,
                socket_path,
            })
            .await
        }
        Role::Client => {
            let peer_public_key = match keys::decode_public_key(
                cfg.peer_public_key
                    .as_deref()
                    .expect("validated: client role requires peer_public_key"),
            ) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("ghostport: peer_public_key: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let config = Arc::new(cfg);
            client::run(client::Context {
                config,
                private_key,
                peer_public_key: Arc::new(peer_public_key),
                state,
                socket_path,
            })
            .await
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghostport: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    match args.command {
        Commands::Keygen { out } => {
            banner();
            run_keygen(&out)
        }
        Commands::Check { config } => run_check(&config),
        Commands::Run { config, socket } => {
            banner();
            let socket = socket.unwrap_or_else(ipc::default_socket_path);
            let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
            runtime.block_on(run_daemon(&config, socket))
        }
        Commands::Status {
            socket,
            watch,
            json,
        } => {
            let socket = socket.unwrap_or_else(ipc::default_socket_path);
            let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
            runtime.block_on(run_status(socket, watch, json))
        }
        Commands::Tui { config, socket } => {
            let socket = socket.unwrap_or_else(ipc::default_socket_path);
            tui::run(config, socket)
        }
    }
}
