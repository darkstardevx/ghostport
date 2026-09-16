mod client;
mod config;
mod framing;
mod ipc;
mod keys;
mod noise;
mod peermatch;
mod protocol;
mod ratelimit;
mod relay;
mod server;
mod stats;
#[cfg(test)]
mod tests_gateflow;
mod theme;
mod tui;

use clap::{Parser, Subcommand};
use config::{Config, Role};
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

/// End-to-end tests against two real, fully-running daemon instances
/// (server role + client role) talking to each other over real loopback
/// TCP sockets, with real Noise handshakes — not mocked at any layer.
/// This is the only thing that actually proves the control-channel
/// signaling / pending-stream-map / per-connection-tunnel design (see
/// server.rs and client.rs module docs) works, since none of that
/// cross-task, cross-role coordination is exercised by the per-module
/// unit tests alone. Lives here (not under `tests/`) because this is a
/// binary crate with no `lib.rs` — an external test file can't see
/// these private modules, an inline `#[cfg(test)]` module can.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::LinkConfig;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A private per-test-per-role socket path — `run()` always spawns
    /// an IPC server at `Context::socket_path`, and two unrelated tests
    /// (or two roles in the same test) sharing one path would race on
    /// the same socket file, exactly the bug this field was added to
    /// prevent in the real CLI (`ghostport run --socket`).
    fn scratch_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghostport-main-test-{name}-{}-{}.sock",
            std::process::id(),
            free_port()
        ))
    }

    /// Bounces back everything it reads, on every accepted connection —
    /// stands in for "the real destination" on both ends (the server's
    /// forward-mode target, the client's reverse-mode target).
    async fn spawn_echo_server(addr: String) {
        let listener = TcpListener::bind(&addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    /// Retries connecting for up to `timeout` — avoids a fixed sleep
    /// racing against how long the daemons take to bind/handshake.
    async fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Ok(s) = TcpStream::connect(addr).await {
                return s;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("failed to connect to {addr} within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn round_trip(addr: &str, payload: &[u8]) -> Vec<u8> {
        let mut sock = connect_with_retry(addr, Duration::from_secs(5)).await;
        sock.write_all(payload).await.unwrap();
        sock.shutdown().await.unwrap(); // signal EOF so the echo's copy() and our read both terminate cleanly
        let mut received = Vec::new();
        sock.read_to_end(&mut received).await.unwrap();
        received
    }

    #[tokio::test]
    async fn forward_and_reverse_links_round_trip_end_to_end() {
        let server_kp = keys::generate();
        let client_kp = keys::generate();
        let server_pub_b64 = keys::encode_public_key(&server_kp.public);
        let client_pub_b64 = keys::encode_public_key(&client_kp.public);

        let control_port = free_port();
        let data_port = free_port();
        let forward_local_port = free_port(); // client listens, for the forward link
        let forward_target_port = free_port(); // server dials, the "remote" echo service
        let reverse_external_port = free_port(); // server listens, for the reverse link
        let reverse_target_port = free_port(); // client dials, the "local" echo service

        spawn_echo_server(format!("127.0.0.1:{forward_target_port}")).await;
        spawn_echo_server(format!("127.0.0.1:{reverse_target_port}")).await;

        let server_config = Config {
            role: Role::Server,
            private_key_path: std::path::PathBuf::new(), // unused: private key is passed in directly below
            peer_public_key: None,
            peers: vec![config::PeerConfig {
                name: "client".to_string(),
                public_key: client_pub_b64,
                links: vec!["fwd".to_string(), "rev".to_string()],
            }],
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![
                LinkConfig {
                    id: "fwd".to_string(),
                    mode: config::LinkMode::Forward,
                    listen: None,
                    target: Some(format!("127.0.0.1:{forward_target_port}")),
                },
                LinkConfig {
                    id: "rev".to_string(),
                    mode: config::LinkMode::Reverse,
                    listen: Some(format!("127.0.0.1:{reverse_external_port}")),
                    target: None,
                },
            ],
        };
        assert!(
            server_config.validate().is_empty(),
            "{:?}",
            server_config.validate()
        );

        let client_config = Config {
            role: Role::Client,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: Some(server_pub_b64),
            peers: vec![],
            listen_control: None,
            listen_data: None,
            server_control_addr: Some(format!("127.0.0.1:{control_port}")),
            server_data_addr: Some(format!("127.0.0.1:{data_port}")),
            links: vec![
                LinkConfig {
                    id: "fwd".to_string(),
                    mode: config::LinkMode::Forward,
                    listen: Some(format!("127.0.0.1:{forward_local_port}")),
                    target: None,
                },
                LinkConfig {
                    id: "rev".to_string(),
                    mode: config::LinkMode::Reverse,
                    listen: None,
                    target: Some(format!("127.0.0.1:{reverse_target_port}")),
                },
            ],
        };
        assert!(
            client_config.validate().is_empty(),
            "{:?}",
            client_config.validate()
        );

        let server_state = Arc::new(stats::SharedState::new(&server_config));
        let client_state = Arc::new(stats::SharedState::new(&client_config));
        let server_config = Arc::new(server_config);
        let client_config = Arc::new(client_config);

        tokio::spawn(server::run(server::Context {
            config: server_config.clone(),
            private_key: Arc::new(server_kp.private),
            peers: Arc::new(vec![peermatch::ResolvedPeer {
                name: "client".to_string(),
                public_key: client_kp.public.clone(),
                links: ["fwd", "rev"].map(String::from).into(),
            }]),
            state: server_state.clone(),
            socket_path: scratch_socket_path("server"),
        }));
        tokio::spawn(client::run(client::Context {
            config: client_config.clone(),
            private_key: Arc::new(client_kp.private),
            peer_public_key: Arc::new(server_kp.public.clone()),
            state: client_state.clone(),
            socket_path: scratch_socket_path("client"),
        }));

        // Forward: hit the client's local port, expect it to have gone
        // client -> tunnel -> server -> forward_target and back.
        let echoed = round_trip(&format!("127.0.0.1:{forward_local_port}"), b"hello-forward").await;
        assert_eq!(echoed, b"hello-forward");

        // Stats should reflect that round trip: the "fwd" link on both
        // sides saw exactly one stream, with real bytes moved.
        assert_eq!(
            server_state.links["fwd"]
                .total_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(
            server_state.links["fwd"]
                .bytes_forward
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            client_state.links["fwd"]
                .total_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Reverse: hit the server's external port, expect it to have
        // gone server -> (control signal) -> client -> reverse_target
        // and back — the path that needs the OpenStream/pending-map
        // machinery, not just a direct dial.
        let echoed = round_trip(
            &format!("127.0.0.1:{reverse_external_port}"),
            b"hello-reverse",
        )
        .await;
        assert_eq!(echoed, b"hello-reverse");
    }

    #[tokio::test]
    async fn wrong_peer_key_fails_the_handshake_instead_of_connecting() {
        let server_kp = keys::generate();
        let client_kp = keys::generate();
        let decoy_kp = keys::generate(); // a second, unrelated allowed peer
        let stranger_kp = keys::generate(); // the actual connecting key -- not on the allowed list at all
        let impostor_kp = keys::generate(); // client will be told THIS is the server's key

        let control_port = free_port();
        let data_port = free_port();

        let server_config = Config {
            role: Role::Server,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: None,
            peers: vec![
                config::PeerConfig {
                    name: "client".to_string(),
                    public_key: keys::encode_public_key(&client_kp.public),
                    links: vec![],
                },
                config::PeerConfig {
                    name: "decoy".to_string(),
                    public_key: keys::encode_public_key(&decoy_kp.public),
                    links: vec![],
                },
            ],
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![],
        };
        let state = Arc::new(stats::SharedState::new(&server_config));
        tokio::spawn(server::run(server::Context {
            config: Arc::new(server_config),
            private_key: Arc::new(server_kp.private),
            peers: Arc::new(vec![
                peermatch::ResolvedPeer {
                    name: "client".to_string(),
                    public_key: client_kp.public.clone(),
                    links: Default::default(),
                },
                peermatch::ResolvedPeer {
                    name: "decoy".to_string(),
                    public_key: decoy_kp.public.clone(),
                    links: Default::default(),
                },
            ]),
            state,
            socket_path: scratch_socket_path("wrongkey"),
        }));

        tokio::time::sleep(Duration::from_millis(200)).await; // let the server finish binding

        // A key that isn't on the allowed list at all -- must exhaust
        // every candidate (both "client" and "decoy") and still fail,
        // not just fail against the first one tried.
        let tcp =
            connect_with_retry(&format!("127.0.0.1:{control_port}"), Duration::from_secs(5)).await;
        let handshake = noise::initiator(&stranger_kp.private, &server_kp.public).unwrap();
        let result = snowstorm::NoiseStream::handshake(tcp, handshake).await;
        assert!(
            result.is_err(),
            "handshake must fail for a key not on the allowed list"
        );

        // Same idea from the other direction: a real allowed client
        // pinned to the wrong *server* key must also fail, not silently
        // connect.
        let tcp =
            connect_with_retry(&format!("127.0.0.1:{control_port}"), Duration::from_secs(5)).await;
        let handshake = noise::initiator(&client_kp.private, &impostor_kp.public).unwrap();
        let result = snowstorm::NoiseStream::handshake(tcp, handshake).await;
        assert!(
            result.is_err(),
            "handshake must fail against the wrong pinned server key"
        );
    }

    /// Proves the rate limiter added in `ratelimit.rs` is actually wired
    /// into the real control listener, not just correct in isolation:
    /// opens more raw TCP connections from one source than the per-IP
    /// budget allows, and confirms the excess connection is dropped by
    /// the server *before* it ever gets a handshake attempt — not queued
    /// or left open pending one. Distinguished by how fast the server
    /// closes it: a connection admitted into the handshake path would
    /// stay open for up to `server::HANDSHAKE_TIMEOUT` (10s) waiting for
    /// bytes we never send; a rejected one is closed almost immediately.
    #[tokio::test]
    async fn control_listener_rejects_connections_beyond_the_per_ip_rate_limit() {
        let server_kp = keys::generate();
        let client_kp = keys::generate();

        let control_port = free_port();
        let data_port = free_port();

        let server_config = Config {
            role: Role::Server,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: None,
            peers: vec![config::PeerConfig {
                name: "client".to_string(),
                public_key: keys::encode_public_key(&client_kp.public),
                links: vec![],
            }],
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![],
        };
        let state = Arc::new(stats::SharedState::new(&server_config));
        tokio::spawn(server::run(server::Context {
            config: Arc::new(server_config),
            private_key: Arc::new(server_kp.private),
            peers: Arc::new(vec![peermatch::ResolvedPeer {
                name: "client".to_string(),
                public_key: client_kp.public.clone(),
                links: Default::default(),
            }]),
            state,
            socket_path: scratch_socket_path("ratelimit"),
        }));

        let control_addr = format!("127.0.0.1:{control_port}");

        // Consume the per-IP budget with plain TCP connects -- no Noise
        // handshake needed, the limiter runs before that ever starts.
        // Spaced slightly apart so the server's accept loop has
        // processed each one (and updated the shared per-IP counter)
        // before the next is opened, rather than racing several accepts
        // against one one-at-a-time counter update.
        let mut budget_conns = Vec::new();
        for _ in 0..ratelimit::MAX_ATTEMPTS_PER_WINDOW {
            let sock = connect_with_retry(&control_addr, Duration::from_secs(5)).await;
            budget_conns.push(sock);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // This one is beyond the budget -- the server should close it
        // right away rather than holding it open for a handshake.
        let mut excess = connect_with_retry(&control_addr, Duration::from_secs(5)).await;
        let mut buf = [0u8; 1];
        let read_result =
            tokio::time::timeout(Duration::from_millis(1500), excess.read(&mut buf)).await;
        match read_result {
            Ok(Ok(0)) => {} // EOF: server closed it immediately, as expected
            Ok(Ok(n)) => panic!("expected the rejected connection to be closed, got {n} unexpected byte(s)"),
            Ok(Err(e)) => panic!("unexpected read error on the rejected connection: {e}"),
            Err(_) => panic!("the (budget+1)th connection was not closed within 1.5s -- rate limit doesn't appear to be enforced on the real listener"),
        }

        drop(budget_conns);
    }

    /// The core proof of multi-peer support: one real server configured
    /// with two distinct peers, each restricted to its own link. Not
    /// mocked at any layer -- real daemons, real distinct Noise
    /// identities, a real running client for the allowed path, and a
    /// real direct handshake (peer A's actual private key) for the
    /// rejected path, so the server-side authorization check is proven
    /// against a genuine identity rather than a config-editor's own
    /// self-restraint.
    #[tokio::test]
    async fn peer_is_rejected_from_a_link_outside_its_own_allowlist() {
        let server_kp = keys::generate();
        let peer_a_kp = keys::generate();
        let peer_b_kp = keys::generate();

        let control_port = free_port();
        let data_port = free_port();
        let link_a_target_port = free_port();
        let link_b_target_port = free_port();
        let client_a_local_port = free_port();

        spawn_echo_server(format!("127.0.0.1:{link_a_target_port}")).await;
        spawn_echo_server(format!("127.0.0.1:{link_b_target_port}")).await;

        let server_config = Config {
            role: Role::Server,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: None,
            peers: vec![
                config::PeerConfig {
                    name: "peer-a".to_string(),
                    public_key: keys::encode_public_key(&peer_a_kp.public),
                    links: vec!["link-a".to_string()],
                },
                config::PeerConfig {
                    name: "peer-b".to_string(),
                    public_key: keys::encode_public_key(&peer_b_kp.public),
                    links: vec!["link-b".to_string()],
                },
            ],
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![
                LinkConfig {
                    id: "link-a".to_string(),
                    mode: config::LinkMode::Forward,
                    listen: None,
                    target: Some(format!("127.0.0.1:{link_a_target_port}")),
                },
                LinkConfig {
                    id: "link-b".to_string(),
                    mode: config::LinkMode::Forward,
                    listen: None,
                    target: Some(format!("127.0.0.1:{link_b_target_port}")),
                },
            ],
        };
        assert!(
            server_config.validate().is_empty(),
            "{:?}",
            server_config.validate()
        );
        let server_state = Arc::new(stats::SharedState::new(&server_config));
        let server_config = Arc::new(server_config);

        tokio::spawn(server::run(server::Context {
            config: server_config.clone(),
            private_key: Arc::new(server_kp.private.clone()),
            peers: Arc::new(vec![
                peermatch::ResolvedPeer {
                    name: "peer-a".to_string(),
                    public_key: peer_a_kp.public.clone(),
                    links: ["link-a".to_string()].into(),
                },
                peermatch::ResolvedPeer {
                    name: "peer-b".to_string(),
                    public_key: peer_b_kp.public.clone(),
                    links: ["link-b".to_string()].into(),
                },
            ]),
            state: server_state.clone(),
            socket_path: scratch_socket_path("multipeer"),
        }));

        // Real client A daemon, only ever configured to use its own
        // allowed link -- proves the *allowed* path works end-to-end
        // through a real, unmodified client::run, not just a hand-rolled
        // handshake.
        let client_a_config = Config {
            role: Role::Client,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: Some(keys::encode_public_key(&server_kp.public)),
            peers: vec![],
            listen_control: None,
            listen_data: None,
            server_control_addr: Some(format!("127.0.0.1:{control_port}")),
            server_data_addr: Some(format!("127.0.0.1:{data_port}")),
            links: vec![LinkConfig {
                id: "link-a".to_string(),
                mode: config::LinkMode::Forward,
                listen: Some(format!("127.0.0.1:{client_a_local_port}")),
                target: None,
            }],
        };
        assert!(
            client_a_config.validate().is_empty(),
            "{:?}",
            client_a_config.validate()
        );
        let client_a_state = Arc::new(stats::SharedState::new(&client_a_config));
        tokio::spawn(client::run(client::Context {
            config: Arc::new(client_a_config),
            private_key: Arc::new(peer_a_kp.private.clone()),
            peer_public_key: Arc::new(server_kp.public.clone()),
            state: client_a_state,
            socket_path: scratch_socket_path("multipeer-client-a"),
        }));

        let echoed = round_trip(
            &format!("127.0.0.1:{client_a_local_port}"),
            b"hello-from-peer-a",
        )
        .await;
        assert_eq!(echoed, b"hello-from-peer-a");
        assert_eq!(
            server_state.links["link-a"]
                .total_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Now prove peer A's real identity is rejected for link-b: a
        // direct data-tunnel handshake using peer A's real private key,
        // then a StreamHello naming the link it's NOT allowed to use.
        // Not relying on client A's own config to simply "not try" --
        // this proves the server enforces it even against a genuine,
        // otherwise-valid identity.
        let tcp =
            connect_with_retry(&format!("127.0.0.1:{data_port}"), Duration::from_secs(5)).await;
        let handshake = noise::initiator(&peer_a_kp.private, &server_kp.public).unwrap();
        let mut tunnel = snowstorm::NoiseStream::handshake(tcp, handshake)
            .await
            .expect("peer A is a real allowed peer -- the handshake itself must still succeed");
        framing::send_json(
            &mut tunnel,
            &protocol::StreamHello {
                link_id: "link-b".to_string(),
                stream_id: None,
            },
        )
        .await
        .unwrap();

        // A working relay would have echoed something once written to;
        // an authorized rejection just closes the connection instead.
        // Timeout-bounded so a regression that *does* relay fails fast
        // rather than hanging the suite.
        let mut buf = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(3), tunnel.read_to_end(&mut buf)).await;
        assert!(
            read_result.is_ok(),
            "server must close an unauthorized link request, not leave it hanging open"
        );
        assert!(
            buf.is_empty(),
            "peer A must not get a working relay for link-b, which it's not authorized for"
        );
        assert_eq!(
            server_state.links["link-b"]
                .total_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an unauthorized attempt must not count as a real stream"
        );
    }
}
