mod client;
mod config;
mod framing;
mod keys;
mod noise;
mod protocol;
mod relay;
mod server;

use clap::{Parser, Subcommand};
use config::{Config, Role};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "ghostport", version = "0.1.0", about = "Encrypted, NAT-traversing port forwarder")]
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
    Run { config: PathBuf },
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

    println!("Private key saved to {} (0600)", path.display());
    println!("Public key saved to  {}", pub_path.display());
    println!();
    println!("Give this public key to the peer, for their config's `peer_public_key`:");
    println!("  {}", keys::encode_public_key(&kp.public));
    ExitCode::SUCCESS
}

fn run_check(config_path: &PathBuf) -> ExitCode {
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let errors = cfg.validate();
    if errors.is_empty() {
        println!("ghostport: {} is valid ({:?} role, {} link{})", config_path.display(), cfg.role, cfg.links.len(), if cfg.links.len() == 1 { "" } else { "s" });
        ExitCode::SUCCESS
    } else {
        eprintln!("ghostport: {} has {} problem(s):", config_path.display(), errors.len());
        for e in &errors {
            eprintln!("  - {e}");
        }
        ExitCode::FAILURE
    }
}

async fn run_daemon(config_path: &PathBuf) -> ExitCode {
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let errors = cfg.validate();
    if !errors.is_empty() {
        eprintln!("ghostport: refusing to start — {} has {} problem(s):", config_path.display(), errors.len());
        for e in &errors {
            eprintln!("  - {e}");
        }
        eprintln!("(run `ghostport check {}` for details)", config_path.display());
        return ExitCode::FAILURE;
    }

    let private_key = match keys::load_private_key(&cfg.private_key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ghostport: {e}");
            return ExitCode::FAILURE;
        }
    };
    let peer_public_key = match keys::decode_public_key(&cfg.peer_public_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ghostport: peer_public_key: {e}");
            return ExitCode::FAILURE;
        }
    };

    let role = cfg.role;
    let config = Arc::new(cfg);
    let private_key = Arc::new(private_key);
    let peer_public_key = Arc::new(peer_public_key);

    let result = match role {
        Role::Server => server::run(server::Context { config, private_key, peer_public_key }).await,
        Role::Client => client::run(client::Context { config, private_key, peer_public_key }).await,
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
        Commands::Run { config } => {
            banner();
            let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
            runtime.block_on(run_daemon(&config))
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
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
            peer_public_key: client_pub_b64,
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![
                LinkConfig { id: "fwd".to_string(), mode: config::LinkMode::Forward, listen: None, target: Some(format!("127.0.0.1:{forward_target_port}")) },
                LinkConfig { id: "rev".to_string(), mode: config::LinkMode::Reverse, listen: Some(format!("127.0.0.1:{reverse_external_port}")), target: None },
            ],
        };
        assert!(server_config.validate().is_empty(), "{:?}", server_config.validate());

        let client_config = Config {
            role: Role::Client,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: server_pub_b64,
            listen_control: None,
            listen_data: None,
            server_control_addr: Some(format!("127.0.0.1:{control_port}")),
            server_data_addr: Some(format!("127.0.0.1:{data_port}")),
            links: vec![
                LinkConfig { id: "fwd".to_string(), mode: config::LinkMode::Forward, listen: Some(format!("127.0.0.1:{forward_local_port}")), target: None },
                LinkConfig { id: "rev".to_string(), mode: config::LinkMode::Reverse, listen: None, target: Some(format!("127.0.0.1:{reverse_target_port}")) },
            ],
        };
        assert!(client_config.validate().is_empty(), "{:?}", client_config.validate());

        tokio::spawn(server::run(server::Context {
            config: Arc::new(server_config),
            private_key: Arc::new(server_kp.private),
            peer_public_key: Arc::new(client_kp.public.clone()),
        }));
        tokio::spawn(client::run(client::Context {
            config: Arc::new(client_config),
            private_key: Arc::new(client_kp.private),
            peer_public_key: Arc::new(server_kp.public.clone()),
        }));

        // Forward: hit the client's local port, expect it to have gone
        // client -> tunnel -> server -> forward_target and back.
        let echoed = round_trip(&format!("127.0.0.1:{forward_local_port}"), b"hello-forward").await;
        assert_eq!(echoed, b"hello-forward");

        // Reverse: hit the server's external port, expect it to have
        // gone server -> (control signal) -> client -> reverse_target
        // and back — the path that needs the OpenStream/pending-map
        // machinery, not just a direct dial.
        let echoed = round_trip(&format!("127.0.0.1:{reverse_external_port}"), b"hello-reverse").await;
        assert_eq!(echoed, b"hello-reverse");
    }

    #[tokio::test]
    async fn wrong_peer_key_fails_the_handshake_instead_of_connecting() {
        let server_kp = keys::generate();
        let client_kp = keys::generate();
        let impostor_kp = keys::generate(); // client will be told THIS is the server's key

        let control_port = free_port();
        let data_port = free_port();

        let server_config = Config {
            role: Role::Server,
            private_key_path: std::path::PathBuf::new(),
            peer_public_key: keys::encode_public_key(&client_kp.public),
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            server_control_addr: None,
            server_data_addr: None,
            links: vec![],
        };
        tokio::spawn(server::run(server::Context {
            config: Arc::new(server_config),
            private_key: Arc::new(server_kp.private),
            peer_public_key: Arc::new(client_kp.public.clone()),
        }));

        // Client pinned to the impostor's public key, not the real
        // server's — the handshake must fail, not silently connect.
        tokio::time::sleep(Duration::from_millis(200)).await; // let the server finish binding
        let tcp = connect_with_retry(&format!("127.0.0.1:{control_port}"), Duration::from_secs(5)).await;
        let handshake = noise::initiator(&client_kp.private, &impostor_kp.public).unwrap();
        let result = snowstorm::NoiseStream::handshake(tcp, handshake).await;
        assert!(result.is_err(), "handshake must fail against the wrong pinned key");
    }
}
