//! `ghostport-metrics` — a Prometheus exporter for a running
//! `ghostport` daemon. A separate sidecar process: it only ever reads
//! the daemon's existing status IPC socket (the same one `ghostport
//! status`/the TUI already use), never touches `ghostport-core`'s
//! handshake/relay path, and the `ghostport` binary never links this
//! crate in at all. See [`render`] for the actual `StatusSnapshot` ->
//! Prometheus-text logic and [`http`] for the minimal server itself.

mod http;
mod render;

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// Runs a small HTTP server that answers `GET /metrics` with a
/// Prometheus-format rendering of a `ghostport` daemon's current
/// status, queried fresh from its status IPC socket on every scrape.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the target daemon's status socket. Defaults to the same
    /// path `ghostport` itself defaults to.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Address to serve `/metrics` on, e.g. `127.0.0.1:9184`. No
    /// default on purpose — this is a new, unauthenticated HTTP
    /// surface, so the bind address is always an explicit choice, not
    /// a guess that might expose it further than intended.
    #[arg(long)]
    listen: std::net::SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let socket_path = args
        .socket
        .unwrap_or_else(ghostport_core::ipc::default_socket_path);

    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ghostport-metrics: failed to bind {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "ghostport-metrics: serving /metrics on http://{} (querying {})",
        args.listen,
        socket_path.display()
    );

    match http::serve(listener, socket_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghostport-metrics: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Real, end-to-end integration tests. Live in this binary crate's own
/// test module rather than an external `tests/` file: `http`/`render`
/// are deliberately private (this crate has no `lib.rs` — nothing else
/// is meant to depend on it), so an external test file couldn't reach
/// them anyway. Same "nothing mocked" philosophy as
/// `ghostport-core`'s own integration tests: a real running server
/// daemon, a real running metrics HTTP server, real TCP requests.
#[cfg(test)]
mod tests {
    use ghostport_core::config::{Config, Role};
    use ghostport_core::{keys, server, stats};
    use std::path::PathBuf;
    use std::sync::Arc;
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

    fn scratch_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghostport-metrics-test-{name}-{}-{}.sock",
            std::process::id(),
            free_port()
        ))
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_real_values_from_a_real_running_daemon() {
        let server_kp = keys::generate();
        let control_port = free_port();
        let data_port = free_port();
        let socket_path = scratch_socket_path("live");

        let server_config = Config {
            role: Role::Server,
            private_key_path: PathBuf::new(),
            peer_public_key: None,
            peers: vec![],
            listen_control: Some(format!("127.0.0.1:{control_port}")),
            listen_data: Some(format!("127.0.0.1:{data_port}")),
            listen_udp: None,
            server_control_addr: None,
            server_data_addr: None,
            server_udp_addr: None,
            links: vec![],
        };
        let state = Arc::new(stats::SharedState::new(&server_config));
        tokio::spawn(server::run(server::Context {
            config: Arc::new(server_config),
            private_key: Arc::new(server_kp.private),
            peers: Arc::new(vec![]),
            state,
            socket_path: socket_path.clone(),
        }));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(crate::http::serve(listener, socket_path));

        // Poll until the metrics server actually reports the daemon up
        // -- both the daemon's own IPC bind and the metrics server's
        // own bind race against this test starting, same reason the
        // rest of this project's own tests poll rather than sleep.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let body = loop {
            let body = http_get(addr, "/metrics").await;
            if body.contains("ghostport_up 1") {
                break body;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("metrics endpoint never reported the daemon up:\n{body}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("ghostport_uptime_seconds"));
        assert!(body.contains("ghostport_control_connected 0")); // nothing has connected yet
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_down_promptly_when_daemon_is_unreachable() {
        let socket_path = scratch_socket_path("unreachable"); // nothing ever listens here

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(crate::http::serve(listener, socket_path));

        let started = tokio::time::Instant::now();
        let body = tokio::time::timeout(Duration::from_secs(3), http_get(addr, "/metrics"))
            .await
            .expect("must respond promptly, not hang, when the daemon is unreachable");
        assert!(body.contains("ghostport_up 0"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an absent socket should fail fast, not wait anywhere near QUERY_TIMEOUT"
        );
    }
}
