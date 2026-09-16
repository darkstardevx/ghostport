//! Unix-socket status IPC. A running daemon binds this socket and
//! answers any connection with one JSON `StatusSnapshot`, then closes —
//! deliberately not a persistent/streaming protocol, since a poll-based
//! `status --watch` or TUI refresh every second or so is simple and
//! sufficient here. A socket (not a periodically-written status file)
//! gives an unambiguous "is the daemon even running" signal: connection
//! refused / no such file means no, cleanly, with no stale-data
//! ambiguity a file would have if the daemon crashed mid-write or a
//! while ago.

use crate::config::Config;
use crate::stats::{SharedState, StatusSnapshot};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Where the status socket lives when no path is overridden:
/// `$HOME/.local/state/ghostport/ghostport.sock`.
pub fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join(".local/state/ghostport/ghostport.sock")
}

/// Runs until the process exits; errors are logged, not fatal to the
/// rest of the daemon — a broken status socket shouldn't take down
/// actual port forwarding.
pub async fn run_ipc_server(state: Arc<SharedState>, config: Arc<Config>, socket_path: PathBuf) {
    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("ghostport: ipc: failed to create {}: {e}", parent.display());
            return;
        }
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    // A socket left behind by an unclean shutdown blocks bind() with
    // "address in use" even though nothing's listening — safe to remove
    // since we're about to replace it with a live one.
    let _ = std::fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "ghostport: ipc: failed to bind {}: {e}",
                socket_path.display()
            );
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "ghostport: ipc: failed to set permissions on {}: {e}",
            socket_path.display()
        );
    }

    loop {
        let (mut conn, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ghostport: ipc: accept failed: {e}");
                continue;
            }
        };
        let snapshot = state.snapshot(&config);
        tokio::spawn(async move {
            let _ = respond(&mut conn, &snapshot).await;
        });
    }
}

async fn respond(conn: &mut UnixStream, snapshot: &StatusSnapshot) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
    conn.write_all(&bytes).await?;
    conn.shutdown().await
}

/// Client side: connect, read until EOF, parse. Used by `status` and the
/// TUI's periodic refresh.
pub async fn query_status(socket_path: &Path) -> Result<StatusSnapshot, String> {
    let mut conn = UnixStream::connect(socket_path).await.map_err(|e| {
        format!(
            "couldn't connect to {} ({e}) — is the daemon running?",
            socket_path.display()
        )
    })?;
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("failed to read status: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("daemon sent an unparseable status: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Role;

    fn scratch_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghostport-ipc-test-{name}-{}.sock",
            std::process::id()
        ))
    }

    fn sample_config() -> Config {
        Config {
            role: Role::Server,
            private_key_path: PathBuf::new(),
            peer_public_key: None,
            peers: vec![],
            listen_control: Some("0.0.0.0:9000".to_string()),
            listen_data: Some("0.0.0.0:9001".to_string()),
            listen_udp: None,
            server_control_addr: None,
            server_data_addr: None,
            server_udp_addr: None,
            links: vec![],
        }
    }

    #[tokio::test]
    async fn query_fails_cleanly_when_nothing_is_listening() {
        let path = scratch_socket_path("nolistener");
        let result = query_status(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn round_trips_a_real_snapshot_over_a_real_socket() {
        let path = scratch_socket_path("roundtrip");
        let config = sample_config();
        let state = Arc::new(SharedState::new(&config));
        state
            .control
            .set_connected("9.9.9.9:1".to_string(), Some("alice".to_string()));

        let config = Arc::new(config);
        tokio::spawn(run_ipc_server(state, config, path.clone()));
        // Give the server a moment to bind — polling connect (as `status
        // --watch` does in practice) rather than a fixed sleep.
        let snapshot = wait_for_query(&path).await;

        assert_eq!(snapshot.role, "server");
        assert!(snapshot.control_connected);
        assert_eq!(snapshot.control_peer_addr.as_deref(), Some("9.9.9.9:1"));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn socket_file_is_owner_only() {
        let path = scratch_socket_path("perms");
        let config = Arc::new(sample_config());
        let state = Arc::new(SharedState::new(&config));
        tokio::spawn(run_ipc_server(state, config, path.clone()));
        wait_for_query(&path).await;

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&path).ok();
    }

    async fn wait_for_query(path: &Path) -> StatusSnapshot {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Ok(snap) = query_status(path).await {
                return snap;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("ipc server never became queryable at {}", path.display());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
