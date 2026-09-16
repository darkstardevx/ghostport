//! Client role: one local UDP listen socket per UDP forward link
//! (`link.listen`), demuxed by *local* source address into independent
//! outbound flows. Each flow dials its own dedicated ephemeral-port
//! session to the server (`Config::server_udp_addr`), runs a real
//! `Noise_KK` handshake as initiator, sends one [`StreamHello`], then
//! relays real payload both ways — symmetric to how [`crate::server`]
//! demuxes inbound sessions by *source* address on its side.

use crate::poller::ConnectedPoller;
use ghostport_core::config::{Config, LinkMode, Transport};
use ghostport_core::noise;
use ghostport_core::protocol::StreamHello;
use snowstorm::NoiseSocket;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

const MAX_DATAGRAM: usize = 65535;

/// Mirrors `server::SESSION_IDLE_TIMEOUT` — same reasoning, same value.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Mirrors `ghostport_core::client`/`server`'s own `HANDSHAKE_TIMEOUT`.
/// Real network round trip this time (unlike the server's responder
/// side, which never needs to wait on one) — a dropped handshake
/// datagram would otherwise hang a flow forever, since
/// `NoiseSocket::handshake_with_verifier` has no retry of its own.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything one running UDP client instance needs.
pub struct Context {
    /// The loaded, validated config — only its UDP-transport forward
    /// links and `server_udp_addr` matter here.
    pub config: Arc<Config>,
    /// This instance's own static Noise private key.
    pub private_key: Arc<Vec<u8>>,
    /// The single pinned peer's static Noise public key.
    pub peer_public_key: Arc<Vec<u8>>,
}

type FlowMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

/// Runs the UDP client role: starts one local listen socket per
/// UDP-transport forward link and demuxes it into per-flow sessions.
/// Runs until the process exits -- including when no link uses UDP at
/// all (`listeners` stays empty): this still never returns. Returning
/// `Ok(())` there would be wrong, not just pointless -- `main.rs`
/// races this against the real `ghostport_core` daemon via
/// `tokio::select!`, and an early return here would look like "the
/// daemon is done" and tear the real one down (see the matching
/// comment in `server.rs::run`, which hit this same real bug first).
pub async fn run(ctx: Context) -> std::io::Result<()> {
    let ctx = Arc::new(ctx);
    let mut listeners = tokio::task::JoinSet::new();

    for link in &ctx.config.links {
        if link.transport == Transport::Udp && link.mode == LinkMode::Forward {
            let listen_addr = link
                .listen
                .clone()
                .expect("validated: udp forward link on client requires listen");
            listeners.spawn(run_forward_listener(
                ctx.clone(),
                link.id.clone(),
                listen_addr,
            ));
        }
    }

    // Waits for every spawned listener to end -- including the
    // "there were none to begin with" case, where this returns
    // immediately. Either way, never actually return Ok(()) below:
    // a listener ending (crashed, or there was nothing to spawn) is
    // not "the client is done."
    while listeners.join_next().await.is_some() {}
    std::future::pending::<()>().await;
    unreachable!("pending() never resolves")
}

async fn run_forward_listener(ctx: Arc<Context>, link_id: String, listen_addr: String) {
    let socket = match UdpSocket::bind(&listen_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ghostport-udp: [{link_id}] failed to bind {listen_addr}: {e}");
            return;
        }
    };
    println!("ghostport-udp: [{link_id}] listening on {listen_addr} (forward)");

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ghostport-udp: [{link_id}] recv failed: {e}");
                continue;
            }
        };

        let existing_tx = flows.lock().await.get(&src).cloned();
        if let Some(tx) = existing_tx {
            // try_send, not send().await -- see the matching comment in
            // server.rs's demux loop. This is the only reader of the
            // shared local listen socket; blocking here for one flow's
            // backed-up channel would stall every other local flow too.
            let _ = tx.try_send(buf[..n].to_vec());
            continue;
        }

        let (tx, rx) = mpsc::channel(16);
        flows.lock().await.insert(src, tx);

        let ctx = ctx.clone();
        let link_id = link_id.clone();
        let socket = socket.clone();
        let flows = flows.clone();
        let first_datagram = buf[..n].to_vec();
        tokio::spawn(async move {
            run_flow(&ctx, &link_id, socket, src, rx, first_datagram).await;
            flows.lock().await.remove(&src);
        });
    }
}

/// One local flow's whole lifecycle: dial+handshake against the
/// server, identify the link via `StreamHello`, then relay real
/// payload both ways until idle or an error ends it. `first_datagram`
/// is the local app's datagram that triggered this flow's creation —
/// relayed as the first real payload once the tunnel is ready, not
/// dropped or treated as anything handshake-related (it's plaintext
/// app data; the handshake below is a wholly separate exchange with
/// the server).
async fn run_flow(
    ctx: &Context,
    link_id: &str,
    local_socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    mut from_local: mpsc::Receiver<Vec<u8>>,
    first_datagram: Vec<u8>,
) {
    let server_udp_addr = ctx
        .config
        .server_udp_addr
        .clone()
        .expect("validated: client role requires server_udp_addr when a udp link exists");

    let tunnel_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ghostport-udp: [{link_id}] {local_addr}: failed to open tunnel socket: {e}");
            return;
        }
    };
    if let Err(e) = tunnel_socket.connect(&server_udp_addr).await {
        eprintln!(
            "ghostport-udp: [{link_id}] {local_addr}: failed to connect to {server_udp_addr}: {e}"
        );
        return;
    }

    let handshake = match noise::initiator(&ctx.private_key, &ctx.peer_public_key) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ghostport-udp: [{link_id}] {local_addr}: {e}");
            return;
        }
    };
    let poller = ConnectedPoller(tunnel_socket);
    let mut noise_socket = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        NoiseSocket::handshake_with_verifier(poller, handshake, &mut (), ()),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("ghostport-udp: [{link_id}] {local_addr}: handshake failed: {e}");
            return;
        }
        Err(_) => {
            eprintln!("ghostport-udp: [{link_id}] {local_addr}: handshake timed out");
            return;
        }
    };

    let hello = StreamHello {
        link_id: link_id.to_string(),
        stream_id: None,
    };
    let Ok(hello_bytes) = serde_json::to_vec(&hello) else {
        return;
    };
    if noise_socket.send(&hello_bytes).await.is_err() {
        eprintln!("ghostport-udp: [{link_id}] {local_addr}: failed to send StreamHello");
        return;
    }
    if noise_socket.send(&first_datagram).await.is_err() {
        return;
    }

    println!("ghostport-udp: [{link_id}] flow from {local_addr} established");

    loop {
        tokio::select! {
            from_local_msg = from_local.recv() => {
                match from_local_msg {
                    Some(bytes) => { let _ = noise_socket.send(&bytes).await; }
                    None => break,
                }
            }
            from_tunnel = noise_socket.recv() => {
                match from_tunnel {
                    Ok(bytes) => { let _ = local_socket.send_to(bytes, local_addr).await; }
                    Err(_) => break,
                }
            }
            () = tokio::time::sleep(FLOW_IDLE_TIMEOUT) => break,
        }
    }
    println!("ghostport-udp: [{link_id}] flow from {local_addr} closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostport_core::config::Role;
    use ghostport_core::keys;
    use std::path::PathBuf;

    fn empty_client_config() -> Config {
        Config {
            role: Role::Client,
            private_key_path: PathBuf::new(),
            peer_public_key: None,
            peers: vec![],
            listen_control: None,
            listen_data: None,
            listen_udp: None,
            server_control_addr: None,
            server_data_addr: None,
            server_udp_addr: None,
            links: vec![],
        }
    }

    /// The client-side twin of `server::run`'s own regression test: a
    /// real bug caught by a smoke test, not a unit test. With no
    /// UDP-transport forward link configured, `run` used to return
    /// `Ok(())` immediately (an empty `JoinSet` resolves `join_next()`
    /// to `None` right away). `main.rs` races this against the real
    /// `ghostport_core::client::run` via `tokio::select!` when the
    /// `udp` feature is enabled -- an early return here tore down the
    /// real daemon the moment it started, for any TCP-only config built
    /// with `--features udp`.
    #[tokio::test]
    async fn run_never_returns_when_no_link_uses_udp() {
        let ctx = Context {
            config: Arc::new(empty_client_config()),
            private_key: Arc::new(keys::generate().private),
            peer_public_key: Arc::new(keys::generate().public),
        };
        let result = tokio::time::timeout(Duration::from_millis(500), run(ctx)).await;
        assert!(
            result.is_err(),
            "run() must never resolve on its own when no link uses UDP -- \
             it must block forever, not return Ok(())"
        );
    }
}
