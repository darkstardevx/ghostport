//! Server role: one shared UDP socket (`Config::listen_udp`), demuxed
//! by source address into independent per-flow Noise sessions. Mirrors
//! how the TCP path multiplexes every link over one shared
//! `listen_data` socket — the difference is UDP has no `accept()`, so
//! this crate does its own demuxing instead of letting the OS do it.
//!
//! Forward-mode only (see [`crate`] docs) — a session's first decrypted
//! message is always a [`StreamHello`] naming which link it's for, the
//! same pattern the TCP data channel already uses, just carried over
//! [`snowstorm::NoiseSocket::send`] instead of `framing::send_json`.

use crate::poller::SharedPeerPoller;
use ghostport_core::config::{Config, LinkMode, Transport};
use ghostport_core::peermatch::{self, ResolvedPeer};
use ghostport_core::protocol::StreamHello;
use ghostport_core::ratelimit::HandshakeLimiter;
use snow::HandshakeState;
use snowstorm::NoiseSocket;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

const MAX_DATAGRAM: usize = 65535;

/// A session with no traffic in either direction for this long is
/// dropped — UDP has no close signal, so this is what actually bounds
/// session lifetime/memory. Deliberately generous: real flows (DNS,
/// game traffic) are bursty, not constant.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Everything one running UDP server instance needs.
pub struct Context {
    /// The loaded, validated config — only its UDP-transport forward
    /// links and `listen_udp` matter here.
    pub config: Arc<Config>,
    /// This instance's own static Noise private key.
    pub private_key: Arc<Vec<u8>>,
    /// Every client identity this server accepts, same resolved shape
    /// the TCP path uses (see `ghostport_core::server::Context::peers`).
    pub peers: Arc<Vec<ResolvedPeer>>,
}

type SessionMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

/// Runs the UDP server role: binds the shared socket and demuxes every
/// incoming datagram by source address, spawning a fresh Noise session
/// for an unrecognized address and routing known addresses' datagrams
/// into their session's channel. Runs until the process exits, or
/// returns immediately if `listen_udp` isn't set (no link actually
/// uses UDP, nothing to do).
pub async fn run(ctx: Context) -> std::io::Result<()> {
    let Some(listen_addr) = ctx.config.listen_udp.clone() else {
        return Ok(());
    };
    let socket = Arc::new(UdpSocket::bind(&listen_addr).await?);
    println!("ghostport-udp: listening on {listen_addr}");

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let limiter = HandshakeLimiter::new();
    let ctx = Arc::new(ctx);

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;

        let existing_tx = sessions.lock().await.get(&src).cloned();
        if let Some(tx) = existing_tx {
            let _ = tx.send(buf[..n].to_vec()).await;
            continue;
        }

        // Unrecognized source address: this datagram must be a fresh
        // handshake message 1, or it's noise/an attacker and
        // match_peer_bytes below will simply fail to match anything.
        let Some(permit) = limiter.try_acquire(src.ip()).await else {
            continue;
        };
        let Ok((peer_index, state)) =
            peermatch::match_peer_bytes(&buf[..n], &ctx.private_key, &ctx.peers)
        else {
            continue;
        };
        // The responder side of Noise_KK finishes in a single reply
        // (message 1 was already consumed above) — there's no further
        // network round trip to bound, so the permit's job is done.
        drop(permit);

        let (tx, rx) = mpsc::channel(16);
        sessions.lock().await.insert(src, tx);

        let ctx = ctx.clone();
        let socket = socket.clone();
        let sessions = sessions.clone();
        let peer_name = ctx.peers[peer_index].name.clone();
        let peer_links = ctx.peers[peer_index].links.clone();
        tokio::spawn(async move {
            run_session(&ctx, socket, src, &peer_name, &peer_links, state, rx).await;
            sessions.lock().await.remove(&src);
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    ctx: &Context,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    peer_name: &str,
    peer_links: &HashSet<String>,
    state: HandshakeState,
    inbound: mpsc::Receiver<Vec<u8>>,
) {
    let poller = SharedPeerPoller {
        socket,
        peer_addr,
        inbound,
    };
    let mut noise_socket = match NoiseSocket::handshake_with_verifier(poller, state, &mut (), ())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ghostport-udp: handshake with {peer_addr} (\"{peer_name}\") failed: {e}");
            return;
        }
    };

    let hello: StreamHello = match noise_socket.recv().await {
        Ok(bytes) => match serde_json::from_slice(bytes) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ghostport-udp: {peer_addr}: malformed StreamHello: {e}");
                return;
            }
        },
        Err(e) => {
            eprintln!("ghostport-udp: {peer_addr}: didn't send a StreamHello: {e}");
            return;
        }
    };

    let Some(link) = ctx.config.links.iter().find(|l| l.id == hello.link_id) else {
        eprintln!(
            "ghostport-udp: {peer_addr}: unknown link id \"{}\"",
            hello.link_id
        );
        return;
    };
    if link.transport != Transport::Udp || link.mode != LinkMode::Forward {
        eprintln!(
            "ghostport-udp: {peer_addr}: link \"{}\" isn't a UDP forward link",
            link.id
        );
        return;
    }
    if !peer_links.contains(&link.id) {
        eprintln!(
            "ghostport-udp: peer \"{peer_name}\" is not authorized for link \"{}\"",
            link.id
        );
        return;
    }

    let target = link
        .target
        .clone()
        .expect("validated: udp forward link on server has target");
    let target_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ghostport-udp: {peer_addr}: failed to bind target socket: {e}");
            return;
        }
    };
    if let Err(e) = target_socket.connect(&target).await {
        eprintln!("ghostport-udp: {peer_addr}: failed to connect to target {target}: {e}");
        return;
    }

    println!(
        "ghostport-udp: [{}] session with {peer_addr} (\"{peer_name}\") -> {target}",
        link.id
    );

    let mut target_buf = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            tunnel_msg = noise_socket.recv() => {
                match tunnel_msg {
                    Ok(payload) => { let _ = target_socket.send(payload).await; }
                    Err(_) => break,
                }
            }
            target_msg = target_socket.recv(&mut target_buf) => {
                match target_msg {
                    Ok(n) => { let _ = noise_socket.send(&target_buf[..n]).await; }
                    Err(_) => break,
                }
            }
            () = tokio::time::sleep(SESSION_IDLE_TIMEOUT) => break,
        }
    }
    println!(
        "ghostport-udp: [{}] session with {peer_addr} closed",
        link.id
    );
}
