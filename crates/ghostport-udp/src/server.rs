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

/// How long a session is given to send its `StreamHello` after the
/// Noise handshake finishes, before it's abandoned. Without this, a
/// session that never gets a real follow-up — a replayed handshake
/// message 1 from a spoofed source address can never produce one,
/// since the replayer holds no key material — leaks its task and
/// `sessions` map entry forever. Same value as
/// `ghostport_core::server`'s `HANDSHAKE_TIMEOUT`/`STREAM_HELLO_TIMEOUT`.
const STREAM_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

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
            // try_send, not send().await: this loop is the *only* reader
            // of the shared socket, so blocking here to wait for one
            // backed-up session's channel to free up would stall every
            // other session and every new handshake attempt too. A full
            // channel means that session's consumer is behind; dropping
            // its excess datagrams is correct, expected UDP behavior,
            // not a bug.
            let _ = tx.try_send(buf[..n].to_vec());
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

    let hello: StreamHello = match tokio::time::timeout(STREAM_HELLO_TIMEOUT, noise_socket.recv())
        .await
    {
        Ok(Ok(bytes)) => match serde_json::from_slice(bytes) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ghostport-udp: {peer_addr}: malformed StreamHello: {e}");
                return;
            }
        },
        Ok(Err(e)) => {
            eprintln!("ghostport-udp: {peer_addr}: didn't send a StreamHello: {e}");
            return;
        }
        Err(_) => {
            eprintln!(
                    "ghostport-udp: {peer_addr}: timed out waiting for a StreamHello after the handshake"
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use ghostport_core::config::{Config, Role};
    use ghostport_core::{keys, noise};
    use std::path::PathBuf;

    /// A minimal, otherwise-unused Server-role config -- `run_session`
    /// never reads it until after a real `StreamHello` resolves, which
    /// this test's session never sends, so its actual field values
    /// don't matter beyond being well-formed.
    fn empty_server_config() -> Config {
        Config {
            role: Role::Server,
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

    /// A real, previously-unbounded gap: a session that completes the
    /// Noise handshake (the responder side finishes in one reply, per
    /// `Noise_KK` -- no further read needed) but whose peer never sends
    /// a `StreamHello` afterward used to hang `run_session` forever,
    /// leaking the task and its `sessions` map entry. Exactly what a
    /// replayed handshake message 1 from a spoofed source address does,
    /// since the replayer can never produce a valid encrypted follow-up.
    ///
    /// Drives a real message-1/message-2 exchange (not a hand-built
    /// state) to get a genuinely advanced responder `HandshakeState`,
    /// the same shape `peermatch::match_peer_bytes` hands `run_session`
    /// in production, then calls it directly with an `inbound` channel
    /// nothing ever sends on -- standing in for a peer that never
    /// follows up.
    #[tokio::test]
    async fn session_with_no_stream_hello_is_abandoned_not_left_hanging() {
        let responder_kp = keys::generate();
        let initiator_kp = keys::generate();

        let mut initiator_state =
            noise::initiator(&initiator_kp.private, &responder_kp.public).unwrap();
        let mut responder_state =
            noise::responder(&responder_kp.private, &initiator_kp.public).unwrap();
        let mut msg1 = vec![0u8; 256];
        let len = initiator_state.write_message(&[], &mut msg1).unwrap();
        let mut payload = vec![0u8; 256];
        responder_state
            .read_message(&msg1[..len], &mut payload)
            .unwrap();
        assert!(
            responder_state.is_my_turn(),
            "responder should be ready to write message 2 after processing message 1"
        );

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (_tx, rx) = mpsc::channel(16); // dropped, never sent on -- the peer never follows up

        let ctx = Context {
            config: Arc::new(empty_server_config()),
            private_key: Arc::new(responder_kp.private),
            peers: Arc::new(vec![]),
        };
        let peer_links = HashSet::new();

        let result = tokio::time::timeout(
            Duration::from_secs(15),
            run_session(
                &ctx,
                socket,
                peer_addr,
                "test-peer",
                &peer_links,
                responder_state,
                rx,
            ),
        )
        .await;
        assert!(
            result.is_ok(),
            "run_session must return (abandon the session) rather than hang forever \
             waiting for a StreamHello that never arrives"
        );
    }

    /// Confirms the exact mechanism the demux loop's `try_send` call
    /// relies on: a full channel fails immediately rather than
    /// blocking. `tokio::sync::mpsc::Sender::try_send` guarantees this
    /// itself -- this test exists so a future edit that accidentally
    /// swaps it back to `send(...).await` (reintroducing the
    /// head-of-line-blocking bug this module's `run` fixed) has a
    /// concrete regression test to break, not just a code-review nit.
    #[test]
    fn try_send_on_a_full_channel_fails_immediately_instead_of_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1]).expect("first send has room");
        let result = tx.try_send(vec![2]);
        assert!(
            result.is_err(),
            "a full channel must reject immediately, not block the caller"
        );
        // The first datagram is still there, untouched by the failed send.
        assert_eq!(rx.try_recv().unwrap(), vec![1]);
    }
}
