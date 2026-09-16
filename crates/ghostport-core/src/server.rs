//! Server role: always reachable, always accepts both the control
//! connection and every data-tunnel connection. Never dials the peer
//! itself — that asymmetry is what lets the client work from behind
//! NAT/unpredictable networks (it only ever needs to make outbound
//! connections, never accept one).
//!
//! Only one control connection is meaningful at a time (single pinned
//! peer pair) — the accept loop below handles one session fully before
//! accepting the next, rather than juggling concurrent sessions.

use crate::config::{Config, LinkMode};
use crate::peermatch::{self, ResolvedPeer};
use crate::protocol::{ControlMessage, StreamHello};
use crate::ratelimit::HandshakeLimiter;
use crate::stats::SharedState;
use crate::{framing, ipc, relay, theme};
use snowstorm::NoiseStream;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit};

/// How long a handshake attempt (Noise handshake, or the underlying TCP
/// connect for the client) is allowed to sit before it's abandoned. A
/// peer that opens a connection and never sends a byte would otherwise
/// hold the handshake — and its task — open indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Streams accepted on a `reverse`-mode link's listener, waiting to be
/// claimed by a data-tunnel connection the client dials in response to
/// the `OpenStream` signal. Removed either when claimed, or by the
/// per-entry timeout in `spawn_reverse_listener` if the client never
/// answers (e.g. it's offline).
type PendingStreams = Arc<Mutex<HashMap<u64, TcpStream>>>;

/// Everything one running server instance needs, shared (via `Arc`)
/// across its listener/accept tasks.
pub struct Context {
    /// The loaded, validated config for this instance.
    pub config: Arc<Config>,
    /// This instance's own static Noise private key.
    pub private_key: Arc<Vec<u8>>,
    /// Every client identity this server accepts. `Noise_KK` needs the
    /// correct remote static key loaded before a handshake message can
    /// be processed at all, so with more than one entry the server
    /// tries each in turn against the incoming handshake (see
    /// `peermatch::match_peer`) rather than learning the identity
    /// mid-handshake the way `IK`/`XX` would.
    pub peers: Arc<Vec<ResolvedPeer>>,
    /// Live link/control-connection counters, shared with the status
    /// IPC socket.
    pub state: Arc<SharedState>,
    /// Where this instance's status IPC socket lives. Not always the
    /// default — running both roles on one machine (e.g. a local demo)
    /// needs two distinct paths, since two daemons can't share one
    /// socket file.
    pub socket_path: PathBuf,
}

/// Runs the server role: a reverse-mode listener for each configured
/// reverse link, the status IPC server, and the control/data accept
/// loops. Runs until the process exits.
pub async fn run(ctx: Context) -> std::io::Result<()> {
    let listen_control = ctx
        .config
        .listen_control
        .clone()
        .expect("validated: server role requires listen_control");
    let listen_data = ctx
        .config
        .listen_data
        .clone()
        .expect("validated: server role requires listen_data");

    let pending: PendingStreams = Arc::new(Mutex::new(HashMap::new()));
    let next_stream_id = Arc::new(AtomicU64::new(1));
    let (open_stream_tx, open_stream_rx) = mpsc::channel::<ControlMessage>(32);
    let limiter = HandshakeLimiter::new();

    for link in &ctx.config.links {
        if link.mode == LinkMode::Reverse {
            let listen_addr = link
                .listen
                .clone()
                .expect("validated: reverse link on server requires listen");
            tokio::spawn(spawn_reverse_listener(
                link.id.clone(),
                listen_addr,
                pending.clone(),
                next_stream_id.clone(),
                open_stream_tx.clone(),
            ));
        }
    }

    let ipc_task = tokio::spawn(ipc::run_ipc_server(
        ctx.state.clone(),
        ctx.config.clone(),
        ctx.socket_path.clone(),
    ));

    let ctx_data = Arc::new(ctx);
    let ctx_control = ctx_data.clone();
    let pending_data = pending.clone();

    let control_limiter = limiter.clone();
    let data_limiter = limiter;
    let control_task = tokio::spawn(async move {
        run_control_accept_loop(ctx_control, listen_control, open_stream_rx, control_limiter).await
    });
    let data_task = tokio::spawn(async move {
        run_data_accept_loop(ctx_data, listen_data, pending_data, data_limiter).await
    });

    let _ = tokio::join!(control_task, data_task, ipc_task);
    Ok(())
}

async fn spawn_reverse_listener(
    link_id: String,
    listen_addr: String,
    pending: PendingStreams,
    next_stream_id: Arc<AtomicU64>,
    open_stream_tx: mpsc::Sender<ControlMessage>,
) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "ghostport: [{}] {}",
                theme::accent(&link_id),
                theme::err(&format!("failed to bind {listen_addr}: {e}"))
            );
            return;
        }
    };
    println!(
        "ghostport: [{}] {}",
        theme::accent(&link_id),
        theme::ok(&format!("listening on {listen_addr} (reverse)"))
    );

    loop {
        let (external_conn, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "ghostport: [{}] {}",
                    theme::accent(&link_id),
                    theme::err(&format!("accept failed: {e}"))
                );
                continue;
            }
        };
        let stream_id = next_stream_id.fetch_add(1, Ordering::Relaxed);
        pending.lock().await.insert(stream_id, external_conn);

        if open_stream_tx
            .send(ControlMessage::OpenStream {
                link_id: link_id.clone(),
                stream_id,
            })
            .await
            .is_err()
        {
            // No control session has ever connected (channel closed only
            // if the accept loop itself is gone) — nothing to do but drop.
            pending.lock().await.remove(&stream_id);
            eprintln!(
                "ghostport: [{}] {}",
                theme::accent(&link_id),
                theme::warn(&format!(
                    "{peer_addr}: control channel unavailable, dropping"
                ))
            );
            continue;
        }

        let link_id_cleanup = link_id.clone();
        let pending_cleanup = pending.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if pending_cleanup.lock().await.remove(&stream_id).is_some() {
                eprintln!(
                    "ghostport: [{}] {}",
                    theme::accent(&link_id_cleanup),
                    theme::warn(&format!(
                        "stream {stream_id} timed out waiting for the client to respond (offline?)"
                    ))
                );
            }
        });
    }
}

/// A connection that's completed its Noise handshake, handed from the
/// acceptor task to the session processor below, along with which
/// configured peer it matched.
type AuthenticatedControlConn = (NoiseStream<TcpStream>, std::net::SocketAddr, String);

async fn run_control_accept_loop(
    ctx: Arc<Context>,
    listen_addr: String,
    mut open_stream_rx: mpsc::Receiver<ControlMessage>,
    limiter: Arc<HandshakeLimiter>,
) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "ghostport: {}",
                theme::err(&format!(
                    "fatal: failed to bind control listener {listen_addr}: {e}"
                ))
            );
            return;
        }
    };
    println!(
        "ghostport: {}",
        theme::ok(&format!("control channel listening on {listen_addr}"))
    );

    // Accepting and handshaking happen in their own spawned task per
    // connection rather than inline in this loop -- a connection that
    // opens a socket and never sends a byte would otherwise hold up
    // *every* subsequent accept (including the real peer's) for up to
    // HANDSHAKE_TIMEOUT each time, since a naive single loop can't move
    // on to accept() again until the current handshake attempt resolves.
    // The rate limiter above only has teeth if bogus connections can't
    // starve it of the chance to even run. Sessions themselves are still
    // processed strictly one at a time below -- that part of the
    // original design (single pinned peer pair, only one session is
    // ever meaningful) is unchanged, just decoupled from accept-loop
    // liveness.
    let (authenticated_tx, mut authenticated_rx) = mpsc::channel::<AuthenticatedControlConn>(4);
    let accept_ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "ghostport: {}",
                        theme::err(&format!("control accept failed: {e}"))
                    );
                    continue;
                }
            };

            let Some(permit) = limiter.try_acquire(peer_addr.ip()).await else {
                eprintln!(
                    "ghostport: {}",
                    theme::warn(&format!(
                        "control: rejected {peer_addr} (too many recent handshake attempts)"
                    ))
                );
                continue;
            };

            let authenticated_tx = authenticated_tx.clone();
            let private_key = accept_ctx.private_key.clone();
            let peers = accept_ctx.peers.clone();
            tokio::spawn(async move {
                let mut tcp = tcp;
                let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                    let (peer_index, state) = peermatch::match_peer(&mut tcp, &private_key, &peers)
                        .await
                        .map_err(|e| e.to_string())?;
                    let stream = NoiseStream::handshake(tcp, state)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok::<_, String>((stream, peer_index))
                })
                .await;
                drop(permit);
                match result {
                    Ok(Ok((stream, peer_index))) => {
                        let _ = authenticated_tx
                            .send((stream, peer_addr, peers[peer_index].name.clone()))
                            .await;
                    }
                    Ok(Err(e)) => {
                        eprintln!(
                            "ghostport: {}",
                            theme::err(&format!("control: handshake with {peer_addr} failed: {e}"))
                        );
                    }
                    Err(_) => {
                        eprintln!(
                            "ghostport: {}",
                            theme::warn(&format!("control: handshake with {peer_addr} timed out"))
                        );
                    }
                }
            });
        }
    });

    while let Some((noise_stream, peer_addr, peer_name)) = authenticated_rx.recv().await {
        println!(
            "ghostport: {}",
            theme::ok(&format!(
                "control channel connected from {peer_addr} (peer \"{peer_name}\")"
            ))
        );
        ctx.state
            .control
            .set_connected(peer_addr.to_string(), Some(peer_name));

        let (mut read_half, mut write_half) = tokio::io::split(noise_stream);
        run_control_session(&mut read_half, &mut write_half, &mut open_stream_rx).await;
        ctx.state.control.set_disconnected();
        println!(
            "ghostport: {}",
            theme::warn(&format!(
                "control channel disconnected from {peer_addr}, awaiting reconnect"
            ))
        );
    }
}

async fn run_control_session(
    read_half: &mut ReadHalf<NoiseStream<TcpStream>>,
    write_half: &mut WriteHalf<NoiseStream<TcpStream>>,
    open_stream_rx: &mut mpsc::Receiver<ControlMessage>,
) {
    loop {
        tokio::select! {
            incoming = framing::recv_json::<ControlMessage>(read_half) => {
                match incoming {
                    Ok(ControlMessage::Ping) => {
                        if framing::send_json(write_half, &ControlMessage::Pong).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {} // Pong/OpenStream aren't expected from the client; ignore rather than error.
                    Err(_) => return,
                }
            }
            Some(msg) = open_stream_rx.recv() => {
                if framing::send_json(write_half, &msg).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn run_data_accept_loop(
    ctx: Arc<Context>,
    listen_addr: String,
    pending: PendingStreams,
    limiter: Arc<HandshakeLimiter>,
) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "ghostport: {}",
                theme::err(&format!(
                    "fatal: failed to bind data listener {listen_addr}: {e}"
                ))
            );
            return;
        }
    };
    println!(
        "ghostport: {}",
        theme::ok(&format!("data channel listening on {listen_addr}"))
    );

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "ghostport: {}",
                    theme::err(&format!("data accept failed: {e}"))
                );
                continue;
            }
        };

        let Some(permit) = limiter.try_acquire(peer_addr.ip()).await else {
            eprintln!(
                "ghostport: {}",
                theme::warn(&format!(
                    "data: rejected {peer_addr} (too many recent handshake attempts)"
                ))
            );
            continue;
        };

        let ctx = ctx.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_data_connection(ctx, tcp, pending, permit).await {
                eprintln!(
                    "ghostport: {}",
                    theme::err(&format!("data connection from {peer_addr}: {e}"))
                );
            }
        });
    }
}

async fn handle_data_connection(
    ctx: Arc<Context>,
    mut tcp: TcpStream,
    pending: PendingStreams,
    permit: OwnedSemaphorePermit,
) -> std::io::Result<()> {
    let (peer_index, mut tunnel) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (peer_index, state) = peermatch::match_peer(&mut tcp, &ctx.private_key, &ctx.peers)
            .await
            .map_err(|e| e.to_string())?;
        let stream = NoiseStream::handshake(tcp, state)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((peer_index, stream))
    })
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(std::io::Error::other(e)),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "handshake timed out",
            ))
        }
    };
    drop(permit);
    let matched_peer = &ctx.peers[peer_index];
    let hello: StreamHello = framing::recv_json(&mut tunnel).await?;

    if !matched_peer.links.contains(&hello.link_id) {
        return Err(std::io::Error::other(format!(
            "peer \"{}\" is not authorized for link \"{}\"",
            matched_peer.name, hello.link_id
        )));
    }

    let Some(link) = ctx.config.links.iter().find(|l| l.id == hello.link_id) else {
        return Err(std::io::Error::other(format!(
            "unknown link id \"{}\"",
            hello.link_id
        )));
    };

    let stats = ctx
        .state
        .links
        .get(&link.id)
        .expect("state's link map is built from this same config");

    match (link.mode, hello.stream_id) {
        (LinkMode::Forward, None) => {
            let target = link
                .target
                .clone()
                .expect("validated: forward link on server has target");
            let target_conn = TcpStream::connect(&target).await?;
            relay::relay(&link.id, stats, tunnel, target_conn).await;
            Ok(())
        }
        (LinkMode::Reverse, Some(stream_id)) => {
            let Some(external_conn) = pending.lock().await.remove(&stream_id) else {
                return Err(std::io::Error::other(format!(
                    "stream {stream_id} for link \"{}\" is unknown or already timed out",
                    link.id
                )));
            };
            relay::relay(&link.id, stats, tunnel, external_conn).await;
            Ok(())
        }
        _ => Err(std::io::Error::other(format!(
            "link \"{}\" mode/stream_id mismatch (protocol error)",
            link.id
        ))),
    }
}
