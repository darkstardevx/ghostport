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
use crate::protocol::{ControlMessage, StreamHello};
use crate::{framing, noise, relay};
use snowstorm::NoiseStream;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Streams accepted on a `reverse`-mode link's listener, waiting to be
/// claimed by a data-tunnel connection the client dials in response to
/// the `OpenStream` signal. Removed either when claimed, or by the
/// per-entry timeout in `spawn_reverse_listener` if the client never
/// answers (e.g. it's offline).
type PendingStreams = Arc<Mutex<HashMap<u64, TcpStream>>>;

pub struct Context {
    pub config: Arc<Config>,
    pub private_key: Arc<Vec<u8>>,
    pub peer_public_key: Arc<Vec<u8>>,
}

pub async fn run(ctx: Context) -> std::io::Result<()> {
    let listen_control = ctx.config.listen_control.clone().expect("validated: server role requires listen_control");
    let listen_data = ctx.config.listen_data.clone().expect("validated: server role requires listen_data");

    let pending: PendingStreams = Arc::new(Mutex::new(HashMap::new()));
    let next_stream_id = Arc::new(AtomicU64::new(1));
    let (open_stream_tx, open_stream_rx) = mpsc::channel::<ControlMessage>(32);

    for link in &ctx.config.links {
        if link.mode == LinkMode::Reverse {
            let listen_addr = link.listen.clone().expect("validated: reverse link on server requires listen");
            tokio::spawn(spawn_reverse_listener(link.id.clone(), listen_addr, pending.clone(), next_stream_id.clone(), open_stream_tx.clone()));
        }
    }

    let ctx_data = Arc::new(ctx);
    let ctx_control = ctx_data.clone();
    let pending_data = pending.clone();

    let control_task = tokio::spawn(async move { run_control_accept_loop(ctx_control, listen_control, open_stream_rx).await });
    let data_task = tokio::spawn(async move { run_data_accept_loop(ctx_data, listen_data, pending_data).await });

    let _ = tokio::join!(control_task, data_task);
    Ok(())
}

async fn spawn_reverse_listener(link_id: String, listen_addr: String, pending: PendingStreams, next_stream_id: Arc<AtomicU64>, open_stream_tx: mpsc::Sender<ControlMessage>) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ghostport: [{link_id}] failed to bind {listen_addr}: {e}");
            return;
        }
    };
    println!("ghostport: [{link_id}] listening on {listen_addr} (reverse)");

    loop {
        let (external_conn, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ghostport: [{link_id}] accept failed: {e}");
                continue;
            }
        };
        let stream_id = next_stream_id.fetch_add(1, Ordering::Relaxed);
        pending.lock().await.insert(stream_id, external_conn);

        if open_stream_tx.send(ControlMessage::OpenStream { link_id: link_id.clone(), stream_id }).await.is_err() {
            // No control session has ever connected (channel closed only
            // if the accept loop itself is gone) — nothing to do but drop.
            pending.lock().await.remove(&stream_id);
            eprintln!("ghostport: [{link_id}] {peer_addr}: control channel unavailable, dropping");
            continue;
        }

        let link_id_cleanup = link_id.clone();
        let pending_cleanup = pending.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if pending_cleanup.lock().await.remove(&stream_id).is_some() {
                eprintln!("ghostport: [{link_id_cleanup}] stream {stream_id} timed out waiting for the client to respond (offline?)");
            }
        });
    }
}

async fn run_control_accept_loop(ctx: Arc<Context>, listen_addr: String, mut open_stream_rx: mpsc::Receiver<ControlMessage>) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ghostport: fatal: failed to bind control listener {listen_addr}: {e}");
            return;
        }
    };
    println!("ghostport: control channel listening on {listen_addr}");

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ghostport: control accept failed: {e}");
                continue;
            }
        };

        let handshake = match noise::responder(&ctx.private_key, &ctx.peer_public_key) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ghostport: control: failed to build handshake state: {e}");
                continue;
            }
        };
        let noise_stream = match NoiseStream::handshake(tcp, handshake).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ghostport: control: handshake with {peer_addr} failed (wrong key?): {e}");
                continue;
            }
        };
        println!("ghostport: control channel connected from {peer_addr}");

        let (mut read_half, mut write_half) = tokio::io::split(noise_stream);
        run_control_session(&mut read_half, &mut write_half, &mut open_stream_rx).await;
        println!("ghostport: control channel disconnected from {peer_addr}, awaiting reconnect");
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

async fn run_data_accept_loop(ctx: Arc<Context>, listen_addr: String, pending: PendingStreams) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ghostport: fatal: failed to bind data listener {listen_addr}: {e}");
            return;
        }
    };
    println!("ghostport: data channel listening on {listen_addr}");

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ghostport: data accept failed: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_data_connection(ctx, tcp, pending).await {
                eprintln!("ghostport: data connection from {peer_addr}: {e}");
            }
        });
    }
}

async fn handle_data_connection(ctx: Arc<Context>, tcp: TcpStream, pending: PendingStreams) -> std::io::Result<()> {
    let handshake = noise::responder(&ctx.private_key, &ctx.peer_public_key).map_err(std::io::Error::other)?;
    let mut tunnel = NoiseStream::handshake(tcp, handshake).await.map_err(std::io::Error::other)?;
    let hello: StreamHello = framing::recv_json(&mut tunnel).await?;

    let Some(link) = ctx.config.links.iter().find(|l| l.id == hello.link_id) else {
        return Err(std::io::Error::other(format!("unknown link id \"{}\"", hello.link_id)));
    };

    match (link.mode, hello.stream_id) {
        (LinkMode::Forward, None) => {
            let target = link.target.clone().expect("validated: forward link on server has target");
            let target_conn = TcpStream::connect(&target).await?;
            relay::relay(&link.id, tunnel, target_conn).await;
            Ok(())
        }
        (LinkMode::Reverse, Some(stream_id)) => {
            let Some(external_conn) = pending.lock().await.remove(&stream_id) else {
                return Err(std::io::Error::other(format!("stream {stream_id} for link \"{}\" is unknown or already timed out", link.id)));
            };
            relay::relay(&link.id, tunnel, external_conn).await;
            Ok(())
        }
        _ => Err(std::io::Error::other(format!("link \"{}\" mode/stream_id mismatch (protocol error)", link.id))),
    }
}
