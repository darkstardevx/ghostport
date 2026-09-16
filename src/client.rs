//! Client role: assumed to be behind NAT/unpredictable networks (the
//! laptop, on whatever WiFi). Never accepts an inbound connection from
//! the peer — only ever dials out, both for the persistent control
//! connection and for every data-tunnel connection, including the ones
//! that fulfill a `reverse`-mode link (dialed in response to the
//! server's `OpenStream` signal, not accepted directly).

use crate::config::{Config, LinkMode};
use crate::protocol::{ControlMessage, StreamHello};
use crate::stats::SharedState;
use crate::{framing, ipc, noise, relay, theme};
use snowstorm::NoiseStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Mirrors `server::HANDSHAKE_TIMEOUT` — a hung dial (e.g. a network
/// intermediary that accepts the TCP connection but never completes the
/// Noise exchange) would otherwise block the client's connect path
/// indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Context {
    pub config: Arc<Config>,
    pub private_key: Arc<Vec<u8>>,
    pub peer_public_key: Arc<Vec<u8>>,
    pub state: Arc<SharedState>,
    /// Where this instance's status IPC socket lives. Not always the
    /// default — running both roles on one machine (e.g. a local demo)
    /// needs two distinct paths, since two daemons can't share one
    /// socket file.
    pub socket_path: PathBuf,
}

pub async fn run(ctx: Context) -> std::io::Result<()> {
    let ctx = Arc::new(ctx);

    tokio::spawn(ipc::run_ipc_server(
        ctx.state.clone(),
        ctx.config.clone(),
        ctx.socket_path.clone(),
    ));

    for link in &ctx.config.links {
        if link.mode == LinkMode::Forward {
            let listen_addr = link
                .listen
                .clone()
                .expect("validated: forward link on client requires listen");
            tokio::spawn(run_forward_listener(
                ctx.clone(),
                link.id.clone(),
                listen_addr,
            ));
        }
    }

    run_control_loop(ctx).await;
    Ok(())
}

async fn run_forward_listener(ctx: Arc<Context>, link_id: String, listen_addr: String) {
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
        theme::ok(&format!("listening on {listen_addr} (forward)"))
    );

    loop {
        let (local_conn, peer_addr) = match listener.accept().await {
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
        let ctx = ctx.clone();
        let link_id = link_id.clone();
        tokio::spawn(async move {
            if let Err(e) = dial_data_tunnel_and_relay(&ctx, &link_id, None, local_conn).await {
                eprintln!(
                    "ghostport: [{}] {}",
                    theme::accent(&link_id),
                    theme::err(&format!("{peer_addr}: {e}"))
                );
            }
        });
    }
}

/// Dials a fresh data-tunnel connection (server always accepts these),
/// identifies it via `StreamHello`, then relays against `local_conn` —
/// used both for forward-mode (`stream_id: None`, triggered by a local
/// accept) and reverse-mode (`stream_id: Some(_)`, triggered by an
/// `OpenStream` signal).
async fn dial_data_tunnel_and_relay(
    ctx: &Context,
    link_id: &str,
    stream_id: Option<u64>,
    local_conn: TcpStream,
) -> std::io::Result<()> {
    let server_data_addr = ctx
        .config
        .server_data_addr
        .clone()
        .expect("validated: client role requires server_data_addr");
    let tcp = TcpStream::connect(&server_data_addr).await?;
    let handshake =
        noise::initiator(&ctx.private_key, &ctx.peer_public_key).map_err(std::io::Error::other)?;
    let mut tunnel =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, NoiseStream::handshake(tcp, handshake)).await
        {
            Ok(result) => result.map_err(std::io::Error::other)?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "handshake timed out",
                ))
            }
        };
    framing::send_json(
        &mut tunnel,
        &StreamHello {
            link_id: link_id.to_string(),
            stream_id,
        },
    )
    .await?;
    let stats = ctx
        .state
        .links
        .get(link_id)
        .expect("state's link map is built from this same config");
    relay::relay(link_id, stats, tunnel, local_conn).await;
    Ok(())
}

/// Reconnect-with-backoff loop around the persistent control channel.
/// Ping/Pong every 15s serves two purposes: keeps intermediate NAT
/// mappings alive (many drop an idle TCP connection after a few minutes
/// of silence — a real concern given this is designed to run over
/// unpredictable consumer WiFi), and gives basic liveness visibility.
/// It does *not* implement a deadline-based dead-peer eviction — a read
/// or write error is what actually triggers a reconnect; a connection
/// that's silently half-dead (open but unresponsive) without ever
/// erroring is a known gap, not worth the added complexity for v1.
async fn run_control_loop(ctx: Arc<Context>) {
    let server_control_addr = ctx
        .config
        .server_control_addr
        .clone()
        .expect("validated: client role requires server_control_addr");
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);

    loop {
        match connect_control(&ctx, &server_control_addr).await {
            Ok(mut noise_stream) => {
                println!(
                    "ghostport: {}",
                    theme::ok(&format!(
                        "control channel connected to {server_control_addr}"
                    ))
                );
                ctx.state
                    .control
                    .set_connected(server_control_addr.clone(), None);
                backoff = Duration::from_secs(1);
                run_control_session(&ctx, &mut noise_stream).await;
                ctx.state.control.set_disconnected();
                println!(
                    "ghostport: {}",
                    theme::warn("control channel disconnected, reconnecting...")
                );
            }
            Err(e) => {
                eprintln!(
                    "ghostport: {}",
                    theme::err(&format!(
                        "control channel connect to {server_control_addr} failed: {e}"
                    ))
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect_control(ctx: &Context, addr: &str) -> std::io::Result<NoiseStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let handshake =
        noise::initiator(&ctx.private_key, &ctx.peer_public_key).map_err(std::io::Error::other)?;
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, NoiseStream::handshake(tcp, handshake)).await {
        Ok(result) => result.map_err(std::io::Error::other),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "handshake timed out",
        )),
    }
}

async fn run_control_session(ctx: &Arc<Context>, noise_stream: &mut NoiseStream<TcpStream>) {
    let mut ping_interval = tokio::time::interval(Duration::from_secs(15));
    ping_interval.tick().await; // first tick fires immediately; consume it

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                if framing::send_json(noise_stream, &ControlMessage::Ping).await.is_err() {
                    return;
                }
            }
            incoming = framing::recv_json::<ControlMessage>(noise_stream) => {
                match incoming {
                    Ok(ControlMessage::Pong) => {}
                    Ok(ControlMessage::Ping) => {
                        if framing::send_json(noise_stream, &ControlMessage::Pong).await.is_err() {
                            return;
                        }
                    }
                    Ok(ControlMessage::OpenStream { link_id, stream_id }) => {
                        if !link_expects_reverse(&ctx.config, &link_id) {
                            eprintln!("ghostport: {}", theme::warn(&format!("received OpenStream for unknown/non-reverse link \"{link_id}\", ignoring")));
                            continue;
                        }
                        let ctx = ctx.clone();
                        tokio::spawn(async move { handle_open_stream(ctx, link_id, stream_id).await; });
                    }
                    Err(_) => return,
                }
            }
        }
    }
}

fn link_expects_reverse(config: &Config, link_id: &str) -> bool {
    config
        .links
        .iter()
        .any(|l| l.id == link_id && l.mode == LinkMode::Reverse)
}

async fn handle_open_stream(ctx: Arc<Context>, link_id: String, stream_id: u64) {
    let Some(link) = ctx.config.links.iter().find(|l| l.id == link_id) else {
        return;
    };
    let Some(target) = link.target.clone() else {
        eprintln!(
            "ghostport: [{}] {}",
            theme::accent(&link_id),
            theme::err(&format!(
                "reverse link has no target configured, can't fulfill stream {stream_id}"
            ))
        );
        return;
    };
    let local_conn = match TcpStream::connect(&target).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "ghostport: [{}] {}",
                theme::accent(&link_id),
                theme::err(&format!("failed to connect to target {target}: {e}"))
            );
            return;
        }
    };
    if let Err(e) = dial_data_tunnel_and_relay(&ctx, &link_id, Some(stream_id), local_conn).await {
        eprintln!(
            "ghostport: [{}] {}",
            theme::accent(&link_id),
            theme::err(&format!("stream {stream_id}: {e}"))
        );
    }
}
