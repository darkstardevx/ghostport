//! `snowstorm::PacketPoller` adapts a datagram transport for
//! `NoiseSocket`. Both adapters here wrap a real `tokio::net::UdpSocket`
//! in a local newtype — Rust's orphan rules block implementing a
//! foreign trait (`PacketPoller`, from `snowstorm`) for a foreign type
//! (`UdpSocket`, from `tokio`) directly from this crate.

use snowstorm::PacketPoller;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Wraps a `UdpSocket` already `connect()`-ed to exactly one peer — the
/// client's shape, since it opens one dedicated socket per local flow.
pub(crate) struct ConnectedPoller(pub UdpSocket);

impl PacketPoller for ConnectedPoller {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<()>> {
        self.0.poll_send(cx, buf).map_ok(|_| ())
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
}

/// One session's view of the server's single shared listening socket.
/// Sends go straight to `peer_addr` via `send_to` — the real socket is
/// never exclusively "owned" by one session, so this can't `connect()`
/// it the way the client side does. Receives come from `inbound`, fed
/// by the central demux loop in `server.rs`, which is the only task
/// that ever calls `recv_from` on the real socket and routes each
/// datagram to the right session by source address.
pub(crate) struct SharedPeerPoller {
    pub socket: Arc<UdpSocket>,
    pub peer_addr: SocketAddr,
    pub inbound: mpsc::Receiver<Vec<u8>>,
}

impl PacketPoller for SharedPeerPoller {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<()>> {
        self.socket
            .poll_send_to(cx, buf, self.peer_addr)
            .map_ok(|_| ())
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.inbound.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                buf.put_slice(&datagram);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
