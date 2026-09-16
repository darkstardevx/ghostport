//! Small JSON messages exchanged over already-Noise-encrypted streams.
//! These never touch the network in plaintext — they ride on top of a
//! `snowstorm::NoiseStream`, which is itself already an
//! `AsyncRead + AsyncWrite`, so `framing::send_json`/`recv_json` treat it
//! like any other stream. Bulk data (the actual proxied bytes, once a
//! link's target is dialed) is *not* one of these messages — it's raw
//! bytes relayed directly via `tokio::io::copy_bidirectional`.

use serde::{Deserialize, Serialize};

/// Sent on the persistent control connection.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ControlMessage {
    /// Liveness probe; the receiving side replies with [`ControlMessage::Pong`].
    Ping,
    /// Reply to [`ControlMessage::Ping`].
    Pong,
    /// Sent by the server when a `reverse`-mode link needs a stream: the
    /// client can't be dialed directly (assumed to be behind NAT), so
    /// this asks it to dial a fresh data-tunnel connection itself and
    /// identify it with `stream_id`.
    OpenStream {
        /// Which configured link this stream is for.
        link_id: String,
        /// Correlates the client's resulting data-tunnel connection
        /// back to the specific accepted connection that triggered it.
        stream_id: u64,
    },
}

/// The first message sent on every freshly-dialed data-tunnel connection
/// (always dialed by the client, per the client-always-dials-out model —
/// see server.rs/client.rs module docs), right after the Noise handshake
/// completes. Tells the accepting side (always the server) which link
/// this stream belongs to, and — for a reverse-mode stream opened in
/// response to `ControlMessage::OpenStream` — which pending accepted
/// connection to pair it with.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StreamHello {
    /// Which configured link this stream carries traffic for.
    pub link_id: String,
    /// Set only when this stream is answering a
    /// [`ControlMessage::OpenStream`] request, so the server can pair
    /// it with the accepted connection that triggered it.
    pub stream_id: Option<u64>,
}
