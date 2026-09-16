//! GhostPort's first real plugin crate — Noise-authenticated UDP
//! forwarding. Depends on `ghostport-core` the same way any future
//! plugin crate would (see `ghostport_core`'s own crate doc "Status"
//! section: this crate is the real second consumer that validated the
//! library extraction, rather than a guessed-at trait boundary).
//!
//! # Status: v1, forward-mode only
//!
//! - **No reverse-mode UDP** — would need the control channel's
//!   `OpenStream`-style signaling, since the client can't be dialed.
//!   Rejected outright by `ghostport_core::config::Config::validate`.
//! - **No NAT-rebind session migration** — a session is identified by
//!   source address; if it changes mid-session, the old session just
//!   times out and a new handshake starts.
//! - **No rekeying** — a session's transport key lives for the
//!   session's lifetime.
//! - **No real replay-window enforcement** — `snowstorm`'s
//!   `PacketVerifier` hook exists and is real, wired to the default
//!   no-op (`()`) for v1.
//!
//! # How it authenticates
//!
//! Still `Noise_KK`, still the exact same pinned-key guarantee the TCP
//! path has (`ghostport_core::noise`/`peermatch` are reused directly,
//! not reimplemented). The handshake itself runs over the real UDP
//! socket via `snowstorm::NoiseSocket` — `ghostport-core` already
//! depends on `snowstorm` for its TCP `NoiseStream`; this is that same
//! crate's sibling API for datagram transports, not a new protocol
//! invented for this crate.
//!
//! # Layout
//!
//! - [`server`] — the server role: one shared UDP socket, demuxed by
//!   source address into per-flow sessions.
//! - [`client`] — the client role: one local UDP listen socket per
//!   link, demuxed by local source address into per-flow sessions that
//!   each dial their own dedicated session to the server.

#![warn(missing_docs)]

pub mod client;
mod poller;
pub mod server;
