//! The forwarding engine behind `ghostport` — encrypted, NAT-traversing
//! port forwarding over a real Noise handshake (`Noise_KK`), with no
//! CLI or TUI dependencies. Extracted from the `ghostport` binary so a
//! real second consumer (a future plugin crate, e.g.
//! `ghostport-wireguard`, using this crate's peer-authenticated
//! control channel to provision something else) has an actual library
//! to depend on, not a private module inside someone else's binary.
//!
//! # Status
//!
//! This is the same engine `ghostport` itself uses — extracted, not
//! rewritten. No plugin trait boundary exists yet (deliberately —
//! designing one before a real second consumer exists to validate it
//! against would mean guessing). This crate's job right now is just to
//! have a real, documented, usable public API.
//!
//! # Layout
//!
//! - [`config`] — the TOML config schema (`Config`, `PeerConfig`,
//!   `LinkConfig`) and its validation.
//! - [`keys`] — static Noise keypair generation/storage and
//!   fingerprinting.
//! - [`noise`] — `Noise_KK_25519_ChaChaPoly_BLAKE2s` handshake state
//!   builders.
//! - [`peermatch`] — matches an incoming handshake against one of
//!   several allowed peers (server role).
//! - [`protocol`] / [`framing`] — the small control-channel/stream-hello
//!   messages, and how they're framed on top of an already-encrypted
//!   stream.
//! - [`ratelimit`] — the connection-flood limiter guarding the
//!   handshake path.
//! - [`relay`] — the bidirectional byte relay once a tunnel is
//!   authenticated.
//! - [`stats`] — live runtime state (link byte/stream counters, control
//!   connection status) shared with the status IPC socket.
//! - [`server`] / [`client`] — the two roles: `server::run` (always
//!   reachable, accepts both channels) and `client::run` (dials out
//!   only, works from behind NAT).
//! - [`ipc`] — the status Unix-socket protocol (`ghostport status`/the
//!   TUI both query this).
//! - [`theme`] — small ANSI color helpers for the daemon roles' own
//!   connection-lifecycle logging (moved here from the binary once it
//!   turned out `server`/`client`/`relay` depend on it directly, not
//!   just CLI presentation).

#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod framing;
pub mod ipc;
pub mod keys;
pub mod noise;
pub mod peermatch;
pub mod protocol;
pub mod ratelimit;
pub mod relay;
pub mod server;
pub mod stats;
pub mod theme;
