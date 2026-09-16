//! The forwarding engine behind `ghostport` — encrypted, NAT-traversing
//! port forwarding over a real Noise handshake (`Noise_KK`), with no
//! CLI or TUI dependencies. Extracted from the `ghostport` binary so a
//! real second consumer has an actual library to depend on, not a
//! private module inside someone else's binary.
//!
//! # Status
//!
//! This is the same engine `ghostport` itself uses — extracted, not
//! rewritten. `ghostport-udp` (UDP forwarding, forward-mode only) is
//! now a real second consumer — the first plugin crate, proving the
//! extraction actually works rather than just being a guess at what
//! one might need. It reuses this crate's [`noise`]/[`peermatch`]
//! directly (still `Noise_KK`, same pinned-key guarantee) rather than
//! inventing its own handshake. No plugin *trait* boundary exists yet
//! — `ghostport-udp` calls this crate's concrete functions directly,
//! which was enough; a trait is still deferred until a second plugin
//! actually needs one, rather than guessed at now.
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
