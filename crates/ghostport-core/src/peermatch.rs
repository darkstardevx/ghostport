//! Matches an incoming Noise handshake attempt against one of several
//! allowed peers, for the server role. `Noise_KK` requires the
//! responder to already have the correct remote static key loaded
//! before `read_message()` on the first handshake message can even be
//! attempted — unlike `IK`/`XX`, there's no way to "peek" at the
//! sender's identity first. With more than one allowed peer, the only
//! correct way to find out which one this is is to try each one's key
//! against the same message: `HandshakeState::read_message` is a pure
//! in-memory function (no I/O, doesn't consume or mutate its input),
//! and `KK`'s `ss` DH token means a wrong candidate key cryptographically
//! cannot produce a matching AEAD tag on message 1's payload —
//! `read_message` is guaranteed to fail for every non-matching
//! candidate, not just likely to fail. Verified against `snow` 0.9.6's
//! and `snowstorm` 0.4.0's real source before relying on this, not
//! assumed: `snowstorm`'s own internal handshake loop
//! (`stream.rs::handshake_with_verifier`) reads a message the exact
//! same way this does — a `u16` LE length prefix, then exactly that
//! many raw bytes — before ever touching `HandshakeState`.

use crate::noise;
use std::collections::HashSet;
use tokio::io::{AsyncRead, AsyncReadExt};

/// One allowed peer, resolved from config into the form `match_peer`
/// needs: the raw public key to try, and which link IDs this peer is
/// permitted to use.
pub struct ResolvedPeer {
    /// The peer's name, as given in config — for logging only.
    pub name: String,
    /// The peer's raw 32-byte static Noise public key.
    pub public_key: Vec<u8>,
    /// Link IDs this peer is allowed to open a data-channel stream on.
    pub links: HashSet<String>,
}

/// Why [`match_peer`] failed.
#[derive(Debug)]
pub enum MatchError {
    /// The underlying TCP read failed before a full handshake message
    /// could even be assembled.
    Io(std::io::Error),
    /// A complete handshake message was read, but no configured peer's
    /// key produced a valid `read_message` result for it.
    NoMatch,
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchError::Io(e) => write!(f, "{e}"),
            MatchError::NoMatch => write!(f, "no configured peer matched"),
        }
    }
}

/// Reads the first handshake message directly off `tcp` (a `u16`-LE
/// length prefix, then that many raw bytes — the same framing
/// `snowstorm`'s own `NoiseStream::handshake` uses) and tries it
/// against each of `peers` via [`match_peer_bytes`]. Returns the
/// matched peer's index and the now-advanced `HandshakeState` — hand it
/// straight to `NoiseStream::handshake` to finish the exchange.
pub async fn match_peer<T: AsyncRead + Unpin>(
    tcp: &mut T,
    private_key: &[u8],
    peers: &[ResolvedPeer],
) -> Result<(usize, snow::HandshakeState), MatchError> {
    let len = tcp.read_u16_le().await.map_err(MatchError::Io)? as usize;
    let mut message = vec![0u8; len];
    tcp.read_exact(&mut message).await.map_err(MatchError::Io)?;
    match_peer_bytes(&message, private_key, peers)
}

/// The transport-agnostic core of peer matching: tries `message`
/// (one complete handshake message — already framed/delimited by
/// whatever transport received it) against each of `peers` in turn.
/// `match_peer` (TCP) is a thin length-prefixed-stream-reading wrapper
/// around this; a UDP transport can call it directly, since a UDP
/// datagram already arrives as one complete message with no framing
/// needed.
pub fn match_peer_bytes(
    message: &[u8],
    private_key: &[u8],
    peers: &[ResolvedPeer],
) -> Result<(usize, snow::HandshakeState), MatchError> {
    let mut payload = vec![0u8; message.len()];
    for (index, peer) in peers.iter().enumerate() {
        let Ok(mut state) = noise::responder(private_key, &peer.public_key) else {
            continue;
        };
        if state.read_message(message, &mut payload).is_ok() {
            return Ok((index, state));
        }
    }
    Err(MatchError::NoMatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use snowstorm::NoiseStream;
    use tokio::net::{TcpListener, TcpStream};

    fn resolved(name: &str, public_key: Vec<u8>, links: &[&str]) -> ResolvedPeer {
        ResolvedPeer {
            name: name.to_string(),
            public_key,
            links: links.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Drives a real initiator handshake against `tcp` in the
    /// background so `match_peer` has a genuine message 1 to read —
    /// exercising the real wire format, not a hand-constructed buffer.
    fn spawn_initiator(tcp: TcpStream, initiator_private: Vec<u8>, responder_public: Vec<u8>) {
        tokio::spawn(async move {
            let handshake = noise::initiator(&initiator_private, &responder_public).unwrap();
            let _ = NoiseStream::handshake(tcp, handshake).await;
        });
    }

    #[tokio::test]
    async fn matches_the_correct_candidate_when_it_is_not_first() {
        let responder_kp = keys::generate();
        let initiator_kp = keys::generate();
        let decoy_kp = keys::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        spawn_initiator(
            client,
            initiator_kp.private.clone(),
            responder_kp.public.clone(),
        );
        let (mut server_side, _) = listener.accept().await.unwrap();

        let peers = vec![
            resolved("decoy", decoy_kp.public.clone(), &["a"]),
            resolved("real", initiator_kp.public.clone(), &["b"]),
        ];

        let (index, state) = match_peer(&mut server_side, &responder_kp.private, &peers)
            .await
            .unwrap();
        assert_eq!(index, 1);
        assert!(
            state.is_my_turn(),
            "responder should be ready to write message 2 next"
        );
    }

    #[tokio::test]
    async fn no_candidate_matches_an_unrecognized_key() {
        let responder_kp = keys::generate();
        let initiator_kp = keys::generate();
        let stranger_kp = keys::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        spawn_initiator(
            client,
            initiator_kp.private.clone(),
            responder_kp.public.clone(),
        );
        let (mut server_side, _) = listener.accept().await.unwrap();

        // Only the stranger's key is allowed -- the real initiator's
        // key isn't in the list at all.
        let peers = vec![resolved("stranger", stranger_kp.public.clone(), &["a"])];

        let result = match_peer(&mut server_side, &responder_kp.private, &peers).await;
        assert!(matches!(result, Err(MatchError::NoMatch)));
    }

    /// `match_peer_bytes` is what a UDP transport calls directly (a
    /// datagram already arrives as one complete message — no framing to
    /// strip first). Proven against a real handshake message-1 buffer,
    /// not a hand-constructed one: drive a real initiator handshake over
    /// a real TCP connection (same as the other tests here), but instead
    /// of handing the stream to `match_peer`, read the length-prefixed
    /// message off it manually and hand just the raw bytes to
    /// `match_peer_bytes` — exactly what a UDP `recv_from` would already
    /// have handed us, with no framing step of its own needed.
    #[tokio::test]
    async fn match_peer_bytes_matches_a_real_message_one_buffer() {
        let responder_kp = keys::generate();
        let initiator_kp = keys::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        spawn_initiator(
            client,
            initiator_kp.private.clone(),
            responder_kp.public.clone(),
        );
        let (mut server_side, _) = listener.accept().await.unwrap();

        let len = server_side.read_u16_le().await.unwrap() as usize;
        let mut message = vec![0u8; len];
        server_side.read_exact(&mut message).await.unwrap();

        let peers = vec![resolved("real", initiator_kp.public.clone(), &["a"])];
        let (index, state) = match_peer_bytes(&message, &responder_kp.private, &peers).unwrap();
        assert_eq!(index, 0);
        assert!(state.is_my_turn());
    }
}
