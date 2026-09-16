//! Noise handshake setup. Uses `Noise_KK` — both peers already know each
//! other's static public key ahead of time (pinned in config), which is
//! exactly what `KK` is for. This matters: unlike `IK`/`XX`, a peer that
//! doesn't hold the private key matching the *expected* remote public
//! key simply can't complete the handshake at all — there's no separate
//! "check the identity after the fact" step needed, the cryptography
//! itself refuses an impostor.

pub const PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

fn builder<'a>(local_private: &'a [u8], remote_public: &'a [u8]) -> snow::Builder<'a> {
    snow::Builder::new(
        PATTERN
            .parse()
            .expect("PATTERN is a valid Noise pattern string"),
    )
    .local_private_key(local_private)
    .remote_public_key(remote_public)
}

pub fn initiator(
    local_private: &[u8],
    remote_public: &[u8],
) -> Result<snow::HandshakeState, String> {
    builder(local_private, remote_public)
        .build_initiator()
        .map_err(|e| format!("failed to build Noise initiator: {e}"))
}

pub fn responder(
    local_private: &[u8],
    remote_public: &[u8],
) -> Result<snow::HandshakeState, String> {
    builder(local_private, remote_public)
        .build_responder()
        .map_err(|e| format!("failed to build Noise responder: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    #[test]
    fn matching_pinned_keys_let_initiator_and_responder_build() {
        let a = keys::generate();
        let b = keys::generate();
        assert!(initiator(&a.private, &b.public).is_ok());
        assert!(responder(&b.private, &a.public).is_ok());
    }
}
