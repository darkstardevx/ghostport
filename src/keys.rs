//! Static Noise keypairs: generation, and loading/saving as base64 text
//! files — private + public halves saved as sibling files at generation
//! time (`identity.key` + `identity.key.pub`), same convention as SSH
//! keypairs, so nothing ever needs to re-derive a public key from a
//! private one later (not cleanly possible via snow's public API anyway
//! — its X25519 implementation is a private internal type). The private
//! key file is locked to 0600 on every write — same self-healing
//! approach as CyberVault's vault file, and for the same reason: this is
//! a secret that must never be group/world-readable. The public key file
//! carries no such requirement; it's meant to be shared with the peer.

use crate::noise::PATTERN;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct Keypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

pub fn generate() -> Keypair {
    let kp = snow::Builder::new(PATTERN.parse().expect("PATTERN is a valid Noise pattern string"))
        .generate_keypair()
        .expect("keypair generation only fails on RNG failure");
    Keypair { private: kp.private, public: kp.public }
}

/// The conventional public-key sibling path for a given private-key path
/// (`identity.key` -> `identity.key.pub`).
pub fn public_key_path(private_key_path: &Path) -> PathBuf {
    let mut s = private_key_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

pub fn save_private_key(path: &Path, private: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    write_base64_line(path, private)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Not secret — meant to be copied into the peer's config, so no
/// restrictive permissions are applied.
pub fn save_public_key(path: &Path, public: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_base64_line(path, public)
}

fn write_base64_line(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(base64_encode(bytes).as_bytes())?;
    file.write_all(b"\n")
}

pub fn load_private_key(path: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    decode_public_key(text.trim()).map_err(|e| format!("{} does not contain a valid key: {e}", path.display()))
}

pub fn encode_public_key(public: &[u8]) -> String {
    base64_encode(public)
}

pub fn decode_public_key(s: &str) -> Result<Vec<u8>, String> {
    let key = base64_decode(s.trim()).map_err(|e| format!("invalid base64 key: {e}"))?;
    if key.len() != 32 {
        return Err(format!("key must be 32 bytes, got {}", key.len()));
    }
    Ok(key)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ghostport-keys-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("identity.key")
    }

    #[test]
    fn generated_keypair_has_32_byte_keys() {
        let kp = generate();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn private_key_save_and_load_round_trip() {
        let path = scratch_path("roundtrip");
        let kp = generate();
        save_private_key(&path, &kp.private).unwrap();

        let loaded = load_private_key(&path).unwrap();
        assert_eq!(loaded, kp.private);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn saved_private_key_file_is_owner_only() {
        let path = scratch_path("perms");
        let kp = generate();
        save_private_key(&path, &kp.private).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn public_key_saved_as_sibling_pub_file() {
        let path = scratch_path("sibling");
        let kp = generate();
        let pub_path = public_key_path(&path);
        save_public_key(&pub_path, &kp.public).unwrap();

        assert_eq!(pub_path, PathBuf::from(format!("{}.pub", path.display())));
        let text = std::fs::read_to_string(&pub_path).unwrap();
        assert_eq!(decode_public_key(text.trim()).unwrap(), kp.public);
        std::fs::remove_file(&pub_path).ok();
    }

    #[test]
    fn public_key_encode_decode_round_trip() {
        let kp = generate();
        let encoded = encode_public_key(&kp.public);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, kp.public);
    }

    #[test]
    fn rejects_wrong_length_public_key() {
        let short = base64_encode(&[1, 2, 3]);
        assert!(decode_public_key(&short).is_err());
    }
}
