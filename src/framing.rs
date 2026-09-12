//! Length-prefixed JSON messages over any `AsyncRead`/`AsyncWrite` —
//! used for `protocol::ControlMessage`/`StreamHello` on top of an
//! already-encrypted `NoiseStream`. `read_exact` correctly reassembles
//! bytes regardless of how `NoiseStream` chunks its internal Noise
//! messages, so this framing is unaffected by that internal chunking.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bounds a malformed/hostile length prefix from causing an unbounded
/// allocation — control/hello messages are always tiny in practice.
const MAX_MESSAGE_LEN: u32 = 64 * 1024;

pub async fn send_json<T: Serialize>(stream: &mut (impl AsyncWrite + Unpin), msg: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub async fn recv_json<T: DeserializeOwned>(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<T> {
    let len = stream.read_u32_le().await?;
    if len > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("framed message length {len} exceeds max {MAX_MESSAGE_LEN}")));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Sample {
        a: u32,
        b: String,
    }

    #[tokio::test]
    async fn round_trips_over_an_in_memory_duplex() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = Sample { a: 42, b: "hello".to_string() };

        send_json(&mut a, &msg).await.unwrap();
        let received: Sample = recv_json(&mut b).await.unwrap();

        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_u32_le(MAX_MESSAGE_LEN + 1).await.unwrap();

        let result: std::io::Result<Sample> = recv_json(&mut b).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn two_messages_in_sequence_dont_interfere() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let first = Sample { a: 1, b: "one".to_string() };
        let second = Sample { a: 2, b: "two".to_string() };

        send_json(&mut a, &first).await.unwrap();
        send_json(&mut a, &second).await.unwrap();

        let r1: Sample = recv_json(&mut b).await.unwrap();
        let r2: Sample = recv_json(&mut b).await.unwrap();
        assert_eq!(r1, first);
        assert_eq!(r2, second);
    }
}
