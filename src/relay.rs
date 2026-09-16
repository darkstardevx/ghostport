//! Bidirectional byte relay between an encrypted tunnel stream and a
//! plaintext local connection (the accepted local app, or the dialed
//! real destination). `tokio::io::copy_bidirectional` does the actual
//! work — `NoiseStream` already implements `AsyncRead + AsyncWrite`, so
//! there's nothing tunnel-specific to hand-roll here.

use crate::stats::LinkStats;
use crate::theme;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn relay<A, B>(link_id: &str, stats: &LinkStats, mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    stats.active_streams.fetch_add(1, Relaxed);
    stats.total_streams.fetch_add(1, Relaxed);

    let result = tokio::io::copy_bidirectional(&mut a, &mut b).await;

    stats.active_streams.fetch_sub(1, Relaxed);
    match result {
        Ok((a_to_b, b_to_a)) => {
            stats.bytes_forward.fetch_add(a_to_b, Relaxed);
            stats.bytes_back.fetch_add(b_to_a, Relaxed);
            println!(
                "ghostport: [{}] stream closed ({a_to_b} bytes forward, {b_to_a} bytes back)",
                theme::accent(link_id)
            );
        }
        Err(e) => {
            eprintln!(
                "ghostport: [{}] {}",
                theme::accent(link_id),
                theme::err(&format!("stream ended with an error: {e}"))
            );
        }
    }
}
