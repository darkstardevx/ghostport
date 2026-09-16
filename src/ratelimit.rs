//! Guards the control/data listeners against unauthenticated connection
//! floods: a global cap on concurrent in-flight Noise handshakes
//! (protects against a burst from many source IPs at once) plus a
//! per-IP sliding-window attempt counter (protects against one source
//! hammering the listener). Both are checked *before* a handshake
//! starts — the cheapest possible rejection point, since a Noise
//! handshake itself costs real CPU (X25519 + `ChaCha20-Poly1305` setup)
//! that an attacker can otherwise trigger for free just by opening TCP
//! connections.
//!
//! Deliberately hand-rolled rather than pulling in a rate-limiting
//! crate — the whole point of a small dependency tree is that it stays
//! auditable by reading it.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const MAX_CONCURRENT_HANDSHAKES: usize = 64;
pub(crate) const MAX_ATTEMPTS_PER_WINDOW: usize = 10;
const WINDOW: Duration = Duration::from_secs(60);

/// Per-IP attempt history isn't ever pruned for IPs that stop
/// connecting entirely (only the entries *within* an active IP's own
/// window are pruned on each check) — a sustained wide-IP scan could
/// grow this map unbounded. Acceptable for v1, same category as the
/// already-documented dead-peer-detection gap: a real simplification,
/// not an oversight, and cheap to revisit later if it matters in
/// practice.
pub struct HandshakeLimiter {
    concurrent: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl HandshakeLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            concurrent: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Returns a permit if `ip` may attempt a handshake right now — both
    /// its own recent-attempt window and the global concurrency cap have
    /// room. Returns `None` if either is exhausted; the caller should
    /// drop the connection without ever calling into `noise`/`snowstorm`
    /// for it. Holding the returned permit for exactly the duration of
    /// the handshake attempt (drop it once the handshake resolves, not
    /// for the connection's whole lifetime) is what bounds concurrent
    /// *handshakes* specifically without also capping how many
    /// already-authenticated streams can be relayed at once.
    pub async fn try_acquire(&self, ip: IpAddr) -> Option<OwnedSemaphorePermit> {
        {
            let mut per_ip = self.per_ip.lock().await;
            let attempts = per_ip.entry(ip).or_default();
            let cutoff = Instant::now() - WINDOW;
            while attempts.front().is_some_and(|t| *t < cutoff) {
                attempts.pop_front();
            }
            if attempts.len() >= MAX_ATTEMPTS_PER_WINDOW {
                return None;
            }
            attempts.push_back(Instant::now());
        }
        self.concurrent.clone().try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[tokio::test]
    async fn allows_up_to_the_per_ip_limit_then_rejects() {
        let limiter = HandshakeLimiter::new();
        let ip = test_ip();

        let mut permits = Vec::new();
        for _ in 0..MAX_ATTEMPTS_PER_WINDOW {
            let permit = limiter.try_acquire(ip).await;
            assert!(
                permit.is_some(),
                "attempt within the limit should be allowed"
            );
            permits.push(permit);
        }

        assert!(
            limiter.try_acquire(ip).await.is_none(),
            "the attempt beyond the per-IP limit should be rejected"
        );
    }

    #[tokio::test]
    async fn different_ips_have_independent_budgets() {
        let limiter = HandshakeLimiter::new();
        let ip_a = test_ip();
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..MAX_ATTEMPTS_PER_WINDOW {
            assert!(limiter.try_acquire(ip_a).await.is_some());
        }
        assert!(
            limiter.try_acquire(ip_a).await.is_none(),
            "ip_a should now be exhausted"
        );
        assert!(
            limiter.try_acquire(ip_b).await.is_some(),
            "ip_b's budget is independent of ip_a's"
        );
    }

    #[tokio::test]
    async fn per_ip_budget_recovers_after_the_window_elapses() {
        let short_window_limiter = {
            // Reuses the real struct fields directly rather than the
            // fixed WINDOW const, so this test doesn't have to wait a
            // full 60s to prove the recovery behavior.
            HandshakeLimiter {
                concurrent: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
                per_ip: Mutex::new(HashMap::new()),
            }
        };
        let ip = test_ip();

        {
            let mut per_ip = short_window_limiter.per_ip.lock().await;
            let attempts = per_ip.entry(ip).or_default();
            let old_enough = Instant::now() - WINDOW - Duration::from_millis(1);
            for _ in 0..MAX_ATTEMPTS_PER_WINDOW {
                attempts.push_back(old_enough);
            }
        }

        assert!(
            short_window_limiter.try_acquire(ip).await.is_some(),
            "attempts entirely outside the window should be pruned, freeing budget"
        );
    }

    #[tokio::test]
    async fn global_concurrency_cap_is_enforced_even_with_per_ip_budget_left() {
        let limiter = HandshakeLimiter {
            concurrent: Arc::new(Semaphore::new(1)),
            per_ip: Mutex::new(HashMap::new()),
        };
        let ip_a = test_ip();
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let first = limiter.try_acquire(ip_a).await;
        assert!(first.is_some());

        // Different IP, well within its own per-IP budget, but the
        // global concurrency cap (1) is already held by ip_a.
        assert!(limiter.try_acquire(ip_b).await.is_none());

        drop(first);
        assert!(
            limiter.try_acquire(ip_b).await.is_some(),
            "releasing the held permit should free the global slot"
        );
    }
}
