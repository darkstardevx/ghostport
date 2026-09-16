# Security Policy

## Threat model

What GhostPort's design actually defends against, and what it doesn't
— read this before deploying it somewhere that matters.

### What's defended

- **Man-in-the-middle.** `Noise_KK_25519_ChaChaPoly_BLAKE2s`
  (`src/noise.rs`) — both peers already know each other's pinned static
  public key ahead of time. An attacker without the matching private
  key cannot complete the handshake at all; there's no separate
  "verify identity after the fact" step for them to bypass. This is
  enforced by the cryptography itself, not a policy check.
- **Eavesdropping / traffic tampering.** Every byte relayed between
  peers — including the small control-channel messages
  (`Ping`/`Pong`/`OpenStream`) — travels only inside the
  Noise-encrypted tunnel. `snowstorm`'s ChaCha20-Poly1305 transport
  gives both confidentiality and integrity per message; nothing is
  sent in the clear after the handshake completes.
- **Unauthenticated connection-flood DoS.** Every handshake attempt
  costs real CPU (X25519 + ChaCha20-Poly1305 setup) before the pinned
  key can even be checked. Every handshake site has a 10s timeout, and
  `src/ratelimit.rs` rejects an attempt before it ever starts a
  handshake once a source IP or the global concurrency budget is
  exhausted.
- **A stuck/malicious connection blocking the real peer.** The control
  listener no longer handshakes inline in its single accept loop — a
  connection that opens a socket and never sends a byte can no longer
  block every other connection (including the real peer's reconnect)
  for the length of the timeout.

### What's NOT defended (by design, or by necessity)

- **A compromised private key file.** `identity.key` is locked to
  `0600` on disk (self-healing on every save), but GhostPort has no
  mechanism to detect or respond to a stolen key — if an attacker
  obtains it, they can complete the handshake as that peer. Treat key
  compromise the same as an SSH private key compromise: regenerate and
  re-pin on both sides.
- **A transcription error in the pinned `peer_public_key`.**
  Historically this surfaced only as an opaque "wrong key?" handshake
  failure. `ghostport keygen`/`ghostport check` print a SHA-256
  fingerprint for exactly this reason — verify it against the peer
  out-of-band (voice call, chat) before trusting a config, the same
  ritual as an SSH host key.
- **Dead-peer / silently-half-open connections.** Ping/Pong exists to
  keep NAT mappings alive on unpredictable WiFi, not as a full
  liveness state machine — a read/write error is what actually
  triggers reconnect. A connection that's open but unresponsive
  without ever erroring won't be noticed. Documented, deliberate v1
  tradeoff (see README's Known limitations), not planned to change.
- **Multiple peers.** GhostPort is built around exactly one pinned
  peer pair. There's no allowlist, no revocation list, no per-peer
  policy. If you need that, this isn't the right tool yet.
- **The host it runs on.** GhostPort assumes the machine it runs on
  isn't already compromised — it doesn't defend against a local
  attacker with access to the running process or its config/key files.
  `systemd/ghostport.service`'s sandboxing (`ProtectSystem=strict`, an
  empty `CapabilityBoundingSet`, etc. — see README's systemd section)
  narrows what a *compromised ghostport process* could do to the rest
  of the system; it isn't protection for ghostport against a
  host-level compromise that happens some other way.

## Supported deployment model

Single pinned peer pair, one role each (server/client). Not
multi-tenant, and not designed for a shared/many-user deployment. If
you're evaluating this for something bigger than "two machines you
personally control talking to each other," the threat model above
hasn't been validated for that.

## Reporting a vulnerability

Email **darkstardevx@gmail.com** (primary) or, as a backup,
**cybercore.sh@gmail.com**. Include:

- the affected file/commit and a minimal repro or PoC
- what you'd expect to happen instead
- how you'd rate the impact (your best guess is fine)

Expect an acknowledgement within a few days. Please don't include
exploit details in a public GitHub issue or PR until a fix has
shipped.

## Supported versions

Only the latest commit on `main` is supported — there's no tagged
release yet.
