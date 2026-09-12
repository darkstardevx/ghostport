# 👻 GhostPort

`Rust` · `Noise Protocol` · `tokio`

**Encrypted, NAT-traversing port forwarder.** Like `ssh -L`/`ssh -R`, but
standalone — no SSH server needed on either end, just two GhostPort
daemons and a pinned keypair.

## 🎯 What it solves

Two machines you control (say, a laptop that roams between neighbors'
WiFi and a library, and a home server with a stable address) that need
to reach each other's services securely, in **both directions**:

- **Forward** (like `ssh -L`) — reach a service near the server from a
  port on your local machine.
- **Reverse** (like `ssh -R` / ngrok) — expose a service near your local
  machine to something reachable via the server, even though your local
  machine can't accept inbound connections at all.

## 🏗️ Design decisions, made explicitly before writing code

Three real forks were resolved with the user before implementation:

1. **Direction** — both forward and reverse from v1, not forward-only.
2. **Connection model** — a fresh Noise handshake per proxied TCP
   connection (like `stunnel`), not one persistent multiplexed tunnel
   carrying many streams. Simpler, no custom stream-multiplexing
   protocol to get right; handshake overhead is sub-millisecond in
   practice.
3. **Topology** — exactly one pinned peer pair (a "server" role, always
   reachable; a "client" role, assumed to be behind NAT/unpredictable
   networks), not a multi-peer allowlist.

Combining (1) and (2) has a real consequence: true reverse tunneling
needs the server to trigger a new stream on demand, but it can't dial
the client directly (NAT). The resolution — one small **persistent
control connection** (client dials the server, auto-reconnects with
backoff) carrying only tiny `OpenStream` signals, while every actual
proxied byte-stream still gets its own fresh per-connection Noise
tunnel, dialed by the client in response. This is the same pattern a
real tool called [rathole](https://github.com/rapiz1/rathole) uses for
exactly this NAT-traversal problem — not invented here, just applied.

Every actual TCP connection in the system — the control connection and
every data tunnel — is always **dialed by the client, accepted by the
server**. This is what makes reverse mode work from behind NAT: the
client only ever needs outbound connectivity, never inbound.

## 🔒 How it actually works

- **Handshake**: `Noise_KK_25519_ChaChaPoly_BLAKE2s` via [`snow`](https://docs.rs/snow) — both peers already know each other's static public key ahead of time (pinned in config), which is exactly what the `KK` pattern is for. Unlike `IK`/`XX`, there's no separate "check the identity after the fact" step: a peer without the matching private key simply can't complete the handshake, the cryptography itself refuses an impostor.
- **Transport wrapper**: [`snowstorm`](https://docs.rs/snowstorm) wraps the handshake + transport state around a `TcpStream`, producing a `NoiseStream` that's itself `AsyncRead + AsyncWrite` — so the actual bulk relay is just `tokio::io::copy_bidirectional`, no hand-rolled framing/encrypt-decrypt loop needed for that path.
- **Control/handshake messages** (`Ping`/`Pong`/`OpenStream`, and the per-stream `StreamHello` identifying which link a tunnel belongs to) are small JSON payloads, length-prefixed on top of the already-encrypted stream (`framing.rs`).
- **Keys**: generated with `ghostport keygen`, saved as sibling files (`identity.key` + `identity.key.pub`) exactly like SSH keypairs — the private key is locked to `0600` (self-healing on every save), the public key is meant to be copied into the peer's config.

## 🚀 Commands

```bash
ghostport keygen --out ~/.config/ghostport/identity.key   # generates identity.key (0600) + identity.key.pub
ghostport check ~/.config/ghostport/config.toml            # validate a config without starting anything
ghostport run ~/.config/ghostport/config.toml               # start the daemon
```

### Example config — server (home server, stable address)

```toml
role = "server"
private_key_path = "/home/you/.config/ghostport/identity.key"
peer_public_key = "<the client's public key, from its keygen output>"
listen_control = "0.0.0.0:9000"
listen_data = "0.0.0.0:9001"

[[links]]
id = "homedb"
mode = "forward"
target = "127.0.0.1:5432"      # server dials this when a "homedb" stream opens

[[links]]
id = "laptop-dev"
mode = "reverse"
listen = "0.0.0.0:8080"        # server listens here for external users
```

### Example config — client (laptop, roams networks)

```toml
role = "client"
private_key_path = "/home/you/.config/ghostport/identity.key"
peer_public_key = "<the server's public key, from its keygen output>"
server_control_addr = "myhome.example.com:9000"
server_data_addr = "myhome.example.com:9001"

[[links]]
id = "homedb"
mode = "forward"
listen = "127.0.0.1:5432"      # laptop listens here — e.g. point a DB client at it

[[links]]
id = "laptop-dev"
mode = "reverse"
target = "127.0.0.1:3000"      # laptop dials this (its own local dev server) when asked
```

Every link needs a matching entry on both sides; `ghostport check` only
validates internal consistency of *one* side's file (role/mode ⇄
`listen`/`target` matrix, valid addresses, unique ids) — it can't see
the peer's file to cross-check the other half of a link.

## 🖥️ systemd

A unit template is at `systemd/ghostport.service` (`Restart=on-failure`,
matching WraithFlow/VortexWall's convention). Not installed by default —
copy it to `/etc/systemd/system/`, adjust the config path, then
`sudo systemctl enable --now ghostport`.

## ✅ Verification

23 tests. Per-module unit tests: config validation (every (role, mode)
⇄ required-field combination, duplicate ids, bad addresses, TOML
round-trip), key generation/save/load/permissions, the JSON framing
layer (round-trip, oversized-length rejection, message-boundary
correctness), and Noise handshake construction.

Two full **end-to-end integration tests** against real running daemon
instances — not mocked at any layer: real loopback TCP sockets, real
Noise handshakes, real `tokio::spawn`ed server + client roles talking to
each other.
- `forward_and_reverse_links_round_trip_end_to_end` — sends bytes through a real forward link *and* a real reverse link, confirming the harder reverse path (control-channel `OpenStream` signal → client dials back → pending-stream-map pairing) actually works, not just the direct forward path.
- `wrong_peer_key_fails_the_handshake_instead_of_connecting` — pins the client to an impostor's public key and confirms the handshake fails outright rather than silently connecting.

## 🧩 Layout

```
src/keys.rs      static keypair generation/save/load, 0600 permissions
src/noise.rs     Noise_KK handshake state construction
src/config.rs    TOML schema + validation
src/protocol.rs  ControlMessage / StreamHello
src/framing.rs   length-prefixed JSON over any AsyncRead/AsyncWrite
src/relay.rs     bidirectional byte relay (tokio::io::copy_bidirectional)
src/server.rs    server role: accepts control + data connections, reverse-mode listeners
src/client.rs    client role: control-channel reconnect loop, forward-mode listeners
src/main.rs      CLI (keygen/check/run) + integration tests
```

## 🗺 Known limitations

- No deadline-based dead-peer detection on the control channel beyond a
  read/write error actually occurring — a connection that goes silently
  half-dead (open but unresponsive) without erroring won't trigger a
  reconnect until something else notices. Ping/Pong every 15s exists
  mainly to keep NAT mappings alive on unpredictable WiFi, not as a full
  liveness state machine.
- Single pinned peer pair only — no multi-peer allowlist/revocation.
- No persistent stream multiplexing — a burst of many simultaneous
  connections through one link means that many concurrent handshakes,
  not one shared pipe. Deliberate v1 tradeoff (see design decisions
  above), not an oversight.
- No TUI/status-monitoring surface yet — CLI only.

## 📄 License

MIT
