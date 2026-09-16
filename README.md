# 👻 GhostPort

[![CI](https://github.com/darkstardevx/ghostport/actions/workflows/ci.yml/badge.svg)](https://github.com/darkstardevx/ghostport/actions/workflows/ci.yml)

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
3. **Topology** — a "server" role, always reachable, and a "client"
   role, assumed to be behind NAT/unpredictable networks. Originally
   exactly one pinned peer pair; later extended to let a server accept
   several distinct, independently-pinned client identities, each
   restricted to its own subset of links (see "Multi-peer support"
   below) — a client still pins exactly one server, no ambiguity to
   resolve on that side.

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
- **Fingerprints**: `keygen` and `check` both print a SHA-256 fingerprint (colon-grouped hex) alongside any key they handle — the same verification ritual as an SSH host key. The pinned key already makes the Noise handshake cryptographically refuse an impostor, but a single mistyped character in the 44-char base64 `peer_public_key` otherwise only surfaces later as an opaque "wrong key?" handshake failure; the fingerprint gives both sides something short to actually read aloud or compare side-by-side.

## 🚀 Commands

```bash
ghostport keygen --out ~/.config/ghostport/identity.key   # generates identity.key (0600) + identity.key.pub
ghostport check ~/.config/ghostport/config.toml            # validate a config without starting anything
ghostport run ~/.config/ghostport/config.toml               # start the daemon
ghostport status                                            # one-shot live status from a running daemon
ghostport status --watch                                    # re-query and reprint every second
ghostport status --json                                     # machine-readable, for scripting
ghostport tui ~/.config/ghostport/config.toml                # interactive management console
```

### Example config — server (home server, stable address)

```toml
role = "server"
private_key_path = "/home/you/.config/ghostport/identity.key"
listen_control = "0.0.0.0:9000"
listen_data = "0.0.0.0:9001"

[[peers]]
name = "laptop"
public_key = "<the laptop's public key, from its keygen output>"
links = ["homedb", "laptop-dev"]

[[links]]
id = "homedb"
mode = "forward"
target = "127.0.0.1:5432"      # server dials this when a "homedb" stream opens

[[links]]
id = "laptop-dev"
mode = "reverse"
listen = "0.0.0.0:8080"        # server listens here for external users
```

#### Multi-peer support

A server can list more than one `[[peers]]` entry — each independently
pinned, each restricted to its own `links` (an id not in a peer's list
is simply unreachable to that peer, enforced server-side when a data
tunnel's `StreamHello` names it, regardless of what that peer's own
config claims to offer). `Noise_KK` needs the responder to already know
the correct remote static key before it can process a handshake
message at all — with more than one allowed peer, the server tries
each configured key against the incoming handshake in turn until one
matches (or none do); an unrecognized key still can't complete the
handshake with *any* candidate, the same cryptographic guarantee as
the single-peer case, just checked against a list. A client still pins
exactly one server (`peer_public_key`, singular) — there's no ambiguity
to resolve on the dialing side.

Real constraint worth knowing: reverse-mode links are still bound by
GhostPort's one-active-control-session-at-a-time design (unchanged by
multi-peer support) — only whichever peer currently holds the control
connection can be signaled to fulfill a reverse-mode request. Forward-
mode links have no such constraint; each data tunnel authenticates and
dials independently, so multiple peers can use their own forward links
concurrently today.

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
copy it to `/etc/systemd/system/`. Its `User`/`Group`/`WorkingDirectory`/
`ExecStart` paths are hardcoded to this repo's own dev machine, not
templated — edit them for your own user/paths before installing, then
`sudo systemctl enable --now ghostport`.

Sandboxed (`NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=read-only` + a narrow `ReadWritePaths` for the one
directory it actually writes to, an empty `CapabilityBoundingSet`,
`RestrictAddressFamilies`, and the standard
`MemoryDenyWriteExecute`/`LockPersonality`/`ProtectKernel*` block) —
`systemd-analyze security ghostport.service` scores 4.8 ("OK") on this
unit. If you adjust the paths above, double-check `ReadWritePaths` too:
it's hardcoded (not `%h`-based) after finding that `%h` resolved to the
wrong home directory in real testing despite `User=` being set — see
the comment in the unit file.

## 📊 Status IPC

A running daemon exposes live state over a Unix socket
(`~/.local/state/ghostport/ghostport.sock` by default, `0600`/`0700`
owner-only) — control-channel connection state, and per-link active
connection counts + cumulative bytes. Deliberately a socket, not a
periodically-written status file: a socket gives an unambiguous "is the
daemon even running" signal (connection refused = no, cleanly), where a
file would leave stale-data ambiguity if the daemon crashed mid-write or
a while ago. Any connection gets one JSON snapshot back, then the
connection closes — not a streaming protocol, since a query every second
or so (what `status --watch` and the TUI both do) is simple and
sufficient.

## 🕹️ TUI — management console

`ghostport tui <config>` — three tabs (`Tab`/`1`/`2`/`3` to switch):

- **Status** — the same live data as `ghostport status`, auto-refreshing
  (`r` to force a refresh). Enriched beyond the raw CLI view: uptime and
  the control-channel's connected-since duration are human-formatted
  (`1h 4m 12s`, not raw seconds), byte counters are human-formatted too
  (`4.2 MB`, not a raw integer), each link shows a **live throughput
  estimate** (computed client-side from two consecutive snapshots — no
  daemon changes needed for this), and a `TOTAL` row sums every column
  across all links.
- **Links** — browse, add (`a`), **fully edit** (`e`), remove (`d`, with
  a confirm). Adding opens a **template chooser** first — a real
  selectable dropdown (`j`/`k`, `enter`), not single-letter keys: SSH,
  HTTP, HTTPS, PostgreSQL, MySQL/MariaDB, Redis, or exposing a local
  dev/web server, each with a sensible default id and port, or "Custom"
  for full manual entry. Picking a template pre-fills the id and jumps
  straight to confirming the address (the mode is implied by the
  template) — accept the suggested `127.0.0.1:<port>` as-is or edit it.
  Editing (`e`) reuses the exact same id → direction → address wizard,
  just pre-filled with the link's current values — changing the id
  renames it in place rather than creating a duplicate. Every
  add/edit/remove is held in memory until you save (`s`), which runs the
  same `Config::validate()` the daemon itself uses before writing
  anything — an invalid edit is refused with the specific reasons, never
  silently written. **No live reload**: saving prepares the config for
  the *daemon's next start* — the natural workflow is edit → save →
  restart (Service tab).
- **Service** — a real selectable menu (`j`/`k`, `enter`), not a wall of
  single-letter keys: Start, Stop, Restart, Enable at boot, Disable at
  boot, Install systemd unit, View recent logs. Everything except
  viewing logs asks for confirmation first, then suspends the TUI
  (leaves the alternate screen, disables raw mode), runs
  `sudo systemctl <action> ghostport` inheriting this process's stdio so
  the password prompt appears exactly as if typed directly — same
  convention as WraithFlow's `--admin` flags — then restores the TUI.
  "Install systemd unit" writes the *actual* `systemd/ghostport.service`
  content (embedded into the binary at compile time via `include_str!`,
  so it works regardless of where the binary ends up) to
  `/etc/systemd/system/` via `sudo tee`, then `systemctl daemon-reload` —
  no more manually copying the template first. "View recent logs" runs
  `journalctl -u ghostport -n 50 --no-pager` — deliberately no sudo, same
  "read-only status needs no privilege" reasoning as `is-active`/
  `is-enabled` (both shown at the top of the tab, refreshed live).

Colors come from the active `cybercore` theme throughout, not just a
couple of accents — forward/reverse links get distinct colors (cyan /
hot pink) everywhere they're shown, key hints are colored per-letter
against muted labels, an active stream count lights up green the moment
it's actually carrying traffic, byte counters get their own accent
color, and each Service menu entry is colored by what it actually does
(green for Start/Enable, red for Stop/Disable, orange for Restart,
purple for Install, cyan for View logs). The plain CLI (`keygen`,
`check`, `status`) is colored the same way via a small shared `theme.rs`
helper — green for success, red for problems, cyan for paths/labels —
and the daemon's own connection logs (`server.rs`/`client.rs`/
`relay.rs`) pick up the same treatment when run in a real terminal.

## ✅ Verification

CI runs on every push (`.github/workflows/ci.yml`): format, clippy
(default + all-features), the full test suite (including the real
network-namespace tests, which need the same Ubuntu 24.04+ AppArmor
`unshare` workaround gateflow's own CI required), and `cargo deny
check`. Run the same gates locally before pushing:

```bash
./scripts/release-gates quick   # fmt/check/clippy only
./scripts/release-gates full    # + tests + cargo-deny
```

72 tests. Per-module unit tests: config validation (every (role, mode)
⇄ required-field combination, duplicate ids, bad addresses, TOML
round-trip, `save()` refusing an invalid config and never touching disk
when it does), key generation/save/load/permissions, the JSON framing
layer, Noise handshake construction, live-stats counters (zeroed at
start, correctly reflecting updates, control connect/disconnect), the
IPC socket (round-trips a real snapshot over a real Unix socket, correct
`0600` permissions, fails cleanly when nothing's listening), duration/
byte/rate formatting (every scale — seconds through days, bytes through
terabytes), and the TUI's link-editing logic: produces correctly-shaped
links per the role/mode matrix, replaces on duplicate id, save clears
the dirty flag and the reloaded file matches, remove marks dirty, an
invalid address is rejected without losing wizard progress, the live
validation indicator reflects what's actually typed, a template
pre-fills its id and skips straight to the address step, editing
pre-fills current values and updates in place, renaming during an edit
removes the old entry rather than duplicating, the service menu wraps
navigation correctly, viewing logs skips the confirm prompt while every
other action requires it.

Two full **end-to-end integration tests** against real running daemon
instances — not mocked at any layer: real loopback TCP sockets, real
Noise handshakes, real `tokio::spawn`ed server + client roles talking to
each other.
- `forward_and_reverse_links_round_trip_end_to_end` — sends bytes through a real forward link *and* a real reverse link, confirming the harder reverse path (control-channel `OpenStream` signal → client dials back → pending-stream-map pairing) actually works, not just the direct forward path — **and** asserts the live stats on both sides actually reflect that traffic (not just that bytes arrived, but that the counters meant to back the status/TUI views are wired correctly).
- `wrong_peer_key_fails_the_handshake_instead_of_connecting` — pins the client to an impostor's public key and confirms the handshake fails outright rather than silently connecting.

CLI smoke-tested directly against a real running daemon too: `status`
and `status --json` both queried a live instance over its real socket
and returned correct live data; `tui` confirmed to fail gracefully
(clear error, no panic) when there's no real TTY — same documented
limitation as every other interactive tool built this session.

**Supply chain**: `cargo deny check` ([`deny.toml`](deny.toml)) runs
the dependency tree against RustSec's real advisory database (known
vulnerabilities), an explicit license allow-list (MIT/Apache-2.0/BSD/
Zlib/Unicode-3.0/etc. — no copyleft), and crates.io as the only allowed
source — install with `cargo install cargo-deny --locked`, run with
`cargo deny check` from the repo root.

## 🧩 Layout

```
src/keys.rs      static keypair generation/save/load, 0600 permissions
src/noise.rs     Noise_KK handshake state construction
src/theme.rs     shared ANSI color helpers for the CLI + daemon logs
src/config.rs    TOML schema + validation + save()
src/stats.rs     live runtime counters (atomics), StatusSnapshot
src/ipc.rs       Unix-socket status server + client query
src/protocol.rs  ControlMessage / StreamHello
src/framing.rs   length-prefixed JSON over any AsyncRead/AsyncWrite
src/relay.rs     bidirectional byte relay (tokio::io::copy_bidirectional), updates stats
src/server.rs    server role: accepts control + data connections, reverse-mode listeners
src/client.rs    client role: control-channel reconnect loop, forward-mode listeners
src/tui/         management console (ratatui): app.rs (state), ui.rs (rendering),
                 mod.rs (event loop, systemctl/journalctl, embedded unit file),
                 templates.rs (link templates), format.rs (duration/bytes/rate)
src/main.rs      CLI (keygen/check/run/status/tui) + integration tests
```

## 🗺 Known limitations

- No deadline-based dead-peer detection on the control channel beyond a
  read/write error actually occurring — a connection that goes silently
  half-dead (open but unresponsive) without erroring won't trigger a
  reconnect until something else notices. Ping/Pong every 15s exists
  mainly to keep NAT mappings alive on unpredictable WiFi, not as a full
  liveness state machine.
- A server can pin several peers, but there's still no *revocation while
  running* — removing a `[[peers]]` entry only takes effect on the next
  restart, and no per-peer rate limiting beyond Phase 1's per-IP limiter
  (shared across all peers on that server). Reverse-mode links are still
  bound by the one-active-control-session-at-a-time design (see
  "Multi-peer support" above) — not a limitation multi-peer support
  introduced, just one it doesn't lift.
- No persistent stream multiplexing — a burst of many simultaneous
  connections through one link means that many concurrent handshakes,
  not one shared pipe. Deliberate v1 tradeoff (see design decisions
  above), not an oversight.
- The TUI's Links tab edits `listen`/`target`/`mode`/`id` only — role,
  addresses, and key paths are set once at initial setup and aren't
  editable from the TUI yet (edit the TOML directly for those).
- No live config reload — editing links in the TUI always needs a
  restart (Service tab) to take effect.

See [SECURITY.md](SECURITY.md) for the full threat model — what's
actually defended (MITM, eavesdropping, connection-flood DoS) versus
what isn't (key compromise, multiple peers, the host itself) — and how
to report a vulnerability.

## 📄 License

MIT
