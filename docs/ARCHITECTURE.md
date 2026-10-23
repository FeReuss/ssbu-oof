# Architecture

```
 game (unmodified) ─ port (STANDARD.md) ── wss://…/ ──► [TLS terminator] ──► oof-server node(s)
                                    └──── UDP 10025/10125 (NAT check) ──────► oof-server node
 game ◄═══════════ Pia P2P UDP (matches, never through the server) ═══════════► game
```

## Crates

| Crate | Role |
| --- | --- |
| `oof-nex` | Pure codecs, no I/O: NEX streams (`stream.rs`), RMC (`rmc.rs`), PRUDP Lite + per-socket virtual connection state machine (`prudp.rs`), Kerberos tickets (`kerberos.rs`). Unit-tested against RFC vectors and round trips. |
| `oof-server` | The binary: axum HTTP + WebSocket listener (`main.rs`), one task per WebSocket (`connection.rs`), RMC dispatch and per-protocol handlers (`protocols/`), gathering store (`matchmaking.rs`), stateless accounts/tokens (`accounts.rs`), UDP NAT check (`natcheck.rs`). |

## Request path

1. `connection::serve` reads a WebSocket binary frame → `prudp::decode_all` → `Endpoint::handle`
   (SYN/CONNECT/DATA/PING/DISCONNECT, ACKs, ordering, fragment reassembly).
2. CONNECT: empty payload = authentication connection; otherwise the Kerberos ticket is checked and
   the player's `Session` (PID, connection ID, outbound channel) is registered in `State`.
3. A complete message → `rmc::decode` → `protocols::dispatch` → handler → `rmc::encode_*` →
   `Endpoint::send` (fragments of 1,300 bytes) → WebSocket frames.
4. Handlers that affect other players (joins, leaves, NAT probes) queue `Call`s on those players'
   channels; each player's own task sends them, so no task ever writes another task's socket.

## Scalability

- **Per-connection work is lock-free**: PRUDP state lives inside the connection's task; tokio
  spreads tasks over all cores. The only shared structures are `sessions` (RwLock, read-mostly) and
  the gathering store (one Mutex, short critical sections, notifications sent after unlocking).
- **Login is stateless**: account passwords, ID tokens and server tickets are all derived from the
  shared `secret`, so any node accepts any player and the auth path needs no database.
- **Scale-out path** (not built yet): gatherings are the only cross-player state. Shard them by
  gathering ID across nodes and route matchmaking by rule bucket (game mode × rule hash), with a
  message bus (e.g. NATS) carrying `Call`s to players connected to other nodes. The protocol layer
  already isolates this behind `State::call` and the `Matchmaking` API.
- Matches are P2P, so server bandwidth per player is small (login, matchmaking, notifications).

## Security boundaries

- Every byte from the network is parsed with bounds checks (`Reader`), list counts are capped, and
  messages are size-limited (`MAX_MESSAGE`, WebSocket frame limit).
- Tickets are authenticated (HMAC-MD5) and expire after 5 minutes; tokens are HMAC-SHA256 and
  expire per `token_ttl_secs`; password and MAC comparisons are constant-time.
- Gathering mutations check ownership; joins check passwords and capacity.
- TLS is expected at the edge (reverse proxy / load balancer).
