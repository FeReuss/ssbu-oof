# Architecture

ssbu-oof 0.2.0.

```
 game (unmodified) ─ port (STANDARD.md) ── wss://…/ ──► [TLS terminator] ──► oof-server
                                    ├──── UDP nncs1 (NAT check) ──────────► oof-server
                                    └──── UDP nncs2 (NAT check) ──────────► oof-server, or `oof-server nat-check` elsewhere
 game ◄═══════════ Pia P2P UDP (matches, never through the server) ═══════════► game
```

## Crates

| Crate | Role |
| --- | --- |
| `oof-nex` | Pure codecs, no I/O: NEX streams (`stream.rs`), RMC (`rmc.rs`), PRUDP Lite + per-socket virtual connection state machine (`prudp.rs`), Kerberos tickets (`kerberos.rs`). Unit-tested against RFC vectors and round trips. |
| `oof-server` | The binary: axum HTTP + WebSocket listener (`main.rs`), one task per WebSocket (`connection.rs`), RMC dispatch and per-protocol handlers (`protocols/`), gathering store (`matchmaking.rs`), accounts, friends and bans (`accounts.rs`), DataStore objects (`objects.rs`), timed events (`events.rs`), UDP NAT check (`natcheck.rs`). |

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
- **Tokens and tickets are stateless**: ID tokens and server tickets are HMACs over the shared `secret`, so checking
  them needs no database. Accounts (Argon2id passwords, device keys, friends, bans) and DataStore objects live in one
  SQLite file (`database`); without it they are kept in memory and lost on restart.
- **The NAT check is stateless**: each address answers its own probes (Pia never needs an answer from the other
  address), so the second address can run as `oof-server nat-check` on another machine.
- **Scale-out path** (not built yet): gatherings and the SQLite file are per node. Several nodes need a shared
  database behind the same `accounts.rs` / `objects.rs` interface, gatherings sharded by ID, matchmaking routed by rule
  bucket (game mode × rule hash), and a message bus (e.g. NATS) carrying `Call`s to players connected to other nodes.
  The protocol layer already isolates this behind `State::call` and the `Matchmaking` API.
- Matches are P2P, so server bandwidth per player is small (login, matchmaking, notifications).

## Security boundaries

- Every byte from the network is parsed with bounds checks (`Reader`), list counts are capped, and
  messages are size-limited (`MAX_MESSAGE`, WebSocket frame limit).
- Tickets are authenticated (HMAC-MD5) and expire after 5 minutes; tokens are HMAC-SHA256 and
  expire per `token_ttl_secs`; passwords are Argon2id hashes and device keys are stored hashed; MAC comparisons are
  constant-time.
- `trust_client_address` (development only) takes players' public addresses from what they claim; it stays off on a
  public server.
- Gathering mutations check ownership; joins check passwords and capacity.
- TLS is expected at the edge (reverse proxy / load balancer).
