# ssbu-oof — Super Smash Bros. Ultimate Open Online Framework

A fast, scalable server for the online features of **Super Smash Bros. Ultimate 13.0.5**, and a
**standard** that lets every native port and emulator use it the same way.

Ports of Switch games (Zelda BotW, TotK, SSBU, …) each handle online play differently, if at all.
ssbu-oof takes the opposite approach: the unmodified game keeps speaking its own network protocols
(NEX over PRUDP Lite/WebSocket, Pia P2P), the server speaks them back, and a port only has to
provide a handful of console services in a standard way ([docs/STANDARD.md](docs/STANDARD.md)).

> Status: early. Login, secure connection, NAT traversal and the matchmaking core (Quickplay,
> co-op, background matchmaking, Battle Arenas) are implemented and tested against a protocol-level
> client. The real game, through a native port, logs in and reaches the online menu; matchmaking
> with the real game is not proven yet. See [docs/PROGRESS.md](docs/PROGRESS.md).

## Features

| Feature | Status |
| --- | --- |
| Accounts: user name + password (no e-mail/phone), device keys, bans, password change | implemented |
| Login (ID token → Kerberos ticket → secure server) | implemented |
| Quickplay / background matchmaking / online co-op | full matches and rematches played with the real game; rule scoring todo |
| Players' online records (DataStore, SQLite) | implemented |
| Battle Arenas (create, browse, join, passwords, updates, Arena ID) | implemented |
| NAT check + NAT traversal for Pia P2P | implemented (SSBU 13.0.5 has no relay to serve) |
| Shared Content (post, browse, download, likes) | replays verified with the real game; other content types todo |
| Online Tourneys | entry and tourney info work; brackets and matches in progress |
| Spectator mode (watching online matches) | **not working yet**: needs Elite Smash and the broadcast uploads |
| Elite Smash (GSP) | reverse-engineered surface documented, server todo |

Details per feature: [docs/features.md](docs/features.md). Protocol findings:
[docs/re/protocols.md](docs/re/protocols.md).

## Quick start

```sh
cargo build --release
cp oof.example.toml oof.toml          # set `secret` (openssl rand -hex 32) and public_host
./target/release/oof-server oof.toml
curl localhost:8080/v1/status
```

- `GET /` — NEX WebSocket endpoint (subprotocol `NEX`) the game connects to through its port.
- `POST /v1/accounts`, `/v1/login`, `/v1/token`, `/v1/logout`, `/v1/password` — accounts, device logins and ID
  tokens for ports (docs/STANDARD.md §2).
- `oof-server oof.toml account|ban|unban <user|pid> …` — administration on the server's database (a ban stops new
  logins and disconnects the player within 30 s).
- UDP 10025/10125 — NAT check for Pia.

Run behind a TLS terminator for `wss://`. Logs: `RUST_LOG=debug` shows every unimplemented call the
game makes.

## Layout

```
crates/oof-nex      wire codecs (NEX streams, RMC, PRUDP Lite, Kerberos), no I/O
crates/oof-server   the server (axum + tokio)
docs/               standard, architecture, features, progress, RE findings
tools/re/           analysis scripts that read your own dump of the game
```

Architecture and scaling notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```sh
cargo test && cargo clippy --all-targets && cargo fmt --check
```

Contributions must follow the clean-room rules in [LEGAL.md](LEGAL.md): no game data, keys,
disassembly listings or code from incompatible licenses.

## Legal

MIT licensed ([LICENSE](LICENSE)). Not affiliated with or endorsed by Nintendo; trademarks belong to
their owners. You need your own legally obtained copy of the game. Protocol documentation by
kinnay/NintendoClients (MIT) was used as a cross-reference ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).
