# ssbu-oof — Super Smash Bros. Ultimate Open Online Framework

**Version 0.2.0** · port standard **v0.2** · HTTP API `/v1`

A server for the online features of **Super Smash Bros. Ultimate 13.0.5**, and a **standard** that lets every native
port and emulator use it the same way.

Ports of Switch games each handle online play differently, if at all. ssbu-oof takes the opposite approach: the
unmodified game keeps speaking its own network protocols (NEX over PRUDP Lite/WebSocket, Pia P2P), the server speaks
them back, and a port only has to provide a handful of console services in a standard way
([docs/STANDARD.md](docs/STANDARD.md)). Ports that follow the standard play together (crossplay).

**Status:** online multiplayer works on a public server: players sign in, meet through Quickplay or Battle Arenas and
play their matches peer to peer. Online Tourneys, Elite Smash and Spectator are still pending (below).

## Supported

| Feature | What works |
| --- | --- |
| Accounts | User name (also the in-game nickname) + password, no e-mail or phone; revocable device keys; password change; bans with a reason, applied to connected players within 30 s |
| Login | ID token → Kerberos ticket → secure NEX connection |
| Quickplay | Matchmaking by the player's rules, background matchmaking, online co-op (two players on one console), rematches |
| Battle Arenas | Create, browse, join (Arena ID, password), rules/comment updates, friends' arenas |
| Friends | Friend lists, requests and blocks kept by the server (standard §7) |
| Player records | The game's online record (disconnects, conduct) persisted in SQLite |
| Shared Content | Post, browse, download, like and unlike replays |
| NAT check + traversal | What Pia needs to connect players P2P: the two NAT check addresses can share a host, sit behind 1:1 NAT, or live on two machines |
| Operation | Service switches and timed events from the config; account lookup, ban and unban from the command line |

Details per feature: [docs/features.md](docs/features.md). Every request the game sends, with its use and the
layout of request and response: [docs/requests.md](docs/requests.md).

## Pending

- **Online Tourneys** — not supported yet. Entering, the bracket and its matches are partly implemented, but a tourney
  never ends for its champion, and rewards and 4-player brackets are missing.
- **Elite Smash** — not supported yet: Smash power (GSP), Matchmake Referee rounds, the Elite threshold.
- **Spectator** — not supported yet; it depends on Elite Smash, whose matches provide the broadcasts.
- Smaller gaps: Quickplay does not yet prefer closer rules or Smash power; Shared Content lacks search by ID,
  stages / Mii fighters / spirit teams / videos, deleting and reporting posts; one server node (no scale-out yet); no
  automated conformance check for ports.

## Quick start

```sh
cargo build --release
cp oof.example.toml oof.toml          # set `secret` (openssl rand -hex 32), public_host, nat_check, database
./target/release/oof-server oof.toml
curl localhost:8080/v1/status
```

| Interface | Use |
| --- | --- |
| `GET /` | NEX WebSocket endpoint (subprotocol `NEX`) the game connects to through its port |
| `POST /v1/accounts`, `/v1/login`, `/v1/token`, `/v1/logout`, `/v1/password` | Accounts, device logins and ID tokens (standard §2) |
| `POST /v1/friends`, `/v1/friends/{add,remove,block,unblock}` | Friends (standard §7) |
| `GET /v1/status` | Version, load and the NAT check addresses ports must resolve |
| `/v1/objects/…` | Shared Content uploads and downloads |
| UDP 10025, 10125 (both NAT check addresses), 33334, 33335 (primary) | Pia's NAT check |
| `oof-server <config> account\|ban\|unban …` | Administration on the server's database |
| `oof-server nat-check <address> [<bind address>]` | The second NAT check address on another machine |

Running a public server (TLS, firewall, NAT check addresses, systemd, backups): [docs/DEPLOY.md](docs/DEPLOY.md).

## Layout

```
crates/oof-nex      wire codecs (NEX streams, RMC, PRUDP Lite, Kerberos), no I/O
crates/oof-server   the server (axum + tokio, SQLite)
docs/               standard, architecture, features, request reference, deployment, development, RE findings
tools/re/           analysis scripts that read your own dump of the game
```

## Development

```sh
cargo test && cargo clippy --all-targets && cargo fmt --check
```

Design notes, testing with the game and the reverse-engineering workflow: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/re/protocols.md](docs/re/protocols.md). Contributions must follow
the clean-room rules in [LEGAL.md](LEGAL.md): no game data, keys, disassembly listings or code from incompatible
licenses.

## Legal

MIT licensed ([LICENSE](LICENSE)). Not affiliated with or endorsed by Nintendo; trademarks belong to their owners. You
need your own legally obtained copy of the game. Public protocol documentation was used as a cross-reference
([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).
