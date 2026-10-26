# Development notes

ssbu-oof 0.2.0. What is pending and the first step for each: [features.md](features.md). Protocol facts:
[re/protocols.md](re/protocols.md).

## Build and test

```sh
cargo test && cargo clippy --all-targets && cargo fmt --check
```

Tests cover the codecs, the handlers (mostly through a WebSocket client: login, Quickplay with two players, arenas,
DataStore, friends), the tourney bracket logic and the NAT check sockets. Run the server with `RUST_LOG=debug` to see every call the game makes
that the server does not implement; `oof_server=trace` also logs each matchmake session key, so a Pia capture of a test
match can be decrypted (`docs/re/protocols.md`, end of "From matchmaking to the Pia mesh").

## Testing with the real game

- Any port that follows [STANDARD.md](STANDARD.md) works; the game version must be 13.0.5.
- Several instances on one machine share one IP. Pia then mixes up their stations and ignores datagrams from a NAT
  check address it also talks to, so give each instance its own virtual address in the port and set
  `trust_client_address = true` on a development server only.
- On one machine the two NAT check addresses can be `127.0.0.1` and the machine's LAN address.
- The game ends Quickplay matches of idle players, players attacking in place and self-destructing players: test inputs
  must move. A match ended that way gives the account a temporary online ban stored in its DataStore record.
- In a Battle Arena the fighter confirmation countdown is about 12 s.
- Online Tourney tests need events in the config (`[[events]]`, switch 9006); a period with `stock = 1` ends a match at
  the first KO. Spectator tests need three instances (two fight, one watches).

## Design decisions

- **Wire-compatible server.** Ports do not translate NEX; they only provide console services (STANDARD.md), so one
  standard serves every port and emulator.
- **Rust + tokio + axum.** One static binary, no GC pauses, one listener for HTTP and WebSocket.
- **SQLite** (`rusqlite`, bundled) for what must survive a restart: accounts, friends, bans, DataStore objects and,
  later, Matchmake Referee stats. One file per node; several nodes would need a shared database behind the same
  `accounts.rs` / `objects.rs` interface.
- **Accounts** are a user name (also the in-game nickname) and an Argon2id password, without e-mail or phone; ports keep
  a revocable device key, never the password; several accounts per person are allowed. ID tokens stay stateless HMACs.
- **NAT check:** each address answers its own probes, so the second address may run on another machine
  (`oof-server nat-check`).
- **No relay:** SSBU 13.0.5 has its Pia relay switched off; the original service had none either.
- **No access key or game server ID in the config:** a PRUDP Lite server does not need them.
- **Clean room** ([LEGAL.md](../LEGAL.md)): facts and addresses in the docs, never listings or game data.

## Reverse-engineering workflow

`tools/re/` reads your own dump of the game (`tools/re/README.md`). Pitfalls met so far:

- The NEX protocol-ID heuristic "immediate before the ClientProtocol constructor" returns service types (1, 2, 12…) for
  classes built through a service client; read the immediate passed to the protocol client's own constructor.
- `ddl.py` decodes requests only. For responses read the method's `extractor` (`nex_protocols.py --json`) with
  `nxre.py dis` or `readers.py`; each result is fetched by `main+0x22eb80(ctx, index)` and read by a type reader (bool
  `main+0x1d0670`; structures test the no-header byte `+0x69`). Use the `site` field, not `function`, which is a coarse
  guess shared by neighbouring methods.
- `llvm-objdump` ships with Xcode (`xcrun llvm-objdump`); `llvm-readelf` does not.
- PRUDP Lite sequence numbers: the client's CONNECT uses reliable id 1, so its DATA starts at 2; the server's DATA
  starts at 1. Client PINGs are reliable and share that sequence space.
- Several RendezVous error constants in `oof-nex/src/rmc.rs` may not match the game; verify one before relying on the
  error code the game shows.
