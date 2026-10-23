# Progress and handoff

Read this first in a new session. Keep it current: update "State" and "Next" whenever a milestone
moves, and record dead ends so nobody repeats them.

## State (2026-10-23)

- **Reverse engineering** of SSBU 13.0.5's online stack: middleware versions, hosts, transport,
  every NEX client protocol with ID evidence and the methods the game links, request layouts for
  the SSBU-specific methods, the port-side system services. → `docs/re/protocols.md`.
- **Tools** to reproduce and extend it: `tools/re/` (strings/xrefs/vtables, protocol inventory,
  DDL decoder). Game dump lives outside the repo (see `tools/re/README.md`).
- **Server** (Rust, `cargo test` = 20 tests incl. an end-to-end two-player login + Quickplay):
  PRUDP Lite over WebSocket, Ticket Granting, Secure Connection, Utility (1/7/8/11), NAT Traversal
  relay, NAT check UDP server, gathering store with Matchmake Extension create/join/auto/browse/find/
  update/passwords and Match Making unregister/URLs/host migration, owner/disconnect notifications.
- **Standard** for ports: `docs/STANDARD.md` v0.1 (accounts, token, DNS, TLS, sockets).
- Nothing has run against the real game yet. No port implements the standard yet.

## Next (in order)

1. **First real login.** Wire NSWMacPort (or an emulator with redirectable DNS/TLS) to the standard
   and watch the server log: `ticket granted` → `secure connection` → warnings `unimplemented RMC
   method` list exactly what the game calls next. Fix wire mismatches with a capture
   (`RUST_LOG=debug`). Expected first surprises: structure versions the client sends, Secure
   Connection method used for Register, whether `codeword` must be server-assigned.
2. **Quickplay end to end** on two instances: rule attributes mapping (log the sessions the game
   creates), Pia NAT traversal, relay decision for symmetric NATs.
3. **Matchmake Referee + GSP** (Elite Smash): decode request/response of 1/3/4/12/14 with `ddl.py`
   and the extractor tables; persistent stats storage (first database dependency: pick SQLite or
   Postgres then).
4. **DataStore + HTTP object storage** (spectator broadcasts, power chart, shared content).
5. **Tournament 201 + communities + game events** (Online Tourneys).
6. Friends API (v0.2 of the standard), conformance script, scale-out (sharded gatherings + bus).

## Decisions

- **Rust + tokio + axum** (user preference; static binary, no GC pauses, one listener for HTTP and
  WebSocket). Go was installed but not chosen.
- **Wire-compatible server**: ports do not translate NEX; they only provide console services
  (STANDARD.md). One standard therefore serves every port and emulator.
- **Stateless accounts** (HMAC-derived passwords and tokens) until accounts need profile data.
- **No access key / game server ID in config**: a Lite server does not need them.
- **Clean room** (LEGAL.md): facts and addresses in docs, never listings or game data.

## Dead ends and pitfalls

- The NEX protocol-ID heuristic "immediate before the ClientProtocol constructor" returns service
  types (1, 2, 12…), not protocol IDs, for classes built through a service client; read the immediate
  passed to the protocol client's own constructor instead (`docs/re/protocols.md` cites each one).
- `llvm-objdump` is in Xcode (`xcrun llvm-objdump`); `llvm-readelf` is not.
- PRUDP Lite sequence numbers: the client's CONNECT uses reliable id 1, so its DATA starts at 2; the
  server's DATA starts at 1 (the CONNECT/ACK is not counted). PINGs from the client are reliable and
  share that sequence space.
