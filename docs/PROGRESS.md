# Progress and handoff

Read this first in a new session. Keep it current: update "State" and "Next" whenever a milestone
moves, and record dead ends so nobody repeats them.

## State (2026-10-25)

- **Reverse engineering** of SSBU 13.0.5's online stack: middleware versions, hosts, transport,
  every NEX client protocol with ID evidence and the methods the game links, request layouts for
  the SSBU-specific methods, the port-side system services. → `docs/re/protocols.md`.
- **Tools** to reproduce and extend it: `tools/re/` (strings/xrefs/vtables, protocol inventory,
  DDL decoder). Game dump lives outside the repo (see `tools/re/README.md`).
- **Server** (Rust, `cargo test` = 28 tests incl. an end-to-end two-player login + Quickplay):
  PRUDP Lite over WebSocket, Ticket Granting, Secure Connection, Utility (1/7/8/9/10/11), NAT Traversal
  relay, NAT check UDP server, gathering store with Matchmake Extension create/join/auto/browse/find/
  update/passwords and Match Making unregister/URLs/host migration, owner/disconnect notifications,
  DataStore calls 8/60/61/83/84/94/95 (empty or zero results).
- **Standard** for ports: `docs/STANDARD.md` v0.1 (accounts, token, DNS, TLS, sockets).
- **Real game reaches the online menu** (2026-10-24) through the MacNativeGames port (`games/ssbu`, branch
  `ssbu-native-port`, its `HANDOFF.md`; standard §2–6 with `OOF_TLS=0`): background login at boot → ticket →
  secure connection → the DataStore calls above → no unimplemented method left; pressing "Online" opens the
  first-time online pages with no error. Before the DataStore methods it failed with 2306-0103.
- **Quickplay eligibility integration:** port experiment confirms DataStore 94 and Utility 9/10 allow
  progression with Utility 10 returning `false`. Those handlers are now integrated with argument parsing
  and a WebSocket regression test (including truncated requests). Binary evidence and limits are in
  `docs/re/protocols.md`, "Quickplay eligibility calls". The external report is an intermediate handoff;
  this file holds the lasting status. No new game run was made for this integration.
- **Post-matchmaking timeout fixed (server side, 2026-10-24):** both players used to leave ~10.33 s after
  AutoMatchmake (owner 21/2, joiner 50/1, "connection error"). Cause: Pia waits up to 10 s for a 3001
  notification naming each of its own players in the gathering, and the server only told the owner about
  joiners. Now the creator and every participant (joiner included) get 3001. Evidence and addresses:
  `docs/re/protocols.md`, "After AutoMatchmake". Two GPU instances no longer leave at +10 s and reach
  Pia's NAT check.

- **Dev option `trust_client_address`** (config, default false): public station URLs keep the address the client
  registers, so several instances on one machine look like separate hosts. Never on a public server.
- **Mesh and NAT traversal (2026-10-25, later):** GetSessionURLs answers one public + one private URL
  (Pia's parser accepts at most two); the public URL takes address, port and CID from the client's Pia
  dummy; a client that never sends ReplaceURL (no NAT) gets a private copy of its public URL; a joiner
  hears a 3001 for every participant already in the gathering. Two instances now complete NAT
  traversal and exchange the Pia connection request.
- **Pia NAT check passes (2026-10-25):** Pia needs `nncs1` and `nncs2` on two different addresses
  (`docs/re/protocols.md`, "Pia NAT check"). The server now runs the NAT check on two IPs × UDP
  10025/10125 (config `nat_check.primary/secondary` are addresses, not socket addresses) and announces
  them in `GET /v1/status`; standard §4/§8 updated. Secure Connection 11/7 ReplaceURL is implemented.
  With the MacNativeGames port two instances now finish the NAT check and report NAT properties.

- **First online match (2026-10-25, evening):** two real instances on one Mac (port's virtual network, this server with
  `trust_client_address`) went from Quickplay to a synced 1-on-1 match. During the match each player posts its
  persistent object with **DataStore 115/21 PostMetaBinary** (data type 16, 900-byte meta binary, persistence slot 0,
  180 days), the slot GetMeta (115/8) reads at login, and changes it with **115/38 ChangeMeta** after the results. The
  server keeps posted objects in **SQLite** (`objects.rs`, config `database`; in memory when omitted), with read
  permission, owner-only changes and a per-player bound, and returns them from GetMeta. The record carries the
  player's disconnect and conduct state (protocols.md), so it must survive restarts. A match was played to the results screen (both views agree on the winner);
  115/82 (sent at match start, empty result) is accepted. Layouts: `docs/re/protocols.md`.

- **Accounts (2026-10-25):** `accounts.rs` + `/v1/login`, `/v1/logout`, `/v1/password`, admin commands
  (`oof-server <config> account|ban|unban`). With the port: both instances registered, signed in and played with
  their device keys; the game shows the account user names.

## Next (in order)

0. **Order requested by the user (2026-10-26):** (1) friends, relay for strict NAT, matchmaking by rules / Smash level;
   (2) Spectator and Shared Content (DataStore uploads over HTTP); (3) Online Tourneys; (4) Elite Smash (Matchmake
   Referee, Smash level).
   - Done: Battle Arenas (Arena ID 109/55/56, verified with two instances); friends (accounts, `/v1/friends*`,
     standard v0.2 section 7; friends' arenas verified with the game); service switches (integer settings
     9002-9011: Online Tourney and Spectator are off without them); game events (`[[events]]`); Tournament 201/9
     entry. Level/rule matching needs nothing more from the server (the client sends exact attributes; brackets
     come from integer settings 1100/1101+), only a level, which comes with (4).
   - **Next: relay for strict NAT.** Pia relays inside the mesh by itself (another participant); for two players
     alone it asks the server NAT Traversal 3/6 `GetRelaySignatureKey` (`NexNatServerAddressResolveJob::
     StepRequestRelayServerSetting`); today the server answers relay mode 0 (no relay). Decode the 3/6 response
     use and Pia's relay-server packets (`NexNatRelay`, `NATTraversalRelayProtocol`), then add a UDP relay.
     Found so far (2026-10-26): the 3/6 extractor (`main+0x259720`) reads exactly the six fields the server sends
     (i32 mode, DateTime, String address, u16 port, i32 address type, u32 game server id); Pia's steps
     `StepRequestRelayServerSetting` / `StepWaitRequestRelayServerSetting` / `StepResolveRelayServerSetting` are at
     `main+0xd2eb0` / `0xd3038` / `0xd312c`, `PrepareNatTraversalByRelay` and the waits at `main+0xf0e64` / `0xf159c` /
     `0xf1670`. `NATTraversalRelayProtocol` has a client-side `Impl` (vtable `main+0x4f5d938`, dispatcher slot 21 =
     `main+0x259a40`, like the Notification protocol the client serves). **Exact next step:** read
     `StepResolveRelayServerSetting` and `PrepareNatTraversalByRelay` to learn which mode value enables the relay and
     what Pia sends to `address:port` first; then answer 3/6 with mode != 0 on a dev config and capture that traffic.
   - Then: Spectator 115/54 (`C2ReplayBroadcastingInfo`) and the replay/broadcast uploads; Shared Content uploads
     (115/66 lists); tourney brackets (201/10-14, response 12 layout open); Matchmake Referee 120.
   Pitfalls: the game ends Quickplay matches of idle/attack-in-place/self-destructing players (test inputs must move);
   in an arena the fighter confirmation countdown is ~12 s (press A on every instance quickly); several RendezVous
   error constants in `oof-nex/src/rmc.rs` may not match the game (verify before relying on shown codes).

1. **Two-instance fight.** Rerun two GPU instances and follow the server log: NAT check UDP (10025/10125,
   needs `[nat_check]` in the config), NAT Traversal 3/x, Match Making 21/41 (GetSessionURLs), then Pia
   P2P. Watch whether the zero DataStore results matter. Run the server with `RUST_LOG=debug` so every
   unimplemented call shows up. Earlier milestone, for history: 109/58 group routing (OOF policy: one
   group per mode 1,2,3,5,7,13, see `docs/re/protocols.md`) let two instances share a gathering.
2. **Matchmake Referee + GSP** (Elite Smash): decode request/response of 1/3/4/12/14 with `ddl.py`
   and the extractor tables; persistent stats in the same SQLite database (`config.database`).
3. **DataStore + HTTP object storage** (spectator broadcasts, power chart, shared content).
4. **Tournament 201 + communities + game events** (Online Tourneys).
5. Friends API (v0.2 of the standard), conformance script, scale-out (sharded gatherings + bus).

## Decisions

- **SQLite (`rusqlite`, bundled, MIT; SQLite is public domain)** for state that must survive a restart, chosen
  2026-10-25 with the DataStore records; Matchmake Referee stats go to the same file. One file per node: several
  nodes would need a shared database (Postgres) behind the same `objects.rs` interface.
- **Rust + tokio + axum** (user preference; static binary, no GC pauses, one listener for HTTP and
  WebSocket). Go was installed but not chosen.
- **Wire-compatible server**: ports do not translate NEX; they only provide console services
  (STANDARD.md). One standard therefore serves every port and emulator.
- **Accounts in the database** (2026-10-25, user request): user name (also the in-game nickname, 3–10 characters)
  + Argon2id password, no e-mail or phone number; ports keep a revocable device key, never the password; bans per
  account (checked at token issue, NEX login, and every 30 s for connected players); several accounts per person are
  allowed. ID tokens stay stateless HMAC so any node verifies them. Standard v0.2 §2.
- **No access key / game server ID in config**: a Lite server does not need them.
- **Clean room** (LEGAL.md): facts and addresses in docs, never listings or game data.

## Dead ends and pitfalls

- **Config change (2026-10-25):** `[nat_check] primary/secondary` are now IPv4 addresses (each serving UDP
  10025 and 10125), no longer `ip:port`; older configs (e.g. the port's `analysis/dev-scripts/oof.toml`) fail to
  parse until updated, and both addresses must differ. On one Mac use 127.0.0.1 and the LAN address.
- The 76-byte packets to nncs1:33335 are Pia NAT Protocol dummies: do not build a service for them first.

- The NEX protocol-ID heuristic "immediate before the ClientProtocol constructor" returns service
  types (1, 2, 12…), not protocol IDs, for classes built through a service client; read the immediate
  passed to the protocol client's own constructor instead (`docs/re/protocols.md` cites each one).
- `llvm-objdump` is in Xcode (`xcrun llvm-objdump`); `llvm-readelf` is not.
- Response layouts are not decoded by `ddl.py` (requests only): read the method's `extractor` from
  `nex_protocols.py --json` with `nxre.py dis`; each result is fetched by `main+0x22eb80(ctx, index)` and then
  read by a type reader (bool `main+0x1d0670`; structures test the no-header byte `+0x69`). The `function`
  field there is a coarse function-start guess shared by neighbouring methods: use `site` instead.
- PRUDP Lite sequence numbers: the client's CONNECT uses reliable id 1, so its DATA starts at 2; the
  server's DATA starts at 1 (the CONNECT/ACK is not counted). PINGs from the client are reliable and
  share that sequence space.
