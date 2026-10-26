# Progress and handoff

Read this first in a new session. Keep it current: update "State" and "Next" whenever a milestone
moves, and record dead ends so nobody repeats them.

## State (2026-10-26)

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
   - Done: persistence of player records (SQLite, `database = "oof.db"` in `oof.example.toml`; test
     `objects_survive_a_restart`; dev configs without `database` stay in memory on purpose); Battle Arenas (Arena ID 109/55/56, verified with two instances); friends (accounts, `/v1/friends*`,
     standard v0.2 section 7; friends' arenas verified with the game); service switches (integer settings
     9002-9011: Online Tourney and Spectator are off without them); game events (`[[events]]`); Tournament 201/9
     entry. Level/rule matching needs nothing more from the server (the client sends exact attributes; brackets
     come from integer settings 1100/1101+), only a level, which comes with (4).
   - Relay for strict NAT: **not applicable** (2026-10-26). SSBU 13.0.5's Pia relay is compiled in but switched off
     (docs/re/protocols.md, "Relay"); the game never calls 3/6, also when direct traffic is blocked on purpose. The
     original service had no relay either. Possible later mitigation (not original behaviour): use the NAT properties
     the game reports (3/5) to avoid pairing two players whose NATs cannot reach each other.
   - **Shared Content works** (2026-10-26): post (115/24 + HTTP upload to `/v1/objects/<id>` + 115/62), browse per tab
     (115/80, 115/66), download and play (115/45 + HTTP GET), likes from the action reports (115/96, action 3).
     Verified with the game (a Vault replay posted by one account, found and played by another). Open: how an unlike
     is reported, search by ID ("X Search"), posting stages / Mii fighters / spirit teams / videos (expected to be the
     same 24 + 62 flow with data types 3 / 0 / 1 / 4), deleting one's own posts, reporting content (Screening 124).
   - **Online Tourney: round 1 is playable** (2026-10-26, later): the bracket screen abort is fixed (the game takes the
     bracket layout from the first TournamentInfo, so phase 0 is now announced when the entry closes, with 8/16/32 seats
     and the matches; empty seats fill the rest), tourney matchmaking (game mode 12) pairs only a match's players, and
     201/13 answered 1 starts the match, a match ends with **201/14** (answered 1; the replay is posted as DataStore type
     18 first) and both players then wait for the next phase (docs/re/protocols.md, "Online Tourney", "Rules and
     result"). Rules go in the event's period params (`[[events.periods]] params = { time_sec, stock, melee_rule }`).
     The whole bracket is now sent (IDs from the final down, `next` links; `tw22`: shown and played).
     **Exact next steps:** (1) **desync in tourney matches** (`tw22`): the two instances ended the same match with
     different results (each view had the other's damage). Quickplay views agreed, so look for what differs in a tourney
     match: a value each client takes from the server (TournamentMatchInfo's `u8`s / `u64`, TournamentInfo's `u32`s,
     the event period) and feeds into the match setup (random seed, rules). Compare with Quickplay's gathering data. This
     may also be port-side (determinism): if the server data is identical for both, tell the port session. (2) After 201/14
     both fetch 201/12 again: answer with the match finished (state 5, second `u8`), the winner put in the next match's
     keys (the winner is the player of both), and `[seq+0x54c]` (TournamentInfo's last `u32`, sent as the entrant
     count) kept for the champion; the screenshots `tw22a/b-k*.png` show who each instance thinks won. Dev scripts in the port's
     `SSBU_build/analysis/dev-scripts/`:
     `tourney_pair.sh <run>` (two instances enter; no server variable needed now), `tourney_fight.sh <run> [s]`
     (both fight; with `stock = 1` in the period a match ends at the first KO, ~30 s; `SUICIDE=1` did not make b fall), `tourney_watch.sh` + `watch_trace.py`/`bracket_dump.py`/`step_trace.py`
     (LLDB on instance a). Pitfalls: idle-interrupted matches give the test accounts a temporary online ban stored in
     their slot-0 record (`analysis/oof-share.db`, data type 16; delete those rows); kill earlier instances first (they
     live 25 min); input-file key holds are capped at 5000 ms (use `down`/`up`).
   - Spectator 115/54 (`C2ReplayBroadcastingInfo`): **not usable yet** (docs/features.md). Quickplay matches upload
     nothing even with switches 9010-9015 on, so broadcasts most likely come from Elite Smash matches (needs Matchmake
     Referee first). Tests need three instances (two fight, one watches; authorized by the maintainer).
   - Then Elite Smash: Matchmake Referee 120 (1/3/4/12/14 layouts in "Request layouts"), Smash power. No game run has
     called the Referee yet (Quickplay posts only DataStore records). Its client wrappers (`main+0x25abc0` StartRound,
     `0x25adc0` EndRound, `0x25b1c0` GetOrCreateStats, `0x25b3c0` 14) are reached only through `+0x20` thunks
     (`main+0x25abb0`...) with no relocation pointing at them, so find the callers from the owning service object (the
     matchmake service's Referee member) or break on the wrappers with LLDB during a Quickplay match.
   - Tools: `tools/re/readers.py` decodes response readers (the counterpart of `ddl.py`); an approximation, check
     surprising results by hand.
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
