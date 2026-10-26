# Online features: how SSBU implements them and what the server does

ssbu-oof 0.2.0. Status: **supported** = implemented and played with the real game; **partial** = works with the gaps
listed; **pending** = not supported yet. Protocol evidence and layouts: [re/protocols.md](re/protocols.md).

## Foundation (every feature)

| Piece | Protocol | Status |
| --- | --- | --- |
| WebSocket + PRUDP Lite transport | — | supported (`crates/oof-nex/src/prudp.rs`) |
| Login: token → ticket | Ticket Granting 10, method 6 (3 for refresh) | supported |
| Secure connection + station URLs | Secure Connection 11, methods 1/4/3/6/7/8 | supported |
| Server → client events | Notification 14 (`ProcessNotificationEvent`) | supported |
| NAT detection | UDP NAT check (`nncs1/2`): two addresses × 10025/10125, Pia dummies on nncs1:33335 | supported |
| NAT traversal for Pia P2P | NAT Traversal 3, methods 1/3 relay `InitiateProbe` | supported |
| Relay for peers that cannot connect | NAT Traversal 6 + Pia relay server | not used by SSBU 13.0.5 (its Pia relay is switched off, as on the original service) |
| Server settings, service switches, unique IDs | Utility 1, 7, 8, 9, 10 | supported (`integer_settings` in the config) |
| Timed events | Utility 11 `GetGameEvents` | supported (`[[events]]` in the config) |

The match itself never touches the server: Pia connects the players P2P (UDP) and runs the delay-based netcode between
them. The server puts the right players in one gathering, tells them each other's addresses and keeps their records.

## Accounts and friends

**Supported.** Accounts are a user name (3–10 characters, also the in-game nickname) and an Argon2id password, stored in
the server's SQLite database; ports keep a revocable device key, never the password (standard §2). Bans carry a reason
and an end, refuse new logins and disconnect connected players within 30 s. Friends, requests and blocks live on the
server by account (standard §7); the game finds friends' Battle Arenas by itself (Matchmake Extension 51).

## Quickplay, background matchmaking, online co-op

Client: Pia `RandomMatchmakeJob` → Matchmake Extension 40 `AutoMatchmakeWithParam_Postpone` with the player's
Preferred Rules in the session attributes and search criteria; then Match Making 41 `GetSessionURLs` and NAT
traversal to reach the host. Matchmake Extension 58 picks the queue group (one group per queue mode).

Server: **supported.** Joins the oldest open session whose attributes satisfy the criteria (exact, range, empty
filters), else creates one with a random Pia session key; announces every participant (3001) to everyone in the
gathering; handles owner/host migration, disconnects, rematches, and two players on one console (participation counts
players, not consoles). Each player's record (DataStore slot 0, 115/21 and 115/38) is kept in SQLite and read back at
login (115/8), so disconnects and conduct warnings persist.

Gap: no preference for closer rules or Smash power (the original service relaxed its search over time).

## Battle Arenas

Client: Matchmake Extension 38 create, 52 browse, 39 join (password / Arena ID), 41/48/49/50/51 find (by ID, owner,
friends), 1/2 close/open, 8/11/12/44 updates, 34 progress score, 36/37 system password, 55/56 Arena ID.

Server: **supported.** All of the above on the in-memory gathering store; each arena gets a 5-character Arena ID
(digits and capitals without look-alikes). Played with the game: create, search by ID, join, matches, friends' arenas.
Browse, passwords and arenas of 3+ players are implemented but not yet exercised with the game.

## Shared Content

Server: **partial.** Posting a replay (DataStore 115/24, HTTP upload to `/v1/objects/<id>`, 115/62), browsing per tab
(115/80, 115/66), downloading and playing it (115/45 + HTTP GET) and likes (115/96) work with the game. Objects and
their data are stored in SQLite.

Gaps: search by ID, unlike, posting stages / Mii fighters / spirit teams / videos (likely the same flow with other
data types), deleting one's own posts, reporting content (Screening 124).

## Online Tourneys — pending

Client: Tournament 201 (SSBU-only; methods 9–14), Utility 11 `GetGameEvents` for the schedule, switch 9006.

Implemented so far: events from the config (`[[events]]`, rules in each period's params); entry (201/9); when entry
closes the server fills a bracket of 8, 16 or 32 seats, pairs the entrants and announces phase 0; tourney matchmaking
(game mode 12) pairs a match's players; 201/13 starts a match; 201/14 reports the winner, who moves on; matches against
empty seats settle themselves; the final's winner is the champion.

Missing before it can be called supported:

1. **End of a tourney.** The champion's game asks for the bracket (201/12) every ~67 ms forever after winning. Find what
   the tourney sequence waits for after 201/12 (its completion path near `main+0x16c3cd0`; TournamentInfo's unknown
   second `u32` and second `u8`), e.g. a "tourney ended" state.
2. Later rounds between real players (needs three or more game instances), rewards, 4-player brackets.

## Elite Smash — pending

Client: the same matchmaking with Smash-power-restricted criteria; results go through Matchmake Referee 120 (1
`StartRound`, 3 `EndRound`, 4 `EndRoundWithoutReport`, 12 `GetOrCreateStats`, 14 SSBU-only); DataStore carries a
`C2SmashPowerChart`. Switches 9010–9015 appear to enable it.

Implemented so far: 120/12 answers new stats at the initial rating (nothing stored).

Missing: Referee rounds and per-fighter stats in SQLite, a Smash power model (proposal: Glicko-2 per player and
fighter, power = percentile × players), the Elite threshold and the power chart. First step: find the screen that shows
Smash power and the call carrying the per-fighter value; the Referee client wrappers are `main+0x25abc0` (StartRound),
`0x25adc0` (EndRound), `0x25b1c0` (GetOrCreateStats), `0x25b3c0` (14).

## Spectator — pending

With switch 9007 on, the menu entry opens and the game asks DataStore 115/54 for a `C2ReplayBroadcastingInfo`; the
server has no broadcasts and the game says the replay cannot be shown. Broadcasts are replays stored in DataStore and
downloaded like Shared Content (reader `main+0x2970b0`). Quickplay matches upload none, so they most likely come from
Elite Smash matches.

Missing: Elite Smash first, then find the call that uploads a broadcast, store it like Shared Content, answer 115/54
with the latest broadcasts, and the calls the game makes while watching (predictions, rewards). Testing takes three
instances (two fight, one watches).

## Not planned yet

Smash World uploads (DataStore), scale-out across several server nodes (see [ARCHITECTURE.md](ARCHITECTURE.md)).
