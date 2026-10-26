# Online features: how SSBU implements them and what the server does

Status: **served** = implemented and tested; **partial** = works with documented gaps;
**todo** = known protocol surface, not implemented. Evidence and layouts: docs/re/protocols.md.

## Foundation (every feature)

| Piece | Protocol | Status |
| --- | --- | --- |
| WebSocket + PRUDP Lite transport | — | served (`crates/oof-nex/src/prudp.rs`) |
| Login: token → ticket | Ticket Granting 10, method 6 (3 for refresh) | served |
| Secure connection + station URLs | Secure Connection 11, methods 1/4/3/6/8 | served |
| Server → client events | Notification 14 (`ProcessNotificationEvent`) | served for gatherings |
| NAT detection | UDP NAT check (`nncs1/2`) on two addresses × 10025/10125 | served; Pia service on nncs1:33335 todo |
| NAT traversal for Pia P2P | NAT Traversal 3, methods 1/3 relay `InitiateProbe` | served |
| Relay for peers that cannot connect | NAT Traversal 6 + Pia relay server | not used by SSBU 13.0.5 (its Pia relay is switched off; the server answers "no relay") |
| Server settings / unique IDs | Utility 1, 7, 8 | served (empty settings) |

The match itself never touches the server: Pia connects the consoles P2P (UDP) and runs the
delay-based netcode between them. The server's job is to put the right players in one gathering,
tell them each other's addresses, and record results.

## Quickplay

Client: Pia `RandomMatchmakeJob` → Matchmake Extension 40 `AutoMatchmakeWithParam_Postpone` with
the player's Preferred Rules encoded in the session (game mode, attributes, matchmake param) and
search criteria; then Match Making 41 `GetSessionURLs` and NAT traversal to reach the host.

Server: **partial** — a whole match was played between two real instances (2026-10-25); each player's slot-0
DataStore object (115/21) is kept in memory and read back by GetMeta. Joins the oldest open session whose attributes satisfy any criteria (string
filters: exact, range, empty), else creates one with a random 32-byte Pia session key; notifies the
owner (3001); handles owner/host migration and disconnects.
Gaps: rule-similarity scoring (the real service prefers close Global Smash Power and similar rules,
falling back to looser rules over time); which attribute index holds which rule needs a capture.

## Elite Smash

Client (hypothesis from type names, to confirm): same matchmaking with GSP-restricted criteria; GSP
and the "Elite" threshold come from the server. The DataStore side carries a `C2SmashPowerChart`
type (presumably the GSP distribution chart), and results flow through Matchmake Referee (1 `StartRound`, 3 `EndRound`, 4 `EndRoundWithoutReport`,
12 `GetOrCreateStats`, 14 SSBU-only).

Server: **todo.** Needs (1) Referee rounds and per-fighter stats storage, (2) a GSP model (rating per
player per fighter, mapped to the GSP scale), (3) the power chart and threshold served through the
DataStore SSBU methods. Design proposal: Glicko-2 per (player, fighter), GSP = percentile × total
players, Elite = top percentile published hourly.

## Online co-op (two players, one console)

Client: one NEX login brings two players; `AutoMatchmakeParam.num_participants = 2`.

Server: **served** for capacity: participation counts players, not consoles, so a pair never lands
in a session without two free seats (tested in `matchmaking::tests`).

## Background matchmaking

Client: issues the same `AutoMatchmakeWithParam_Postpone` while the player stays in offline modes,
then waits for Pia to complete the mesh. "Postpone" = the server may answer with a session that is
still filling up.

Server: **served** by the Quickplay path; a session lives until its participants leave.

## Battle Arenas

Client: Matchmake Extension 38 `CreateMatchmakeSessionWithParam` (arena rules in the session,
optional password), 52 `Browse…` (search by rules), 39 `JoinMatchmakeSessionWithParam` (password /
Arena ID), 41/48/49/50/51 `Find…` (by ID, owner, friends as participants), 1/2 close/open,
8/11/12/44 updates (rules, comment, attributes), 34 progress score, 36/37 system password,
55/56 Arena ID (code of a gathering / gathering of a code).

Server: **partial.** All of the above are implemented on the in-memory gathering store. The server issues
each arena a 5-character Arena ID (digits and capitals without look-alikes) on the first 109/55. Verified with
the real game (2026-10-25): create, ID shown, search by ID, join, a full 1-on-1 match and back to the arena.
Not yet run with the game: public browse (52), passwords (36/37 and join), leaving / owner leaving, 3+ players,
spectators. Gaps: friends-only visibility (needs the friends service), arena description moderation.

## Online Tourneys

Client: the Tournament protocol (201, SSBU-only; methods 9–14 sent, 15 understood), Utility 11
`GetGameEvents` for the schedule, communities (Matchmake Extension 17–22, 54: persistent gatherings)
for tourney lobbies, `TournamentMatchInfo` / `TournamentPlayerInfo` types for brackets.

Server: **todo.** Utility 11 answers an empty event list (no tourneys scheduled). Next: decode the
Tournament responses (extractor tables), model events → communities → bracket rounds of matchmake
sessions, rewards as event results.

## Spectator mode

**Not usable yet: watching online matches in Spectator does not work with ssbu-oof.** With switch 9007 on, the menu
entry opens and the game asks DataStore 115/54 (no parameters) for a `C2ReplayBroadcastingInfo`; the server has no
broadcasts to give, and the game shows that it could not show the replay.

What is known (docs/re/protocols.md, "Spectator"): the response is read by `main+0x2970b0` (lists of entries that hold
a `DataStoreMetaInfo`-like object, fighters, a download descriptor and dates), so broadcasts are replays stored in
DataStore and downloaded like Shared Content. No match uploads one so far: Quickplay matches post only the players'
records (115/82, 21, 38), also with switches 9010-9015 on. In the original game Spectator showed Elite Smash battles,
so the uploads most likely come from Elite Smash matches.

To do: Elite Smash first (Matchmake Referee 120, Smash power), then find which call uploads a broadcast replay, store
it like Shared Content (`/v1/objects`), answer 115/54 with the latest broadcasts, and the related calls the game makes
while watching (predictions, rewards). Testing it takes three game instances on one Mac (two fight, one watches; one
fighter may run without GPU submission).

## Shared Content

**Works** (2026-10-26): posting a Vault replay, browsing per tab, downloading and playing it, likes. Open: search by
ID, posting stages, Mii fighters, spirit teams and videos (expected to be the same flow), deleting one's posts,
reporting (Screening 124). Details: docs/re/protocols.md, "Shared Content".

## Not requested but on the same stack

Smash World uploads (DataStore).
