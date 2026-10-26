# Request reference

ssbu-oof 0.2.0. Every request Super Smash Bros. Ultimate 13.0.5 sends to the server, what it is for, and the layout of
the request and the answer, as the server implements them. `110/10` means protocol 110, method 10. Evidence (reader
and serializer addresses, captures) is in [re/protocols.md](re/protocols.md); the state of each feature is in
[features.md](features.md).

A method not listed here is answered with `Core::NotImplemented`; `RUST_LOG=debug` logs every such call.

## Notation

All values are little-endian.

| Type | Encoding |
| --- | --- |
| `u8` … `u64`, `i32`, `i64`, `bool` | fixed size; `bool` is one byte |
| `PID` | `u64` player ID |
| `String` | `u16` length including the NUL, the UTF-8 bytes, NUL |
| `Buffer` / `qBuffer` | `u32` / `u16` length, then the bytes |
| `List<T>` | `u32` count, then the items |
| `Map<K, V>` | `u32` count, then key/value pairs |
| `Struct{…}` | `u8` version, `u32` length, then the fields (each level of an inherited structure has its own header) |
| `DateTime` | `u64`: `second \| minute << 6 \| hour << 12 \| day << 17 \| month << 22 \| year << 26` |
| `Variant` | `u8` type, then the value: 0 none, 1 `i64`, 2 `f64`, 3 `bool`, 4 `String`, 5 `DateTime`, 6 `u64` |
| `Result` | `u32` NEX result code; `0x00010001` is success |
| `StationURL` | `String` such as `prudp:/address=…;port=…;CID=…;PID=…;RVCID=…;natf=…;natm=…;type=…` |
| `AnyDataHolder` | `String` class name, `u32` length + 4, `u32` length, the object |

Transport: PRUDP Lite frames inside binary WebSocket messages (subprotocol `NEX`). A request carries the protocol ID,
a call ID, the method ID and the parameters; the answer carries the call ID and method, then either the response body
or an error `Result`.

## Ticket Granting (10) — authentication connection

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 10/6 `ValidateAndRequestTicketWithParam` | Login with the ID token the port got from `/v1/token` | `Struct{u32 platform, String user name (decimal PID), AnyDataHolder AuthenticationInfo{… String token}}` | `Struct{PID, Buffer ticket, String secure server URL, DateTime server time, String server build, String source key}`; a banned account gets `RendezVous::AccountDisabled` |
| 10/3 `RequestTicket` | New ticket for the secure server | `PID source, PID target` | `Result, Buffer ticket, String source key` |

## Secure Connection (11)

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 11/1 `Register` | Register the player's station after login | `List<StationURL>` local URLs | `Result, u32 connection ID, StationURL public URL` |
| 11/4 `RegisterEx` | Same, with login data | `List<StationURL>`, login data (ignored) | as 11/1 |
| 11/3 `RequestURLs` | Another player's station | `u32 connection ID, PID` | `bool found, List<StationURL>` (one public, one private) |
| 11/6 `UpdateURLs` | Replace the stored URLs | `List<StationURL>` | — |
| 11/7 `ReplaceURL` | After Pia's NAT check: the URL with the Pia port, `CID` and NAT properties | `StationURL old, StationURL new` | — |
| 11/8 `SendReport` | Client diagnostics | report | — |

## NAT Traversal (3)

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 3/1 `RequestProbeInitiation` | Ask peers to probe the caller | `List<StationURL> targets` | —; the server sends each target 3/2 |
| 3/3 `RequestProbeInitiationExt` | Ask peers to probe a given station | `List<StationURL> targets, StationURL station` | —; the server sends each target 3/2 |
| 3/2 `InitiateProbe` (server → client) | Start probing a station | `StationURL station` | — |
| 3/4, 3/5, 3/7 | NAT traversal results and NAT properties (telemetry) | report | — |
| 3/6 `GetRelaySignatureKey` | Relay server for strict NATs; SSBU 13.0.5 never calls it (relay switched off) | — | `i32 mode (0 = no relay), DateTime, String, u16, i32, u32` |

## Match Making (21), Match Making Ext (50), Matchmake Extension (109)

Gatherings are the sessions players meet in: Quickplay, Battle Arenas and tourney matches. `MatchmakeSession` is the
standard NEX structure (Gathering, then game mode, attributes, open flag, matchmake system, application buffer,
participation count, progress score, session key, option, matchmake param, start time, user password, refer gathering,
user password and system password flags, codeword).

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 21/2 `UnregisterGathering` | Owner closes a gathering | `u32 gathering ID` | `bool` |
| 21/41 `GetSessionURLs` | Joiner asks for the host's station (answered once the host's NAT check is done, at most 10 s) | `u32 gathering ID` | `List<StationURL>` (one public, one private) |
| 21/42 `UpdateSessionHost` | Host migration | `u32 gathering ID, bool migrate owner` | — |
| 50/1 `EndParticipation` | Leave a gathering | `u32 gathering ID, String message` | `bool` |
| 109/1, 109/2 `Close` / `OpenParticipation` | Arena open or closed to new players | `u32 gathering ID` | — |
| 109/8 `ModifyCurrentGameAttribute` | Change one attribute | `u32 gathering ID, u32 index, u32 value` | — |
| 109/11 `UpdateApplicationBuffer` | Game data attached to the gathering | `u32 gathering ID, Buffer` | — |
| 109/12 `UpdateMatchmakeSessionAttribute` | Rule attributes | `u32 gathering ID, List<u32>` | — |
| 109/34 `UpdateProgressScore` | Arena progress | `u32 gathering ID, u8 score` | — |
| 109/36 `GenerateMatchmakeSessionSystemPassword` | Password friends join with | `u32 gathering ID` | `String password` |
| 109/37 `ClearMatchmakeSessionSystemPassword` | Remove it | `u32 gathering ID` | — |
| 109/38 `CreateMatchmakeSessionWithParam` | Create a Battle Arena | `CreateMatchmakeSessionParam{MatchmakeSession, List<PID> additional participants, u32 gathering ID check, u32 option, String join message, u16 participation count}` | `MatchmakeSession` |
| 109/39 `JoinMatchmakeSessionWithParam` | Join an arena (Arena ID, password, friends) | `JoinMatchmakeSessionParam{u32 gathering ID, List<PID>, u32, u32 option, u8 behaviour, String user password, String system password, String join message, u16 participation count, …}` | `MatchmakeSession` |
| 109/40 `AutoMatchmakeWithParam_Postpone` | Quickplay, background matchmaking, tourney matches: join the oldest session matching the criteria or create one | `AutoMatchmakeParam{MatchmakeSession source, List<PID>, u32, u32 option, String join message, u16 participation count, List<MatchmakeSessionSearchCriteria>, List<u32> target gathering IDs, …}` | `MatchmakeSession` |
| 109/41, 109/49 `FindMatchmakeSessionByGatheringIdDetail` / `BySingleGatheringId` | One gathering | `u32 gathering ID` | `MatchmakeSession` |
| 109/44 `UpdateMatchmakeSessionPart` | Arena rules and description | `UpdateMatchmakeSessionParam{u32 gathering ID, u32 modification flags, List<u32> attributes, bool open, Buffer application data, u8 progress, matchmake param, DateTime started, String user password, u32 game mode, String description, u16 min, u16 max, u32 system, u32 policy, u32 policy argument, String codeword}` | — |
| 109/48 `FindMatchmakeSessionByGatheringId` | Several gatherings | `List<u32>` | `List<MatchmakeSession>` |
| 109/50 `FindMatchmakeSessionByOwner` | A player's arenas | `PID owner, …` | `List<MatchmakeSession>` |
| 109/51 `FindMatchmakeSessionByParticipant` | Friends' arenas | `Struct{List<PID>}` | `List<Struct{PID, MatchmakeSession}>` |
| 109/52 `BrowseMatchmakeSessionNoHolderNoResultRange` | Search arenas by rules | `MatchmakeSessionSearchCriteria, …` | `List<MatchmakeSession>` |
| 109/55 (SSBU) | Arena ID of a gathering, shown by its creator | `u32 gathering ID` | `Struct{String Arena ID, DateTime}` |
| 109/56 (SSBU) | Gathering of a typed Arena ID | `Struct{String Arena ID, DateTime}` | `u32 gathering ID` |
| 109/58 (SSBU) | Queue group for a queue mode; the game puts it in session/search attribute 0 | `u32 queue mode (1, 2, 3, 5, 7, 13)` | `u32 group` (ssbu-oof: group = mode) |

### Notifications (server → client, Notification 14/1 `ProcessNotificationEvent`)

`NotificationEvent` (Switch revision 1) with a type `category × 1000 + subtype` and parameters:

| Type | Meaning | Parameters |
| --- | --- | --- |
| 3001 | A participant joined (also sent about each player to itself; Pia waits for it) | gathering ID, participant PID |
| 3002, 3007 | A participant left / disconnected | gathering ID, participant PID |
| 4000 | Owner changed | gathering ID, new owner |
| 109000 | Gathering closed | gathering ID |
| 110000 | Host changed | gathering ID, new host |
| 201000+ | Online Tourney changed: fetch it again with 201/12 | tourney ID, phase (low byte) |

## Utility (110)

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 110/1 `AcquireNexUniqueId` | IDs for uploaded content | — | `u64` |
| 110/7 `GetIntegerSettings` | Service switches: index 0 keys 9002–9015 turn online services on (9006 Online Tourney, 9007 Spectator); 1100/1101+ Smash level brackets | `u32 index` | `Map<u16, i32>` from `integer_settings` |
| 110/8 `GetStringSettings` | String settings | `u32 index` | `Map<u16, String>` (empty) |
| 110/9 (SSBU) | Eligibility data before Quickplay (seen `6, 3, "US"`) | `Struct{u32, u32, String}` | `Struct{u32, u32, u32}` (zeros) |
| 110/10 (SSBU) | Eligibility check before Quickplay; `true` makes the game show its unstable-network message | `Struct{Struct{u32, u32, u32}, i32}` | `Struct{bool false, u32 0}` |
| 110/11 `GetGameEvents` | Timed events: menu banner (kinds 4), tourney screen (kinds 3) | `Struct{u32 kinds, String language}` | `List<GameEvent>` (below) |

`GameEvent = Struct{u32 id, u32 kinds, u16, String title, String text, DateTime t0, t1, t2, t3, Map<String, Variant>
params, Map<String, List<Variant>> lists, List<GameEventPeriod>}`; `GameEventPeriod = Struct{u32 id, u32, DateTime
start, DateTime end, Map<String, Variant>, Map<String, List<Variant>>, u32}`. The parameter keys the game reads are
listed in re/protocols.md, "Game events".

## DataStore (115)

Objects are the players' records (data type 16, persistence slot 0) and Shared Content (replays and other posts).
Their payloads move over HTTP: `PUT`/`POST /v1/objects/<id>` to upload, `GET` to download.

`DataStoreMetaInfo = {u64 data ID, PID owner, u32 size, String name, u16 data type, qBuffer meta binary, permission,
delete permission, DateTime created, DateTime updated, u16 period, u8 status, u32 referred count, u32 refer data ID,
u32 flag, DateTime referred, DateTime expire, List<String> tags, List<rating>}`. A permission is
`Struct{u8 kind (0 public, 2 listed PIDs, 3 owner only), List<PID>}`.

`DataStorePreparePostParam = Struct{u32 size, String name, u16 data type, qBuffer meta binary, permission, delete
permission, u32 flag, u16 period, u32 refer data ID, List<String> tags, List<rating init>, Struct{u16 persistence slot,
bool delete last}, List<String> extra data}`.

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 115/8 `GetMeta` | Read a record at login (data ID 0 = by owner and slot) | `Struct{u64 data ID, Struct{PID owner, u16 slot}, u8 result option, u64 access password}` | `DataStoreMetaInfo`, or `DataStore::NotFound` |
| 115/21 `PostMetaBinary` | Store the player's record (at match start) | `DataStorePreparePostParam` | `u64 data ID` |
| 115/24 `PreparePostObject` | Start posting Shared Content | `DataStorePreparePostParam` | `Struct{u64 data ID, String upload URL, List request headers, List form fields, Buffer root CA}` |
| 115/25 `PrepareGetObject` | Download one object | `Struct{u64 data ID, u32 lock ID, Struct{PID owner, u16 slot}, u64 access password, List<String>}` | `Struct{String URL, List request headers, u32 size, Buffer root CA, u64 data ID}` |
| 115/26 `CompletePostObject` | Upload finished | `Struct{u64 data ID, bool success}` | — |
| 115/38 `ChangeMeta` | Update the record after a match | `Struct{u64 data ID, u32 modifies flags, String name, permission, delete permission, u16 period, qBuffer meta binary, List<String> tags, u64 update password, u32 referred count, u16 data type, u8 status, Struct{u32 compare flags}, Struct{PID owner, u16 slot}}` | — |
| 115/45 `GetObjectInfos` | Download info for Shared Content being played | `List<u64> data IDs` | `List<download info as 115/25>, List<Result>` |
| 115/62 (SSBU) | Finish a Shared Content post and list it | `DataStorePreparePostParam, Struct{u64 data ID, bool success}, Struct{share description}` | `String content ID` (shown as "ID: …") |
| 115/66 (SSBU) | Shared Content tab (newest first) | `Struct{String language, u16 data type (0xFFFF = "Hot!"), u8, u8, Struct{u32 offset, u32 size}, List<Struct{u16 data type, u32 version}>}` | `Struct{List<C2ShareMetaInfo>}` then `Struct{u16 total}` |
| 115/96 (SSBU) | Shared Content actions in batches; action 3 = like, 4 = like taken back | `Struct{List<(Struct{Map<String, Variant>}, Struct{u64 data ID})>}` | — |
| 115/74, 115/75 (SSBU) | Sent after playing a replay; meaning open | `Struct{u64 data ID, u8, u32}` / a list of them | — / `List<Result>` |
| 115/80 (SSBU) | Asked before a Shared Content tab | — | empty list |
| 115/82 (SSBU) | Sent by both players at match start | `Struct{u8, u32, u32, u32, u64, u32}` | — |
| 115/83 (SSBU) | Console region and language at login | `Struct{u8, Struct{String}, Struct{String × 4}}` | — |
| 115/60, 61, 84, 95 (SSBU) | Login queries | — | empty list / `u32 0` / `List, Struct{u32, u32, u32, u64}` empty / `Struct{bool false}` |
| 115/94 (SSBU) | Sent before Quickplay | `Struct{bool, bool}` | — |
| 115/97 (SSBU) | Play statistics at login | named counters | — |
| 115/54 (SSBU) | Spectator: broadcast list `C2ReplayBroadcastingInfo` | — | **not implemented** (Spectator pending) |

`C2ShareMetaInfo = {DataStoreMetaInfo, u8, u8, u8, Buffer fighters, String content ID, List<Struct{bool, u64, u32}>,
Struct{bool, u8, String poster nickname, String, String}}`.

## Matchmake Referee (120) — Elite Smash, pending

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 120/12 `GetOrCreateStats` | A player's rating (seen: category 1, rating 1500) | `Struct{u32 category, u32 initial rating}` | `Struct{u64 ID, u32 category, PID, u32 × 14 counters (the 13th is the rating)}`; ssbu-oof answers the initial rating and stores nothing |
| 120/1 `StartRound`, 120/3 `EndRound`, 120/4 `EndRoundWithoutReport`, 120/14 (SSBU) | Rounds and results | `Struct{u32, u32, List<u64>}`, `Struct{u64, List<Struct{u64, u32, u32, u32, qBuffer, u32}>}`, `u64`, `Struct{u32, u32, u32}` | **not implemented** |

## Tournament (201) — Online Tourneys, pending

The game learns its tourney only from 201000+ notifications (above); then it fetches it with 201/12.

| Method | Use | Request | Response |
| --- | --- | --- | --- |
| 201/9 | Enter a tourney (one entry per local player) | `Struct{u64 event ID, u32, u16, List<Struct{u8 fighter, u8 costume, u8, String name, qBuffer × 3}>}` | `u32 tourney ID` |
| 201/10 | Leave before the tourney ID is known | by event | **not implemented** |
| 201/11 | Leave the tourney | `Struct{u32 tourney ID}` | `u32` |
| 201/12 | The bracket | `Struct{u32 tourney ID}` | `TournamentInfo{u32 ID, u32, u8 phase, u8, u32 champion, Map<u32, TournamentMatchInfo>, Map<u32, TournamentPlayerInfo>}` |
| 201/13 | Ready to play a match; `1` starts it, `0` sends both players away | `Struct{u32 tourney ID, u32 match ID}` | `u32` |
| 201/14 | Match result | `Struct{u32 tourney ID, u32 match ID, u32 winner's key, u64 replay data ID or 0}` | `u32` |

`TournamentMatchInfo = {u32 ID, u32 next match, u8 round, u8 state (5 = finished), u8, List<u32> player keys, u8,
u64}`, IDs counted from the final (0). `TournamentPlayerInfo = {u32 key, PID, u32, u16, u8, u8, u8, List<entry as in
201/9>}`.

## Outside NEX

- **HTTP API `/v1`** (accounts, tokens, friends, status): [STANDARD.md](STANDARD.md) §2, §7, §8.
- **NAT check (UDP 10025/10125)**: 16-byte probes `u32 type, u32 port, u32 IPv4, u32 address` (big-endian). Type 101
  to nncs1 is answered from the same socket, 102 to nncs1 from the other port, 103 to nncs2 from the same socket; the
  answer carries the sender's public port and IPv4 as the server saw them.
- **Pia dummies (UDP 33335 on nncs1)**: 76-byte Pia packets whose `NatProbeData` (RVCID, CID) tells the server each
  player's public UDP address; no answer. 16 zero bytes to 33334 need no answer either.
