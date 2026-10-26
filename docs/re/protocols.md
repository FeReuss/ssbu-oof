# SSBU 13.0.5 online stack: findings

Facts recovered from the game's own code, each with the address it was read from (`main+0x…` =
offset in `main.elf` as produced by `tools/re/README.md`). "Wiki" marks values that match
kinnay/NintendoClients' public documentation; "binary" marks what was confirmed in the game.
Method names come from the wiki where it has them; `?` = unnamed so far.

## Build

| Item | Value | Source |
| --- | --- | --- |
| Program title | `01006A800016E000`, update 13.0.5 | update NSP |
| `main` NSO SHA-256 | `eb79e639e47d9a0c79bcfe2ec50fc807afa9601800226627b58bd6a1a83dc52d` | ExeFS |
| `main` build ID | `21450c647b8c5940ed5b68218ea128fd3c5d597d` | NSO header |
| NintendoSDK | 8.2.1 | `SDK MW+Nintendo+NintendoSdk_nnSdk-8_2_1` (sdk) |
| NEX | 4.6.13 (`NEX-4_6_13-appc2`, game-specific build) | `SDK MW` strings (main) |
| Pia | 5.19.1 (`PiaNex-5_19_1-forNEX-4_6_3`) | `SDK MW` strings (main) |

`main` exports 4,918 symbols (mostly gameplay); NEX and Pia are statically linked without symbols
but keep RTTI type names, which is how classes below were located.

## Hosts and transport

| What | Value | Source |
| --- | --- | --- |
| NEX game server host | `g%08x-%%.s.n.srv.nintendo.net`, the `%` filled by `nn::nsd::ResolveEx` (retail: `lp1`) | binary `main+0x249354` |
| Game server ID | `0x23380901` (stored at offset +8 of the NEX config built at `main+0x22b8ecc`) | binary; wiki agrees |
| Access key | an 8-character key next to the server ID; only feeds the client's CONNECT signature, which a WebSocket server does not need to check | binary `main+0x22b8ebc` |
| Transport | PRUDP **Lite** over WebSocket (`wss://`, `ws://` also compiled in), subprotocol `NEX` | RTTI `PRUDPEndPointTemplatePRUDPLiteImp`, `ClientWebSocketDriver`; strings `Sec-WebSocket-Protocol` |
| NAT check | `nncs1-%.n.n.srv.nintendo.net`, `nncs2-%.n.n.srv.nintendo.net` (UDP 10025 / 10125) | binary strings; ports per wiki |
| Relay | Compiled in but switched off in 13.0.5: the game never calls NAT Traversal method 6 (see "Relay" below) | disassembly, `relay1` run |
| Out of scope | `api-%%.znc.srv.nintendo.net` (phone-app voice chat), `www-aaaba-%-hac.cdn.nintendo.net` (news pages) | binary strings |

## RMC encoding details confirmed in the binary

- Protocol header writer `main+0x22b480`: `u8 id | 0x80` for requests; IDs above `0x7E` are written as
  `0x7F|0x80` followed by `u16 id` (Tournament 201 uses this form).
- Method ID writer `main+0x22b400`; byte-stream write primitive `main+0x1d0460`.
- Structures carry the NEX 3.5+ header (`u8 version`, `u32 length`); the "no header" flag is the
  stream byte at `+0x69`.
- String = `u16 length incl. NUL` + bytes (`main+0x228510`); qBuffer = `u16 length` + bytes (`main+0x228c80`).
- Every client protocol has a per-method result-extractor table, filled by each `CallXxx` the first time it
  runs, and a dispatcher (vtable slot 21) that bounds the method ID. The bound gives the highest
  method the client understands; the `CallXxx` functions present give the methods the game can send
  (the linker drops unused ones).

## Protocols

| Protocol | ID | ID evidence | Highest method | Methods the game can send |
| --- | --- | --- | --- | --- |
| Ticket Granting | 10 | `main+0x245650` | 6 | not attributed; 6 `ValidateAndRequestTicketWithParam` inferred from the `AuthenticationInfo` and `ValidateAndRequestTicketParam/Result` types it alone uses |
| Secure Connection | 11 | `main+0x245730` | 8 | Register path; exact set not attributed yet |
| NAT Traversal | 3 | wiki, method set matches | 7 | 3 `RequestProbeInitiationExt`, 4 `ReportNATTraversalResult`, 5 `ReportNATProperties`, 6 `GetRelaySignatureKey` (`main+0x258900..0x2592a8`) |
| Notification | 14 | wiki | — | client *serves* it (`_Proto_NotificationProtocolServer`); server sends method 1 `ProcessNotificationEvent` |
| Match Making | 21 | `main+0x24ab60` | 44 | 1 `RegisterGathering`, 2 `UnregisterGathering`, 41 `GetSessionURLs`, 42 `UpdateSessionHost`, 44 `MigrateGatheringOwnership` |
| Match Making Ext | 50 | `main+0x24ab6c` | 6 | none attributed |
| Matchmake Extension | 109 | `main+0x24e014` | 59 | 1, 2, 8, 11, 12, 17–22, 34, 36–41, 44, 48–52, 54, 55, 56, 58 (names below) |
| Utility | 110 | ctor call `main+0x25cde8` | 11 | 7 `GetIntegerSettings`, 9 ?, 10 ?, 11 `GetGameEvents` |
| DataStore | 115 | ctor call `main+0x261c68` | 97 | 1–70, 74–80, 82–97 (standard set + SSBU additions above ~50) |
| Matchmake Referee | 120 | ctor call `main+0x25aaf4` | 14 | 1 `StartRound`, 3 `EndRound`, 4 `EndRoundWithoutReport`, 12 `GetOrCreateStats`, 14 ? (SSBU) |
| Screening | 124 | ctor call `main+0x2ae2f4` | 2 | 1 `ReportDataStoreContent`, 2 `ReportUser` |
| Tournament | 201 | ctor call `main+0x2af47c` | 15 | 9–14 (SSBU-only protocol) |

Also present: `NATTraversalRelay` (Pia relay client), `NintendoNotificationEvent` (friend presence,
client-served), `SmartDeviceVoiceChat` (phone-app HTTP API, out of scope), `AcquireNsaIdToken`.

Matchmake Extension methods the game sends, by number: 1 `CloseParticipation`, 2 `OpenParticipation`,
8 `ModifyCurrentGameAttribute`, 11 `UpdateApplicationBuffer`, 12 `UpdateMatchmakeSessionAttribute`,
17 `CreateCommunity`, 18 `UpdateCommunity`, 19 `JoinCommunity`, 20 `FindCommunityByGatheringId`,
21 `FindOfficialCommunity`, 22 `FindCommunityByParticipant`, 34 `UpdateProgressScore`,
36 `GenerateMatchmakeSessionSystemPassword`, 37 `ClearMatchmakeSessionSystemPassword`,
38 `CreateMatchmakeSessionWithParam`, 39 `JoinMatchmakeSessionWithParam`,
40 `AutoMatchmakeWithParam_Postpone`, 41 `FindMatchmakeSessionByGatheringIdDetail`,
44 `UpdateMatchmakeSessionPart`, 48 `FindMatchmakeSessionByGatheringId`,
49 `FindMatchmakeSessionBySingleGatheringId`, 50 `FindMatchmakeSessionByOwner`,
51 `FindMatchmakeSessionByParticipant`, 52 `BrowseMatchmakeSessionNoHolderNoResultRange`,
54 `FindCommunityByOwner`, 55 Arena ID of a gathering, 56 gathering of an Arena ID, 58 ? (names for 55/56 are
ours, from their layouts and the 2026-10-25 arena run below).

## Request layouts decoded from the game's serializers

`tools/re/ddl.py` output, condensed (`Struct{…}` = structure with header; lists of structs shown inline).

| Call | Request | Notes |
| --- | --- | --- |
| Tournament 9 | `Struct{u64, u32, u16, List<Struct{u8, u8, u8, String, qBuffer, qBuffer, qBuffer}>}` | per-entry strings + three blobs: likely match report |
| Tournament 10, 11, 12 | `Struct{u32}` | tournament ID |
| Tournament 13 | `Struct{u32, u32}` | |
| Tournament 14 | `Struct{u32, u32, u32, u64}` | |
| Utility 9 | `Struct{u32, u32, String}` | matches wiki "MethodParam9" |
| Utility 10 | `Struct{Struct{u32, u32, u32}, u32}` | matches wiki "MethodParam10" |
| Utility 11 | `Struct{u32, String}` | `GetGameEventsParam` |
| Matchmake Extension 54 | `u64` | owner PID |
| Matchmake Extension 55 | `u32` | gathering ID |
| Matchmake Extension 55 → response | `Struct{String, DateTime}` | extractor `main+0x253d50` → reader `main+0x256c20` (String `0x228650`, DateTime `0x1b0580`) |
| Matchmake Extension 56 | `Struct{String, DateTime}` | same structure as 55's response; the game fills only the String (the typed ID, `main+0x172c4b0`); response `u32` gathering ID (extractor `main+0x253e90`) |
| Matchmake Extension 58 | `u32` | queue mode; result selects session/search attribute 0 (see trace below) |
| Matchmake Extension 17 | `PersistentGathering` (Gathering + `u32 type, String password, List<u32> attribs, Buffer, DateTime, DateTime, u32, u32`) + `String` | communities back Online Tourneys |
| Matchmake Referee 1 | `Struct{u32, u32, List<u64>}` | round: gathering, category, participants |
| Matchmake Referee 3 | `Struct{u64, List<Struct{u64, u32, u32, u32, qBuffer, u32}>}` | round ID + per-player result |
| Matchmake Referee 4 | `u64` | round ID |
| Matchmake Referee 12 | `Struct{u32, u32}` | stats target |
| Matchmake Referee 14 | `Struct{u32, u32, u32}` | SSBU-only |

### DataStore calls made at login

Right after `secure connection` the game calls these DataStore methods (seen from the real game through
the MacNativeGames port, 2026-10-23) and abandons the session with error **2306-0103** when one fails.
Responses were read from the per-method result extractors (`nex_protocols.py --json`, field `extractor`).

| Call (order seen) | Request | Response | Evidence |
| --- | --- | --- | --- |
| 61 | none | `u32` | extractor `main+0x28e550` (inline 4-byte read) |
| 83 | `Struct{u8, Struct{String}, Struct{String, String, String, String}}` (60 bytes) | none | extractor `main+0x28ee80` is an empty function |
| 95 | none | `Struct{bool}` | extractor `main+0x28f390` → reader `main+0x2845d0` (bool via `main+0x1d0670`) |
| 84 | none | container (`u32` count, ≤ 0x10000 entries) + `Struct{u32, u32, u32, u64}` | extractor `main+0x28ee90` → readers `main+0x298420`, `main+0x2852f0` |
| 60 | none | `List<Struct>` (elements 0x38 bytes, polymorphic) | extractor `main+0x28e4b0` → reader `main+0x297cb0` |

Values seen in 83: `3`, `"eu_es"`, then `"US"`, `"unknown"`, `"2000-01-01"`, `"eu_es"` (console
region/language settings of the test profile). The structure readers skip to the end of the declared
length, so later fields added by the server would be ignored, but missing ones fail.

Verified against the standard NEX 4 layouts (field order identical): `MatchmakeSession`
(serializer `main+0x254b00`: Gathering structure, then the MatchmakeSession structure ending in
`codeword`), `MatchmakeSessionSearchCriteria` (method 52), `UpdateMatchmakeSessionParam` (method 44),
`FindMatchmakeSessionByParticipantParam` (method 51), `AuthenticationInfo`.

## SSBU data types without a layout yet

From RTTI: `C2ReplayBroadcastingInfo`, `C2ShareMetaInfo`, `C2ShareScoreInfo`, `C2SmashPowerChart`
(DataStore side), `TournamentMatchInfo`, `TournamentPlayerInfo` (Tournament), `GameEvent`,
`GameEventPeriod` (Utility 11; wiki layout exists). Their serializers are not virtual; find them from
the extractor tables (`nex_protocols.py --json`, field `extractor`).

## System services the game uses for online play

From `main`'s imports (this is what a port must provide; see `docs/STANDARD.md`):

- `nn::nifm`: `Initialize`, `SubmitNetworkRequest(AndWait)`, `IsNetworkAvailable`, `GetCurrentPrimaryIpAddress`, `GetCurrentIpConfigInfo`, `GetCurrentProxySetting`, `HandleNetworkRequestErrorResult`.
- `nn::account`: `EnsureNetworkServiceAccountAvailable`, `IsNetworkServiceAccountAvailable`, `EnsureNetworkServiceAccountIdTokenCacheAsync`, `LoadNetworkServiceAccountIdTokenCache`, `GetNetworkServiceAccountId`, `GetNickname`, `LoadCachedNintendoAccountInfo`, user selection functions.
- `nn::nsd::ResolveEx` (host name environment), `nn::socket::*` (BSD sockets incl. `GetAddrInfo`, UDP `SendTo/RecvFrom`), `nn::ssl::Context::Create / ImportServerPki` (TLS for `wss://`).
- `nn::friends`: friend list, profiles, presence, play history, blocked users.
- `nn::ldn` (local wireless) is not online play and is not covered.

## Quickplay eligibility calls (port experiment, 2026-10-24)

The port session supplied `~/Documents/ssbu-oof-experimento-quickplay.patch` and its report.
The server now handles these calls, with required fields decoded rather than merely skipping the
outer structure. Response evidence below comes from that session's binary analysis and game runs;
this integration has transport-level regression tests but has not been rerun with the real game.

| Protocol/method | Request | Response | Reported binary evidence |
| --- | --- | --- | --- |
| DataStore 115/94 | `Struct{bool, bool}`; observed bytes `00 02000000 01 01` | empty | extractor `main+0x28f380` returns immediately; boolean interpretation inferred from observed bytes |
| Utility 110/9 | `Struct{u32, u32, String}`; observed `6, 3, "US"` | `Struct{u32, u32, u32}` (zeros) | reader `main+0x25e710` |
| Utility 110/10 | `Struct{Struct{u32, u32, u32}, i32}`; observed sentinel `-1` | `Struct{bool, u32}` (`false, 0`) | reader `main+0x25e8d0`, boolean reader `main+0x1d0670` |

In the port experiment `true` in 110/10 immediately produced the unstable-network message;
`false` let the game proceed. The field meanings remain unconfirmed; these are neutral compatibility
responses, not an implemented restriction policy. The experiment's next missing call was **DataStore
115/8 (37-byte request)**. Quickplay matchmaking and Pia NAT traversal remain unverified.

The experimental patch's full RMC-body logging was not imported: bodies can contain account tokens.

### DataStore 115/8: GetMeta

The 37-byte request is `Struct{u64 dataId, Struct{PID ownerId, u16 persistenceSlotId},
u8 resultOption, u64 accessPassword}`. The request serializer at `main+0x289c90` (from the method-8
call's `request_calls`) confirms the field widths; names follow the public NEX DataStore reference.
A zero data ID selects a persistent owner/slot lookup. The response extractor `main+0x28c3f0`
delegates to the structure reader at `main+0x28a310` (`DataStoreMetaInfo`).

The server currently has no stored objects. Both direct-ID and persistent-slot queries therefore
return the RMC error `DataStore::NotFound` (`0x80690004`, public NEX error table), after parsing all
required fields. Returning successful fabricated metadata would claim an object that cannot be
retrieved. Access passwords are not logged. Transport tests cover both lookup forms, all truncated
request prefixes, and continued session usability after a miss.

**Runtime confirmed:** the port's two-instance retry accepted NotFound and reached fighter selection.
Our no-submit runs `confirm58a/b` also accepted it and proceeded to matchmaking. This implements
empty-store lookup, not DataStore persistence or uploads; later content features still require storage.

**Objects posted with 115/21 are now found** (2026-10-25): by data ID, or with data ID 0 by owner and persistence
slot, subject to the object's read permission (0 public, 2 listed PIDs, 3 owner only; friend kinds admit only the
listed PIDs for now). The reader at `main+0x28a310` reads, in order: `u64 dataId, PID owner, u32 size, String name,
u16 dataType, qBuffer metaBinary, DataStorePermission permission, DataStorePermission delPermission, DateTime
created, DateTime updated, u16 period, u8 status, u32 referredCnt, u32 referDataId, u32 flag, DateTime referred,
DateTime expire, List<String> tags, List<ratings>` (helpers: String `0x228650`, qBuffer `0x228cf0`, permission
`0x28b0a0`, DateTime `0x1b0580`, tag list `0x2560e0`, rating list `0x28a850`) — the public NEX `DataStoreMetaInfo`.

### DataStore 115/21: PostMetaBinary (2026-10-25)

Sent by **both players when a match starts** (966-byte requests, right after 115/82) **if GetMeta found no slot-0
record at login**; when it found one, the match start sends 115/38 ChangeMeta for it instead (run `battle26f`). In one
run without stored records each player posted a second time ~40 s later.
The method-21 serializer writes the public `DataStorePreparePostParam`: `u32 size, String name, u16 dataType, qBuffer
metaBinary, Struct{u8 permission, List<PID> recipients} permission, same for delete, u32 flag, u16 period, u32
referDataId, List<String> tags, List<Struct{u8 slot, Struct{u8, u8, u8, i64, i32, i32, u8, u16}}> ratingInitParams,
Struct{u16 persistenceSlotId, …} persistenceInitParam, List<String> extraData`. The extractor `main+0x28cd10` reads a
single `u64` (the new data ID), as in the public `PostMetaBinary`. The server stores the metadata (no payload upload
is involved) and returns a fresh ID; slot `0xffff` means none. What the game keeps there (name, data type) is logged
at DEBUG by the server; its meaning is still to be identified.

### DataStore 115/38: ChangeMeta (2026-10-25)

Sent by **both players right after a Quickplay match's results** (1025-byte requests). The method-38 serializer writes
the public `DataStoreChangeMetaParam`: `u64 dataId, u32 modifiesFlag, String name, permission, delete permission, u16
period, qBuffer metaBinary, List<String> tags, u64 updatePassword, u32 referredCnt, u16 dataType, u8 status,
Struct{u32 comparisonFlag, String name, permission, delete permission, u16 period, qBuffer metaBinary, List<String>
tags, u32 referredCnt, u16 dataType, u8 status} compareParam, Struct{PID owner, u16 slot} persistenceTarget`. The
extractor `main+0x28d7e0` is a bare `ret` (empty result). The server applies the fields selected by the modifies flag
(bits in field order: name 0x1 … status 0x100) to the caller's own object, found by data ID or, with data ID 0, by the
persistence target; the compare param is not checked yet. Observed: `modifiesFlag = 0x58` (period 0x8, meta binary
0x10, referred count 0x40 in that order), the data ID of the slot-0 object, comparison flag 0, persistence target
unused (`0, 0xffff`), a 900-byte meta binary. The bit order is taken from the field order (as in the public NEX
behaviour); 0x10 = meta binary is the one that matters here. Together with 115/21 this is the player's slot-0 record:
posted at match start, changed after the results, read by GetMeta at login.

**The record carries the disconnect state.** A client that dropped mid-match (port crash, run `battle26e`) sent the
pending ChangeMeta for that match at its next login, and after GetMeta returned the record the game showed its own
warning ("the match was interrupted in the middle of your last online battle; disconnecting too often may restrict
online play"). Every test run starts from a fresh copy of the same local save, so the warning can only come from the
server's record: online penalties are judged by the client from this object. Losing the records (server restart,
in-memory store) silently forgives disconnects.

### DataStore 115/82 (2026-10-25)

`Struct{u8, u32, u32, u32, u64, u32}` (30 bytes; the u64 is computed by the serializer). Both players send it when the
match starts (after the host's Matchmake Extension 109/1 and 109/11), right before 115/21; values seen: `1, 1460, 123,
1460, 0, 1` in every run. The extractor `main+0x28ee70` is a bare `ret`: an empty result. Accepted and logged.

### Battle Arenas: Arena ID (109/55, 109/56), 2026-10-25

- After 109/38 creates an arena, the creator calls **109/55** with the gathering ID (`main+0x172c3c0` → wrapper
  `main+0x251ee0`) and shows the response's String as **"ID: …"** in the arena (seen: `ID: ATJ33`). The server picks
  the code; the client never proposes one.
- "Buscar salas → Buscar por ID" opens a software keyboard for exactly **5 characters** (port log: type 8, 5–5
  characters, disabled-key flags 0xac), then calls **109/56** with that String and, on success, **109/48** with the
  returned gathering ID to show the arena card; joining is the usual 109/39.
- The response DateTime's meaning is not established (issue time or expiry); the game accepted a past time (the
  gathering's creation).
- A 1-on-1 arena match between two instances played to the end and returned both to the arena with no server call
  during the match: arena matches post no DataStore record (unlike Quickplay's 115/82 → 21/38). Ring, fighter
  confirmation, quick chat and results travel over Pia.

## Service switches: Utility 110/7 `GetIntegerSettings` (2026-10-25)

At login the game asks for index 0 (`Map<u16, i32>` response). The online menu's Lua calls the native binding
`is_invalid_online_sequence(sequence)` (`main+0x1bef500`, registered in the online binding table at `main+0x50ac750`)
before opening an online sequence; it maps the sequence to a setting key and treats the sequence as available only when
that setting reads exactly 1 (lookup `main+0x1739120`: the server's value when the key was sent, otherwise a default from
the game's own parameter data). Unavailable shows the message `pop_online_service_error` ("this service is not
available, see the news").

| Sequence | Key | Observed |
| --- | --- | --- |
| `0x7010100` | 9002 | |
| `0x7010200` | 9003 | |
| `0x7010300` | 9004 | |
| `0x7010600` | 9011 | |
| `0x7020000` | 9006 | Online Tourney: unavailable without the key |
| `0x7070000` | 9007 | Spectator: unavailable without the key |

Quickplay, Battle Arenas and Background search work with an empty map (their defaults are on). With all six keys set to
1, Online Tourney opens (Utility 110/11 with kinds 3, then Tournament 201/9) and Spectator opens (DataStore 115/54).

### Quickplay attributes and Smash level brackets (2026-10-25)

A Quickplay search (109/40) seen from the game: session attributes `[1, 0, 0, 0, 0, 0]`, one criteria list with
attributes `["1", "0", "0", "", "", ""]` (exact values). The game fills them in `main+0x16963d0`:

- attribute 0: the queue group from 109/58 (above);
- attribute 1: the player's **Smash level bracket**: the index of the first threshold, among integer settings
  1101, 1102, ... (as many as setting **1100**), that is not below the player's level (`main+0x1696914..0x169695c`);
  without settings every player is in bracket 0;
- attribute 2: 1 for queue mode 3, else 0.

The player's level comes from `main+0x1696b40` (integer setting 1000 as a base, then the player's online level data;
the fighter select shows "Smash level ---" while there is none). The search sets exact values through Pia's attribute
setter (`main+0x116c50`); the server's criteria filter already enforces them, so level and rule matching follow
whatever the client asks once players have a level (Elite Smash / stats).

## Game events: Utility 110/11 `GetGameEvents` (2026-10-25)

Request `Struct{u32 kinds, String language}` (`language` seen: `"es"`). The online menu asks for kinds 4 at login and the
tourney screen asks for kinds 3; the game's own filter (`main+0x170bda0`) keeps the events whose second field shares a
bit with the mask it wants, so the server should return only matching events.

Response `List<GameEvent>`; layouts decoded from the readers (`GameEvent` `main+0x25d780`, element size 0xd0;
`GameEventPeriod` `main+0x25e070`), matching kinnay/NintendoClients' wiki (which names no fields):

- `GameEvent = Struct{u32 id, u32 kinds, u16, String title, String text, DateTime t0, DateTime t1, DateTime t2,
  DateTime t3, Map<String, Variant> params, Map<String, List<Variant>> lists, List<GameEventPeriod> periods}`.
- `GameEventPeriod = Struct{u32 id, u32, DateTime start, DateTime end, Map<String, Variant>, Map<String, List<Variant>>,
  u32}`.

Observed with the real game (local time UTC-3):

- kinds 4: the online menu banner shows `title` and "on <day> (from <t1> to <end of the current period>)".
- kinds 1: one tourney card on the tourney screen, "in progress <t1 day> > <period end>"; the card's name and
  description come from the game's own templates, not from `title`; the fighter select shows the current period
  ("from <period start> to <period end>").
- kinds 2: not shown by the tourney screen in the same test (meaning open).

Keys the game reads from `params` (`Map<String, Variant>`, getter `main+0x1722330` for integers, `main+0x17251e0` for
strings): `operation_id`, `amiibo`, `team`, `melee_kind`, `melee_rule`, `time_sec`, `stock`, `hp`, `spirits`,
`defence_reaction`, `charge`, `stage_gimmick`, `is_suddendeath`, `scaledown_stage`, `drop_bomb`, `speed`, `camera`,
`body_size`, `head_option`, `body_option`, `state_option`, `weight`, `item_appear`, `url1`, `url2`,
`tournament_entry_max_seconds` (default 60), `competition_aggregate_at`, `birthday_mustbeafter`,
`birthday_mustbebefore`. From `lists` (`main+0x17224b0`): `fighter_flags`, `competition_stage_flags`,
`competition_stage_type`, `item_flags`, `prize_type`, `prize_index`, `prize_value`, `prize_param0`, `prize_param1`.
Their values' meanings are not established yet.

## Online Tourney: Tournament 201 (2026-10-25, 2026-10-26)

Entering a tourney (fighter chosen, +) sends **201/9**: `Struct{u64 event id, u32, u16, List<Struct{u8 fighter,
u8 costume, u8, String name, qBuffer, qBuffer, qBuffer}>}`; seen `1, 1500, 80, [{6 (Kirby), 0, 0, "oofdev1", -, -, -}]`
(one entry per local player). 9, 10, 11, 13 and 14 return a `u32` (extractors `main+0x2b1be0..0x2b1f40`). After 9 the
game waits in the "searching for rivals" stage; `tournament_entry_max_seconds` (60) is the countdown shown.

**The game learns its tourney only from notifications.** Its handler (`main+0x171f9d0`) accepts NotificationEvent types
201000-201999 (category 201; subtype ignored): param1 = the tourney ID, param2's low byte = a phase. With no tourney
yet it takes only phase 0; afterwards only the same ID. Entering (`main+0x1736f20`) clears both (ID 0, phase 0xFF), so
the 9 response alone does nothing. The tourney sequence (`main+0x16c3cd0`) compares the phase with the last one it saw
and, when it grows, fetches the tourney again. Requests 10-14 all send `Struct{u32 tourney ID}` (13: `{u32, u32}`,
14: `{u32, u32, u32, u64}`) built by the request switch at `main+0x1736cd0` (kinds 0-5 → 9, 10/11, 12, 11, 13, 14).

**201/12** (sent after each phase notification), response `TournamentInfo` (reader `main+0x2b03a0`): `Struct{u32 ID,
u32, u8 phase, u8, u32, Map<u32, TournamentMatchInfo>, Map<u32, TournamentPlayerInfo>}` — both containers are maps (a
`u32` key before each structure; readers `main+0x2b0660`, `main+0x2b0870`).
- `TournamentMatchInfo` (`main+0x2b0fb0`): `Struct{u32, u32, u8, u8, u8, List<u32>, u8, u64}`.
- `TournamentPlayerInfo` (`main+0x2b1740`): `Struct{u32, u64 PID, u32, u16, u8, u8, u8, List<entry as in 9>}`.
- A wrong layout shows error 2306-0116. If `+0x14` (phase) already equals the next notification's phase, the game does
  not refetch.

Verified: phase 0 notification → 201/12 with the entrants and no matches → no error, the game keeps waiting. **Open:**
with one match (players' keys 0 and 1, any of the tried values for the match's first two `u32`s and for TournamentInfo's
`u32`s), the bracket screen aborts both games with `std::out_of_range` (empty vector reaching `main+0x1d0e590`, from
`main+0x1d07cb4`). The screen's round index is computed by `main+0x239d150` from the game's bracket model (round count
at `+4`, one 0x18-byte vector of matches per round; scene field `+0x2a8` set at `main+0x18ba01c`). The model is built
after 201/12 by the completion handler registered at `main+0x17379f8` (`main+0x1737dd0`); reading it gives the meaning
of the match fields (round, position) and of TournamentInfo's `u32`s.

## Spectator: DataStore 115/54 (2026-10-25)

Opening Spectator (with key 9007 on) sends **115/54** with no parameters; its extractor (`main+0x28e240`) reads a
`C2ReplayBroadcastingInfo` (`main+0x2970b0`). Without an answer the game says it could not show the replay. The
broadcasts are replays of other players' matches kept in DataStore; the layout and the upload side are open.

## Shared Content (2026-10-26): post, browse, download

Verified with the game: a replay saved in the Vault was posted ("Content posted."), listed by another account under
Online > Shared Content, opened (title, rules, length, ID, poster, version shown) and played back after downloading it.

| Step | Call | Layout | Evidence |
| --- | --- | --- | --- |
| Post (Vault > Replays > replay > Post, title from the software keyboard) | **115/24 PreparePostObject** | request: the public `DataStorePreparePostParam` (data type 2 for a replay, 976-byte meta binary, period 90, no persistence slot, tag `lang:<language>`); response `DataStoreReqPostInfo{u64 data ID, String url, List<{String key, String value}> request headers, List<same> form fields, Buffer root CA}` (reader `main+0x2907b0`) | `rep2`..`rep5` runs |
| Upload | HTTP to the URL from 24 (through the game's own HTTP client) | the whole replay file (472,552 bytes for a 6:11 replay) | server log |
| Complete and list | **115/62** | request: (`DataStorePreparePostParam` again, `DataStoreCompletePostParam{u64 data ID, bool success}`, share description); response `String` content ID (extractor `main+0x28e5f0`) | `rep3` capture |
| Browse (a tab) | 115/80 (no parameters; `List<u64>`, empty is fine), then **115/66** per tab | see below | `rep5`, `view1` |
| Play | **115/45 GetObjectInfos** `List<u64> data IDs` → `List<DataStoreReqGetInfo>`, `List<Result>` (extractor `main+0x28db50`); then HTTP GET of the URL | `DataStoreReqGetInfo{String url, List<key/value> headers, u32 size, Buffer root CA, u64 data ID}` (reader `main+0x288ee0`) | `view1` |
| Likes, views | **115/96**, batched every few minutes | `Struct{List<(Struct{Map<String, Variant>}, Struct{u64 data ID})>}`; map keys `action_type` (0 listed, 1 opened, 3 liked, 6 played), `alg`, `list_page_type`, `thumbnail_size`, `play_time`; no response | `view2` |

Share description (the third parameter of 62, structure version 1, serializer `main+0x283d80`): `u8 kind` (3 for a replay),
`u8`, `u8` (255 seen), `String` poster nickname, `String`, `String`, `Buffer` fighters (one byte each: 6, 63 = Kirby,
Bayonetta), `u8` (1 seen), `Map<String, Variant>` search attributes (`country`, `fighter_1`, `fighter_2`, `melee_kind`,
`melee_mode`, `melee_rule`, `movie_time` (seconds), `nickname`, `score`, `stage`, `stage_type`, `use_spirits`,
`version` = 0x9000), `u32`, `u32`.

115/66 request: `Struct{String language, u16 data type (0xFFFF on "Hot!"), u8 (4 seen), u8 (3 seen), Struct{u32 offset,
u32 size (100)}, List<{u16 data type, u32 version}>}`; the tabs ask for data type 4 (videos), 2 (replays), 3 (stages), 0
(Mii fighters), 1 (spirit teams), and the list names what the game can show (0/0, 1/0x4000, 2/0x9000, 3/0x9000,
4/0x3000). Response (reader `main+0x286dd0`): a structure that extends another, so the base part comes first with its
own header: `Struct{List<C2ShareMetaInfo>}` then `Struct{u16}` (the total). Without the second part the game shows error
2306-0116.

`C2ShareMetaInfo` (reader `main+0x287cb0`): `DataStoreMetaInfo`, `u8`, `u8`, `u8` (the description's first three),
`Buffer` fighters, `String` (shown as "ID: ..."), `List<Struct{bool, u64, u32}>` (reader `main+0x288380`; empty is
accepted), `Struct{bool, u8, String, String, String}` (reader `main+0x2886b0`; the poster nickname shows from the first
string).

### Matchmake Extension 109/58 (2026-10-24)

Both real game instances reached fighter confirmation after accepting GetMeta/NotFound, then called
109/58 with 4-byte bodies and received NotImplemented (port log `logs/oof-current.log`,
04:38:30 and 04:38:43 UTC). No match was established. The request writer at `main+0x252418..0x252430`
sets method 58 and writes four bytes. Extractor `main+0x253f30` reads one four-byte result, with no
structure header. Thus the wire contract is **u32 -> u32**. The subsequent trace below establishes its use.
The previous "gathering ID" label was an assumption, not a verified field meaning.

Further static tracing establishes the operational meaning of the result:

| Step | SSBU 13.0.5 evidence |
| --- | --- |
| Request input comes from the queue-mode selector | `main+0x16a76b8..0x16a76f8` passes mode to `main+0x17086f0`; only modes in mask `0x20ae` (1,2,3,5,7,13) enter this path (`main+0x16a757c..0x16a7594`). Mode 13 substitutes an event-configured mode. |
| Async request/result | `main+0x172c1b0..0x172c1c0` passes the mode to the method-58 wrapper at `main+0x252300`, with output at context+0x120. Completion at `main+0x170252c..0x1702534` copies it to queue-manager+0xb0. |
| Group used in session creation | `main+0x16a78e4..0x16a78f0` passes that value through `main+0x168ae00` to `main+0x16963d0`; `main+0x16969e8..0x16969fc` stores it at setting+0x4c with presence byte +0x58. `main+0x37077f8..0x3707810` sends that value to the attribute setter with index **0** (`main+0xc10e0`). |
| Same group used in search | `main+0x3707f5c..0x3707f74` passes setting+0x4c to the search attribute setter with index **0** (`main+0x116c50`). |
| Also indexes client policy masks | `main+0x16cd684..0x16cd69c` computes `1 << group` and tests integer setting 10010. Keep groups below 32; `0xffffffff` is the client's unset sentinel. |
| Queue mode is not always NEX game_mode | `main+0x1696438..0x1696440` maps input mode 3 to NEX game_mode 1. Distinct queue groups can therefore be necessary even when NEX game_mode matches. |

We call this **ResolveMatchmakingGroup(queueMode)** descriptively; the original method name and Nintendo's
assignment policy are not recovered. It selects session/search attribute 0, rather than returning a gathering
ID or a per-fighter GSP value. This does not rule out a role in separating ranked queues; it does not establish
GSP calculation or Elite thresholds either. Attribute 1 is populated separately (`main+0x1696970`,
`main+0x3707814..0x370782c`).

**OOF policy:** one stable group per admitted queue mode (`group = mode`, IDs 1,2,3,5,7,13). This is our routing
policy, not a claim about Nintendo's choices. It requires no existing gathering or per-connection assignment,
works across nodes, and does not rotate groups while a client caches the result. Unknown modes and bodies other
than four bytes fail with InvalidArgument. The normal criteria matcher enforces the resulting attribute-0
filter, including rejecting a gathering missing a required attribute. Tests prove that clients in one group
meet and clients in another group do not, even with the same NEX game_mode. This is queue separation, not a
completed GSP/rules-preference ranking implementation.

Runtime verification (local no-GPU-submission port run `confirm58a`, same 13.0.5 executable):
2026-10-24 04:50:56 UTC, the server resolved **mode 1 -> group 1**, then accepted **AutoMatchmake 109/40**
and created gathering 1 for the same principal. The client loaded `lua2cpp_donkey` and did not show
2306-0103 at that point. Logs: port `SSBU_build/logs/confirm58a.log`, isolated server
`/private/tmp/ssbu-oof-method58-confirm.log`. This confirms progression past 58; it does not prove
Nintendo's original assignment policy or a P2P fight. No GPU submission was enabled.

Two-instance follow-up (`confirm58c/d`, both no-submit, distinct accounts and game-slot directories):
at **04:53:38 UTC** both resolved mode 1 -> group 1; at **04:53:39 UTC** AutoMatchmake returned
**gid=3, players=1** then **gid=3, players=2**. `/v1/status` reported one session and two online players.
This verifies that real game requests carrying the selected group can pair in the same gathering.
It does not establish a P2P connection, input exchange or completed battle. The temporary verification
listener was 127.0.0.1:18090; no Nintendo service was contacted and no GPU submission enabled.

## After AutoMatchmake: Pia waits for its own participation notification (2026-10-24)

Pia's NEX session jobs (`NexMatchCreateSessionJob`, `NexMatchJoinSessionJob`; step names are strings in
`main`) go `…WaitCreateMatchmake / WaitJoinMatchmake → WaitNotification → StartNatSession → WaitStartNatSession`.

| Fact | Evidence |
| --- | --- |
| Entering `WaitNotification` sets a deadline of now + 10,000 ms; past it the job fails (code `0xac5a`). This is the ~10.33 s timeout seen with two instances, after which the owner sent 21/2 and the joiner 50/1. | `main+0x105638` (schedule), step function `main+0x1057a0` (deadline compare at `+0x105894`) |
| `WaitNotification` asks, for every local player, whether a participation for (current gathering, that player) was recorded, and needs all of them. | `main+0x1058f4..` (loop over local players, AND of the results) |
| Pia's NEX notification handler (`NexMatchMeshLayerController::NexNotificationEventHandler`, vtable slot 2) reads the event type at +0x18 as category = type / 1000, subtype = type % 1000, param1 at +0x20 (compared with the gathering ID) and param2 at +0x28. Categories handled: 3, 4, 109, 110, 120, 121, 122. | `main+0xef5d0` |
| 3001 (category 3, subtype 1) records participant = param2 in gathering = param1, with a player count taken from the text's first character when it is `1`–`4` (empty text = 1); 3007 and other subtypes of 3 take the leave path. 4000 (category 4) handles an owner change. | `main+0xefa44..`, register `main+0xef000` |
| A notification for a gathering Pia does not track yet gets a slot (`main+0xedea0`), so arrival before the RMC response is harmless. | `main+0xef274` |

Server rule derived from this (implemented in `matchmaking.rs`): on create the creator receives 3001
about itself; on join every participant, the joiner included, receives 3001 {param1 = gathering,
param2 = joiner}. Confirmed with two GPU instances (2026-10-24 05:35 UTC): no more 21/2 and 50/1
at +10 s; Pia moves on to its NAT check.

Pia resolves the NAT check hosts itself: `main+0xc4f6c`/`+0xc4fa4` pass the `nncs1-%`/`nncs2-%`
patterns (port 10025 set at `+0xc4fc0`) to its resolver `main+0xba850`, which calls
`nn::socket::GetAddrInfo` directly (stub `main+0x39c0b70`, GOT `0x529f498`) with no `nsd::ResolveEx` in
between. The `%` is therefore left to the socket resolver, as on the console (`docs/STANDARD.md` §4).

## Relay (2026-10-26): switched off in SSBU 13.0.5

Pia 5.19's relay (`NexNatRelay`, vtable `main+0x4f4b488`) is linked but never enabled, so no relay server can help two
players whose NATs block each other; the original service had none either.

- Every relay path first tests the Pia NEX facade's byte `+0xb2` (`main+0xc36d0`; the facade pointer is the global the
  GOT slot `main+0x52a4d88` points to). The facade constructor (`main+0xc3220`) clears it and nothing in the game writes
  it (no other byte store at that offset on the facade). With it clear, `StepRequestRelayServerSetting` (`main+0xd2fb0`)
  → `NexNatRelay` slot 7 (`main+0xd1bb0`) returns before `CallGetRelaySignatureKey` (`main+0x259190`), and sends never
  get a relay header (`main+0x10f960`).
- Observed: no session ever called NAT Traversal 3/6; with the port's peer-to-peer traffic dropped on purpose (run
  `relay1`, two instances, the server answering mode 1 with an address) the game still did not call it: after its
  probes it reported the failure (3/4) and left the gathering.
- For the record, what an enabled relay would use: 3/6 answers `mode` (> 0 enables it), the server's current time,
  `address` (type 1 = host name, else an IPv4 literal; `main+0xd19c0`), `port` (0 means 12525) and the game server ID.
  Each Pia packet would get a 44-byte header (`main+0xd2590` writes it, `main+0xd2790` checks it): `F5 D0 00 00`,
  source IPv4, destination IPv4, source port, destination port, game server ID ^ 0xDB319579, a 32-bit value
  ^ 0xBEE17D2F, server time in seconds (accepted within ±150 s), then MD5 (Pia's `Md5Context`) over a 16-byte key, the
  first 28 header bytes and the first 50 payload bytes. The value and the key come from bytes `+0x568..+0x57b` of a
  session structure (`main+0xed8f0`); their origin was not traced.

## Pia NAT check (2026-10-25)

Seen from the real game (two local instances, `OOF_NET_TRACE=1` datagram dumps) and the 13.0.5 binary.

| Fact | Evidence |
| --- | --- |
| The NAT check `Start` (`main+0xd3290` → `0xc61f0` → `0xc64e0` → `0xcb4b0`) returns `0x10c08` unless it finds two server addresses: the first resolved one, and the first later one with the **same port and a different IP** (`main+0xc6590..0xc65f0`; `0xb2850` = address set and port ≠ 0, `0xb2820` = same 16-byte address). With `nncs1` and `nncs2` on one IP there is no second server, Pia never opens its socket, and the game shows 2618-0006. | LLDB on the real game: `0xc3d2c` result `0x10c08` before, 0 once `nncs2` resolved to another address |
| Pia resolves `nncs1`/`nncs2` with port 10025 (`main+0xc4fc0`) and 10125 (`+0xc5018`): four addresses. | disassembly |
| Probes are 16 bytes, `u32 type, u32 port, u32 IPv4, u32 address` (big-endian). Observed per round: type 101 ×5 to nncs1:10025 (answer from the same socket), 102 ×5 to nncs1:10025 (answer from nncs1:10125), 103 ×5 to nncs2:10025 (answer from the same socket). Two rounds per session, each on a new socket bound to a random port. | datagram dumps, server `natcheck.rs` |
| Pia also sends 16 zero bytes ×5 to **nncs1:33334** per round (port set at `main+0xcafac`/`0xcb53c`); no answer was needed for the NAT check to finish. | datagram dumps |
| Result: `ReportNATProperties` (3/5, 12 bytes), then Secure Connection **ReplaceURL (11/7)**: old = the registered local URL (`address=<LAN>;port=2;…;Tpt=2;natf=0;natm=0`), new = `address=<LAN>;port=<Pia UDP port>;CID=…;natf=17;natm=1;…`. ssbu-oof replaces the stored URL with the same scheme/address/port (`secure.rs`). | server log, test `replace_url_updates_the_registered_station` |
| Next, each client sends a 76-byte unencrypted **Pia packet** ×3 to **nncs1:33335** (header version 4 = Pia 5.18–5.21, connection id 0 = sent to an address). Its message is **NAT Protocol (0x34)**, port 0, with `NatProbeData` probe type **0xFF = dummy** (layout per the Pretendo wiki's Pia pages): a mapping-opening dummy that expects **no answer**. Sent from Pia's dispatch (`main+0x10fba0` ← `0x10f6ac` ← `0x162c74` ← `0x1649fc` ← `0x13b620`); the address is the first NAT check server's with port 33335 (`main+0xcc2c0`). Not the cause of the failure below. | datagram dumps, guest frames of the send |
| With every NAT check probe leaving from one address (as behind a home router), `natm=1`, `natf=17`. Then Pia job steps (LLDB, names at `[job+0x40]`): **owner** `RandomMatchmakeJob::CreateMesh` → `NexCreateMeshJob::SetupLocalPlayerInfo` → `StartMonitoringServerAddressResolution` → `SetupLocalStation` (done) → **`ProcessJoinRequestJob::InitialStep` returns 3** → `SessionStatusCheckJob::CheckSessionStatus4JointSession` 3 → `RandomMatchmakeJob::CompleteFailure`; **joiner** `RandomMatchmakeJob::GetStationConnection` → `WaitGetStationConnection` → `CheckSessionStatus4JointSession` 3 → `CompleteFailure`. Both show 2618-0006. No UDP datagram between the two clients was seen. `CheckSessionStatus4JointSession` is `main+0x14f310` (its session status call `[[0x52a5080]+8]->vtable+0x30` returned 0 throughout). | LLDB `mesh25a/b`, `status25b` |
| Why both abort: `GetStationConnection` (`main+0x142f40`), `WaitGetStationConnection` (`0x1430f0`) and the status check all read the session state `main+0x146ba0(S)`, S = `[[0x52a5080]]`: `[S+0xd8]` in 2..7 gives state `[S+0xd8]+2`, else `[S+0xd4]` in 2..4 gives `[S+0xd4]-1`. States 5–8 (`[S+0xd8]` = 3, 4, 5, 6) abort with `0xc406`, `0xa471`, `0xc420`, `0xc421` (jump table `0x4497e28`). Which value is set, and by whom, is the next thing to trace (write watchpoint on `S+0xd8`). | disassembly |

## From matchmaking to the Pia mesh (2026-10-25, second session)

Two real-game instances on one Mac (MacNativeGames port, `OOF_NET_TRACE=1`, LLDB job-step traces). Each fact below was
needed to get one step further; the server rules derived from them are in `secure.rs`, `matchmaking.rs`, `natcheck.rs`.

| Fact | Evidence |
| --- | --- |
| The earlier "state 3 / 0xc406" aborts were the port's socket errno, not the server: Pia maps `GetLastErrno` with **Linux numbers** (`main+0xb9de0`: 4/11/12/16 → 0x2c09 "no data", 100/104/107/110 → 0xc406, 9/22/88/90/95/97 → 0x10c07, anything else → 0x10c08) and the port returned macOS's EAGAIN (35). Fixed in the port; the owner then completes `CreateMesh`. | disassembly of the jump tables at `0x4494448`/`0x4494284`, LLDB `upd25`/`steperr25` |
| **GetSessionURLs** (21/41): Pia's parser (`main+0xc2460`) takes **one or two** station URLs; with two, exactly one must be public (`type` bit 2, read at `0x160350` from the parsed flags) and one private. Three URLs → 0x10c07 and `WaitGetStationConnection` fails. Peers with the same public address use the private one. | LLDB `gsc25c` (result 0x10c07 after the 21/41 answer), disassembly |
| 13.0.5 **registers two placeholder URLs** (`port=1`, `port=2`, no `type`). Behind a NAT it later replaces the `port=2` one (11/7) with its real local address, Pia UDP port, `CID`, `natf`/`natm`. **Not behind a NAT it sends no ReplaceURL** (seen when the public and local addresses are equal). | server log `Register local=[…]`, runs `lan25`/`same25` |
| The station URL fields map to Pia ids: `PID` = station **constant id** (u64), `CID` = **variable id** (u32, also the last field of `NatProbeData`), `RVCID` = the NEX connection id. | decrypted packets below (`0x000eaeb9477794f3` = PID 4132760465151219) |
| The Pia NAT dummy to nncs1:33335 carries `NatProbeData` = `u32 RVCID, u8 0xFF, pad, u64 timestamp, u32 CID`; after matchmaking it is the same message encrypted (80 bytes). It expects no answer. The server learns the client's public address **and CID** from it. | decrypted with the session key |
| A joiner given a host URL with `CID=0` received the host's probe requests and never answered them. | runs `splitc25`, `cid25` |
| NAT traversal: each side sends **RequestProbeInitiationExt (3/3)** (targets = the other station, station = itself, `probeinit=1` on the joiner); the server relays **InitiateProbe (3/2)**. Probes are `NatProbeData` type 0 (request) / 1 (reply), encrypted, peer to peer. Traversal completed in both directions (`WaitForNatTraversalCompleted` → 0). | `samealias25`, `pia_decrypt.py` |
| Pia ignores datagrams from a NAT check server's **IP** (port ignored: `main+0xcfc94` with `0xb2820`, a 16-byte address compare). A local test whose clients share an IP with nncs1/nncs2 can never connect; the port's `OOF_NAT_ALIAS` gives the game virtual NAT check addresses. Not a production concern. | disassembly, `alias*25` runs |
| Before sending its connection request the joiner checks the host's **PID was announced in a 3001 for this gathering** (`NexConnectStationJob` vtable+0x40 = `main+0xf1db0` → registry lookup `main+0xee8d0`, count > 0). The server only announced each player to itself and the joiner to the owner, so `SendConnectionRequest` failed at once. | LLDB `coverc25` |
| Station protocol (0x14) connection request (Pia 5.19 layout): type 1, protocol list (9 × id/version 0: 0x14 0x18 0x1c 0x34 0x58 0x68 0x7c 0x94 0xa4), connection id, inverse flag, target constant id, target variable id, station location. The host answered **type 2, result 3** — not a version problem: `main+0x19df4c` is reached when the host finds a station at the requester's address but none with the requester's id (`StationManager` vtable+0x48 = `0x166d80`, compares the station's byte `+0x38` with the low byte of the requester location's `+0x74`, which was 5 = its RVCID) or constant id. The table held only the host's own entry (IP 192.168.1.7, port 2) and the address lookup compares only the IP (`0x19c010` → `0xb2820`): with both test instances on one IP the joiner collides with the host's own entry. A one-Mac artifact; two distinct public addresses avoid it. Pia's helpers: `0xb2940` = private address (10/8, 172.16/12, 192.168/16, 169.254/16), `0xb2a30` = loopback. | LLDB `ack25`, `ackc25` |

Pia packet crypto (Kinnay's NintendoClients wiki, verified on these captures): AES-128-GCM, key = the matchmake session key's
first 16 bytes, nonce = connection id (1 byte) + gathering id & 0xFFFFFF (3 bytes, big-endian) + the header's 8-byte
nonce, tag at header offset 0x10, no AAD. The server logs the session key at TRACE so a test capture can be decrypted
(the port's `SSBU_build/analysis/dev-scripts/pia_decrypt.py`).
