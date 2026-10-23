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
| Relay | Pia asks NEX for a relay server (`NexNatServerAddressResolveJob::StepRequestRelayServerSetting`) via NAT Traversal method 6 | binary strings |
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
54 `FindCommunityByOwner`, 55 ?, 56 ?, 58 ?.

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
| Matchmake Extension 56 | `Struct{String, …}` | rest not decoded (variant/holder) |
| Matchmake Extension 58 | `u32` | gathering ID |
| Matchmake Extension 17 | `PersistentGathering` (Gathering + `u32 type, String password, List<u32> attribs, Buffer, DateTime, DateTime, u32, u32`) + `String` | communities back Online Tourneys |
| Matchmake Referee 1 | `Struct{u32, u32, List<u64>}` | round: gathering, category, participants |
| Matchmake Referee 3 | `Struct{u64, List<Struct{u64, u32, u32, u32, qBuffer, u32}>}` | round ID + per-player result |
| Matchmake Referee 4 | `u64` | round ID |
| Matchmake Referee 12 | `Struct{u32, u32}` | stats target |
| Matchmake Referee 14 | `Struct{u32, u32, u32}` | SSBU-only |

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
