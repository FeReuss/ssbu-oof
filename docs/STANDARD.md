# OOF port standard v0.2

Implemented by ssbu-oof 0.2.0.

What a native port or emulator of **Super Smash Bros. Ultimate 13.0.5** must do so the unmodified
game plays online through an ssbu-oof server. The game keeps speaking its own protocols; the port
only provides the console services those protocols sit on. Every requirement below comes from the
services the game imports (docs/re/protocols.md, "System services").

Keywords MUST / SHOULD follow RFC 2119. Version history at the end.

## 1. Configuration a port exposes

| Key | Meaning | Example |
| --- | --- | --- |
| `oof.server` | host:port of the ssbu-oof HTTP/WebSocket endpoint | `play.example.org:443` |
| `oof.tls` | whether that endpoint uses TLS | `true` |
| `oof.ca` | optional PEM file trusted for that endpoint instead of the system store | `oof-ca.pem` |

The port MUST NOT require game files, keys or Nintendo account data to be sent to the server.

## 2. Identity (`nn::account`)

Every player has an **account** on the server: a user name and a password chosen by the player, with no e-mail address
or phone number. The user name is unique on the server (without regard to case), has 3–10 characters (letters,
digits, `_`, `-`, `.`) and is also the player's **nickname in the game**. The account is independent of the game's
save data: any local save can log in to it. The server knows which account every connection belongs to (bans,
protection); it does not try to prevent one person from having several accounts.

1. Register (once): `POST {server}/v1/accounts` `{"username", "password"}` → `201 {"pid", "username"}`;
   `409` when the name is taken, `400` with `error` when the name or the password (8–128 characters) is invalid.
2. Log in on a device: `POST {server}/v1/login` `{"username", "password", "device"?}` →
   `200 {"pid", "username", "device_key": "<hex>"}`. The port MUST keep the device key (with the profile, owner-only)
   and MUST NOT keep the password. `401` on wrong credentials; `403 {"error": "banned", "reason", "until"}` while the
   account is banned (`until`: Unix time, `null` = permanent).
3. Each time the game asks for an ID token: `POST {server}/v1/token` `{"pid", "device_key"}` →
   `{"id_token": "oof1.…", "expires_in": <secs>, "nex_username": "<decimal pid>", "username"}`. `401`: the device
   key was revoked (log in again); `403`: banned, as above. The port SHOULD show the ban's reason and end.
4. `POST /v1/logout` `{"pid", "device_key"}` forgets one device; `POST /v1/password`
   `{"username", "password", "new_password"}` changes the password and logs every device out.

PIDs are below 2^53 so JSON parsers keep them exact. A ban also refuses the NEX login of a token issued before it, and
disconnects a connected player within 30 s.

| Game call | Port behaviour |
| --- | --- |
| `IsNetworkServiceAccountAvailable`, `EnsureNetworkServiceAccountAvailable` | MUST succeed once an OOF account exists |
| `EnsureNetworkServiceAccountIdTokenCacheAsync` | MUST fetch a fresh token (async context signals when done; failure → network error result) |
| `LoadNetworkServiceAccountIdTokenCache(size*, buf, cap)` | MUST copy the token's ASCII bytes and report their length |
| `GetNetworkServiceAccountId` | MUST return the OOF `pid` |
| `GetNickname` | MUST return the account's user name while playing on an OOF server (other players see it) |
| `LoadCachedNintendoAccountInfo` | SHOULD return the local profile's values (country/birthday affect rules shown, not the server) |

## 3. Network availability (`nn::nifm`)

`SubmitNetworkRequest(AndWait)` MUST complete accepted and `IsNetworkAvailable` MUST return true
while `oof.server` is configured; `GetCurrentPrimaryIpAddress` and `GetCurrentIpConfigInfo` MUST
return the host's LAN address (Pia advertises it to peers on the same LAN).

## 4. Name resolution (`nn::nsd`, `nn::socket::GetAddrInfo`)

- `nsd::ResolveEx` MUST replace `%` in the host pattern with `lp1`.
- The socket resolver (`GetAddrInfo`, `GetHostByName`) MUST do the same replacement itself, as the
  console's does: Pia passes the pattern unexpanded (`GetAddrInfo("nncs1-%.n.n.srv.nintendo.net")`,
  seen from the real game; without it the game shows 2618-0203 after matchmaking).
- `GetAddrInfo` MUST resolve these names as follows; others MAY fail:
  - `g23380901-lp1.s.n.srv.nintendo.net` (NEX game server) → `oof.server`'s address
  - `nncs1-lp1.n.n.srv.nintendo.net` → `nat_check.primary` and `nncs2-lp1.n.n.srv.nintendo.net` →
    `nat_check.secondary`, the two NAT check addresses in `GET {server}/v1/status` (§8), fetched once.
    They are always different: Pia takes its second NAT check server as the first address with the
    same port and another IP, and without one the NAT check fails and the game shows 2618-0006 after
    matchmaking. A server that announces none cannot host online battles.
- A TCP `Connect` to those addresses on port 443 MUST be redirected to `oof.server`'s port.

## 5. TLS (`nn::ssl`)

The game opens `wss://g23380901-lp1.s.n.srv.nintendo.net/` and imports Nintendo's server PKI with
`ImportServerPki`. The port MUST perform the handshake with the host TLS stack against `oof.server`,
validating it with `oof.ca` or the system trust store, and MUST ignore the imported Nintendo PKI for
those names. With `oof.tls = false` the port MUST pass the bytes through unencrypted (development
only). The server never sees anything that depends on Nintendo certificates.

Shared Content transfers (DataStore uploads and downloads) go to `https://<public host>:<public port>/v1/objects/...`
URLs the server hands out; the game's HTTP client opens them through the same `nn::ssl` calls, so the rule above applies
to them unchanged: the host `oof.server` uses, validated the same way, plain bytes with `oof.tls = false`.

## 6. Sockets (`nn::socket`)

- TCP: the WebSocket above. Standard BSD semantics (`Poll`, non-blocking `Fcntl`) are required.
- `GetLastErrno` MUST use Horizon's errno numbers, which are Linux's (EAGAIN = 11, EINPROGRESS = 115, ECONNRESET = 104…),
  whatever the host OS uses: Pia treats any number it does not know as a failure and drops the session
  (`docs/re/protocols.md`, "From matchmaking to the Pia mesh").
- UDP: Pia's P2P traffic and NAT probes. The port MUST map game UDP sockets to host UDP sockets
  bound to the same port number when it is free (the game advertises that port in its station
  URLs) and SHOULD keep one host socket per game socket so NAT mappings stay stable.

## 7. Friends (`nn::friends`) — v0.2

Friendships live on the server, by account. Every call below is `POST` with `{pid, device_key}` (section 2) and, where
named, `user` (a user name or a PID):

| Endpoint | Does | Answers |
| --- | --- | --- |
| `/v1/friends` | the caller's lists | `{friends: [{pid, username, online}], incoming, outgoing, blocked: [{pid, username}], max}` |
| `/v1/friends/add` | asks `user`, or accepts `user`'s request | `{state: "requested" \| "friends"}`; 404 unknown, 403 blocked, 409 list full (`max` = 300) |
| `/v1/friends/remove` | ends a friendship, withdraws or declines a request | 204; 404 nothing to change |
| `/v1/friends/block`, `/v1/friends/unblock` | blocking also ends the friendship and requests | 204; 404 |

`online` means connected to this server's NEX service. A port MUST:

- answer `nn::friends::GetFriendList` with the accepted friends, each friend's NetworkServiceAccountId = its PID (as for
  the player's own account, section 2), nickname = user name, presence status online/offline from `online`;
- answer `GetProfileList` (nicknames by account ID) and `GetBlockedUserList` from the same lists;
- refresh the lists while the game runs (friends come online, requests get accepted);
- give the player a way to add, accept, remove and block (the console's own friend screens are outside the game).

The game then finds friends' Battle Arenas by itself (Matchmake Extension 109/51 with the friends' PIDs).
A port MAY keep returning empty lists (v0.1 behaviour); friends' arenas then stay empty.

## 8. What the server guarantees

- The game's NEX traffic is served unmodified: PRUDP Lite over WebSocket (subprotocol `NEX`) at `/`.
- HTTP API under `/v1` is stable within a major version; new fields may be added.
- `GET /v1/status` reports server version and load, and `nat_check: {"primary", "secondary"}`
  (two different IPv4 addresses, each serving UDP 10025 and 10125) when the server runs the NAT check.

## 9. Conformance

A port is v0.2-compliant when, against a test server, the game reaches the online menu, and two
instances meet through Quickplay. A scripted check (`oof-conformance`) is planned; until then the
server log (`ticket granted`, `secure connection`, `auto matchmake`) shows each stage.

## Version history

- v0.1 (2026-10-23): initial draft from the 13.0.5 import table and NEX/Pia analysis.
- v0.1 (2026-10-24): §4 clarified: the socket resolver also expands `%` (found with the real game).
- v0.1 (2026-10-25): §1 `oof.natcheck` removed; §4/§8 the NAT check hosts come from `/v1/status` and
  are two different addresses (the game requires it).
- v0.2 (2026-10-25): §2 accounts with a player-chosen user name and password (no e-mail or phone), device keys
  instead of stored passwords, bans (`403` with reason), logout and password change; `GetNickname` returns the user
  name. The v0.1 anonymous `POST /v1/accounts` with an empty body and `{"pid", "password"}` tokens are gone.
- v0.2 (2026-10-25): §7 friends kept by the server.
- v0.2 (2026-10-26): first public release, with ssbu-oof 0.2.0.
