# OOF port standard, v0.1 (draft)

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
| `oof.natcheck` | optional host for UDP NAT check (defaults to the `oof.server` host) | `play.example.org` |

The port MUST NOT require game files, keys or Nintendo account data to be sent to the server.

## 2. Identity (`nn::account`)

The server issues accounts; the port stores one per local user profile.

1. First time online: `POST {server}/v1/accounts` → `{"pid": <u64>, "password": "<hex>"}`. Store both
   with the user profile. PIDs are below 2^53 so JSON parsers keep them exact.
2. Each time the game asks for an ID token: `POST {server}/v1/token` with `{"pid", "password"}` →
   `{"id_token": "oof1.…", "expires_in": <secs>, "nex_username": "<decimal pid>"}`.

| Game call | Port behaviour |
| --- | --- |
| `IsNetworkServiceAccountAvailable`, `EnsureNetworkServiceAccountAvailable` | MUST succeed once an OOF account exists |
| `EnsureNetworkServiceAccountIdTokenCacheAsync` | MUST fetch a fresh token (async context signals when done; failure → network error result) |
| `LoadNetworkServiceAccountIdTokenCache(size*, buf, cap)` | MUST copy the token's ASCII bytes and report their length |
| `GetNetworkServiceAccountId` | MUST return the OOF `pid` |
| `GetNickname`, `LoadCachedNintendoAccountInfo` | SHOULD return the local profile's values (country/birthday affect rules shown, not the server) |

## 3. Network availability (`nn::nifm`)

`SubmitNetworkRequest(AndWait)` MUST complete accepted and `IsNetworkAvailable` MUST return true
while `oof.server` is configured; `GetCurrentPrimaryIpAddress` and `GetCurrentIpConfigInfo` MUST
return the host's LAN address (Pia advertises it to peers on the same LAN).

## 4. Name resolution (`nn::nsd`, `nn::socket::GetAddrInfo`)

- `nsd::ResolveEx` MUST replace `%` in the host pattern with `lp1`.
- `GetAddrInfo` MUST resolve these names to `oof.server`'s address; others MAY fail:
  - `g23380901-lp1.s.n.srv.nintendo.net` (NEX game server)
  - `nncs1-lp1.n.n.srv.nintendo.net`, `nncs2-lp1.n.n.srv.nintendo.net` (NAT check → `oof.natcheck`)
- A TCP `Connect` to those addresses on port 443 MUST be redirected to `oof.server`'s port.

## 5. TLS (`nn::ssl`)

The game opens `wss://g23380901-lp1.s.n.srv.nintendo.net/` and imports Nintendo's server PKI with
`ImportServerPki`. The port MUST perform the handshake with the host TLS stack against `oof.server`,
validating it with `oof.ca` or the system trust store, and MUST ignore the imported Nintendo PKI for
those names. With `oof.tls = false` the port MUST pass the bytes through unencrypted (development
only). The server never sees anything that depends on Nintendo certificates.

## 6. Sockets (`nn::socket`)

- TCP: the WebSocket above. Standard BSD semantics (`Poll`, non-blocking `Fcntl`) are required.
- UDP: Pia's P2P traffic and NAT probes. The port MUST map game UDP sockets to host UDP sockets
  bound to the same port number when it is free (the game advertises that port in its station
  URLs) and SHOULD keep one host socket per game socket so NAT mappings stay stable.

## 7. Friends (`nn::friends`) — v0.1

MAY return empty lists. A friends API (presence for "friends' arenas") is planned for v0.2.

## 8. What the server guarantees

- The game's NEX traffic is served unmodified: PRUDP Lite over WebSocket (subprotocol `NEX`) at `/`.
- HTTP API under `/v1` is stable within a major version; new fields may be added.
- `GET /v1/status` reports server version and load.

## 9. Conformance

A port is v0.1-compliant when, against a test server, the game reaches the online menu, and two
instances meet through Quickplay. A scripted check (`oof-conformance`) is planned; until then the
server log (`ticket granted`, `secure connection`, `auto matchmake`) shows each stage.

## Version history

- v0.1 (2026-10-23): initial draft from the 13.0.5 import table and NEX/Pia analysis.
