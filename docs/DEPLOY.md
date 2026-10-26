# Running a public server

ssbu-oof 0.2.0 on Linux with systemd (build with `cargo build --release` on a machine with the same or an older
glibc than the server). Addresses below are documentation examples (RFC 5737).

## What the server needs

| Need | Why |
| --- | --- |
| Two public IPv4 addresses | Pia's NAT check refuses to start unless `nncs1` and `nncs2` have different IPs. They can be two addresses of one host, two addresses behind 1:1 NAT (`primary_bind`, `secondary_bind`), or the second on another machine (`remote_secondary`, below). Without them players can sign in but not play online battles. |
| TLS in front of the HTTP port | Ports connect with `wss://` and `https://` (standard §5). Any terminator works (Caddy, nginx, a cloud load balancer); set `public_port` to the port players use. |
| `database` | Accounts, friends, bans and player records live in this SQLite file. Without it they are lost on restart. |
| `secret` | `openssl rand -hex 32`. Signs tokens and tickets; keep it out of version control. Changing it signs everyone out. |

Firewall, inbound:

| Port | Where |
| --- | --- |
| TCP: the TLS terminator's port (e.g. 443) | main server |
| UDP 10025, 10125, 33334, 33335 | `nat_check.primary` |
| UDP 10025, 10125 | `nat_check.secondary` |

Matches are peer to peer between players; the server needs no other port.

## Configuration

Start from `oof.example.toml`:

```toml
listen = "127.0.0.1:8080"          # the TLS terminator forwards here
public_host = "play.example.org"
public_port = 443
secret = "<64 hex characters>"
database = "/var/lib/ssbu-oof/oof.db"

[nat_check]
primary = "203.0.113.10"
secondary = "198.51.100.20"
# remote_secondary = true          # when 198.51.100.20 is another machine (below)
```

Turn on the online services the game should offer under `[integer_settings.0]` (see the example file); keys 9006 and
9007 (Online Tourney, Spectator) stay off until those features are supported.

## systemd

`/etc/systemd/system/ssbu-oof.service` (binary and config in `/opt/ssbu-oof`, a system user `ssbu-oof`, config
readable by that group only):

```ini
[Unit]
Description=ssbu-oof server
After=network-online.target
Wants=network-online.target

[Service]
User=ssbu-oof
Group=ssbu-oof
ExecStart=/opt/ssbu-oof/oof-server /opt/ssbu-oof/oof.toml
WorkingDirectory=/var/lib/ssbu-oof
StateDirectory=ssbu-oof
StateDirectoryMode=0700
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

## The second NAT check address on another machine

When the main host has one IPv4, any other machine with a public IPv4 can serve `nncs2`. It needs neither the config
nor the secret, only the binary:

```ini
# /etc/systemd/system/ssbu-oof-natcheck.service — same [Unit], [Install] and hardening as above
[Service]
User=ssbu-oof
Group=ssbu-oof
ExecStart=/opt/ssbu-oof/oof-server nat-check 198.51.100.20
Restart=on-failure
```

Behind 1:1 NAT pass the machine's local address as a second argument. On the main server set
`remote_secondary = true`; it then serves only `primary`. Check from outside that a 16-byte probe of type 103
(`00 00 00 67` followed by 12 zero bytes) sent to UDP 10025 comes back from the same address and port.

## Operation

- `oof-server /opt/ssbu-oof/oof.toml account|ban|unban <user|pid> …` administers accounts in the same database (run it
  as the `ssbu-oof` user while the server runs; a ban disconnects the player within 30 s).
- Back up the SQLite file with `sqlite3 oof.db ".backup oof-backup.db"` (safe while the server runs).
- `GET /v1/status` reports version, players online, open sessions and the NAT check addresses.
- `RUST_LOG=debug` logs every call the game makes that the server does not implement.
