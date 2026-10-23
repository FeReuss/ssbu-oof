# Third-party notices

## Documentation used as a cross-reference

- **kinnay/NintendoClients** and its wiki (MIT, © Yannik Marchand):
  https://github.com/kinnay/NintendoClients — public descriptions of PRUDP, RMC, Kerberos tickets
  and NEX protocol method tables. ssbu-oof's code is an independent implementation; every format it
  relies on was checked against the SSBU 13.0.5 binary where noted in `docs/re/`.

No source code from other server projects is included.

## Rust dependencies

Fetched by Cargo at build time under their own licenses (all MIT and/or Apache-2.0): `tokio`, `axum`,
`serde`, `serde_json`, `toml`, `tracing`, `tracing-subscriber`, `md-5`, `hmac`, `sha2`, `base64`,
`getrandom`, and for tests `tokio-tungstenite` and `futures-util`. Run `cargo tree` for the full set.

## Algorithms

The civil-calendar conversion in `crates/oof-nex/src/stream.rs` follows Howard Hinnant's public
domain algorithms.
