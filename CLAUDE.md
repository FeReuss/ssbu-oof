# Agent notes

- Start with `docs/PROGRESS.md` (state, next steps, pitfalls); RE facts are in `docs/re/protocols.md`.
- Project language is English (code, docs, commits). The maintainer may talk to you in Spanish.
- Never add game data, keys, disassembly listings or code from AGPL/GPL projects (`LEGAL.md`).
- Game dump for analysis: `~/Downloads/emulacion nsw/juegos/SSBU_work.noindex/v1305/elf/main.elf`
  (outside the repo; recreate with `tools/re/README.md`).
- Build/test: `cargo test`, `cargo clippy --all-targets`, `cargo fmt`. Rust via `~/.cargo/bin`.
- Commits: `-c user.name=FeReuss -c user.email=102842515+FeReuss@users.noreply.github.com`.
