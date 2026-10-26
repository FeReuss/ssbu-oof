# Agent notes

- Start with `README.md` and `docs/features.md` (what works, what is pending, the first step for each pending
  feature); design notes and testing pitfalls are in `docs/DEVELOPMENT.md`, RE facts in `docs/re/protocols.md`.
- Project language is English (code, docs, commits). The maintainer may talk to you in Spanish.
- Never add game data, keys, disassembly listings or code from AGPL/GPL projects (`LEGAL.md`). The game dump used for
  analysis stays outside the repository (`tools/re/README.md`).
- Build/test: `cargo test`, `cargo clippy --all-targets`, `cargo fmt`.
- Keep every doc on the version in `Cargo.toml` (`[workspace.package] version`) and the standard's version.
