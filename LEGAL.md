# Legal and clean-room policy

ssbu-oof is an independent, non-commercial interoperability project. It is not affiliated with,
endorsed by or sponsored by Nintendo, Bandai Namco, Sora Ltd. or any other rights holder.
"Nintendo Switch" and "Super Smash Bros." are trademarks of their owners and are used here only to
describe what this software interoperates with.

## What this repository contains

- Original source code written for this project (MIT).
- Descriptions of network behaviour needed for interoperability: protocol and method numbers,
  field order and types of messages, state machines. These are facts about how two programs talk,
  written in our own words.
- Analysis tools that read a binary the user supplies from their own legally obtained copy.

## What this repository must never contain

Contributors must check every change against this list. A pull request that adds any of these is
rejected and the content is purged from history.

1. Game, firmware or SDK files of any kind: executables, NSO/NRO/ELF modules, RomFS assets, shaders,
   fonts, sounds, text tables, save files, DLC, tickets or certificates.
2. Keys and secrets: console/title keys (`prod.keys`, `title.keys`), certificates, account
   credentials, or Nintendo service secrets. Per-game values the server needs (none today) are
   read from configuration, never committed.
3. Disassembly or decompilation listings, pseudocode, or byte dumps of Nintendo code. Notes may cite
   an address (`main+0x22b480`) and describe what the code does; they may not reproduce it.
4. Code copied from projects under incompatible licenses (for example AGPL/GPL servers). Use their
   public documentation as a reference only, never their source.
5. Nintendo logos, artwork or other branding.

## Method

Reverse engineering is done on a dump of the user's own copy (SSBU 13.0.5) for the purpose of
interoperability with independently created software, as permitted in many jurisdictions (for
example EU Directive 2009/24/EC art. 6 and 17 U.S.C. §1201(f)). Findings are recorded as facts in
`docs/re/`; the extracted files stay outside the repository (`tools/re/README.md` explains where).

Public, permissively licensed documentation is used as a cross-reference and credited in
`THIRD_PARTY_NOTICES.md`.
