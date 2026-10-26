# Reverse-engineering tools

Stdlib-only Python 3 scripts that read the user's own dump; nothing here contains game data
(LEGAL.md). Run them with `python3 -I`.

## 1. Get `main.elf` (outside this repository)

The extraction reuses NSWMacPort's verified scripts (any equivalent tool works):

```sh
NSW=~/Documents/Proyectos/NSWMacPort       # needs its .venv (cryptography, lz4)
W="$HOME/Downloads/emulacion nsw/juegos/SSBU_work.noindex/v1305"   # keep outside the repo
$NSW/.venv/bin/python -I $NSW/games/totk/scripts/extract_exefs.py "<ssbu 13.0.5 update>.nsp" \
    --keys "<prod.keys>" --title-id 0x01006A800016E000 --update --output "$W/exefs"
$NSW/.venv/bin/python -I $NSW/games/totk/scripts/prepare_modules.py "$W/exefs" --output "$W/elf"
```

Check `main` SHA-256 = `eb79e639…dc52d` (docs/re/protocols.md). The ELF keeps original virtual
addresses: `main+0x…` in the docs is an address in `main.elf`.

## 2. Tools

| Script | Use |
| --- | --- |
| `nxre.py str <elf> <regex>` | strings with addresses |
| `nxre.py xref <elf> <addr>…` | code that builds an address with `adrp+add/ldr` (index cached in `<elf>.xrefs`) |
| `nxre.py dis <elf> <addr> [n]`, `func <elf> <addr>` | `llvm-objdump` around an address / its function |
| `nxre.py vtable <elf> <RTTI name>` | vtables of a class (applies `R_AARCH64_RELATIVE` relocations) |
| `nex_protocols.py <elf> --json out.json` | every NEX client protocol: ID evidence, dispatcher bound, `CallXxx` functions, result extractors |
| `ddl.py <elf> out.json [--class X] [--method N]` | request layouts decoded from the serializers |
| `readers.py <elf> <addr> [--depth N]` | approximate layout a response extractor or structure reader reads (`--depth 0`: one function, callees as `@addr`) |

Typical loop: `nex_protocols.py` → pick a method → `ddl.py --class X --method N` → for what the
decoder prints as `?addr` or `(computed)`, read the code with `nxre.py func`.

## 3. Methodology (how the patterns were found)

1. RTTI names (`N2nn3nex…ProtocolClientE`) locate each class; typeinfo and vtables are found through
   relocation addends, since NSO pointers are zero until relocated.
2. Slot 21 of each protocol client's vtable is the result dispatcher: `(method & 0x7fff) - 1` is
   bounded by `cmp` (highest method) and indexes a table in `.bss` whose GOT slot it loads.
3. `CallXxx` functions call the protocol-header writer, then the method-ID writer with the method as
   an immediate, then the parameter serializers, then store their result extractor in
   `table[method-1]` through the same GOT slot, which ties the function to its class.
4. Serializers start by testing the stream's "no structure header" byte (`ldrb [x0, #0x69]`),
   write version + length, then fields through the stream write primitive with the size in `w2`;
   lists are a count followed by a loop over an element serializer.
5. Protocol IDs: the owning service client calls the protocol client constructor with the ID in `w1`.

Known gaps: methods whose parameters are polymorphic (`AnyDataHolder`) or written through
virtual calls decode partially; ownership of some `CallXxx` functions in Secure Connection, NAT
Traversal and Screening was attributed by address ranges.
