#!/usr/bin/env python3
"""Inventory of the NEX RMC client protocols compiled into a Switch game's main.elf.

  nex_protocols.py <main.elf> [--json out.json]

For every nn::nex::*ProtocolClient class (found by RTTI) it prints the protocol ID (from the
constructor), each method ID the game can send (from the CallXxx functions), the address of
that CallXxx function, the request serializer calls and the response extractor.

How the patterns were found (SSBU 13.0.5, NEX 4.6.13) is in docs/re/methodology.md.
The four helper addresses below are SSBU 13.0.5 specific; `--helpers` overrides them.
"""
import argparse
import array
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nxre  # noqa: E402

# SSBU 13.0.5 main.elf: nn::nex helpers recognised by their bodies (see methodology.md).
HELPERS = {
    'write_protocol': 0x22b480,   # Message::AddProtocolHeader(u16 protocol, bool request): u8 (id|0x80) [+u16]
    'write_method': 0x22b400,     # Message::AddMethodID(u32 method)
    'client_ctor': 0x234fb0,      # ClientProtocol::ClientProtocol(u16 protocol)
    'stream_write': 0x1d0460,     # ByteStream::Write(const void*, size)
}


# Calls that end request serialization: Result construction, message release, send.
REQUEST_END = {0x1b4200, 0x22b430, 0x22a7f0, 0x1d0c90}


def decode_bitmask32(n, immr, imms):
    """AArch64 DecodeBitMasks for 32-bit logical immediates (`orr wN, wzr, #imm`)."""
    length = (n << 6 | (~imms & 0x3F)).bit_length() - 1
    if length < 1:
        return None
    size = 1 << length
    s, r = imms & (size - 1), immr & (size - 1)
    if s == size - 1:
        return None
    elem = (1 << (s + 1)) - 1
    elem = ((elem >> r) | (elem << (size - r))) & ((1 << size) - 1)
    out = 0
    for i in range(0, 32, size):
        out |= elem << i
    return out


def imm_to_reg(w):
    """(register, value) when `w` loads a small immediate into a W register, else None."""
    if (w & 0xFF800000) == 0x52800000:  # movz wd, #imm16, lsl hw
        return w & 31, ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))
    if (w & 0xFF8003E0) == 0x320003E0:  # orr wd, wzr, #bitmask
        value = decode_bitmask32((w >> 22) & 1, (w >> 16) & 0x3F, (w >> 10) & 0x3F)
        return (w & 31, value) if value is not None else None
    return None


class Elf:
    def __init__(self, path):
        self.path = path
        self.data = Path(path).read_bytes()
        self.text_va, off, size, _ = nxre.text_segment(self.data)
        self.words = array.array('I', self.data[off:off + size - size % 4])
        self.relocs = nxre.relocations(self.data)
        targets, sites = nxre.xrefs(path, self.data)
        self.refs_from = dict(zip(sites, targets))  # site -> target

    def word(self, va):
        return self.words[(va - self.text_va) // 4]

    def bl(self, va):
        w = self.word(va)
        if (w & 0x7C000000) == 0x14000000:  # b / bl
            imm = w & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            return ('bl' if w & 0x80000000 else 'b'), va + imm * 4
        return None

    def callers(self, target, tail=False):
        out = []
        for i, w in enumerate(self.words):
            if (w & 0xFC000000) == 0x94000000 or (tail and (w & 0xFC000000) == 0x14000000):
                imm = w & 0x3FFFFFF
                if imm & (1 << 25):
                    imm -= 1 << 26
                if self.text_va + (i + imm) * 4 == target:
                    out.append(self.text_va + i * 4)
        return out

    def imm_before(self, site, reg, window=6):
        for va in range(site - 4, site - 4 * window - 4, -4):
            got = imm_to_reg(self.word(va))
            if got and got[0] == reg:
                return got[1]
        return None

    def function_end(self, start, limit=4000):
        for va in range(start, start + 4 * limit, 4):
            if self.word(va) == 0xD65F03C0:  # ret
                return va
        return start + 4 * limit


def protocol_clients(elf):
    names = sorted(set(m.group(1).decode() for m in re.finditer(
        rb'\0(N2nn3nex\d+\w+?Protocol(?:Ext)?Client)E\0', elf.data)))
    out = []
    for name in names:
        group = nxre.vtables(elf.data, name + 'E')  # primary and secondary vtables of the class
        for vt, fns in group:
            if len(fns) >= 23:
                out.append({'class': re.sub(r'^N2nn3nex\d+', '', name), 'vtable': vt, 'dispatch': fns[21],
                            'vtable_symbols': [v - 0x10 for v, _ in group]})
    return out


def dispatch_table(elf, fn):
    """GOT slot of the per-method result-extractor table and the method count, from vtable[21]."""
    got = count = None
    for va in range(fn, fn + 4 * 24, 4):
        if va in elf.refs_from and elf.refs_from[va] in elf.relocs and got is None:
            got = elf.refs_from[va]
        w = elf.word(va)
        if (w & 0xFFC0001F) == 0x7100001F and count is None:  # cmp wN, #imm
            count = (w >> 10) & 0xFFF
    return got, count


def protocol_id(elf, symbols):
    """The protocol ID is the u16 argument the owner passes to the ProtocolClient constructor.

    The constructor is the function that stores one of the class vtables (through a GOT slot);
    its callers load the ID into w1 (`mov w1, #id` or `mov w20, #id; mov w1, w20`).
    """
    slots = {s for s, t in elf.relocs.items() if t in symbols}
    ctors = {nxre.function_start(elf.data, site) for site, target in elf.refs_from.items() if target in slots}
    for ctor in sorted(ctors):
        for site in elf.callers(ctor, tail=True):
            value = elf.imm_before(site, 1, 8) or _reg_imm(elf, nxre.function_start(elf.data, site), site)
            if value:
                return value
    return None


def _reg_imm(elf, start, site):
    """Protocol ID moved into w1 from another register (`mov w20, #id; mov w1, w20`)."""
    for va in range(site - 4, start - 4, -4):
        w = elf.word(va)
        if (w & 0xFFE0FFFF) == 0x2A0003E1:  # mov w1, wM
            return elf.imm_before(va, (w >> 16) & 31, 12)
    return None


def call_methods(elf, clients):
    by_table = {c['table_got']: c for c in clients if c.get('table_got')}
    methods = []
    for site in elf.callers(HELPERS['write_method']):
        method = elf.imm_before(site, 1)
        start = nxre.function_start(elf.data, site)
        end = elf.function_end(site)
        owner = extractor = None
        calls, collecting = [], True
        for va in range(site + 4, end, 4):
            ref = elf.refs_from.get(va)
            if ref in by_table and owner is None:
                owner = by_table[ref]
                # next GOT load is the extractor stored into table[method-1]
                for vb in range(va + 4, va + 16, 4):
                    r2 = elf.refs_from.get(vb)
                    if r2 in elf.relocs and r2 != ref:
                        extractor = elf.relocs[r2]
                        break
            call = elf.bl(va)
            if call and call[0] == 'bl' and call[1] in REQUEST_END:
                collecting = False
            if call and call[0] == 'bl' and collecting:
                calls.append([va, call[1]])
        methods.append({'site': site, 'function': start, 'method': method, 'owner': owner and owner['class'],
                        'extractor': extractor, 'request_calls': calls})
    # Methods without results never touch the table: attribute them to the class whose
    # CallXxx functions surround them (the compiler lays out a class's methods together).
    known = sorted((m['site'], m['owner']) for m in methods if m['owner'])
    for m in methods:
        if not m['owner'] and known:
            before = [o for f, o in known if f <= m['site']]
            after = [o for f, o in known if f > m['site']]
            if before and after and before[-1] == after[0]:
                m['owner'], m['owner_inferred'] = before[-1], True
    return methods


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf')
    ap.add_argument('--json', type=Path)
    args = ap.parse_args()
    elf = Elf(args.elf)
    clients = protocol_clients(elf)
    for c in clients:
        c['table_got'], c['method_count'] = dispatch_table(elf, c['dispatch'])
        c['protocol_id'] = protocol_id(elf, set(c['vtable_symbols']))
    methods = call_methods(elf, clients)
    for c in clients:
        own = sorted((m for m in methods if m['owner'] == c['class']), key=lambda m: m['method'] or 0)
        c['methods'] = own
        print(f"{c['class']}: protocol {c['protocol_id']} vtable {c['vtable']:#x} max method {c['method_count']}")
        for m in own:
            ext = f" result {m['extractor']:#x}" if m['extractor'] else ' no result'
            inf = ' (owner inferred)' if m.get('owner_inferred') else ''
            print(f"   method {m['method']}: Call {m['function']:#x}{ext}{inf} request "
                  + ' '.join(f'{t:#x}' for _, t in m['request_calls']))
    orphans = [m for m in methods if not m['owner']]
    if orphans:
        print('unattributed:', ' '.join(f"{m['function']:#x}/m{m['method']}" for m in orphans))
    if args.json:
        args.json.write_text(json.dumps(clients, indent=1, default=lambda o: o) + '\n')


if __name__ == '__main__':
    main()
