#!/usr/bin/env python3
"""Recover the wire layout of NEX DDL serializers (requests) and extractors (responses).

  ddl.py <main.elf> <protocols.json> [--class Tournament] [--method 9]

protocols.json comes from nex_protocols.py. Output is one line per method:
  Tournament.9  request: Struct{u64@10 u32@18 u16@1c List<Struct{u8@9 u8@a u8@b String@10 ...}>@20}
Fields are `type@offset-in-the-C++-object`; offsets help match a later field to the same member
in the response. Types are inferred from the write size (u8 may be a bool, u64 a PID/DateTime).

Recognised helpers are SSBU 13.0.5 addresses (see docs/re/methodology.md); an unknown callee is
decoded recursively and printed as `?<addr>{...}`.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nxre  # noqa: E402
from nex_protocols import Elf, imm_to_reg  # noqa: E402

STREAM_WRITE = 0x1d0460
STREAM_SEEK = 0x1d0430
NAMED = {
    0x228510: 'String',     # u16 length (with NUL) + bytes
    0x228c80: 'qBuffer',    # u16 length + bytes
}
NAMED_READ = {
    0x228cf0: 'qBuffer',
}
SIZES = {1: 'u8', 2: 'u16', 4: 'u32', 8: 'u64'}
LIBRARY_START = 0x392c000  # libc++/allocator stubs at the end of SSBU's .text; never serializers


def is_prologue(w):
    return ((w & 0xFF0003FF) == 0xD10003FF or (w & 0xFFC003E0) == 0xA98003E0  # sub sp / stp ..., [sp, #-n]!
            or (w & 0xFFE00FE0) == 0xF8000FE0)  # str xN, [sp, #-n]!


def x1_source(elf, site):
    """('obj', offset) when x1 points into the serialized object, ('local', None) for stack temporaries."""
    for va in range(site - 4, site - 4 * 8, -4):
        w = elf.word(va)
        if (w & 0xFF80001F) == 0x91000001:  # add x1, xN, #imm
            base = (w >> 5) & 31
            return ('local', None) if base == 31 else ('obj', (w >> 10) & 0xFFF)
        if (w & 0xFFE0FFFF) == 0xAA0003E1:  # mov x1, xM
            return ('obj', 0)
        if (w & 0xFFE00C1F) == 0x9A800001:  # csel x1, ...
            return ('local', None)
        if (w & 0xFFC0001F) == 0xF9400001 or (w & 0xFFC0001F) == 0xA9400001 or (w & 0xFFC0001F) == 0xA9C00001:
            return ('obj', None)  # ldr/ldp x1 from memory: pointer member
    return ('obj', None)


def size_w2(elf, site):
    got = elf.imm_before(site, 2, 8)
    return got


class Decoder:
    def __init__(self, elf):
        self.elf = elf
        self.memo = {}

    def function_extent(self, start, limit=1500):
        """Last instruction before padding or the next function's prologue after a ret/tail branch."""
        for va in range(start + 4, start + 4 * limit, 4):
            w, prev = self.elf.word(va), self.elf.word(va - 4)
            ends = prev == 0xD65F03C0 or (prev & 0xFC000000) == 0x14000000
            if ends and (w == 0 or is_prologue(w)):
                return va - 4
        return start + 4 * limit

    def write_events(self, fn):
        elf = self.elf
        end = self.function_extent(fn)
        # ldrb wN, [x0, #0x69] at the top: the stream's "no structure header" flag, so this is a Structure
        header = any((elf.word(va) & 0xFFFFFFE0) == 0x3941A400 for va in range(fn, fn + 4 * 12, 4))
        events = []
        for va in range(fn, end + 4, 4):
            w = elf.word(va)
            call = elf.bl(va)
            if call and call[0] == 'bl':
                target = call[1]
                if target == STREAM_SEEK:
                    continue
                src = x1_source(elf, va)
                if target == STREAM_WRITE:
                    size = size_w2(elf, va)
                    events.append(('prim', va, SIZES.get(size, f'bytes{size}'), src))
                elif not self.is_serializer(target):
                    continue
                else:
                    events.append(('call', va, target, src))
            elif (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000:  # b.cond / cbz / cbnz
                imm = ((w >> 5) & 0x7FFFF) if (w & 0xFF000010) == 0x54000000 else ((w >> 5) & 0x7FFFF)
                if imm & (1 << 18):
                    imm -= 1 << 19
                target = va + imm * 4
                if target < va:
                    events.append(('loop', va, target, None))
        return header, events

    def is_serializer(self, fn, depth=0):
        """True when `fn` (transitively, 2 levels) writes to the stream: skips allocators, locks, libc."""
        if fn in NAMED or fn == STREAM_WRITE:
            return True
        if fn >= LIBRARY_START or depth > 2:
            return False
        key = ('ser', fn)
        if key not in self.memo:
            self.memo[key] = False
            end = self.function_extent(fn)
            for va in range(fn, end + 4, 4):
                call = self.elf.bl(va)  # bl, or a tail-call b outside this function
                if call and (call[0] == 'bl' or not fn <= call[1] <= end) and self.is_serializer(call[1], depth + 1):
                    self.memo[key] = True
                    break
        return self.memo[key]

    def decode_write(self, fn, depth=0):
        if fn in NAMED:
            return NAMED[fn]
        if fn in self.memo:
            return self.memo[fn]
        if depth > 6:
            return f'?{fn:#x}'
        self.memo[fn] = f'<recursive {fn:#x}>'
        header, events = self.write_events(fn)
        loops = [(e[2], e[1]) for e in events if e[0] == 'loop']
        fields = []
        skip_locals = 2 if header else 0
        i = 0
        while i < len(events):
            kind, va, what, src = events[i]
            if kind == 'loop':
                i += 1
                continue
            loop = next(((a, b) for a, b in loops if a <= va <= b), None)
            if kind == 'prim' and src[0] == 'local':
                nxt = next((e for e in events[i + 1:] if e[0] != 'loop'), None)
                if skip_locals:
                    skip_locals -= 1
                elif nxt and nxt[0] == 'call' and any(a <= nxt[1] <= b for a, b in loops) and not loop:
                    pass  # element count of the List that follows
                elif header and nxt is None:
                    pass  # structure length back-patch
                else:
                    fields.append(f'{what}(computed)')
                i += 1
                continue
            off = '' if src[1] is None else f'@{src[1]:x}'
            if kind == 'prim':
                item = what + off
            else:
                item = self.decode_write(what, depth + 1) + off
            if loop and kind == 'call':
                item = f'List<{item}>'
                # one entry per loop
                while i + 1 < len(events) and events[i + 1][0] != 'loop' and loop[0] <= events[i + 1][1] <= loop[1]:
                    i += 1
            fields.append(item)
            i += 1
        body = ' '.join(fields)
        out = f'Struct{{{body}}}' if header else (f'{{{body}}}' if len(fields) != 1 else body)
        if not fields:
            out = f'?{fn:#x}'
        self.memo[fn] = out
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf')
    ap.add_argument('protocols', type=Path)
    ap.add_argument('--class', dest='cls')
    ap.add_argument('--method', type=int)
    args = ap.parse_args()
    elf = Elf(args.elf)
    dec = Decoder(elf)
    skip = {0x1b4200, 0x1d0c90, 0x22b430}  # Result construction / error reporting / message cleanup
    for c in json.loads(args.protocols.read_text()):
        name = c['class'].replace('ProtocolClient', '').replace('ProtocolExtClient', 'Ext')
        if args.cls and not name.startswith(args.cls):
            continue
        for m in c['methods']:
            if args.method and m['method'] != args.method:
                continue
            params = []
            for site, target in m['request_calls']:
                if target == STREAM_WRITE:
                    size = size_w2(elf, site)
                    params.append(SIZES.get(size, f'bytes{size}'))
                elif target not in skip and dec.is_serializer(target):
                    params.append(dec.decode_write(target))
            print(f"{name}.{m['method']}\trequest: {', '.join(params) or '(none)'}")


if __name__ == '__main__':
    main()
