#!/usr/bin/env python3
"""Approximate wire layout read by a NEX DDL reader (response extractor or structure reader).

  readers.py <main.elf> <addr> [--depth N]

The game's readers inline every fixed-size read (the buffer's size is at +0x18) and call helpers for strings, buffers, lists and nested structures.
Each inline read is a bounds check on (buffer size - cursor). This walks a function in address order (control flow ignored: a list's element reader appears once, optional
fields appear as present) and prints one token per read: u8/u16/u32/u64, a known helper's name, or
`?<addr>{...}` for a callee that reads in turn. Confirm anything surprising with `nxre.py dis`.
"""
import argparse
import re
import subprocess
import sys

KNOWN = {
    0x1d0670: 'bool',
    0x228cf0: 'qBuffer',
    0x228650: 'String',
    0x22eb80: '',  # result fetch (ctx, index): not a read
    0x1d0460: '', 0x1d0480: '', 0x1d0630: '', 0x1cb870: '', 0x22b510: '', 0x22b400: '',  # stream/buffer internals
    0x1af850: '', 0x22a520: '', 0x1b3cb0: '', 0x1b52a0: '', 0x228480: '', 0x242360: '',  # containers, strings
}
SIZES = {1: 'u8', 2: 'u16', 4: 'u32', 8: 'u64'}
LIBRARY_START = 0x392c000
INS = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')


def disassemble(elf, start, limit=0x1800):
    out = subprocess.run(['xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', f'--start-address={start:#x}',
                          f'--stop-address={start + limit:#x}', elf], capture_output=True, text=True, check=True).stdout
    ins = []
    for line in out.splitlines():
        m = INS.match(line)
        if m:
            ins.append((int(m.group(1), 16), m.group(2), m.group(3).split('//')[0].split('<')[0].strip()))
    # one function: stop at the first ret that is followed by padding or a new prologue
    end = len(ins)
    for i, (_, op, _) in enumerate(ins):
        if op == 'ret' and (i + 1 == len(ins) or ins[i + 1][1] in ('udf', 'stp', 'sub', 'str') and
                             ('sp, #-' in ins[i + 1][2] or ins[i + 1][2].startswith('sp, sp'))):
            end = i + 1
            break
    return ins[:end]


def events(elf, fn, depth, seen):
    ins = disassemble(elf, fn)
    toks = []
    for i, (va, op, args) in enumerate(ins):
        if op == 'cmp' and any(a == 'ldr' and b.endswith(', #0x18]') for _, a, b in ins[max(0, i - 3):i]):
            # bounds check before an inline read: remaining (size - cursor) against the read size
            nxt = ins[i + 1][1] if i + 1 < len(ins) else ''
            m = re.match(r'x\d+, #0x([0-9a-f]+)$', args)
            size = None
            if m and nxt in ('b.hs', 'b.lo', 'b.cs', 'b.cc'):
                size = int(m.group(1), 16)
            elif m and nxt in ('b.hi', 'b.ls'):
                size = int(m.group(1), 16) + 1
            elif re.match(r'x\d+, x\d+$', args) and nxt in ('b.ne', 'b.eq'):
                size = 1
            if size:
                toks.append(SIZES.get(size, f'bytes{size}'))
        elif op == 'bl':
            target = int(args.split()[0], 16)
            if target in KNOWN:
                if KNOWN[target]:
                    toks.append(KNOWN[target])
            elif target < LIBRARY_START and depth > 0 and target not in seen:
                inner = events(elf, target, depth - 1, seen | {target})
                if inner:
                    toks.append(f'?{target:#x}{{{" ".join(inner)}}}')
            elif target < LIBRARY_START and depth == 0:
                toks.append(f'@{target:#x}')
    return toks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf')
    ap.add_argument('addr', type=lambda s: int(s, 16))
    ap.add_argument('--depth', type=int, default=4)
    a = ap.parse_args()
    print(' '.join(events(a.elf, a.addr, a.depth, {a.addr})))


if __name__ == '__main__':
    sys.exit(main())
