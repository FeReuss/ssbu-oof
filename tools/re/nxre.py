#!/usr/bin/env python3
"""Small static-analysis helpers for AArch64 Switch ELFs (output of NSWMacPort's prepare_modules.py).

  nxre.py str  <elf> <regex>          strings matching regex, with their virtual address
  nxre.py xref <elf> <vaddr> [...]    code sites that build <vaddr> with adrp+add/ldr
  nxre.py dis  <elf> <vaddr> [count]  disassemble <count> instructions (llvm-objdump)
  nxre.py func <elf> <vaddr>          disassemble the function containing <vaddr> (prologue heuristic)
  nxre.py vtable <elf> <mangled>      vtables of a class by RTTI name, e.g. N2nn3nex24MatchmakeExtensionClientE

Reads only the file given; never writes next to it except the xref cache (<elf>.xrefs).
Stdlib only, so it runs with `python3 -I`.
"""
import array
import bisect
import os
import re
import struct
import subprocess
import sys


def segments(data):
    assert data[:4] == b'\x7fELF' and data[4] == 2, 'expected ELF64'
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    segs = []
    for i in range(phnum):
        ptype, flags, off, vaddr, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if ptype == 1:
            segs.append((vaddr, off, filesz, flags))
    return segs


def text_segment(data):
    return next(s for s in segments(data) if s[3] & 1)


def read_va(data, va, size):
    for vaddr, off, filesz, _ in segments(data):
        if vaddr <= va < vaddr + filesz:
            return data[off + va - vaddr: off + va - vaddr + size]
    raise ValueError(f'{va:#x} not in a file-backed segment')


def cstring(data, va, limit=512):
    raw = read_va(data, va, limit)
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


def build_xrefs(data):
    """Every (target, site) formed by adrp followed within 8 instructions by add/ldr/str on the same register."""
    vaddr, off, filesz, _ = text_segment(data)
    words = array.array('I', data[off:off + filesz - filesz % 4])
    pairs = []
    n = len(words)
    for i in range(n):
        w = words[i]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 31
        imm = ((w >> 5) & 0x7FFFF) << 2 | (w >> 29) & 3
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = vaddr + i * 4
        page = (pc & ~0xFFF) + (imm << 12)
        for j in range(i + 1, min(i + 9, n)):
            u = words[j]
            rn = (u >> 5) & 31
            if rn != rd:
                if (u & 31) == rd and (u & 0x1F000000) != 0x14000000:  # rd clobbered (crude)
                    break
                continue
            top = u & 0xFFC00000
            if top in (0x91000000, 0x91400000):  # add xd, xn, #imm{, lsl 12}
                pairs.append((page + (((u >> 10) & 0xFFF) << (12 if top == 0x91400000 else 0)), vaddr + j * 4))
                break
            scale = {0xF9400000: 8, 0xB9400000: 4, 0x79400000: 2, 0x39400000: 1, 0xFD400000: 8, 0xBD400000: 4,
                     0xF9000000: 8, 0xB9000000: 4, 0x3D400000: 1, 0x3DC00000: 16}.get(top)
            if scale:
                pairs.append((page + ((u >> 10) & 0xFFF) * scale, vaddr + j * 4))
                break
    pairs.sort()
    return pairs


def xrefs(path, data):
    cache = path + '.xrefs'
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(path):
        flat = array.array('Q')
        with open(cache, 'rb') as f:
            flat.frombytes(f.read())
    else:
        flat = array.array('Q', [v for pair in build_xrefs(data) for v in pair])
        with open(cache + '.partial', 'wb') as f:
            f.write(flat.tobytes())
        os.replace(cache + '.partial', cache)
    return flat[0::2], flat[1::2]


def relocations(data):
    """{slot vaddr: target vaddr} for R_AARCH64_RELATIVE entries (NSO pointers are only valid after these)."""
    dyn = next(s for s in segments(data) if s[3] == 6)
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    for i in range(phnum):
        ptype, _, off, vaddr, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if ptype == 2:
            dynamic = data[off:off + filesz]
    tags = dict(struct.iter_unpack('<QQ', dynamic))
    rela = read_va(data, tags[7], tags[8])  # DT_RELA, DT_RELASZ
    return {r_off: addend for r_off, info, addend in struct.iter_unpack('<QQq', rela) if info & 0xFFFFFFFF == 1027}


def vtables(data, mangled):
    """Vtables whose typeinfo name is `mangled` (e.g. N2nn3nex24MatchmakeExtensionClientE): [(vtable, [fn, ...])]."""
    relocs = relocations(data)
    name_va = None
    for vaddr, off, filesz, flags in segments(data):
        if not flags & 1:
            i = data.find(b'\0' + mangled.encode() + b'\0', off, off + filesz)
            if i >= 0:
                name_va = vaddr + i + 1 - off
                break
    assert name_va is not None, f'{mangled} not found'
    by_target = {}
    for slot, target in relocs.items():
        by_target.setdefault(target, []).append(slot)
    text_end = text_segment(data)[2]
    out = []
    for typeinfo in (s - 8 for s in by_target.get(name_va, [])):
        for slot in by_target.get(typeinfo, []):
            fns, p = [], slot + 8
            while 0 < relocs.get(p, -1) < text_end:
                fns.append(relocs[p])
                p += 8
            out.append((slot + 8, fns))  # slot + 8 = first virtual function; the symbol is 16 bytes earlier
    return out


def objdump(path, start, stop):
    return subprocess.run(['xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', f'--start-address={start:#x}',
                           f'--stop-address={stop:#x}', path], capture_output=True, text=True, check=True).stdout


def function_start(data, va):
    """Walk back to the nearest `stp x29, x30, [sp, #-N]!`/`sub sp, sp` preceded by a ret/branch (heuristic)."""
    vaddr, off, _, _ = text_segment(data)
    pc = va & ~3
    while pc > vaddr:
        w, = struct.unpack_from('<I', data, off + pc - vaddr)
        prev, = struct.unpack_from('<I', data, off + pc - 4 - vaddr)
        is_entry = (w & 0xFFC003E0) in (0xA98003E0, 0xD10003E0) or (w & 0xFF8003FF) == 0xD10003FF
        if is_entry and (prev == 0xD65F03C0 or (prev & 0xFC000000) == 0x14000000):
            return pc
        pc -= 4
    return vaddr


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    data = open(path, 'rb').read()
    if cmd == 'str':
        rx = re.compile(sys.argv[3].encode())
        for vaddr, off, filesz, flags in segments(data):
            if flags & 1:
                continue
            blob = data[off:off + filesz]
            for m in re.finditer(rb'[\x20-\x7e]{4,}', blob):
                if rx.search(m.group()):
                    print(f'{vaddr + m.start():#x}\t{m.group().decode()}')
    elif cmd == 'xref':
        targets, sites = xrefs(path, data)
        for arg in sys.argv[3:]:
            t = int(arg, 0)
            i = bisect.bisect_left(targets, t)
            while i < len(targets) and targets[i] == t:
                print(f'{t:#x}\t<- {sites[i]:#x}')
                i += 1
    elif cmd == 'dis':
        start = int(sys.argv[3], 0)
        print(objdump(path, start, start + 4 * int(sys.argv[4] if len(sys.argv) > 4 else 32)))
    elif cmd == 'vtable':
        for vt, fns in vtables(data, sys.argv[3]):
            print(f'vtable {vt:#x}: ' + ' '.join(f'[{i}]{f:#x}' for i, f in enumerate(fns)))
    elif cmd == 'func':
        va = int(sys.argv[3], 0)
        start = function_start(data, va)
        print(objdump(path, start, max(va + 64, start + 4 * int(sys.argv[4] if len(sys.argv) > 4 else 128))))
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
