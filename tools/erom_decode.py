#!/usr/bin/env python3
"""Decode a Broadcom AXI (bcma) enumeration ROM dumped by obs/regdump.ko.

Input: the `# range ADDR +LEN` / `ADDR: w0 w1 w2 w3` text that
`cat /proc/regdump` produces. Output: the core table (manufacturer, core id,
revision, and every address descriptor).

Entry format follows drivers/bcma/scan.h of the Linux kernel.
"""
import re
import sys

CORE_NAMES = {}


def load_core_names(header):
    try:
        for line in open(header):
            m = re.match(r'#define\s+BCMA_CORE_(\w+)\s+0x([0-9A-Fa-f]+)', line)
            if m:
                CORE_NAMES[int(m.group(2), 16)] = m.group(1).lower()
    except OSError:
        pass


def parse_dump(path):
    """-> {base_addr: [words]} in dump order."""
    blocks, cur, base = [], None, None
    for line in open(path):
        m = re.match(r'#\s*range\s+([0-9a-f]+)', line)
        if m:
            base = int(m.group(1), 16)
            cur = []
            blocks.append((base, cur))
            continue
        m = re.match(r'([0-9a-f]+):((?:\s+[0-9a-f]{8})+)', line)
        if m and cur is not None:
            cur.extend(int(w, 16) for w in m.group(2).split())
    return blocks


SZ_NAMES = {0: '4K', 1: '8K', 2: '16K'}


def decode(base, words):
    i = 0
    core = 0
    out = []
    while i < len(words):
        cia = words[i]
        if cia in (0, 0xFFFFFFFF) or not (cia & 1):
            break
        tag = cia & 0xE
        if tag == 0xE:                      # end marker
            out.append('  -- end of erom --')
            break
        if tag != 0:                        # not a component-info entry
            i += 1
            continue
        cib = words[i + 1]
        i += 2
        manuf = (cia >> 20) & 0xFFF
        cid = (cia >> 8) & 0xFFF
        cls = (cia >> 4) & 0xF
        rev = (cib >> 24) & 0xFF
        nsw = (cib >> 19) & 0x1F
        nmw = (cib >> 14) & 0x1F
        nsp = (cib >> 9) & 0x1F
        nmp = (cib >> 4) & 0x1F
        out.append('core %2d: id 0x%03x %-16s rev %3d manuf 0x%03x class %d  '
                   'mp %d sp %d mw %d sw %d'
                   % (core, cid, CORE_NAMES.get(cid, '?'), rev, manuf, cls,
                      nmp, nsp, nmw, nsw))
        for _ in range(nmp):                # master port descriptors
            i += 1
        while i < len(words):
            ent = words[i]
            if not (ent & 1) or (ent & 0x6) != 0x4:
                break
            i += 1
            addr = ent & 0xFFFFF000
            if ent & 0x8:                   # 64-bit address
                i += 1
            szc = (ent & 0x30) >> 4
            if szc == 3:
                size = words[i] & 0xFFFFF000
                i += 1
                if words[i - 1] & 0x8:      # 64-bit size
                    i += 1
            else:
                size = 0x1000 << szc
            typ = {0: 'slave', 0x40: 'bridge', 0x80: 'swrap', 0xC0: 'mwrap'}[ent & 0xC0]
            out.append('           %-6s port %d  0x%08x  size 0x%08x'
                       % (typ, (ent & 0xF00) >> 8, addr, size))
        core += 1
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: erom_decode.py <regdump.txt> [bcma.h]')
    load_core_names(sys.argv[2] if len(sys.argv) > 2 else
                    'kernel-6.6/src/linux-6.6.93/include/linux/bcma/bcma.h')
    for base, words in parse_dump(sys.argv[1]):
        print('=== erom at 0x%08x (%d words)' % (base, len(words)))
        for line in decode(base, words):
            print(line)


if __name__ == '__main__':
    main()
