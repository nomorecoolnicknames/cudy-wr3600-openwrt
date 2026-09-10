#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""modpvfix.py - make a 4.19 ARM module's .pv_table conform to the 6.6 ABI.

Problem (found 2026-09-07 loading the stock hnd.ko on 6.6.93):

    Unable to handle kernel paging request at virtual address 0x7e1aaf50
    PC is at __fixup_a_pv_table+0x2c/0x58, Process insmodf

CONFIG_ARM_PATCH_PHYS_VIRT modules carry a `.pv_table` listing the
instructions whose phys<->virt immediate the loader must patch. The way an
entry names its instruction CHANGED between the two kernels:

  4.19 (vendor, arch/arm/kernel/head.S):
        ldrcc r7, [r4], #4      @ entry value, post-increment
        ldr   ip, [r7, r3]      @ r3 = 0 for modules -> instruction at ENTRY
     => entries are ABSOLUTE addresses (R_ARM_ABS32 against .text).

  6.6 (arch/arm/kernel/phys2virt.S:.Lloop/.Lnext):
        ldrcc r7, [r4]          @ entry value, r4 = address OF THE ENTRY
        ldr   ip, [r7, r4]      @ instruction at entry_value + entry_address
     => entries are RELATIVE offsets from the entry's own address.

So 6.6 adds the table slot's address to an already-absolute pointer and walks
off into nowhere - exactly the fault above.

Fix, done statically and without touching the kernel: flip the relocation type
in `.rel.pv_table` from R_ARM_ABS32 (2) to R_ARM_REL32 (3). The 6.6 module
loader computes, for REL32 (arch/arm/kernel/module.c:228):

    *loc += sym->st_value - loc

i.e. addend(.text offset) + .text runtime base - address of the slot
     = instruction address - slot address = exactly the relative form 6.6 wants.

Nothing else in the module changes, and the resulting table is correct for the
running kernel's real pv_offset - unlike simply deleting the section, which
would leave the placeholder immediates in place.

Usage:  modpvfix.py <input.ko> <output.ko>
        modpvfix.py --check <module.ko>
"""
import struct
import sys

SHT_REL = 9
R_ARM_ABS32 = 2
R_ARM_REL32 = 3


def sections(data):
    e_shoff = struct.unpack("<I", data[0x20:0x24])[0]
    e_shentsize = struct.unpack("<H", data[0x2E:0x30])[0]
    e_shnum = struct.unpack("<H", data[0x30:0x32])[0]
    e_shstrndx = struct.unpack("<H", data[0x32:0x34])[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        f = struct.unpack("<IIIIIIIIII", data[o:o + 40])
        secs.append(dict(zip(
            ("name", "type", "flags", "addr", "off", "size",
             "link", "info", "align", "entsz"), f)) | {"idx": i})
    strtab = secs[e_shstrndx]
    stab = data[strtab["off"]:strtab["off"] + strtab["size"]]
    for s in secs:
        s["sname"] = stab[s["name"]:stab.find(b"\0", s["name"])].decode()
    return secs


def find_pv_rel(secs):
    pv = next((s for s in secs if s["sname"] == ".pv_table"), None)
    if pv is None:
        return None, None
    rel = next((s for s in secs if s["type"] == SHT_REL and
                s["info"] == pv["idx"]), None)
    return pv, rel


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        data = open(sys.argv[2], "rb").read()
        pv, rel = find_pv_rel(sections(data))
        if pv is None:
            print("no .pv_table - nothing to do")
            return
        if rel is None:
            print(".pv_table (%d bytes) has NO relocations - cannot convert"
                  % pv["size"])
            return 1
        kinds = {}
        for o in range(rel["off"], rel["off"] + rel["size"], 8):
            t = struct.unpack("<I", data[o + 4:o + 8])[0] & 0xff
            kinds[t] = kinds.get(t, 0) + 1
        print(".pv_table %d bytes, %d relocs, types %s"
              % (pv["size"], pv["size"] // 4,
                 {("ABS32" if k == R_ARM_ABS32 else
                   "REL32" if k == R_ARM_REL32 else k): v
                  for k, v in kinds.items()}))
        return

    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[-2])

    data = bytearray(open(sys.argv[1], "rb").read())
    pv, rel = find_pv_rel(sections(bytes(data)))
    if pv is None:
        open(sys.argv[2], "wb").write(data)
        print("no .pv_table, copied unchanged")
        return
    if rel is None:
        sys.exit("error: .pv_table has no relocation section")

    n = 0
    for o in range(rel["off"], rel["off"] + rel["size"], 8):
        info = struct.unpack("<I", data[o + 4:o + 8])[0]
        if (info & 0xff) == R_ARM_ABS32:
            data[o + 4:o + 8] = struct.pack("<I", (info & ~0xff) | R_ARM_REL32)
            n += 1

    open(sys.argv[2], "wb").write(data)
    print("converted %d/%d .pv_table relocs ABS32 -> REL32 -> %s"
          % (n, pv["size"] // 4, sys.argv[2]))


if __name__ == "__main__":
    main()
