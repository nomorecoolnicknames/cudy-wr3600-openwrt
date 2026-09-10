#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""modvermagic.py — rewrite the vermagic of a stock BCA 4.19 .ko copy.

Why: stock blobs carry `vermagic=4.19.294 SMP preempt mod_unload ARMv7 p2v8`
(43 chars); our 6.6.93 target needs `6.6.93 SMP mod_unload modversions
ARMv7 p2v8` (45 chars). The kernel's modinfo check is a plain strcmp, so
the value must match EXACTLY (trailing space included).

The new value is 2 bytes longer than the old slot, so a naive in-place
overwrite would corrupt the next modinfo entry. This tool:
  1. parses the ELF section headers, locates `.modinfo`;
  2. parses `key=value\\0` entries sequentially (like the kernel does);
  3. replaces the `vermagic` value; if it fits into the section slack
     (trailing zero padding), shifts only the section tail in place;
     otherwise rebuilds the section (shifts all following sections and
     fixes sh_offset/sh_offset fields + e_shoff);
  4. writes the result to a NEW file (never overwrites the input).

NOTE: patching vermagic alone is NOT sufficient to load a blob built
without CONFIG_MODVERSIONS on our CONFIG_MODVERSIONS=y kernel — symbol
version (CRC) checks still fail. Loading ALWAYS uses `insmod -f`
(CONFIG_MODULE_FORCE_LOAD=y, see SHIM_C_SUMMARY.md). The patched vermagic
makes failures debuggable (dmesg shows version problems instead of
"vermagic mismatch") and allows plain insmod once MODVERSIONS handling
is revisited (lane B).

Usage:
    modvermagic.py <input.ko> <output.ko> [new-vermagic] [--fix-pv]
    modvermagic.py --check <input.ko>
Default new-vermagic is read from the freshly built bcm_shim.ko.

--fix-pv (lane E2, 2026-09-07): statically repair a 4.19 LPAE blob's
`.pv_table` for the 6.6 non-LPAE loader, then hide the table so the
loader skips its `fixup_pv_table` pass:
  * rewrite each patch site in `.text` with the final immediates for
    pv_offset = PHYS-PAGE = 0x40000000 (RAM at 0, PAGE_OFFSET 0xC0000000):
    `mov rX,#0x81` -> `mvn rX,#0` (hi = -1, so `adc` carry folds to 0),
    `adds`/`sub rD,rN,#0x81000000` -> `#0x40000000` (imm12 0x481 -> 0xC40);
  * unname `.pv_table` + `.rel.pv_table` (sh_name = 0). The loader finds
    the table by NAME (find_mod_section), so it skips the fixup; the
    relocations still apply harmlessly in place. No bytes move, so no
    alignment hazard (cf. the +64 rebuild logic above).
Why not just REL32-flip the table (tools/modpvfix.py): the 6.6 non-LPAE
fixup loop misreads the stock LPAE 3-insn sequences (mov_hi+adds+adc) --
it would patch the hi-word `mov` to #0x40, yielding 64-bit PAs with
hi=0x41 instead of 0. And why not strip the table only: the sites would
keep the 0x81_81000000 compile-time placeholders, which are never valid
at runtime. This option makes the conversions correct AND crash-free.
Site list is DERIVED from .rel.pv_table (no hardcoded offsets); any
unexpected site shape aborts loudly instead of guessing.

Lane owner: E (vermagic/rel-patching domain).

E3 EXTENSION (2026-09-07, SHIM_M3_PREP_REPORT.md section 5.2 + 11):
rel-patch modes for wl.ko under the 6.6 struct pci_dev layout.

KSYMTAB EXTENSION (2026-09-08, triaging/shim/m3run/M3RUN_H3_SUMMARY.md):
--fix-ksymtab mode for all exported 4.19 tables, including wl.ko.
"""
import os
import subprocess
import tempfile
import struct
import sys

SH_OFF, SH_ESZ, SH_NUM, SH_STR = 0x20, 0x2E, 0x30, 0x32


def parse_elf(data):
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise ValueError("not a 32-bit ELF file")
    e_shoff = struct.unpack("<I", data[SH_OFF:SH_OFF + 4])[0]
    e_shentsize = struct.unpack("<H", data[SH_ESZ:SH_ESZ + 2])[0]
    e_shnum = struct.unpack("<H", data[SH_NUM:SH_NUM + 2])[0]
    e_shstrndx = struct.unpack("<H", data[SH_STR:SH_STR + 2])[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        f = struct.unpack("<IIIIIIIIII", data[o:o + 40])
        secs.append({"name": f[0], "type": f[1], "flags": f[2],
                     "addr": f[3], "off": f[4], "size": f[5],
                     "link": f[6], "info": f[7], "align": f[8],
                     "entsz": f[9], "idx": i, "shoff": o})
    shstr = secs[e_shstrndx]
    stab = data[shstr["off"]:shstr["off"] + shstr["size"]]

    def sname(o):
        return stab[o:stab.find(b"\x00", o)].decode()

    for s in secs:
        s["sname"] = sname(s["name"])
    return secs, e_shoff, e_shentsize


def write_sec(buf, s):
    buf[s["shoff"] + 16:s["shoff"] + 20] = struct.pack("<I", s["off"])
    buf[s["shoff"] + 20:s["shoff"] + 24] = struct.pack("<I", s["size"])


def patch_vermagic(data, new_vermagic):
    secs, e_shoff, e_shentsize = parse_elf(data)
    mi = next(s for s in secs if s["sname"] == ".modinfo")
    blob = data[mi["off"]:mi["off"] + mi["size"]]
    # sequential entry parse, exactly like the kernel's module_next_tag_pair
    entries, pos = [], 0
    while pos < len(blob):
        end = blob.find(b"\x00", pos)
        if end < 0:
            break
        if end > pos:
            entries.append((pos, blob[pos:end]))
        pos = end + 1
    old = next((e for _, e in entries if e.startswith(b"vermagic=")), None)
    if old is None:
        raise ValueError("no vermagic entry in .modinfo")
    new_ent = b"vermagic=" + new_vermagic
    delta = len(new_ent) - len(old)
    buf = bytearray(data)
    if delta <= 0:
        # shrink in place, pad with zeros
        start = mi["off"] + next(p for p, e in entries if e == old)
        buf[start:start + len(new_ent)] = new_ent
        for i in range(start + len(new_ent), start + len(old)):
            buf[i] = 0
        return bytes(buf), "in-place"
    # grow: rebuild section content, shift the file tail
    new_blob = blob.replace(old + b"\x00", new_ent + b"\x00", 1)
    #
    # The tail of the file is shifted by `grow` bytes, so `grow` MUST be a
    # multiple of the alignment of every section that moves. Rounding the
    # *section size* to 4 (what this did before) is not the same thing: if
    # .modinfo did not start out 4-aligned in size, grow came out as 2 or 3
    # and every following section landed misaligned. The kernel then takes
    # `.gnu.linkonce.this_module` straight out of the image as a struct
    # module *, and on ARM the first set_bit() on mod->taints hits the
    # "assert word-aligned" trap in _set_bit -> Oops in try_to_force_load
    # (observed 2026-09-07 loading bcm_knvram66.ko: PC at _set_bit+0x4,
    # LR at try_to_force_load+0x34, mod = 0xe0d68305).
    #
    tail_off_pre = mi["off"] + mi["size"]
    step = max([s["align"] for s in secs
                if s["off"] >= tail_off_pre and s["align"] > 1] + [4])
    grow = len(new_blob) - mi["size"]
    if grow % step:
        new_blob += b"\x00" * (step - grow % step)
    grow = len(new_blob) - mi["size"]
    tail_off = mi["off"] + mi["size"]
    buf[tail_off:tail_off] = b"\x00" * grow  # insert space
    buf[mi["off"]:mi["off"] + len(new_blob)] = new_blob
    # if the section header table sits after the insertion point, it moves
    # too — and so do the in-file offsets of every section header entry.
    shdr_moved = e_shoff >= tail_off
    if shdr_moved:
        e_shoff += grow
        buf[SH_OFF:SH_OFF + 4] = struct.pack("<I", e_shoff)
    for s in secs:
        if shdr_moved:
            s["shoff"] += grow
        if s["off"] >= tail_off and s["idx"] != mi["idx"]:
            s["off"] += grow
            write_sec(buf, s)
    mi["size"] = len(new_blob)
    write_sec(buf, mi)
    return bytes(buf), "rebuilt(+%d)" % grow


def read_vermagic(data):
    secs, _, _ = parse_elf(data)
    mi = next(s for s in secs if s["sname"] == ".modinfo")
    blob = data[mi["off"]:mi["off"] + mi["size"]]
    for part in blob.split(b"\x00"):
        if part.startswith(b"vermagic="):
            return part.decode()
    return None


# --- --fix-pv (lane E2): static LPAE-pv_table repair + hide. ---
# Target offset: PHYS_OFFSET - PAGE_OFFSET = 0x00000000 - 0xC0000000.
PV_OFFSET_LO32 = 0x40000000
# 0x40000000 as ARM rotated imm: ROR(0x40, 8) -> rot field 4, imm8 0x40.
# (Checked against the stock placeholder: ROR(0x81, 8) = 0x81000000.)
PV_IMM12 = 0x440
# Stock placeholder imm12 in adds/sub sites (imm8=0x81, rot=4).
PV_PLACEHOLDER_IMM12 = 0x481


def fix_pv_table(buf):
    """Rewrite LPAE pv sites to final values, unname .pv_table sections.

    Returns a list of human-readable change lines. Raises ValueError on
    anything unexpected (wrong reloc type, site outside .text, unknown
    instruction shape). `buf` is a bytearray holding the FINAL image
    (call after patch_vermagic); section headers are re-parsed here.
    Site list is DERIVED from .rel.pv_table (no hardcoded offsets).
    """
    data = bytes(buf)
    secs, _, _ = parse_elf(data)
    text = _sec_by_name(secs, ".text")
    pv = next((s for s in secs if s["sname"] == ".pv_table"), None)
    rel = next((s for s in secs if s["sname"] == ".rel.pv_table"), None)
    if pv is None or rel is None:
        raise ValueError("no .pv_table/.rel.pv_table section (already fixed?)")
    symtab = _sec_by_name(secs, ".symtab")
    if symtab["entsz"] != 16:
        raise ValueError("symtab entsize %d != 16" % symtab["entsz"])
    changes = []
    for (r_off, r_sym, r_typ) in _rel_entries(data, rel):
        if r_typ != 2:  # R_ARM_ABS32 expected from a 4.19 LPAE build
            raise ValueError("pv rel @%x: unexpected type %d (want ABS32=2)"
                             % (r_off, r_typ))
        so = symtab["off"] + r_sym * 16
        _, _, _, _, _, st_shndx = struct.unpack("<III BBH", data[so:so + 16])
        if st_shndx != text["idx"]:
            raise ValueError("pv rel @%x: symbol not in .text (shndx %d)"
                             % (r_off, st_shndx))
        addend, = struct.unpack("<I", data[pv["off"] + r_off:
                                           pv["off"] + r_off + 4])
        if addend >= text["size"]:
            raise ValueError("pv rel @%x: site 0x%x outside .text (size 0x%x)"
                             % (r_off, addend, text["size"]))
        woff = text["off"] + addend
        w, = struct.unpack("<I", buf[woff:woff + 4])
        if w >> 28 != 0xE:
            raise ValueError("site 0x%x: non-AL cond (%08x), refusing"
                             % (addend, w))
        cls = w & 0x0FF00000  # I:opcode:S, Rn-agnostic
        if cls == 0x03A00000 and w & 0xFFF == 0x081:
            # mov rX, #0x81 (mov_hi placeholder) -> mvn rX, #0 (hi = -1,
            # so the following adc folds the adds-carry to exactly 0).
            nw = (w & 0xF000F000) | 0x03E00000
            kind = "mov_hi->mvn0"
        elif cls in (0x02900000, 0x02400000) \
                and w & 0xFFF == PV_PLACEHOLDER_IMM12:
            # adds rD,rN,#0x81000000 / sub rD,rN,#0x81000000 ->
            # same op with #0x40000000 (imm12 0x481 -> 0xC40). Rn/Rd/S
            # bits preserved; only the rotated immediate changes.
            kind = ("adds->adds#0x40000000" if cls == 0x02900000
                    else "sub->sub#0x40000000")
            nw = (w & ~0xFFF) | PV_IMM12
        else:
            raise ValueError("site 0x%x: unknown shape %08x, refusing "
                             "(need re-audit)" % (addend, w))
        buf[woff:woff + 4] = struct.pack("<I", nw)
        changes.append("site 0x%05x: %08x -> %08x (%s)"
                       % (addend, w, nw, kind))
    # hide the table: sh_name = 0 (points at shstrtab[0] == '\0').
    # find_mod_section() matches by NAME, so the 6.6 loader skips fixup;
    # .rel.pv_table still applies in place, harmlessly. Nothing moves.
    for s in (pv, rel):
        buf[s["shoff"]:s["shoff"] + 4] = struct.pack("<I", 0)
    changes.append("unnamed .pv_table + .rel.pv_table (sh_name=0)")
    return changes


def default_vermagic():
    try:
        data = open("/home/n8n/cudy_be3600/bsp-6.6/compat/bcm_shim.ko",
                    "rb").read()
        return read_vermagic(data).split("=", 1)[1].encode()
    except Exception:
        return b"6.6.93 SMP mod_unload modversions ARMv7 p2v8 "


def main(argv):
    if len(argv) == 3 and argv[1] == "--check":
        print(read_vermagic(open(argv[2], "rb").read()))
        return 0
    if len(argv) == 4 and argv[1] == "--layout-patch":
        data = open(argv[2], "rb").read()
        out, how = patch_pci_layout(data)
        open(argv[3], "wb").write(out)
        print("layout-patch: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--rename-warn":
        data = open(argv[2], "rb").read()
        out, how = patch_warn_rename(data)
        open(argv[3], "wb").write(out)
        print("rename-warn: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--rename-notifier":
        data = open(argv[2], "rb").read()
        out, how = patch_notifier_rename(data)
        open(argv[3], "wb").write(out)
        print("rename-notifier: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--rename-netdev":
        data = open(argv[2], "rb").read()
        out, how = patch_netdev_rename(data)
        open(argv[3], "wb").write(out)
        print("rename-netdev: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--rename-wiphy":
        data = open(argv[2], "rb").read()
        out, how = patch_wiphy_rename(data)
        open(argv[3], "wb").write(out)
        print("rename-wiphy: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--rename-lookup":
        data = open(argv[2], "rb").read()
        out, how = patch_lookup_rename(data)
        open(argv[3], "wb").write(out)
        print("rename-lookup: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "--fix-ksymtab":
        data = open(argv[2], "rb").read()
        out, how = patch_ksymtab(data)
        open(argv[3], "wb").write(out)
        print("fix-ksymtab: %s -> %s" % (how, argv[3]))
        return 0
    if len(argv) == 2 and argv[1] == "--selftest-ksymtab":
        return selftest_ksymtab()
    if len(argv) == 3 and argv[1] == "--verify":
        return verify_cli(argv[2])
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        print("E3 modes: --layout-patch IN OUT | --rename-warn IN OUT | "
              "--rename-notifier IN OUT | --rename-netdev IN OUT | "
              "--rename-wiphy IN OUT | --rename-lookup IN OUT | "
              "--verify FILE | --selftest")
        print("ksymtab modes: --fix-ksymtab IN OUT | --selftest-ksymtab")
        return 2
    src, dst = argv[1], argv[2]
    rest = argv[3:]
    fix_pv = "--fix-pv" in rest
    rest = [a for a in rest if a != "--fix-pv"]
    new = rest[0].encode() if rest else default_vermagic()
    data = open(src, "rb").read()
    print("old: %s" % read_vermagic(data))
    out, how = patch_vermagic(data, new)
    if fix_pv:
        buf = bytearray(out)
        for line in fix_pv_table(buf):
            print("pv: %s" % line)
        out = bytes(buf)
        how += "+pvfix"
        probs = check_alignment(out)
        if probs:
            raise SystemExit("alignment broken after pv fix: %s" % probs)
    open(dst, "wb").write(out)
    print("new: %s (%s) -> %s" % (read_vermagic(out), how, dst))
    return 0


# ---------------------------------------------------------------------------
# E3 rel-patch domain (SHIM_M3_PREP_REPORT.md section 5.2 + 11).
#
# Common anchor: stock radio/wl.ko md5 f0ccb1274f19fc8c77790b4ff3443e46.
# Every patch below aborts (no output written) unless the input matches the
# audited pre-image EXACTLY — a different blob revision must be re-audited,
# never force-patched.
# ---------------------------------------------------------------------------

# (text_vaddr, old_imm12, new_imm12, kind, field) — kind is "ldr" or "add".
# Order: the 12 SHIM_M3_PREP_REPORT section-11 sites first, then the 2 E3-found.
LAYOUT_SITES = [
    (0x30f1f0, 396, 644, "ldr", "pdev->irq"),
    (0x30f324, 396, 644, "ldr", "pdev->irq"),
    (0x30f378, 480, 712, "ldr", "resource[2].start.lo"),
    (0x30f37c, 484, 716, "ldr", "resource[2].start.hi"),
    (0x30f384, 488, 720, "ldr", "resource[2].end.lo"),
    (0x30f3a4, 560, 776, "ldr", "resource[4].start.lo"),
    (0x30f39c, 564, 780, "ldr", "resource[4].start.hi"),
    (0x30f3ac, 568, 784, "ldr", "resource[4].end.lo"),
    (0x30f3d8, 396, 644, "ldr", "pdev->irq"),
    (0x30f3e4, 400, 648, "ldr", "resource[0].start.lo"),
    (0x30f444, 572, 788, "ldr", "resource[4].end.hi"),
    (0x30f4bc, 396, 644, "ldr", "pdev->irq"),
    (0x30f46c, 492, 724, "ldr", "resource[2].end.hi (E3-found)"),
    (0x30e270, 560, 776, "add", "resource[4].start.lo via add+ldrd (E3-found)"),
]

WARN_OLD_NAME = b"warn_slowpath_fmt"
WARN_NEW_NAME = b"bcm_shim_warn_slowpath_fmt"
R_ARM_CALL = 28
R_ARM_JUMP24 = 29

# 4 expected warn_slowpath_fmt call sites (.text vaddrs, report section 5.1).
WARN_SITES = (0x24a0, 0x30b40c, 0x30bf80, 0x3136c4)

# Notifier UND renames (S9/M3 trampoline lane): redirect the blob's two
# netdevice-notifier registrations to the shim wrappers, which swap the
# trampoline into nb->notifier_call at runtime. Audited reloc sets
# (readelf -r -W on md5 f0ccb127): each symbol is referenced by exactly
# one R_ARM_CALL (direct pkt fwd site in wl_pktfwd_sys_init/fini) and one
# R_ARM_JUMP24 (wl_cfg80211_register/unregister_notifier stub tail-call).
# The .data ABS32 nb initializers (@0x3440 cfg80211, @0x1cc pkt fwd) and
# the callback bodies are untouched.
NOTIFY_RENAMES = (
    (b"register_netdevice_notifier",
     b"bcm_shim_register_netdevice_notifier",
     frozenset({(".rel.text", 0x636c, R_ARM_CALL),
                (".rel.text", 0x2fa044, R_ARM_JUMP24)})),
    (b"unregister_netdevice_notifier",
     b"bcm_shim_unregister_netdevice_notifier",
     frozenset({(".rel.text", 0x6064, R_ARM_CALL),
                (".rel.text", 0x2fa050, R_ARM_JUMP24)})),
)
# Mutual exclusion with the H7e single-site ldr patch
# (wl_taskfix.patch_network_worker rewrites .text 0x2d01c8 to read
# native+460): a patched reader misreads a legacy view (+460 there is
# netdev_ops, not ieee80211_ptr), so the rename refuses patched input.
NOTIFY_CONFLICT_ADDR = 0x2d01c8
NOTIFY_CONFLICT_OLD = 0xe5948274

# Netdev alloc/register redirect (H24 netdev-write lane): redirect the
# blob's single netdev source and its register/unregister to the shim
# wrappers, which serve a 4.19 legacy view (H10/H11 registry) instead of a
# native 6.6 object. Audited reloc sets (readelf -W -r on md5 f0ccb127,
# exact symbol names):
#  - alloc_netdev_mqs: exactly one R_ARM_CALL in the whole blob
#    (wl_get_driver_info+0x164, the single netdev source for wl0 and all
#    secondary/monitor ifs — hence the redirect is complete by
#    construction). ether_setup stays a kernel import (MOVW/MOVT pair at
#    0x309400/04, used only as the setup-cookie guard).
#  - register_netdev: 4x R_ARM_CALL (wl0 wl_attach 0x30e9e0, monitor
#    _wl_add_monitor_if 0x30a49c, _wl_add_if 0x30b228, wl_register_interface
#    0x313628). All repeat the same 4.19-offset write idiom, so one rename
#    covers them uniformly. register_netdevice (2x CALL, monitor paths) is
#    deliberately NOT renamed here (H25 co-requirement with xmit).
#  - unregister_netdev: 1x R_ARM_JUMP24 tail-call (0x30bcb0; the sibling
#    JUMP24 at 0x30bca0 is unregister_netdevice_queue — different symbol,
#    not renamed).
NETDEV_RENAMES = (
    (b"alloc_netdev_mqs", b"bcm_shim_alloc_netdev_mqs",
     frozenset({(".rel.text", 0x309420, R_ARM_CALL)})),
    (b"register_netdev", b"bcm_shim_register_netdev",
     frozenset({(".rel.text", 0x30a49c, R_ARM_CALL),
                (".rel.text", 0x30b228, R_ARM_CALL),
                (".rel.text", 0x30e9e0, R_ARM_CALL),
                (".rel.text", 0x313628, R_ARM_CALL)})),
    (b"unregister_netdev", b"bcm_shim_unregister_netdev",
     frozenset({(".rel.text", 0x30bcb0, R_ARM_JUMP24)})),
)
# Mutual exclusion with a crash-site-only ldr patch (rewriting .text
# 0x30e76c from [r7,#636] to a native offset): a patched reader applied to
# a legacy view would read legacy+464 (ethtool_ops) as dev_addr, so the
# rename refuses such input — pick exactly one fix class.
NETDEV_CONFLICT_ADDR = 0x30e76c
NETDEV_CONFLICT_OLD = 0xe597327c

# Lookup bridge redirect (P0 vendor30 netdev-lookup lane): redirect the
# blob's five dev_get_by_name call sites to the shim bridge, which serves
# the 4.19 legacy view (H10/H11 registry) holding the single lookup ref
# instead of the native 6.6 object (whose [native+1408] garbage Oopsed
# wl_bsscfg_find on NULL+8 — triaging/shim/h30/vendor30/fault-full-recovery.log).
# Audited reloc set (readelf -W -r on stage-rxpoolfix/wl-h7.ko, one UND sym,
# all R_ARM_CALL == 28, no JUMP24/ABS32; hnd.ko and wlshared.ko carry no such
# import):
#  - 0x206c   wl_handle_blog_event (r0=init_net, r1=event+46; NULL-checked;
#    paired bcm_dev_put @0x2164 is legacy-aware, no blob edit needed there)
#  - 0x63cd2c nlwifi_pre_doit, 0x63ced4 nlwifi_dump_chlist,
#    0x63d18c nlwifi_dump_stalist, 0x63d740 nlwifi_dump_aplist
#    (all NULL-checked; the lookup ref is dropped by the blob's INLINE pcpu
#    dec via [dev,#892], which reaches the native counter through the legacy
#    slot — no bcm_dev_put reloc in these functions).
# No conflict guard: no other patch class touches these five .text words
# (layout sites are 0x24a0/0x30exxx/0x3136c4, warn/notifier/netdev/wiphy
# renames hit disjoint UNDs). Blob drift is refused by the exact reloc set
# below (mismatch-отказ via _rename_und).
LOOKUP_RENAMES = (
    (b"dev_get_by_name", b"bcm_shim_dev_get_by_name_legacy",
     frozenset({(".rel.text", 0x206c, R_ARM_CALL),
                (".rel.text", 0x63cd2c, R_ARM_CALL),
                (".rel.text", 0x63ced4, R_ARM_CALL),
                (".rel.text", 0x63d18c, R_ARM_CALL),
                (".rel.text", 0x63d740, R_ARM_CALL)})),
)
# Wiphy lifecycle redirect (H28 wiphy-reject lane): redirect the blob's six
# wiphy/regulatory UNDs to the shim wrappers, which serve a 4.19 legacy
# view (H14 registry) instead of a native 6.6 object and publish a deep
# translation at register time. Audited reloc sets (readelf -W -r on md5
# f0ccb127, exact symbol names, all R_ARM_CALL == 28, no JUMP24):
#  - wiphy_new_nm: 1x CALL @0x2e4698 (wl_cfg80211_attach: ops=.data table,
#    priv=0x25538, name=NULL). The wrapper attaches the passed table as
#    the lane-D blob ops and allocates against the translated wl_66_ops.
#  - wiphy_register: 1x CALL @0x2fe2c8 (wl_cfg80211_register_wiphy+0x58).
#  - wiphy_free: 3x CALL @0x2e3bc4 (attach fail path), @0x2e5418
#    (detach path), @0x2fe304 (register_wiphy error unwind, REPORT §4).
#  - wiphy_unregister: 2x CALL @0x2e3c3c (detach), @0x2e548c (re-attach
#    cleanup after wiphy_unregister of the previous instance).
#  - wiphy_apply_custom_regulatory: 2x CALL @0x2cc710 (reinit path,
#    regulatory_flags|=1 just before) and @0x2e4894 (attach, static
#    regdomain with alpha2 "99", n_reg_rules=9).
#  - regulatory_hint: 1x CALL @0x2cdc08 (runtime hint path).
# No conflict guard: no other patch class touches these ten sites (the
# layout/pv patches hit pci_dev/pv_table words, warn/notifier/netdev
# renames hit disjoint UNDs). Blob drift is refused by the exact reloc
# sets below (mismatch-отказ via _rename_und).
WIPHY_RENAMES = (
    (b"wiphy_new_nm", b"bcm_shim_wiphy_new_nm",
     frozenset({(".rel.text", 0x2e4698, R_ARM_CALL)})),
    (b"wiphy_register", b"bcm_shim_wiphy_register",
     frozenset({(".rel.text", 0x2fe2c8, R_ARM_CALL)})),
    (b"wiphy_free", b"bcm_shim_wiphy_free",
     frozenset({(".rel.text", 0x2e3bc4, R_ARM_CALL),
                (".rel.text", 0x2e5418, R_ARM_CALL),
                (".rel.text", 0x2fe304, R_ARM_CALL)})),
    (b"wiphy_unregister", b"bcm_shim_wiphy_unregister",
     frozenset({(".rel.text", 0x2e3c3c, R_ARM_CALL),
                (".rel.text", 0x2e548c, R_ARM_CALL)})),
    (b"wiphy_apply_custom_regulatory",
     b"bcm_shim_wiphy_apply_custom_regulatory",
     frozenset({(".rel.text", 0x2cc710, R_ARM_CALL),
                (".rel.text", 0x2e4894, R_ARM_CALL)})),
    (b"regulatory_hint", b"bcm_shim_regulatory_hint",
     frozenset({(".rel.text", 0x2cdc08, R_ARM_CALL)})),
)


def _sec_by_name(secs, name):
    return next(s for s in secs if s["sname"] == name)


def _ror32(v, r):
    r &= 31
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF


def _arm_imm12_encode(value):
    """Encode value as ARM rotated-immediate imm12; raise if impossible."""
    for rot in range(16):
        for imm8 in range(256):
            if _ror32(imm8, rot * 2) == value:
                return (rot << 8) | imm8
    raise ValueError("value %d not encodable as ARM imm12" % value)


def _arm_imm12_decode(imm12):
    return _ror32(imm12 & 0xFF, ((imm12 >> 8) & 0xF) * 2)


def check_alignment(data):
    """Return list of misaligned-section problems (empty = all aligned).

    Mirrors the lane-H lesson in patch_vermagic(): every file-backed
    section must sit at a file offset that is a multiple of its
    sh_addralign, or the kernel's forced-load path Oopses on
    .gnu.linkonce.this_module. NOBITS (.bss) has no file image: skipped.
    """
    secs, e_shoff, _ = parse_elf(data)
    problems = []
    for s in secs:
        if s["type"] == 8:  # SHT_NOBITS
            continue
        if s["align"] > 1 and s["off"] % s["align"]:
            problems.append("%s: off %#x not multiple of align %d"
                            % (s["sname"], s["off"], s["align"]))
    if e_shoff % 4:
        problems.append("e_shoff %#x not 4-aligned" % e_shoff)
    return problems


def _rel_entries(data, relsec):
    n = relsec["size"] // 8
    out = []
    for i in range(n):
        o = relsec["off"] + i * 8
        r_off, r_info = struct.unpack("<II", data[o:o + 8])
        out.append((r_off, r_info >> 8, r_info & 0xFF))
    return out


def patch_pci_layout(data):
    """Rewrite the 14 audited ARM immediates in .text; return (bytes, how).

    Raises ValueError on any pre-image mismatch. Idempotent: if all 14
    sites already hold the new immediates, returns the input unchanged
    with how == "already-patched". Mixed old/new state is an error.
    """
    secs, _, _ = parse_elf(data)
    text = _sec_by_name(secs, ".text")
    buf = bytearray(data)
    n_old, n_new = 0, 0
    for vaddr, old_imm, new_imm, kind, field in LAYOUT_SITES:
        foff = text["off"] + (vaddr - text["addr"])
        word, = struct.unpack("<I", bytes(buf[foff:foff + 4]))
        if kind == "ldr":
            if word & 0x0FF00000 != 0x05900000:
                raise ValueError("%#x: not LDR-imm (%08x), re-audit (%s)"
                                 % (vaddr, word, field))
            cur = word & 0xFFF
            new_word = (word & ~0xFFF) | new_imm
        else:  # add
            if word & 0x0FF00000 != 0x02800000:
                raise ValueError("%#x: not ADD-imm (%08x), re-audit (%s)"
                                 % (vaddr, word, field))
            cur = _arm_imm12_decode(word & 0xFFF)
            new_word = (word & ~0xFFF) | _arm_imm12_encode(new_imm)
        if cur == old_imm:
            buf[foff:foff + 4] = struct.pack("<I", new_word)
            n_old += 1
        elif cur == new_imm:
            n_new += 1
        else:
            raise ValueError("%#x (%s): imm %d != old %d nor new %d "
                             "(word %08x) — blob revision drift, re-audit"
                             % (vaddr, field, cur, old_imm, new_imm, word))
    if n_new == len(LAYOUT_SITES):
        return bytes(buf), "already-patched(14/14 new)"
    if n_new:
        raise ValueError("partial layout state (%d old, %d new) — "
                         "refusing to continue" % (n_old, n_new))
    probs = check_alignment(bytes(buf))
    if probs:
        raise ValueError("alignment broken after layout patch: %s" % probs)
    return bytes(buf), "patched(14 instr)"


def _rename_und(data, old_name, new_name, expect):
    """Core of patch_warn_rename/patch_notifier_rename; return (bytes, how).

    Appends new_name to the end of .strtab (tail-shift scheme shared with
    patch_vermagic, incl. the max-sh_addralign step rule) and rewrites
    st_name in place. Aborts unless the relocs referencing the entry are
    exactly expect (set of (relsec, offset, type)). Idempotent no-op when
    the entry already carries new_name.
    """
    if len(new_name) > 120:
        raise ValueError("replacement name too long")
    secs, e_shoff, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    if symtab["entsz"] != 16:
        raise ValueError("symtab entsize %d != 16" % symtab["entsz"])
    # locate the entry by NAME (never by index — index may drift).
    tgt, nm = None, None
    for i in range(symtab["size"] // 16):
        o = symtab["off"] + i * 16
        st_name, _, _, st_info, _, st_shndx = struct.unpack(
            "<III BBH", data[o:o + 16])
        s = data[strtab["off"] + st_name:
                 data.find(b"\x00", strtab["off"] + st_name)]
        if s in (old_name, new_name):
            tgt, nm = (o, i, st_name, st_info, st_shndx), s
            break
    if tgt is None:
        raise ValueError("no UND %s entry found" % old_name.decode())
    o, idx, st_name, st_info, st_shndx = tgt
    if nm == new_name:
        start = strtab["off"] + st_name
        if data[start:start + len(new_name) + 1] == new_name + b"\x00":
            return data, "already-patched(sym #%d)" % idx
        raise ValueError("entry #%d claims new name but st_name does not "
                         "resolve to it — corrupt input" % idx)
    if st_shndx != 0 or (st_info >> 4) != 1 or (st_info & 0xF) != 0:
        raise ValueError("entry #%d is not GLOBAL/NOTYPE/UND" % idx)
    # every reloc pointing at idx must be in the audited set.
    hits = []
    for s in secs:
        if s["type"] != 9:  # SHT_REL
            continue
        for (r_off, sym, typ) in _rel_entries(data, s):
            if sym == idx:
                hits.append((s["sname"], r_off, typ))
    if set(hits) != expect:
        raise ValueError("reloc set on sym #%d != audited %s: %s"
                         % (idx, sorted(expect), hits))
    # append new name to .strtab end (same shift scheme as patch_vermagic).
    blob = new_name + b"\x00"
    tail_off_pre = strtab["off"] + strtab["size"]
    step = max([s["align"] for s in secs
                if s["off"] >= tail_off_pre and s["align"] > 1] + [4])
    grow = len(blob)
    if grow % step:
        blob += b"\x00" * (step - grow % step)
    grow = len(blob)
    buf = bytearray(data)
    tail_off = strtab["off"] + strtab["size"]
    buf[tail_off:tail_off] = b"\x00" * grow
    buf[tail_off:tail_off + len(new_name) + 1] = new_name + b"\x00"
    shdr_moved = e_shoff >= tail_off
    if shdr_moved:
        e_shoff += grow
        buf[SH_OFF:SH_OFF + 4] = struct.pack("<I", e_shoff)
    for s in secs:
        if shdr_moved:
            s["shoff"] += grow
        if s["off"] >= tail_off and s["idx"] != strtab["idx"]:
            s["off"] += grow
            write_sec(buf, s)
    strtab["size"] += grow
    write_sec(buf, strtab)
    # symtab sits BEFORE strtab: its file offset did not move (assert).
    assert o == symtab["off"] + idx * 16, "symtab moved, abort"
    struct.pack_into("<I", buf, o, tail_off - strtab["off"])
    out = bytes(buf)
    probs = check_alignment(out)
    if probs:
        raise ValueError("alignment broken after rename: %s" % probs)
    return out, "renamed(sym #%d, +%dB strtab)" % (idx, grow)


def patch_warn_rename(data, new_name=WARN_NEW_NAME):
    """Rename UND warn_slowpath_fmt -> new_name; return (bytes, how).

    Aborts unless exactly the 4 audited R_ARM_CALL relocs reference the
    entry. Idempotent via явный no-op.
    """
    expect = {(".rel.text", v, R_ARM_CALL) for v in WARN_SITES}
    return _rename_und(data, WARN_OLD_NAME, new_name, expect)


def notifier_state(data):
    """Return [(old_str, cur_str|None, idx|None)] for the notifier UNDs."""
    secs, _, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    out = []
    for old_name, new_name, _ in NOTIFY_RENAMES:
        found = (None, None)
        for i in range(symtab["size"] // 16):
            o = symtab["off"] + i * 16
            st_name, _, _, _, _, st_shndx = struct.unpack(
                "<III BBH", data[o:o + 16])
            if st_shndx != 0:
                continue
            end = data.find(b"\x00", strtab["off"] + st_name)
            s = data[strtab["off"] + st_name:end]
            if s in (old_name, new_name):
                found = (i, s.decode())
                break
        out.append((old_name.decode(), found[1], found[0]))
    return out


def patch_notifier_rename(data):
    """Rename both notifier UNDs to the bcm_shim_* wrappers.

    Returns (bytes, how). Refuses input carrying the H7e single-site ldr
    patch at NOTIFY_CONFLICT_ADDR (mutually exclusive fixes), refuses
    mixed renamed/unrenamed pairs, and is idempotent on fully renamed
    input. Reloc sets are audited per symbol (1xCALL + 1xJUMP24 each).
    """
    secs, _, _ = parse_elf(data)
    text = _sec_by_name(secs, ".text")
    foff = text["off"] + (NOTIFY_CONFLICT_ADDR - text["addr"])
    word, = struct.unpack("<I", data[foff:foff + 4])
    if word != NOTIFY_CONFLICT_OLD:
        raise ValueError("0x%x holds %08x, not the audited %08x — "
                         "H7e ldr patch present or blob drift, re-audit"
                         % (NOTIFY_CONFLICT_ADDR, word,
                            NOTIFY_CONFLICT_OLD))
    out, hows, n_new = data, [], 0
    for old_name, new_name, expect in NOTIFY_RENAMES:
        out, how = _rename_und(out, old_name, new_name, expect)
        hows.append("%s:%s" % (old_name.decode(), how))
        n_new += how.startswith("renamed")
    if n_new == len(NOTIFY_RENAMES):
        return out, "renamed(%s)" % " ".join(hows)
    if n_new == 0:
        return out, "already-patched(2/2 renamed)"
    raise ValueError("partial notifier state (%s) — refusing to continue"
                     % " ".join(hows))


def netdev_state(data):
    """Return [(old_str, cur_str|None, idx|None)] for the netdev UNDs."""
    secs, _, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    out = []
    for old_name, new_name, _ in NETDEV_RENAMES:
        found = (None, None)
        for i in range(symtab["size"] // 16):
            o = symtab["off"] + i * 16
            st_name, _, _, _, _, st_shndx = struct.unpack(
                "<III BBH", data[o:o + 16])
            if st_shndx != 0:
                continue
            end = data.find(b"\x00", strtab["off"] + st_name)
            s = data[strtab["off"] + st_name:end]
            if s in (old_name, new_name):
                found = (i, s.decode())
                break
        out.append((old_name.decode(), found[1], found[0]))
    return out


def patch_netdev_rename(data):
    """Rename the three netdev UNDs to the bcm_shim_* wrappers.

    Returns (bytes, how). Refuses input carrying a crash-site ldr patch
    at NETDEV_CONFLICT_ADDR (mutually exclusive fix class), refuses mixed
    renamed/unrenamed sets, and is idempotent on fully renamed input.
    Reloc sets are audited per symbol (1xCALL / 4xCALL / 1xJUMP24).
    """
    secs, _, _ = parse_elf(data)
    text = _sec_by_name(secs, ".text")
    foff = text["off"] + (NETDEV_CONFLICT_ADDR - text["addr"])
    word, = struct.unpack("<I", data[foff:foff + 4])
    if word != NETDEV_CONFLICT_OLD:
        raise ValueError("0x%x holds %08x, not the audited %08x — "
                         "crash-site ldr patch present or blob drift, re-audit"
                         % (NETDEV_CONFLICT_ADDR, word,
                            NETDEV_CONFLICT_OLD))
    out, hows, n_new = data, [], 0
    for old_name, new_name, expect in NETDEV_RENAMES:
        out, how = _rename_und(out, old_name, new_name, expect)
        hows.append("%s:%s" % (old_name.decode(), how))
        n_new += how.startswith("renamed")
    if n_new == len(NETDEV_RENAMES):
        return out, "renamed(%s)" % " ".join(hows)
    if n_new == 0:
        return out, "already-patched(3/3 renamed)"
    raise ValueError("partial netdev state (%s) — refusing to continue"
                     % " ".join(hows))


def wiphy_state(data):
    """Return [(old_str, cur_str|None, idx|None)] for the wiphy UNDs."""
    secs, _, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    out = []
    for old_name, new_name, _ in WIPHY_RENAMES:
        found = (None, None)
        for i in range(symtab["size"] // 16):
            o = symtab["off"] + i * 16
            st_name, _, _, _, _, st_shndx = struct.unpack(
                "<III BBH", data[o:o + 16])
            if st_shndx != 0:
                continue
            end = data.find(b"\x00", strtab["off"] + st_name)
            s = data[strtab["off"] + st_name:end]
            if s in (old_name, new_name):
                found = (i, s.decode())
                break
        out.append((old_name.decode(), found[1], found[0]))
    return out


def patch_wiphy_rename(data):
    """Rename the six wiphy/regulatory UNDs to the bcm_shim_* wrappers.

    Returns (bytes, how). No conflict guard: no other patch class touches
    these ten call sites (layout hits pci_dev words, pv hits .pv_table,
    warn/notifier/netdev renames hit disjoint UNDs). Refuses mixed
    renamed/unrenamed sets and any reloc-set drift (mismatch-отказ via
    _rename_und), and is idempotent on fully renamed input. Reloc sets
    are audited per symbol (1/1/3/2/2/1 x R_ARM_CALL).
    """
    out, hows, n_new = data, [], 0
    for old_name, new_name, expect in WIPHY_RENAMES:
        out, how = _rename_und(out, old_name, new_name, expect)
        hows.append("%s:%s" % (old_name.decode(), how))
        n_new += how.startswith("renamed")
    if n_new == len(WIPHY_RENAMES):
        return out, "renamed(%s)" % " ".join(hows)
    if n_new == 0:
        return out, "already-patched(6/6 renamed)"
    raise ValueError("partial wiphy state (%s) — refusing to continue"
                     % " ".join(hows))


def lookup_state(data):
    """Return [(old_str, cur_str|None, idx|None)] for the lookup UND."""
    secs, _, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    out = []
    for old_name, new_name, _ in LOOKUP_RENAMES:
        found = (None, None)
        for i in range(symtab["size"] // 16):
            o = symtab["off"] + i * 16
            st_name, _, _, _, _, st_shndx = struct.unpack(
                "<III BBH", data[o:o + 16])
            if st_shndx != 0:
                continue
            end = data.find(b"\x00", strtab["off"] + st_name)
            s = data[strtab["off"] + st_name:end]
            if s in (old_name, new_name):
                found = (i, s.decode())
                break
        out.append((old_name.decode(), found[1], found[0]))
    return out


def patch_lookup_rename(data):
    """Rename the dev_get_by_name UND to the bcm_shim_* bridge wrapper.

    Returns (bytes, how). No conflict guard: no other patch class touches
    these five call sites (layout hits pci_dev words, pv hits .pv_table,
    warn/notifier/netdev/wiphy renames hit disjoint UNDs). Refuses mixed
    renamed/unrenamed sets and any reloc-set drift (mismatch-отказ via
    _rename_und), and is idempotent on fully renamed input. The audited
    reloc set is 5x R_ARM_CALL on the single UND entry.
    """
    out, hows, n_new = data, [], 0
    for old_name, new_name, expect in LOOKUP_RENAMES:
        out, how = _rename_und(out, old_name, new_name, expect)
        hows.append("%s:%s" % (old_name.decode(), how))
        n_new += how.startswith("renamed")
    if n_new == len(LOOKUP_RENAMES):
        return out, "renamed(%s)" % " ".join(hows)
    if n_new == 0:
        return out, "already-patched(1/1 renamed)"
    raise ValueError("partial lookup state (%s) — refusing to continue"
                     % " ".join(hows))


# ---------------------------------------------------------------------------
# KSYMTAB domain (M3RUN_H3 2026-09-07/08: __ksymtab 4.19 8B vs 6.6 12B).
#
# Stock 4.19 blobs carry __ksymtab entries {value32, name32} (8 B, no
# namespace). Our ARM32 6.6 needs struct kernel_symbol {value, name,
# namespace} = 12 B (kernel/module/internal.h:35-43; ARM does NOT select
# HAVE_ARCH_PREL32_RELOCATIONS — only arm64/x86 do — so entries are 3
# plain absolute words, each applied via R_ARM_ABS32). The 6.6 loader
# counts num_syms = size/12 and steps 12, so a stock table registers
# garbage and NONE of the real exports (853 in hnd.ko, 8 in wlshared.ko);
# every wl.ko UND against hnd then fails with "Unknown symbol" (M3:
# 370/371 router Unknowns are hnd exports; the E3 rel-patches were
# proven innocent by the M3 audit).
#
# Fix, same tail-shift technique as patch_vermagic/patch_warn_rename:
# rewrite each entry as {value32, name32, ns32=0} (NULL namespace),
# rewrite the .rel__ksymtab r_offsets from 8-stride to 12-stride
# (same R_ARM_ABS32 types and symbols; REL addends travel with the
# copied words), shift the file tail by a max-sh_addralign multiple.
# The alignment gap is OUTSIDE sh_size: the loader enumerates size/12
# entries, including during duplicate-export checks before module_init.
#
# Why ns=NULL and NOT "" (empty string, what modpost emits for a 6.6
# in-tree module via __kstrtabns_<sym> + a 3rd ABS32 reloc per entry —
# verified on bsp-6.6/compat/bcm_shim.ko: 95x12B, 3xABS32/entry):
#   * the ONLY in-kernel consumer of an export's namespace is
#     verify_namespace_is_imported() (main.c:1062), which is NULL-safe:
#     `if (namespace && namespace[0])` — NULL and "" behave identically;
#   * NULL needs no __ksymtab_strings growth, no new reloc entries and
#     no symtab edits — minimal surgery, minimal align/shift hazard.
#
# Idempotent: a 12-stride table reports "already-fixed" and is returned
# unchanged (never double-expanded); anything matching neither the
# 8-stride (4.19) nor the 12-stride (6.6) shape aborts loudly.
# ---------------------------------------------------------------------------

KSYM_OLD_ENT = 8
KSYM_NEW_ENT = 12
KSYM_NAMES = ("__ksymtab", "__ksymtab_gpl")
R_ARM_ABS32 = 2
SHT_REL = 9
SHT_RELA = 4
STT_SECTION = 3


def _symtab_entries(data, symtab):
    n = symtab["size"] // 16
    out = []
    for i in range(n):
        o = symtab["off"] + i * 16
        out.append(struct.unpack("<III BBH", data[o:o + 16]))
    return out


def _ksymtab_step(secs, tail_off_pre):
    """Max-sh_addralign step for a tail insertion (shared shift rule)."""
    return max([s["align"] for s in secs
                if s["off"] >= tail_off_pre and s["align"] > 1] + [4])


def _ksymtab_needing_fix(data, secs):
    """Return (ksym, rel, n) for the first 8-stride table, else None.

    12-stride tables are skipped (already fixed); anything matching
    neither shape raises ValueError. Padded v1 tables are rejected:
    the loader derives its count from sh_size, not relocations.
    """
    for s in secs:
        if s["sname"] not in KSYM_NAMES:
            continue
        rel = next((r for r in secs if r["type"] == SHT_REL
                    and r["info"] == s["idx"]), None)
        if rel is None:
            if s["size"] == 0:
                continue
            raise ValueError("%s: size %#x but no SHT_REL with sh_info=%d"
                             % (s["sname"], s["size"], s["idx"]))
        nrel = rel["size"] // 8
        if nrel == 0 and s["size"] == 0:
            continue  # empty table: nothing to do
        if nrel % 2:
            raise ValueError("%s: odd reloc count %d — re-audit"
                             % (s["sname"], nrel))
        n = nrel // 2
        offs = sorted(o for o, _, _ in _rel_entries(data, rel))
        match8 = (s["size"] == KSYM_OLD_ENT * n
                  and offs == [x for i in range(n)
                               for x in (8 * i, 8 * i + 4)])
        match12 = (offs == [x for i in range(n)
                            for x in (12 * i, 12 * i + 4)]
                   and s["size"] == KSYM_NEW_ENT * n)
        if match12 and not match8:
            continue  # already fixed
        if match8 and not match12:
            return s, rel, n
        raise ValueError("%s: size %#x with %d relocs matches neither "
                         "8-stride (4.19) nor 12-stride (6.6) — re-audit"
                         % (s["sname"], s["size"], nrel))
    return None


def _ksymtab_expand_one(data, secs, e_shoff, ksym, rel, n):
    """Expand one 8-stride table (tail-shift); return (bytes, n_mapsyms)."""
    symtab = _sec_by_name(secs, ".symtab")
    if symtab["entsz"] != 16:
        raise ValueError("symtab entsize %d != 16" % symtab["entsz"])
    strings = _sec_by_name(secs, "__ksymtab_strings")
    strtab = _sec_by_name(secs, ".strtab")
    syms = _symtab_entries(data, symtab)
    entries = _rel_entries(data, rel)
    if len(entries) != 2 * n:
        raise ValueError("%s: %d relocs != 2x%d entries"
                         % (ksym["sname"], len(entries), n))
    # file-order shape pin: pairs must be (value@8i, name@8i+4), all ABS32.
    for j, (r_off, _, r_typ) in enumerate(entries):
        if r_typ != R_ARM_ABS32:
            raise ValueError("%s rel #%d: unexpected type %d (want ABS32=2)"
                             % (ksym["sname"], j, r_typ))
        if r_off != 8 * (j // 2) + 4 * (j % 2):
            raise ValueError("%s rel #%d: offset %#x breaks the 8-stride "
                             "pair shape — re-audit" % (ksym["sname"], j,
                                                        r_off))
    # name-side relocs must all reference the __ksymtab_strings SECTION
    # symbol (value-side symbols vary per export and travel untouched).
    name_syms = {sym for _, sym, _ in entries[1::2]}
    if len(name_syms) != 1:
        raise ValueError("%s: name relocs reference %d symbols, want 1"
                         % (ksym["sname"], len(name_syms)))
    nsym = name_syms.pop()
    if nsym >= len(syms):
        raise ValueError("%s: name sym #%d out of range" % (ksym["sname"],
                                                            nsym))
    _, _, _, st_info, _, st_shndx = syms[nsym]
    if st_shndx != strings["idx"] or (st_info & 0xF) != STT_SECTION:
        raise ValueError("%s: name sym #%d is not the __ksymtab_strings "
                         "SECTION symbol" % (ksym["sname"], nsym))
    # nothing else may point into the table: any non-SECTION symtab entry
    # with st_shndx == ksymtab, or any reloc in another section resolving
    # to such a symbol, would go stale under the 8->12 re-stride.
    # EXCEPTION: ARM mapping symbols ($a/$t/$d, STT_NOTYPE) — one $d per
    # entry start in these blobs (853 in hnd.ko). They are debug-only
    # (objdump markers; the loader never reads .symtab), so their
    # st_value is REMAPPED to the same intra-entry byte of the 12B entry
    # instead of aborting. Anything else aborts.
    problems = []
    mapsyms = []
    for i, (st_name, st_value, _, st_info2, _, st_shndx2) in enumerate(syms):
        if st_shndx2 != ksym["idx"] or (st_info2 & 0xF) == STT_SECTION:
            continue
        nm = data[strtab["off"] + st_name:
                  data.find(b"\x00", strtab["off"] + st_name)]
        if (st_info2 & 0xF) == 0 and len(nm) >= 2 and nm[:1] == b"$" \
                and nm[1:2] in b"atd":
            if st_value >= 8 * n:
                problems.append("symtab #%d ($map) value %#x outside %s"
                                % (i, st_value, ksym["sname"]))
            else:
                mapsyms.append((i, st_value))
            continue
        problems.append("symtab #%d (%s) points into %s"
                        % (i, nm, ksym["sname"]))
    for s2 in secs:
        if s2["type"] == SHT_RELA and s2["info"] == ksym["idx"]:
            problems.append("%s: unexpected RELA against %s"
                            % (s2["sname"], ksym["sname"]))
        if s2["type"] != SHT_REL or s2["idx"] == rel["idx"]:
            continue
        for (r_off, r_sym, _) in _rel_entries(data, s2):
            if r_sym < len(syms) and syms[r_sym][5] == ksym["idx"]:
                problems.append("%s+%#x references %s (sym #%d)"
                                % (s2["sname"], r_off, ksym["sname"], r_sym))
    if problems:
        raise ValueError("%s: %d external reference(s) would go stale: %s"
                         % (ksym["sname"], len(problems), problems[:4]))
    # name addends (REL in-place) must land inside __ksymtab_strings.
    old = data[ksym["off"]:ksym["off"] + ksym["size"]]
    for i in range(n):
        addend, = struct.unpack("<I", old[8 * i + 4:8 * i + 8])
        if addend >= strings["size"]:
            raise ValueError("%s entry #%d: name addend %#x outside "
                             "__ksymtab_strings (%#x)"
                             % (ksym["sname"], i, addend, strings["size"]))
    # rebuild content: {value, name} -> {value, name, ns=NULL}.
    new_blob = b"".join(old[8 * i:8 * i + 8] + b"\x00\x00\x00\x00"
                        for i in range(n))
    # tail shift, same max-sh_addralign step rule as patch_vermagic.
    tail_off_pre = ksym["off"] + ksym["size"]
    step = _ksymtab_step(secs, tail_off_pre)
    grow = len(new_blob) - ksym["size"]
    if grow % step:
        grow += step - grow % step
    # Insert enough file space to preserve every following alignment,
    # but retain the exact table size. Zero bytes in this file gap must
    # never become unrelocated {value=0,name=NULL,namespace=NULL} exports.
    buf = bytearray(data)
    tail_off = ksym["off"] + ksym["size"]
    # NOTE: capture the reloc file position BEFORE the shift loop below:
    # the loop mutates rel["off"] in place, so adding grow afterwards
    # would double-count (this exact bug once shipped new r_offsets 3456B
    # past the section — caught by the stride re-check in selftest).
    rel_file_off = rel["off"]
    rel_moved = rel_file_off >= tail_off
    buf[tail_off:tail_off] = b"\x00" * grow  # insert space
    buf[ksym["off"]:ksym["off"] + len(new_blob)] = new_blob
    shdr_moved = e_shoff >= tail_off
    if shdr_moved:
        e_shoff += grow
        buf[SH_OFF:SH_OFF + 4] = struct.pack("<I", e_shoff)
    for s in secs:
        if shdr_moved:
            s["shoff"] += grow
        if s["off"] >= tail_off and s["idx"] != ksym["idx"]:
            s["off"] += grow
            write_sec(buf, s)
    ksym["size"] = len(new_blob)
    write_sec(buf, ksym)
    # rewrite reloc offsets 8-stride -> 12-stride at the (moved) reloc
    # position; r_info words (type+symbol) are preserved verbatim.
    rel_off = rel_file_off + (grow if rel_moved else 0)
    for j, (_, r_sym, r_typ) in enumerate(entries):
        new_off = 12 * (j // 2) + 4 * (j % 2)
        struct.pack_into("<II", buf, rel_off + j * 8,
                         new_off, (r_sym << 8) | r_typ)
    # remap ARM mapping-symbol st_values in place (.symtab size unchanged;
    # symtab["off"] already carries the tail shift from the loop above).
    for i, v in mapsyms:
        struct.pack_into("<I", buf, symtab["off"] + i * 16 + 4,
                         12 * (v // 8) + (v % 8))
    out = bytes(buf)
    probs = check_alignment(out)
    if probs:
        raise ValueError("alignment broken after ksymtab fix: %s" % probs)
    return out, len(mapsyms)


def patch_ksymtab(data):
    """Expand every 4.19 8B __ksymtab to 6.6 12B; return (bytes, how).

    Idempotent: fully 12-stride input is returned unchanged with
    how == "already-fixed".
    """
    done = []
    while True:
        secs, e_shoff, _ = parse_elf(data)
        nxt = _ksymtab_needing_fix(data, secs)
        if nxt is None:
            break
        ksym, rel, n = nxt
        data, nmap = _ksymtab_expand_one(data, secs, e_shoff, ksym, rel, n)
        done.append("%s %d entries 8->12B (%d $map remapped)"
                    % (ksym["sname"], n, nmap))
    if not done:
        return data, "already-fixed"
    return data, "fixed(%s)" % ", ".join(done)


def ksymtab_state(data):
    """Return list of (name, stride, n) for __ksymtab sections.

    Cross-check relocation count against the exact section size.
    Padded v1 tables and other unknown shapes report stride 0.
    """
    secs, _, _ = parse_elf(data)
    out = []
    for s in secs:
        if s["sname"] not in KSYM_NAMES:
            continue
        rel = next((r for r in secs if r["type"] == SHT_REL
                    and r["info"] == s["idx"]), None)
        nrel = rel["size"] // 8 if rel is not None else -1
        n = nrel // 2 if nrel % 2 == 0 else -1
        offs = sorted(o for o, _, _ in _rel_entries(data, rel)) \
            if rel is not None else []
        if n >= 0 and s["size"] == KSYM_OLD_ENT * n and offs == \
                [x for i in range(n) for x in (8 * i, 8 * i + 4)]:
            out.append((s["sname"], 8, n))
            continue
        if n >= 0 and offs == [x for i in range(n)
                               for x in (12 * i, 12 * i + 4)] \
                and s["size"] == KSYM_NEW_ENT * n:
            out.append((s["sname"], 12, n))
            continue
        out.append((s["sname"], 0, -1))
    return out


def layout_state(data):
    """Return (n_old, n_new) over LAYOUT_SITES without modifying."""
    secs, _, _ = parse_elf(data)
    text = _sec_by_name(secs, ".text")
    n_old, n_new = 0, 0
    for vaddr, old_imm, new_imm, kind, _ in LAYOUT_SITES:
        foff = text["off"] + (vaddr - text["addr"])
        word, = struct.unpack("<I", data[foff:foff + 4])
        cur = (word & 0xFFF) if kind == "ldr" else \
            _arm_imm12_decode(word & 0xFFF)
        if cur == old_imm:
            n_old += 1
        elif cur == new_imm:
            n_new += 1
    return n_old, n_new


def warn_state(data):
    """Return (idx, name) of the warn_slowpath UND entry, or (None, None)."""
    secs, _, _ = parse_elf(data)
    symtab = _sec_by_name(secs, ".symtab")
    strtab = _sec_by_name(secs, ".strtab")
    for i in range(symtab["size"] // 16):
        o = symtab["off"] + i * 16
        st_name, _, _, _, _, st_shndx = struct.unpack(
            "<III BBH", data[o:o + 16])
        if st_shndx != 0:
            continue
        end = data.find(b"\x00", strtab["off"] + st_name)
        s = data[strtab["off"] + st_name:end]
        if s in (WARN_OLD_NAME, WARN_NEW_NAME):
            return i, s.decode()
    return None, None


def verify_cli(path):
    data = open(path, "rb").read()
    n_old, n_new = layout_state(data)
    idx, nm = warn_state(data)
    probs = check_alignment(data)
    print("file: %s" % path)
    print("layout: %d old-imm / %d new-imm (of %d sites)"
          % (n_old, n_new, len(LAYOUT_SITES)))
    print("warn_sym: #%s %s" % (idx, nm))
    for old, cur, at in notifier_state(data):
        print("notifier_sym: %s -> %s (#%s)" % (old, cur or "ABSENT", at))
    for old, cur, at in netdev_state(data):
        print("netdev_sym: %s -> %s (#%s)" % (old, cur or "ABSENT", at))
    for old, cur, at in wiphy_state(data):
        print("wiphy_sym: %s -> %s (#%s)" % (old, cur or "ABSENT", at))
    for old, cur, at in lookup_state(data):
        print("lookup_sym: %s -> %s (#%s)" % (old, cur or "ABSENT", at))
    print("align: %s" % ("OK" if not probs else "BROKEN: %s" % probs))
    ok = (n_old == 0 and n_new == len(LAYOUT_SITES)
          and nm == WARN_NEW_NAME.decode() and not probs)
    print("state: %s" % ("FULLY-PATCHED" if ok else "NOT-FULLY-PATCHED"))
    print("note: FULLY-PATCHED covers layout+warn only; notifier rename "
          "(S9/M3 trampoline) is reported separately and applies on top")
    return 0 if ok else 1


def selftest():
    """Apply both patches to a wl.ko copy; verify bytes/relocs/align/idem."""
    src = "/home/n8n/cudy_be3600/radio/wl.ko"
    fails = []

    def check(cond, msg):
        print(("PASS " if cond else "FAIL ") + msg)
        if not cond:
            fails.append(msg)

    orig = open(src, "rb").read()
    n_old, _ = layout_state(orig)
    check(n_old == len(LAYOUT_SITES), "pre: all %d sites hold old imm"
          % len(LAYOUT_SITES))
    idx0, nm0 = warn_state(orig)
    check(nm0 == WARN_OLD_NAME.decode(), "pre: UND sym is %s (#%s)"
          % (WARN_OLD_NAME.decode(), idx0))
    check(not check_alignment(orig), "pre: sections aligned")
    tmp = tempfile.mkdtemp(prefix="e3self_")
    try:
        p1 = os.path.join(tmp, "wl_layout.ko")
        open(p1, "wb").write(patch_pci_layout(orig)[0])
        n_old1, n_new1 = layout_state(open(p1, "rb").read())
        check(n_old1 == 0 and n_new1 == len(LAYOUT_SITES),
              "layout: 14/14 new-imm after patch")
        # byte-exact spot check of all 14 new words.
        secs, _, _ = parse_elf(open(p1, "rb").read())
        text = _sec_by_name(secs, ".text")
        d1 = open(p1, "rb").read()
        ok = True
        for vaddr, _, new_imm, kind, _ in LAYOUT_SITES:
            foff = text["off"] + (vaddr - text["addr"])
            word, = struct.unpack("<I", d1[foff:foff + 4])
            cur = (word & 0xFFF) if kind == "ldr" else \
                _arm_imm12_decode(word & 0xFFF)
            ok &= (cur == new_imm)
        check(ok, "layout: byte-exact new words at all 14 vaddrs")
        p2 = os.path.join(tmp, "wl_both.ko")
        out2, how2 = patch_warn_rename(open(p1, "rb").read())
        open(p2, "wb").write(out2)
        idx2, nm2 = warn_state(out2)
        check(nm2 == WARN_NEW_NAME.decode(),
              "rename: sym #%s now %s (%s)" % (idx2, nm2, how2))
        check(idx2 == idx0, "rename: symtab index stable (#%s)" % idx0)
        check(not check_alignment(out2), "post: sections aligned")
        # reloc audit: still exactly 4 R_ARM_CALL on the renamed entry.
        secs2, _, _ = parse_elf(out2)
        hits = [(s["sname"], o, t) for s in secs2 if s["type"] == 9
                for (o, sym, t) in _rel_entries(out2, s) if sym == idx2]
        check(set(hits) == {(".rel.text", v, R_ARM_CALL)
                            for v in WARN_SITES},
              "rename: 4xR_ARM_CALL follow the renamed entry")
        # idempotency: second run must no-op.
        _, how_l2 = patch_pci_layout(out2)
        _, how_w2 = patch_warn_rename(out2)
        check(how_l2.startswith("already-patched") and
              how_w2.startswith("already-patched"),
              "idempotency: layout=%s warn=%s" % (how_l2, how_w2))
        # readelf -r diff: only the 4 symbol names may change.
        try:
            r1 = subprocess.run(["readelf", "-W", "-r", p1],
                                capture_output=True, text=True).stdout
            r2 = subprocess.run(["readelf", "-W", "-r", p2],
                                capture_output=True, text=True).stdout
            l1 = [ln for ln in r1.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            l2 = [ln for ln in r2.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            # NOTE: "Relocation section ... at offset ..." headers shift by
            # the strtab grow (same tail-shift as patch_vermagic) — excluded
            # on purpose; only entry lines must match modulo the rename.
            diff = [(a, b) for a, b in zip(l1, l2) if a != b]
            same_len = len(l1) == len(l2)
            only_names = same_len and all(
                a.replace(WARN_OLD_NAME.decode(), WARN_NEW_NAME.decode())
                == b for a, b in diff) and len(diff) == 4
            check(same_len and only_names,
                  "readelf -r diff: exactly 4 renamed lines")
        except FileNotFoundError:
            check(False, "readelf missing for -r diff")
        # notifier rename on top of layout+warn (S9/M3 trampoline lane).
        pre_n = notifier_state(open(p1, "rb").read())
        check(all(cur == old for old, cur, _ in pre_n),
              "notifier: pre both UNDs unrenamed")
        idx_pre = [at for _, _, at in pre_n]
        p3 = os.path.join(tmp, "wl_all.ko")
        out3, how3 = patch_notifier_rename(open(p2, "rb").read())
        open(p3, "wb").write(out3)
        post_n = notifier_state(out3)
        check(all(cur and cur.startswith("bcm_shim_") for _, cur, _ in post_n),
              "notifier: post both renamed (%s)" % how3)
        check([at for _, _, at in post_n] == idx_pre,
              "notifier: symtab indices stable (#%s)" % idx_pre)
        check(not check_alignment(out3), "notifier: post sections aligned")
        secs3, _, _ = parse_elf(out3)
        ok_n = True
        for (old, new, expect), (_, _, at) in zip(NOTIFY_RENAMES, post_n):
            hits = {(s["sname"], o, t) for s in secs3 if s["type"] == 9
                    for (o, sym, t) in _rel_entries(out3, s) if sym == at}
            ok_n &= (hits == set(expect))
        check(ok_n, "notifier: 2x(CALL+JUMP24) follow renamed entries")
        try:
            r2 = subprocess.run(["readelf", "-W", "-r", p2],
                                capture_output=True, text=True).stdout
            r3 = subprocess.run(["readelf", "-W", "-r", p3],
                                capture_output=True, text=True).stdout
            l2 = [ln for ln in r2.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            l3 = [ln for ln in r3.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            # exact last-field compare: register_* nests inside
            # unregister_*, so substring replacement is unsound here.
            want = {o.decode(): n.decode() for o, n, _ in NOTIFY_RENAMES}
            heads2 = [ln.split()[:-1] for ln in l2]
            heads3 = [ln.split()[:-1] for ln in l3]
            tails2 = [ln.split()[-1] for ln in l2]
            tails3 = [ln.split()[-1] for ln in l3]
            changed = [(a, b) for a, b in zip(tails2, tails3) if a != b]
            check(len(l2) == len(l3) and heads2 == heads3 and
                  len(changed) == 4 and
                  all(want.get(a) == b for a, b in changed),
                  "readelf -r diff: only 4 notifier names change")
        except FileNotFoundError:
            check(False, "readelf missing for notifier -r diff")
        out3b, how3b = patch_notifier_rename(out3)
        check(out3b == out3 and how3b.startswith("already-patched"),
              "notifier: idempotent (%s)" % how3b)
        # conflict guard: H7e-patched ldr word must refuse the rename.
        secs_c, _, _ = parse_elf(orig)
        text_c = _sec_by_name(secs_c, ".text")
        co = text_c["off"] + (NOTIFY_CONFLICT_ADDR - text_c["addr"])
        bad = bytearray(orig)
        struct.pack_into("<I", bad, co, 0xe59481cc)
        try:
            patch_notifier_rename(bytes(bad))
        except ValueError:
            check(True, "notifier: H7e-patched ldr refused")
        else:
            check(False, "notifier: H7e-patched ldr refused")
        # netdev rename on top of layout+warn+notifier (H24 lane): 1xCALL
        # alloc source, 4xCALL register sites, 1xJUMP24 unregister tail.
        pre_d = netdev_state(out3)
        check(all(cur == old for old, cur, _ in pre_d),
              "netdev: pre all 3 UNDs unrenamed")
        idx_pre_d = [at for _, _, at in pre_d]
        p4 = os.path.join(tmp, "wl_all_netdev.ko")
        out4, how4 = patch_netdev_rename(out3)
        open(p4, "wb").write(out4)
        post_d = netdev_state(out4)
        check(all(cur and cur.startswith("bcm_shim_") for _, cur, _ in post_d),
              "netdev: post all renamed (%s)" % how4)
        check([at for _, _, at in post_d] == idx_pre_d,
              "netdev: symtab indices stable (#%s)" % idx_pre_d)
        check(not check_alignment(out4), "netdev: post sections aligned")
        secs4, _, _ = parse_elf(out4)
        ok_d = True
        for (old, new, expect), (_, _, at) in zip(NETDEV_RENAMES, post_d):
            hits = {(s["sname"], o, t) for s in secs4 if s["type"] == 9
                    for (o, sym, t) in _rel_entries(out4, s) if sym == at}
            ok_d &= (hits == set(expect))
        check(ok_d, "netdev: 1xCALL+4xCALL+1xJUMP24 follow renamed entries")
        try:
            r3 = subprocess.run(["readelf", "-W", "-r", p3],
                                capture_output=True, text=True).stdout
            r4 = subprocess.run(["readelf", "-W", "-r", p4],
                                capture_output=True, text=True).stdout
            l3 = [ln for ln in r3.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            l4 = [ln for ln in r4.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            want_d = {o.decode(): n.decode() for o, n, _ in NETDEV_RENAMES}
            heads3 = [ln.split()[:-1] for ln in l3]
            heads4 = [ln.split()[:-1] for ln in l4]
            tails3 = [ln.split()[-1] for ln in l3]
            tails4 = [ln.split()[-1] for ln in l4]
            changed = [(a, b) for a, b in zip(tails3, tails4) if a != b]
            check(len(l3) == len(l4) and heads3 == heads4 and
                  len(changed) == 6 and
                  all(want_d.get(a) == b for a, b in changed),
                  "readelf -r diff: only 6 netdev names change")
        except FileNotFoundError:
            check(False, "readelf missing for netdev -r diff")
        out4b, how4b = patch_netdev_rename(out4)
        check(out4b == out4 and how4b.startswith("already-patched"),
              "netdev: idempotent (%s)" % how4b)
        # conflict guard: crash-site-patched ldr word must refuse rename.
        bad2 = bytearray(orig)
        co2 = text_c["off"] + (NETDEV_CONFLICT_ADDR - text_c["addr"])
        struct.pack_into("<I", bad2, co2, 0xe59731d0)
        try:
            patch_netdev_rename(bytes(bad2))
        except ValueError:
            check(True, "netdev: crash-site-patched ldr refused")
        else:
            check(False, "netdev: crash-site-patched ldr refused")
        # wiphy rename on top of layout+warn+notifier+netdev (H28 lane):
        # 1x + 1x + 3x + 2x + 2x + 1x = 10x R_ARM_CALL follow renamed
        # entries. No conflict guard: no other patch class touches these
        # ten sites, so only drift (reloc-set mismatch) can refuse.
        pre_w = wiphy_state(out4)
        check(all(cur == old for old, cur, _ in pre_w),
              "wiphy: pre all 6 UNDs unrenamed")
        idx_pre_w = [at for _, _, at in pre_w]
        p5 = os.path.join(tmp, "wl_all_wiphy.ko")
        out5, how5 = patch_wiphy_rename(out4)
        open(p5, "wb").write(out5)
        post_w = wiphy_state(out5)
        check(all(cur and cur.startswith("bcm_shim_") for _, cur, _ in post_w),
              "wiphy: post all renamed (%s)" % how5)
        check([at for _, _, at in post_w] == idx_pre_w,
              "wiphy: symtab indices stable (#%s)" % idx_pre_w)
        check(not check_alignment(out5), "wiphy: post sections aligned")
        secs5, _, _ = parse_elf(out5)
        ok_w = True
        for (old, new, expect), (_, _, at) in zip(WIPHY_RENAMES, post_w):
            hits = {(s["sname"], o, t) for s in secs5 if s["type"] == 9
                    for (o, sym, t) in _rel_entries(out5, s) if sym == at}
            ok_w &= (hits == set(expect))
        check(ok_w, "wiphy: 1+1+3+2+2+1 CALL follow renamed entries")
        try:
            r4 = subprocess.run(["readelf", "-W", "-r", p4],
                                capture_output=True, text=True).stdout
            r5 = subprocess.run(["readelf", "-W", "-r", p5],
                                capture_output=True, text=True).stdout
            l4 = [ln for ln in r4.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            l5 = [ln for ln in r5.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            want_w = {o.decode(): n.decode() for o, n, _ in WIPHY_RENAMES}
            heads4 = [ln.split()[:-1] for ln in l4]
            heads5 = [ln.split()[:-1] for ln in l5]
            tails4 = [ln.split()[-1] for ln in l4]
            tails5 = [ln.split()[-1] for ln in l5]
            changed = [(a, b) for a, b in zip(tails4, tails5) if a != b]
            check(len(l4) == len(l5) and heads4 == heads5 and
                  len(changed) == 10 and
                  all(want_w.get(a) == b for a, b in changed),
                  "readelf -r diff: only 10 wiphy names change")
        except FileNotFoundError:
            check(False, "readelf missing for wiphy -r diff")
        out5b, how5b = patch_wiphy_rename(out5)
        check(out5b == out5 and how5b.startswith("already-patched"),
              "wiphy: idempotent (%s)" % how5b)
        # mismatch refusal (blob drift): flipping one audited reloc type
        # (wiphy_register site 0x2fe2c8 CALL->JUMP24) must abort the
        # whole rename instead of patching around the drift.
        secs_b, _, _ = parse_elf(out4)
        relt_b = _sec_by_name(secs_b, ".rel.text")
        bad3 = bytearray(out4)
        flipped = False
        for j in range(relt_b["size"] // 8):
            o = relt_b["off"] + j * 8
            r_off, r_info = struct.unpack("<II", bytes(bad3[o:o + 8]))
            if r_off == 0x2fe2c8 and (r_info & 0xFF) == R_ARM_CALL:
                struct.pack_into("<I", bad3, o + 4,
                                 (r_info & ~0xFF) | R_ARM_JUMP24)
                flipped = True
                break
        check(flipped, "wiphy: drift fixture reloc found")
        try:
            patch_wiphy_rename(bytes(bad3))
        except ValueError:
            check(True, "wiphy: drifted reloc set refused")
        else:
            check(False, "wiphy: drifted reloc set refused")
        # lookup bridge rename on top of layout+warn+notifier+netdev+wiphy
        # (P0 vendor30 netdev-lookup lane): 5x R_ARM_CALL on the single
        # dev_get_by_name UND follow the renamed entry. No conflict guard:
        # no other patch class touches these five words, so only drift
        # (reloc-set mismatch) can refuse.
        pre_l = lookup_state(out5)
        check(all(cur == old for old, cur, _ in pre_l),
              "lookup: pre UND unrenamed")
        idx_pre_l = [at for _, _, at in pre_l]
        p6 = os.path.join(tmp, "wl_all_lookup.ko")
        out6, how6 = patch_lookup_rename(out5)
        open(p6, "wb").write(out6)
        post_l = lookup_state(out6)
        check(all(cur and cur.startswith("bcm_shim_") for _, cur, _ in post_l),
              "lookup: post renamed (%s)" % how6)
        check([at for _, _, at in post_l] == idx_pre_l,
              "lookup: symtab index stable (#%s)" % idx_pre_l)
        check(not check_alignment(out6), "lookup: post sections aligned")
        secs6, _, _ = parse_elf(out6)
        ok_l = True
        for (old, new, expect), (_, _, at) in zip(LOOKUP_RENAMES, post_l):
            hits = {(s["sname"], o, t) for s in secs6 if s["type"] == 9
                    for (o, sym, t) in _rel_entries(out6, s) if sym == at}
            ok_l &= (hits == set(expect))
        check(ok_l, "lookup: 5xCALL follow renamed entry")
        try:
            r5 = subprocess.run(["readelf", "-W", "-r", p5],
                                capture_output=True, text=True).stdout
            r6 = subprocess.run(["readelf", "-W", "-r", p6],
                                capture_output=True, text=True).stdout
            l5 = [ln for ln in r5.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            l6 = [ln for ln in r6.splitlines()
                  if ln.strip() and not ln.startswith("Relocation section")]
            want_l = {o.decode(): n.decode() for o, n, _ in LOOKUP_RENAMES}
            heads5 = [ln.split()[:-1] for ln in l5]
            heads6 = [ln.split()[:-1] for ln in l6]
            tails5 = [ln.split()[-1] for ln in l5]
            tails6 = [ln.split()[-1] for ln in l6]
            changed = [(a, b) for a, b in zip(tails5, tails6) if a != b]
            check(len(l5) == len(l6) and heads5 == heads6 and
                  len(changed) == 5 and
                  all(want_l.get(a) == b for a, b in changed),
                  "readelf -r diff: only 5 lookup names change")
        except FileNotFoundError:
            check(False, "readelf missing for lookup -r diff")
        out6b, how6b = patch_lookup_rename(out6)
        check(out6b == out6 and how6b.startswith("already-patched"),
              "lookup: idempotent (%s)" % how6b)
        # mismatch refusal (blob drift): flipping one audited reloc type
        # (blog-event site 0x206c CALL->JUMP24) must abort the whole rename
        # instead of patching around the drift.
        secs_bl, _, _ = parse_elf(out5)
        relt_bl = _sec_by_name(secs_bl, ".rel.text")
        bad4 = bytearray(out5)
        flipped = False
        for j in range(relt_bl["size"] // 8):
            o = relt_bl["off"] + j * 8
            r_off, r_info = struct.unpack("<II", bytes(bad4[o:o + 8]))
            if r_off == 0x206c and (r_info & 0xFF) == R_ARM_CALL:
                struct.pack_into("<I", bad4, o + 4,
                                 (r_info & ~0xFF) | R_ARM_JUMP24)
                flipped = True
                break
        check(flipped, "lookup: drift fixture reloc found")
        try:
            patch_lookup_rename(bytes(bad4))
        except ValueError:
            check(True, "lookup: drifted reloc set refused")
        else:
            check(False, "lookup: drifted reloc set refused")
    finally:
        for f in os.listdir(tmp):
            os.unlink(os.path.join(tmp, f))
        os.rmdir(tmp)
    print("SELFTEST: %s" % ("ALL-PASS" if not fails else
                             "%d FAILURES" % len(fails)))
    return 0 if not fails else 1


def selftest_ksymtab():
    """Expand __ksymtab on hnd.ko/wlshared.ko copies; verify everything.

    Checks per blob: entry count, 12-stride shape, value/name words
    preserved + ns==0, reloc types/symbols preserved with 12-stride
    offsets, name-list equivalence old(step-8) vs new(step-12),
    idempotency, alignment, readelf -r diff (only Offset column moves),
    and .pv_table bytes untouched (hnd).
    """
    fails = []

    def check(cond, msg):
        print(("PASS " if cond else "FAIL ") + msg)
        if not cond:
            fails.append(msg)

    for src, want_n in (("/home/n8n/cudy_be3600/radio/hnd.ko", 853),
                        ("/home/n8n/cudy_be3600/radio/wlshared.ko", 8),
                        ("/home/n8n/cudy_be3600/radio/wl.ko", 2)):
        tag = src.split("/")[-1]
        orig = open(src, "rb").read()
        st = ksymtab_state(orig)
        check(st == [("__ksymtab", 8, want_n)], "%s: pre %dx8B" % (tag,
                                                                   want_n))
        out, how = patch_ksymtab(orig)
        check(how.startswith("fixed("), "%s: how=%s" % (tag, how))
        check(ksymtab_state(out) == [("__ksymtab", 12, want_n)],
              "%s: post %dx12B" % (tag, want_n))
        check(not check_alignment(out), "%s: sections aligned" % tag)
        secs_o, _, _ = parse_elf(orig)
        secs_n, _, _ = parse_elf(out)
        ko, kn = _sec_by_name(secs_o, "__ksymtab"), _sec_by_name(
            secs_n, "__ksymtab")
        check(kn["size"] == 12 * want_n,
              "%s: loader sh_size/12 == %d exactly (no ghost exports)"
              % (tag, want_n))
        ro = next(s for s in secs_o if s["type"] == SHT_REL
                  and s["info"] == ko["idx"])
        rn = next(s for s in secs_n if s["type"] == SHT_REL
                  and s["info"] == kn["idx"])
        eo, en = _rel_entries(orig, ro), _rel_entries(out, rn)
        check([t for _, _, t in en] == [t for _, _, t in eo]
              and all(t == R_ARM_ABS32 for _, _, t in en),
              "%s: reloc types/symbols preserved, all ABS32" % tag)
        check([s for _, s, _ in en] == [s for _, s, _ in eo],
              "%s: reloc symbol order identical" % tag)
        check([o for o, _, _ in en] == [12 * (j // 2) + 4 * (j % 2)
                                        for j in range(2 * want_n)],
              "%s: reloc offsets 12-stride exact" % tag)
        bo = orig[ko["off"]:ko["off"] + ko["size"]]
        bn = out[kn["off"]:kn["off"] + kn["size"]]
        ok = all(bn[12 * i:12 * i + 8] == bo[8 * i:8 * i + 8]
                 and bn[12 * i + 8:12 * i + 12] == b"\x00\x00\x00\x00"
                 for i in range(want_n))
        check(ok, "%s: value/name words preserved, ns==0" % tag)
        # name-list equivalence: step-8 walk of old vs step-12 of new.
        strs_o = _sec_by_name(secs_o, "__ksymtab_strings")
        strs_n = _sec_by_name(secs_n, "__ksymtab_strings")
        so = orig[strs_o["off"]:strs_o["off"] + strs_o["size"]]
        sn = out[strs_n["off"]:strs_n["off"] + strs_n["size"]]
        check(so == sn, "%s: __ksymtab_strings untouched" % tag)

        def names(blob, sec, stride, stab, count):
            r = []
            for i in range(count):
                a, = struct.unpack("<I", blob[sec["off"] + stride * i + 4:
                                              sec["off"] + stride * i + 8])
                z = stab.find(b"\x00", a)
                r.append(stab[a:z].decode())
            return r
        no = names(orig, ko, 8, so, want_n)
        nn = names(out, kn, 12, sn, kn["size"] // 12)
        check(no == nn and len(nn) == want_n and all(nn),
              "%s: step-12 walk yields same %d names" % (tag, want_n))
        # bsearch needs a sorted table (loader find_symbol): the stock
        # 4.19 order must already be sorted — else re-striding is not
        # enough and the blob needs a re-sort lane (abort, re-audit).
        check(no == sorted(no), "%s: stock order is sorted (bsearch-safe)"
              % tag)
        # Reproduce the loader's count and relocated name pointers. A
        # zero addend is valid ONLY when its name slot has a relocation.
        # v1's padded records had no such relocation and became NULL.
        def loader_names(blob, sec, relocs):
            result = []
            name_slots = {o for o, _, _ in relocs}
            for i in range(sec["size"] // 12):
                slot = 12 * i + 4
                if slot not in name_slots:
                    raise ValueError("unrelocated/NULL export name")
                a, = struct.unpack_from("<I", blob, sec["off"] + slot)
                end = sn.find(b"\0", a)
                if end <= a:
                    raise ValueError("invalid export name")
                result.append(sn[a:end])
            return result

        loaded_names = loader_names(out, kn, en)
        def lookup(key):
            lo, hi = 0, len(loaded_names)
            while lo < hi:
                mid = lo + (hi - lo) // 2
                candidate = loaded_names[mid]
                if key == candidate:
                    return mid
                if key > candidate:
                    lo = mid + 1
                else:
                    hi = mid
            return None

        check(all(lookup(key) == i for i, key in enumerate(loaded_names)),
              "%s: loader lookup resolves every real export" % tag)
        misses = [b"", b"\xff"] + [name + b"\x01" for name in loaded_names]
        check(all(lookup(key) is None for key in misses),
              "%s: missing-name lookups before/between/after exports" % tag)
        poison = bytearray(out)
        poison_sec = dict(kn)
        poison_sec["size"] += 12
        write_sec(poison, poison_sec)
        try:
            patch_ksymtab(bytes(poison))
        except ValueError:
            check(True, "%s: padded v1 shape rejected" % tag)
        else:
            check(False, "%s: padded v1 shape rejected" % tag)
        try:
            loader_names(bytes(poison), poison_sec, en)
        except ValueError:
            check(True, "%s: loader simulation detects v1 NULL ghost" % tag)
        else:
            check(False, "%s: loader simulation detects v1 NULL ghost" % tag)
        out2, how2 = patch_ksymtab(out)
        check(out2 == out and how2 == "already-fixed",
              "%s: idempotent (%s)" % (tag, how2))
        # ARM $d mapping symbols remapped 8i -> 12i (same count, sorted).
        sym_n = _sec_by_name(secs_n, ".symtab")
        vals = sorted(e[1] for e in _symtab_entries(out, sym_n)
                      if e[5] == kn["idx"] and (e[3] & 0xF) != STT_SECTION)
        check(vals == [12 * i for i in range(want_n)],
              "%s: %d $d mapsyms remapped to 12-stride" % (tag, len(vals)))
        if tag == "hnd.ko":
            pv_o = _sec_by_name(secs_o, ".pv_table")
            pv_n = _sec_by_name(secs_n, ".pv_table")
            rp_o = next(s for s in secs_o if s["sname"] == ".rel.pv_table")
            rp_n = next(s for s in secs_n if s["sname"] == ".rel.pv_table")
            same_pv = (orig[pv_o["off"]:pv_o["off"] + pv_o["size"]]
                       == out[pv_n["off"]:pv_n["off"] + pv_n["size"]]
                       and orig[rp_o["off"]:rp_o["off"] + rp_o["size"]]
                       == out[rp_n["off"]:rp_n["off"] + rp_n["size"]])
            check(same_pv, "hnd.ko: .pv_table + .rel.pv_table untouched")
        try:
            tmp = tempfile.mkdtemp(prefix="ksself_")
            po = os.path.join(tmp, "old.ko")
            pn = os.path.join(tmp, "new.ko")
            open(po, "wb").write(orig)
            open(pn, "wb").write(out)
            r1 = subprocess.run(["readelf", "-W", "-r", po],
                                capture_output=True, text=True).stdout
            r2 = subprocess.run(["readelf", "-W", "-r", pn],
                                capture_output=True, text=True).stdout

            def entries(t, name):
                cap, cur = False, []
                for ln in t.splitlines():
                    if ln.startswith("Relocation section"):
                        cap = (name in ln)
                        continue
                    if cap and ln.strip() and not ln.strip().startswith(
                            "Offset"):
                        cur.append(ln)
                return cur
            l1 = entries(r1, ".rel__ksymtab")
            l2 = entries(r2, ".rel__ksymtab")
            same_len = len(l1) == len(l2) == 2 * want_n
            kept = l1[0] == l2[0] and l1[1] == l2[1]  # entry0: 0/4 -> 0/4
            rest = all(a.split()[1:] == b.split()[1:] and a.split()[0]
                       != b.split()[0] for a, b in zip(l1[2:], l2[2:]))
            check(same_len and kept and rest,
                  "%s: readelf -r: %d lines, only Offset moves" % (
                      tag, len(l2)))
        except FileNotFoundError:
            check(False, "readelf missing for -r diff")
        finally:
            for f in os.listdir(tmp):
                os.unlink(os.path.join(tmp, f))
            os.rmdir(tmp)
    print("SELFTEST-KSYMTAB: %s" % ("ALL-PASS" if not fails else
                                    "%d FAILURES" % len(fails)))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
