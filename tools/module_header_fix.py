#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Translate a stock module's init/exit relocations using a native template.

H7: stock init@216 corrupted module memory descriptors when #110 expected
init@204. sizeof(struct module) remained 448, so the size check missed it.
This transformer accepts only zero-initialized headers with a module name
at +12 and zero-addend ABS32 init_module/cleanup_module relocations.
"""
import struct
import modvermagic as mv


def describe(data):
    secs, _, _ = mv.parse_elf(data)
    section = mv._sec_by_name(secs, '.gnu.linkonce.this_module')
    rel = next(s for s in secs if s['type'] == mv.SHT_REL and
               s['info'] == section['idx'])
    symbols = mv._symtab_entries(data, mv._sec_by_name(secs, '.symtab'))
    strings = mv._sec_by_name(secs, '.strtab')
    names = data[strings['off']:strings['off'] + strings['size']]
    raw = data[section['off']:section['off'] + section['size']]
    end = raw.find(b'\0', 12)
    assert 12 < end < 72, 'unexpected module name layout'
    assert not any(raw[:12] + raw[end:]), 'nonzero fields require a separate ABI audit'
    slots = {}
    for index, (offset, sym, kind) in enumerate(mv._rel_entries(data, rel)):
        n = symbols[sym][0]
        name = names[n:names.find(b'\0', n)]
        assert name in (b'init_module', b'cleanup_module'), name
        assert kind == mv.R_ARM_ABS32
        assert struct.unpack_from('<I', raw, offset)[0] == 0
        assert name not in slots
        slots[name] = (offset, index)
    assert b'init_module' in slots
    return section, rel, slots


def patch(data, native):
    section, rel, slots = describe(data)
    target, _, native_slots = describe(native)
    assert section['size'] == target['size'], 'module header resize not implemented'
    result = bytearray(data)
    for name, (old_offset, index) in slots.items():
        new_offset, _ = native_slots[name]
        struct.pack_into('<I', result, rel['off'] + index * 8, new_offset)
    return bytes(result)
