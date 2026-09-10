# enet6764 — BCM6764 Ethernet for Linux 6.6 (Cudy WR3600)

Minimal but correct Ethernet bring-up driver for the Broadcom BCM6764
(4× Cortex-A7, ARMv7, 32-bit, non-LPAE), built against
`kernel-6.6/src/linux-6.6.93` with the stock DTB used as-is.

Written from the vendor GPL U-Boot 2019.07 driver stack, which demonstrably
works on this exact board, plus the vendor Linux PMC driver for the parts
U-Boot does differently. It replaces the four-module draft in
`port66/sysport/`, which is left untouched.

---

## 1. Files

| Path | Contents |
|---|---|
| `enet6764.h` | Register offsets, bit definitions, marker map, internal prototypes. Every non-obvious constant cites its reference file and line. |
| `pmc6764.c` | PMB keyhole transport in the procmon block, BPCM read/write, `PowerOnDevice`/`PowerOnZone`, switch power-up, SYSTEMPORT soft reset. |
| `sf2_6764.c` | SF2 switch core init/open/close, MDIO master, internal single EGPHY power-up with the 25 ms workaround, `phy_advertise_caps`. |
| `sysport6764.c` | SYSTEMPORT v2.1 MAC, RX/TX descriptor handling, NAPI, netdev, and the module entry point that registers all three platform drivers. |
| `Makefile` | `obj-m += enet6764.o`, three objects into one module. |

Total: 1 header + 3 C files, 2186 lines, of which 1396 are code (the rest are
blank lines and the reference citations the task requires).

**Build (verified clean, including `W=1`, zero warnings):**

```sh
make -C /home/n8n/cudy_be3600/kernel-6.6/src/linux-6.6.93 \
     O=/home/n8n/cudy_be3600/kernel-6.6/build \
     M=/home/n8n/cudy_be3600/port66/enet66 \
     ARCH=arm \
     CROSS_COMPILE=/home/n8n/cudy_be3600/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi- \
     modules
```

Produces `enet6764.ko`, 31 KB, `vermagic 6.6.93 SMP modversions ARMv7 p2v8`,
`depends=` empty. `bcm96764_mark` resolved against
`kernel-6.6/build/Module.symvers` (line 135, `EXPORT_SYMBOL_GPL`), so modpost
is already happy — no placeholder was needed.

---

## 2. Insmod order

**There is none.** All three drivers live in one module:

```sh
insmod enet6764.ko
```

`enet6764_init()` calls `platform_register_drivers()` with the array
`{ pmc6764, sf2_6764, sysport6764 }`, which registers them in that order, so
each dependency is bound before the driver that needs it probes. Each probe
still returns `-EPROBE_DEFER` if its dependency is somehow not present
(`sf2` needs `pmc6764_ready()`, `sysport` needs `sf2_6764_get()`), so the
deferred-probe machinery is the safety net rather than the mechanism.

This is a deliberate change from the four-module draft. Splitting the drivers
across `.ko` files buys nothing here and adds a whole failure class (a module
loading before its provider, cross-module `EXPORT_SYMBOL` version mismatches)
that the marker channel cannot easily distinguish from a hardware fault.

Optional module parameter:

```sh
insmod enet6764.ko poll_us=1000   # RX/TX poll period, default 1000 us
```

---

## 3. Exact register write sequence

Ordering mirrors U-Boot: `sysport_probe` → `ethsw_ops->init()`, then
`sysport_init` (eth start) → `ethsw_ops->open()` → `__sp_init` → enable DMA.

`UB` = `gpl/openwrt/21.02/package/extra/bcm/src/bcm-bootloader/bootloaders/u-boot-2019.07/`
`KD` = `gpl/openwrt/21.02/package/extra/bcm/src/bcmdrivers/opensource/`
Local copies of the four most-quoted files are in `port66/`.

### 3.1 `pmc6764_probe()` — marker `0x60`

| Step | Write / read | Reference |
|---|---|---|
| map `procmon` by DT reg-name (phys `0xffb20000`) | — | `KD/misc/pmc/impl1/pmc_drv_dt.c:167-174` |
| read `procmon + 0x100` (PmbBus.config), extract `num_regs = (v >> 20) & 0x3ff` | read | `KD/misc/pmc/impl1/6764/pmc.h:205-208`; `pmc_drv.c:316` |
| reject `0x00000000` / `0xffffffff` / `num_regs == 0` | — | added; marker `0xE1` |

Keyhole transport, used by every BPCM access below
(`KD/misc/pmc/impl1/pmc_drv.c:300-363`):

```
bus     = (devAddr >> 12) & 0x3                      pmc_drv.c:303, pmc_addr.h:38
address = (devAddr & 0xff) * num_regs | wordOffset   pmc_drv.c:315-317
read : W procmon+0x110 = START|bus<<20|(0<<24)|address
       poll procmon+0x110 until !(v & (1<<28))       pmc_drv.c:319-323
       fail if v & (1<<30)                           pmc_drv.c:325
       R procmon+0x11c                               pmc_drv.c:328
write: W procmon+0x114 = value                       pmc_drv.c:351
       W procmon+0x110 = START|bus<<20|(1<<24)|address
       poll procmon+0x110 until !(v & (1<<28))       pmc_drv.c:352-357
```

Keyhole 0 is used (`pmc_drv.c:365-378`). `procmon+0x118` is the *mutex*
register, not `rd_data` — the draft read it by mistake.
Whole transaction under `spin_lock_irqsave`, poll bounded at 1000 × `udelay(1)`
= 1 ms; the reference spins unbounded.

### 3.2 `sf2_6764_init()` — markers `0x61`, `0x62`, `0x64`, `0x65`, `0x63`

Mirrors `UB/drivers/net/bcmbca/bcm_ethsw_impl1.c:49-151`, CONFIG_BCM6764 branches.

| # | Action | Reference |
|---|---|---|
| 1 | `pmc_switch_power_up()`: BPCM `0x008` (`PMB_ADDR_CNP`), read word 1 for `num_zones`, then for each zone read ctrl (word `32+8z`) and status (word `35+8z`); if `!(sts & (1<<15))` write ctrl with `pwr_dn_req=0, dpg_ctl_en=1, pwr_up_req=1, mem_pwr_ctl_en=1, blk_reset_assert=1` | `pmc_drv.c:775-799, 832-863`; `pmc_addr.h:68-73`; `BPCM.h:336-358, 390-410, 508-521`; `pmc_switch.c:96-99` |
| 2 | poll zone 0 status until `pwr_on_state` (≤ 50 ms) → **`0x61`** | added (the vendor never waits) |
| 3 | `pmc_switch_enable_rgmii_zone_clk()` — **omitted**, its body is compiled only for 63138/63148/4908/63158 | `pmc_switch.c:41-105` |
| 4 | `core+0x3c8 \|= (1<<7)\|(1<<4)`, poll until bit 7 clears (≤ 100 ms), `usleep 1 ms` → **`0x62`** | `impl1.c:75-79` |
| 5 | GPHY workaround, `phy_wkard_timeout = 25000` from DT: `sphy \|= RESET`; wait; `phytest = 1`; `sphy &= ~(IDDQ_BIAS\|IDDQ_GLOBAL)`; wait; `sphy \|= IDDQ_BIAS`; `sphy \|= IDDQ_GLOBAL`; wait; `sphy &= ~RESET`; wait; `phytest = 0` | `bcm_ethsw_phy.c:236-268` |
| 6 | `sgphy_powerup(8)`: `sphy &= ~(IDDQ_BIAS\|EXT_PWR_DOWN\|PHYAD)`, `\|= RESET\|(8<<8)`; 1 us; `&= ~IDDQ_GLOBAL`; 1 ms; `&= ~RESET`; 1 ms | `bcm_ethsw_phy.c:147-174` |
| 7 | read back `sphy-ctrl`, require RESET clear and `PHYAD == 8` → **`0x64`** | added |
| 8 | dummy MDIO read of PHY 8 reg 2, then read PHY 8 reg 2 as ID1; reject `0x0000`/`0xffff` → **`0x65`** | `bcm_ethsw_phy.c:315-317` |
| 9 | `phy_advertise_caps(8 \| ADVERTISE_ALL_GMII \| PHY_ADV_CFG_VALID)`: rewrite ANAR (reg 4) 10/100 bits, K1CTL (reg 9) 1000 bits, then always OR in `K1CTL_REPEATER_DTE` (0x400) | `bcm_ethsw_phy.c:114-145`; `impl1.c:99-103, 319` |
| 10 | the "wait until hardware enables the ports" loop is **skipped** on 6764 (reverse logic; waiting would hang) | `impl1.c:86-97` |
| 11 | ports 0..7: `core+0x00+8i = (v & 0xff) \| RXTX_DISABLE` | `impl1.c:110-115` |
| 12 | `core+0x058 = ((v & 0xff) \| FORWARDING_EN \| RETRY_LIMIT_DIS) & ~MANAGED_MODE` | `impl1.c:118-121` |
| 13 | `core+0x1018 = 0` (BRCM header off) | `impl1.c:122` |
| 14 | `core+0x110 = (v & 0xffb0) \| MII_DUMP_FORWARDING_EN \| MII2_VOL_SEL` | `impl1.c:123-124` |
| 15 | `core+0x72080 = XGMII_MODE\|USE_REG_CONTENTS\|TXFLOW_PAUSE\|RXFLOW_PAUSE\|DUPLEX\|LINK_PASS\|SPEED_10G` = `0x1f3` | `impl1.c:126-131` |
| 16 | read back `core+0x058`, require `FORWARDING_EN` → **`0x63`** | added |

### 3.3 `sf2_6764_open()` — marker `0x66`

Mirrors `impl1.c:187-214` plus the save half of `extsw_register_save_restore()`
(`impl1.c:161-168`):

* save `core+0x00+8i & 0xff` and `core+0x18800+16i & 0xffff` for i = 0..7;
* `core+0x18800+16i = 0x100` (`PBMAP_MIPS`, CPU-only fan-out);
* `core+0x00+8i = ((v & 0xff) & ~(RXTX_DISABLE|PORT_STATUS_M)) | NO_STP`.

`ndo_stop` restores both, preserving `PORT_CTRL_SWITCH_RESERVE`
(`impl1.c:170-181`).

### 3.4 `sp_hw_init()` — line-for-line `__sp_init()` (`bcmbca_sysport_v2.c:162-278`)

```
rbuf+0x00 : &= ~0x3, &= ~(1<<2), &= ~(1<<3), |= (1<<4)      v2.c:169-175
rbuf+0x04 = 0x80                                             v2.c:177
rdma+0x10b0 = (1<<17) | 32                                   v2.c:201
rdma+0x10d0 = 11                                             v2.c:202
rdma+0x1110 = 0                                              v2.c:207
              (PINDEX is read-only on 6764 — not written)    v2.c:208-210
rdma+0x1170 = 0 ; rdma+0x1174 = 0                            v2.c:214-215
rdma+0x0000 : 32 descriptors, {rx_pa[i], 2048<<18 | addr_hi} v2.c:68-80, 218
rdma+0x11b0 = 5                                              v2.c:225
tdma+0x0200 = 0x2                                            v2.c:239
tdma+0x0780 = 0x0808                                         v2.c:242
tdma+0x0480 = 0                                              v2.c:244
tdma+0x0600 = 0 ; tdma+0x0604 = 0                            v2.c:246-247
tdma+0x0500 = 0x40                                           v2.c:249
tdma+0x0800 = 0x1                                            v2.c:251
tdma+0x0700 = 0                                              v2.c:253
tdma+0x0400 = 0x3                                            v2.c:254
tdma+0x0380 = 0x00100009                                     v2.c:255
tdma+0x0950 = 0x1                                            v2.c:257
tdma+0x0910..0x091c = 0x1 (four)                             v2.c:258-261
tdma+0x0930..0x093c = 0xff,0xff00,0xff0000,0xff000000        v2.c:262-265
tdma+0x0904 : &= ~(1<<1), &= ~(1<<19), &= ~(1<<27)           v2.c:267-271
tdma+0x0930 = 0x1                                            v2.c:274
```

Then, still mirroring `sysport_init()` (`v2.c:378-451`):

```
rdma+0x1080 |= 1 ; poll rdma+0x1084 until !(v & 3)          v2.c:122-141, 409
tdma+0x0904 |= 1 | (1<<29) ; poll tdma+0x0908 until !(v&3)  v2.c:83-102, 416
usleep 100 us                                                v2.c:441
```
→ marker **`0x67`**, then `register_netdev` → **`0x68`**.

GIB, UMAC and `xbow_ipa` blocks from the reference are skipped: the stock DT
exposes no `systemport-gib-base`, `systemport-umac-base` or `systemport-ipa`
reg-name, so the reference's own `!= NULL` guards would skip them too.

### 3.5 TX (`__sp_send()`, `v2.c:454-508`)

```
copy payload into the coherent TX buffer (padded to ETH_ZLEN)
tdma+0x0000 = pa_lo                       word 0
tdma+0x0004 = (len<<18)|(3<<16)|(1<<11)   word 1   v2.c:470
tdma+0x0000 = 0                           word 2   v2.c:485  <- SAME address
tdma+0x0004 = 0                           word 3   v2.c:489  <- SAME address
```

The two trailing writes go back to `WRITE_PORT[0].LO/.HI`, **not** to +8/+12.
The write port is 8 bytes per ring (`bcmbca_sysport_v2.h:158-162`), so +8/+12
is ring 1 — the draft's bug.

Completion is detected by watching the consumer index in
`tdma+0x0480` bits 31:16 move away from the value sampled just before the
descriptor was pushed. That is more robust than the reference's
`while (p != c)`, which has a race in the window before the hardware bumps the
producer index.

### 3.6 RX (`__sp_recv()`, `v2.c:558-589`)

```
p = rdma+0x10f0 & 0xffff ; c = rdma+0x1110 & 0xffff
if (p == c) nothing to do
idx  = c % 32
w1   = rdma + 0x0000 + idx*8 + 4
len  = (w1 >> 18) & 0x3fff             <- bits 31:18, NOT w1 & 0x3fff
accept 60 <= len <= 2048, else rx_error
copy out, re-arm descriptor {rx_pa[idx], 2048<<18|addr_hi}
rdma+0x1110 = (c + 1) & 0xffff
```

Descriptor layout is `struct PktDesc` (`bcmbca_sysport_v2.h:36-41`):
`{ u32 address; u32 address_hi:8, status:10, length:14; }`. On a
little-endian build `length` occupies bits 31:18.

Re-arming the descriptor after consumption is an addition: the hardware writes
`status` and `length` back in place, and restoring the initial values is
idempotent whether or not the hardware re-reads them.

### 3.7 64-bit switch registers

`port_traffic_ctrl` and `software_reset` are declared `uint64_t` in the
reference. They are accessed through the switchreg-base scratch pair, in the
order the vendor MAC driver uses (`mac_drv_sf2.c:186-247`):

* write: `switchreg+0x08 = hi`, then `core+off = lo`
* read: `lo = core+off`, then `hi = switchreg+0x0c`

Only the low half carries meaningful bits for the registers this driver
touches, but keeping the protocol makes the bus traffic identical to the
working reference.

---

## 4. What was fixed relative to `port66/sysport/`

Each numbered item is the corresponding row of
`REVIEW_PRE_FLASH_2026-09-06.md` §6.

1. **Compatibles.** Bound to `brcm,bca-pmc-3-2`, `brcm,bcmbca-sf2`,
   `brcm,bcmbca-systemport-v2.0` — the strings that are actually in the stock
   DTB.
2. **Nobody called the switch.** `sysport6764_probe()` calls `sf2_6764_init()`
   (which calls `pmc6764_switch_power_up()` first); `sp_open()` calls
   `sf2_6764_open()` before `sp_hw_init()`.
3. **Hardcoded addresses.** Removed entirely. Every window comes from
   `devm_platform_ioremap_resource_byname()` with the DT reg-name; a missing
   resource is a probe failure with a marker, never a fallback.
4. **PMC.** Rewritten as the procmon keyhole (§3.1).
5. **TX words 2/3.** Now the same two addresses (§3.5).
6. **RX descriptor length.** Initialised to 2048 and restored on every refill.
7. **RX length extraction.** `(w1 >> 18) & 0x3fff`.
8. **GPHY workaround.** `sphy_init_power_workaround()` runs whenever
   `phy_wkard_timeout != 0`; the stock DTB sets 25000, and `phy-test-ctrl` is
   now actually written.
9. **`phy_advertise_caps`.** Called for every GMII port found in the DT.
10. **Dead timeouts.** Every poll is a bounded `for` loop that returns
    `-ETIMEDOUT` and writes a distinct error marker. No `while (timeout--)`
    anywhere.
11. **`IS_ERR` vs `NULL`.** `devm_platform_ioremap_resource_byname()` only ever
    returns a valid pointer or an `ERR_PTR`; with no fallback path there is no
    `NULL` to miss.
12. **Long busy-wait under the TX lock.** `ndo_start_xmit` holds `tx_lock` only
    for the memcpy and four register writes. The optional completion spin runs
    **after** the lock is dropped and is bounded at 100 × `udelay(2)` = 200 µs.

Verified-correct parts of the draft were reused: the RBUF/RDMA/TDMA/TOPCTRL
offset tables, the `__sp_init` write order, the TX word-1 encoding
`(len<<18)|(3<<16)|(1<<11)`, and the MDIO command layout (BUSY 29, FAIL 28,
CMD 26, PHY 21, REG 16).

---

## 5. Marker map

Repeated here for the flash/capture loop; the authoritative copy is the header
comment in `enet6764.h`.

| Code | Meaning |
|---|---|
| `0x60` | pmc probe done, PMB config sane |
| `0x61` | switch BPCM zone reports `pwr_on_state` |
| `0x62` | SF2 software reset self-cleared |
| `0x63` | `switch_mode` readback shows `FORWARDING_EN` |
| `0x64` | sphy-ctrl: RESET clear, PHYAD == 8 |
| `0x65` | PHY 8 ID1 is neither `0x0000` nor `0xffff` |
| `0x66` | ports enabled, PBVLAN = CPU-only |
| `0x67` | RDMA and TDMA both ready |
| `0x68` | netdev registered |
| `0x69` | first TX descriptor consumed |
| `0x6A` | first RX packet delivered |
| `0xE0` | procmon resource missing / ioremap failed |
| `0xE1` | PMB config all-zero or all-ones |
| `0xE2` | PMB keyhole timeout |
| `0xE3` | switch BPCM zone never powered |
| `0xE4` | an sf2 reg window failed to map |
| `0xE5` | SF2 software reset never cleared |
| `0xE6` | switch core register file stuck |
| `0xE7` | MDIO stayed BUSY |
| `0xE8` | PHY ID1 `0x0000`/`0xffff` |
| `0xE9` | a systemport reg window failed to map |
| `0xEA` | DMA allocation failed / out of range |
| `0xEB` | RDMA never ready |
| `0xEC` | TDMA never ready |
| `0xED` | `register_netdev()` failed |
| `0xEF` | TX descriptor never consumed (runtime, non-fatal) |

`0xEE` is deliberately unused: `bcm96764_panic()`
(`arch/arm/mach-bcm/bcm96764.c:109-113`) writes it.

Everything is also logged with `dev_info`/`dev_err`, which becomes readable
once TX works and `dmesg` can be shipped off-box.

Interpreting a stall: the last marker names the step that *completed*, so a box
sitting at `0x62` died in the GPHY power-up between `0x62` and `0x64`.

---

## 6. Which socket to plug into

**Use the WAN jack.** This matters for the ping test.

In the stock DTB the SF2 switch node `sf2@200000` has exactly one usable
copper port for this driver:

* `port_gphy`, `reg = 0`, `phy-mode = "gmii"`, internal EGPHY at MDIO
  address 8 — driven here;
* `port_sgmii0`, `reg = 5` and `port_sgmii1`, `reg = 6` — `phy-mode =
  "serdes"`, skipped;
* `port_imp`, `reg = 8` — the CPU-side management port, configured via
  `imp_port_state`.

The four LAN jacks are **not** on this switch. They hang off a second SF2
device (`stock.dts:3437-3498`, `compatible = "brcm,bcmbca-extsw"`,
`extswsgmii_addr = <6>`, phandle referenced as `ethsw_ext` by the sysport node)
reached over the SGMII/serdes link, with their own EGPHYs at MDIO addresses
0..3. Bringing that up needs the serdes/10GAE PHY driver, which is out of
scope here and explicitly excluded by the task.

So: link and traffic will only appear on the internal GPHY port.

---

## 7. Deliberate deviations from the reference

| Deviation | Why |
|---|---|
| Polled RX/TX instead of interrupts | The six SYSTEMPORT interrupts live on a separate `sysport-blk` node (GIC SPI `0x4c`..`0x51`). The vendor consumer (`KD/char/archer/impl1/archer_gpl.c:690-716`) only maps them by index and never documents which index is RX buffer-done, so claiming one blind risks an unhandled-IRQ storm. |
| One module instead of four | Removes the insmod-ordering failure class; see §2. |
| Every poll bounded, with a marker | The box must keep booting and self-reboot on failure; the 80 s hardware watchdog armed in `bcm96764_init_early()` is a last resort, not a design. |
| `msleep`/`usleep_range` where the reference uses `udelay` | `phy_wkard_timeout` is 25000 µs and the workaround runs it four times. All of these calls are in process context. |
| TX completion via consumer-index delta | Avoids the reference's race between the descriptor write and the producer-index bump. |
| RX descriptor re-armed after each packet | Idempotent; removes any dependence on whether the hardware re-reads `length`. |
| `dma_alloc_coherent` for buffers | No cache maintenance to get wrong on a non-LPAE ARMv7 during bring-up. Costs throughput, not correctness. |

---

## 8. Known limitations and open questions

1. **Poll rate is capped by the tick.** The build has `CONFIG_HZ=100` and
   `CONFIG_HIGH_RES_TIMERS` off, so the 1 ms `hrtimer` actually fires every
   10 ms. RX latency and TX-completion latency are therefore up to 10 ms, and
   sustained TX is bounded near 100 pkt/s once the 200 µs inline spin misses.
   This is fine for ARP and ping. If it becomes a problem, enable
   `CONFIG_HIGH_RES_TIMERS` or raise `CONFIG_HZ` — no driver change needed.
2. **No PHY link management.** `netif_carrier_on()` is asserted
   unconditionally at open, and nothing polls the PHY link/speed or programs
   the MAC to match. The reference does this in `phy_poll()` /
   `mac_set_cfg_by_phy()` through the full `phy_drv`/`mac_drv` framework, which
   is far more code than a bring-up needs; the IMP port is pinned to
   link-up/full-duplex by `imp_port_state`, and the GPHY autonegotiates on its
   own after `phy_advertise_caps`.
3. **`pmc6764_sysport_reset()` is implemented but not called.** It matches
   `pmc_sysport_reset_system_port()` (`pmc_switch.c:123-147`, which *is*
   compiled for 6764 in the vendor tree — `IS_BCMCHIP(6764)` is in the guard).
   U-Boot only calls it on remove, so neither does this driver. Not exercised,
   therefore not verified.
4. **Could not verify: the exact width of the SF2 registers written here.**
   All of them (`port_traffic_ctrl`, `switch_mode`, `switch_ctrl`,
   `software_reset`, `brcm_hdr_ctrl`, `port_vlan_ctrl`, `imp_port_state`) are
   ≤ 16 bits in the 53xx register map, so the scratch upper half should be
   don't-care. The write protocol is kept anyway (§3.7).
5. **Could not verify: whether U-Boot leaves the switch already powered.**
   `PowerOnZone` checks `pwr_on_state` first and skips zones that are already
   up, so both cases are handled; the log line says which happened.
6. **Could not verify: `imp_port_state = SPEED_10G` on a board whose IMP link
   is not 10G.** It is what the 6764 branch of `impl1.c:126-131` writes, so it
   is reproduced verbatim. If RX works and TX does not (or frames are
   truncated), this register is the first thing to bisect.
7. **Could not verify: `TDMA_DESC_RING_MAPPING = 0x40`.** Decoded as
   `IGNORE_STATUS | qid 0 | port_id 0`, i.e. TX steered at port 0 — which
   happens to be the internal GPHY port. Copied verbatim from `v2.c:249`.
8. **`phy_advertise_caps` writes ANAR/K1CTL but never restarts
   autonegotiation.** The reference does not either, relying on the PHY having
   just come out of reset. If link never comes up, setting BMCR bit 9
   (restart aneg) on PHY 8 is the obvious next probe.
9. **MTU is left at 1500** and the RX length check rejects anything below 60 or
   above 2048, matching `ENET_ZLEN`/`MAX_PKT_LEN` in the reference. Frames with
   a Broadcom tag would exceed this; `brcm_hdr_ctrl = 0` should prevent any
   from being generated.
10. **`bcm96764_mark` is `EXPORT_SYMBOL_GPL`,** so the module declares
    `MODULE_LICENSE("GPL")`. Do not change that or the module will not load.

---

## 9. Suggested first bring-up run

```sh
insmod enet6764.ko
ip link set eth0 up
ip addr add <bench-ip>/24 dev eth0
# plug the cable into the WAN jack, then from the peer:
arping -I <iface> <bench-ip>     # expect a reply from 02:10:18:00:00:02
ping <bench-ip>
```

Reading the marker afterwards:

* stops at `0x68` → the stack is up but no packet ever moved; check the cable
  is in the WAN jack, then look at open-time markers.
* reaches `0x69` but never `0x6A` → TX path good, RX path or switch forwarding
  bad; suspect `imp_port_state`, PBVLAN, or the RX descriptor refill.
* reaches `0x6A` but no ping reply → the frames arrive but the reply does not
  leave; suspect TX ring 0 mapping.
* any `0xEx` → the table in §5 names the exact step.
