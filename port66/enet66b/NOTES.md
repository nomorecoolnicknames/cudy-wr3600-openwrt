# enet66b — LAN-side link bring-up for the BCM6764 (Cudy WR3600) on Linux 6.6

Two modules that take the LAN path from "SoC MAC exists" to "cable in LAN2
links": the Merlin16 serdes on SF2 port 5 (forced 2500Base-X) and the external
BCM53134 switch behind it.

Nothing in here touches `port66/enet66/`.

```
files
  enet66b.h                    MDIO API + marker map (shared header)
  serdes6764.c                 Merlin16 "shortfin" bring-up, core 0 lane 0
  merlin16_shortfin_ucode.h    PMD microcode, generated (31664 B, D102_0A, crc 0x4949)
  gen_ucode.sh                 regenerates the above from the vendor GPL header
  extsw6764.c                  BCM53134 reset / ID / SGMII port 8 / ports 0..3 / GPHYs
  sf2_mdio_local.c             standalone SF2 MDIO master (temporary)
  Kbuild, Makefile
```

## 1. Which vendor driver this is a port of

The stock kernel log names (`merlin_core_init`, `merlin16_serdes_init`,
`merline_speed_set_core`, `merlin_load_firmware`, `merlin_wait_uc_active`)
come from the **146 class / 10GAE** driver, not from `phy_drv_shortfin.c`.
`phy_drv_shortfin.c` is a different, newer state machine for the same silicon
family and is *not* what runs on this board.

All paths below are relative to

```
gpl/openwrt/21.02/package/extra/bcm/src/bcm-bootloader/bootloaders/u-boot-2019.07/drivers/
```

| role | file |
|---|---|
| PHY driver entry | `net/bcmbca/phy/phy_drv_146class_serdes.c` |
| state machine | `net/bcmbca/phy/Serdes146Class/merlin16_shortfin_config.c` |
| register tables | `net/bcmbca/phy/Serdes146Class/M1_merlin.h` |
| offsets / host regs | `net/bcmbca/phy/Serdes146Class/phy_drv_ethtop_merlin16.h`, `phy_drv_merlin16.h` |
| indirect register access | `net/bcmbca/phy/serdes_access.c`, `serdes_access_6764.h` |
| Merlin API library | `net/bcmbca/phy/merlin_shortfin/` |
| microcode | `net/bcmbca/phy/Serdes146Class/merlin16_shortfin_ucode_image.h` |
| DT plumbing | `net/bcmbca/phy/dt_parsing.c`, `phy/phy_drv_dsl_serdes.c` |
| external switch | `net/bcmbca/bcm_ethsw_ext.c`, `net/bcmbca/mii_shared.h` |
| MDIO | `net/bcmbca/phy/mdio_drv_sf2.c`, `mdio_drv_common.c`, `net/bcmbca/bcm_ethsw_phy.c` |
| GPIO | `gpio/gpio-bcm-bca.c` |

The 4.19 vendor kernel ships the same files under
`bcmdrivers/opensource/phy/`; the U-Boot copies were used because the task
called for them, and the two `merlin16_shortfin_config.c` differ only in
places that do not affect this path.

## 2. Serdes registers are memory-mapped, not MDIO

`serdes_access.c:35..67` binds `brcm,serdes1` (stock DTB `reg = <0x282000
0x1300>` under ubus-bus, phys `0x80282000`) and reaches the Merlin core
through an indirect-access window. PRTAD 6 from the DT is written into the
control register's `serdes_prtad` field; it is **not** an MDIO address that
this driver ever puts on the wire.

Register map (`serdes_access_6764.h:22..36`, core 0; core 1 is `+0x1000`):

| offset | register |
|---|---|
| 0x0004 | INDIR_ACC_ADDR — `dev<<27 \| lane<<16 \| reg` |
| 0x0008 | INDIR_ACC_MASK — 1 = preserve |
| 0x000c | CONTROL — iddq/refclk_reset/serdes_reset/prtad/comclk_enable |
| 0x0010 | STATUS — sigdet/cdr_lock/link/pll_lock |
| 0x0020 | AN_STATUS — per-lane AN link |
| 0x0024 | STATUS_1 — per-lane speed nibbles |
| 0x0800 | INDIR_ACC_CNTRL — data[15:0], r_w[16], start_busy[17], delayed_ack[18] |

`ETH_PHYS_TOP_BASE + 0x2020 / 0x2024` in `phy_drv_ethtop_merlin16.h:48..49`
(used by `merlin_chk_lane_link_status`) is `0x80280000 + 0x2020` =
`0x80282020` = the same AN_STATUS / STATUS_1 registers, so the link check
reads the serdes block, not the eth-phy-top block.

Every Merlin core register is written on device address 1 (`PMD_DEV`,
`merlin_shortfin/serdes_wrapper.c:52..66`); the PCS registers use device 3.

The vendor's mask handling looks odd and is reproduced exactly:
`serdes_access_write_mask()` writes `~mask` where `mask` is a promoted
`uint16_t`, so the mask register always ends up with its top half set. The
port writes `0xffff0000 | preserve`.

## 3. Exact serdes sequence implemented

`serdes6764_init_2p5g()`:

| # | step | vendor source |
|---|---|---|
| 1 | latch PRTAD 6 into CONTROL[10:6] | `phy_drv_146class_serdes.c:184..188` |
| 2 | power up / down / up (`serdes_access_config`) | `merlin16_shortfin_config.c:1417..1419`, `serdes_access.c:251..306` |
| 3 | XFI Tx + Rx polarity inversion (0xd0e3/0xd0d3 bit 0) | `phy_drv_146class_serdes.c:212..235`, `:414..417` |
| 4 | `host_reg_write(R2PMI_LP_BCAST_MODE_CNTRL=0x01b0, 0)` | `merlin16_shortfin_config.c:147..165` |
| 5 | `serdes_core_reset`: 1.0xd0f1 = 0, 1ms, = 1, 1ms | `:137..145` |
| 6 | mdio_multi_prts_en=0 (0xffdd[15]), brcst_port_addr=6 (0xffdc[4:0]) | `:100..117` |
| 7 | `uc_reset(1)` — 33 register writes, verified byte-for-byte | `merlin_shortfin/src/merlin16_shortfin_config.c:462..523` |
| 8 | ucode load: RAM init x2, 15832 16-bit writes to 0xd206 | `:691..740` |
| 9 | ucode read-back verify, 15832 reads of 0xd20a | `:742..785` |
| 10 | `uc_reset(0)` — start the micro | `:511..521` |
| 11 | wait `uc_active` (0xd0f4[15]) | `:525..538` |
| 12 | ucode CRC via DSC command 20 (`CMD_CALC_CRC`), expect 0x4949 | `access.c:91..96`, `config.c:73..84` |
| 13 | info-table signature check (`"Inf"` at program RAM 0x100) | `config.c:540..614` |
| 14 | **pass 1**, forced 1000Base-X: `restore_regs`, `PMD_setup_80_10p3125_VCO`, `wait_uc_active`, core RAM `vco_rate=19`, `datapath_reset_core`, 1.0xd0a2 en_hpf=0, lane RAM = 0, `force_speed_1g`, PLL lock | `:1119..1374` |
| 15 | `lpi_enable` (3.0xC450[2]) | `:1455` |
| 16 | **pass 2**, forced 2500Base-X: `restore_regs`, `Initialize_12p5_VCO`, `PMD_setup_80_12p5_VCO`, `wait_uc_active`, core RAM `vco_rate=28`, `datapath_reset_core`, en_hpf=0, lane RAM = 0, `force_speed_2p5g`, PLL lock | same function, second call |
| 17 | re-apply XFI polarity (deviation, see §7) | — |

### Why the stock log shows two VCO passes

`merline_speed_set_core()` picks the VCO from the inter-phy type, not the
speed (`merlin16_shortfin_config.c:1153..1155`):

```
vco_12p5g = phy_mode == INTER_PHY_TYPE_1GBASE_X   ||
            phy_mode == INTER_PHY_TYPE_2P5GBASE_X ||
            phy_mode == INTER_PHY_TYPE_2500BASE_X ||
            phy_mode == INTER_PHY_TYPE_5GBASE_X   ||
            phy_mode == INTER_PHY_TYPE_5000BASE_X;
```

* `merlin16_serdes_init()` forces `INTER_PHY_TYPE_1000BASE_X` "to fully
  exercise hardware status" (`:1445..1449`). `1000BASE_X` is **not** in that
  list, so the first pass runs at 10.3125 GHz with `vco_rate = 10.3125*4-22 =
  19`. That is the log's `Config Speed to 2` (`MLN_SPD_FORCE_1G = 0x0002`,
  `phy_drv_merlin16.h:131`) plus `RAM variable vco_rate is 19`.
* The DT's `config-xfi = "2500Base-X"` maps to `INTER_PHY_TYPE_2500BASE_X`
  (`phy_drv_dsl_serdes.c:68..69`), which **is** in the list, so the real
  speed pass runs at 12.5 GHz with `vco_rate = 12.5*4-22 = 28`. That is the
  second `PMD Setup 80MHz, 12.5GHz VCO programming`.

`separate_vco` is a live option in the vendor table
(`merlin16_shortfin_config.c:50..56` returns 1), so the 12.5 GHz path also
programs `Initialize_12p5_VCO` before the PMD setup. `MERLIN_LOAD_FIRMWARE`
and `VERBOSE` are also 1; `ML_C_VCO_10P3125`, `ML_C_VCO_12P5`, `ML_REFCLK_50`
and `ML_REFCLK_400` are not in the table, so they return 0.

### `force-2p5g-10gvco` in the DT does nothing on this SoC

`PhyIsForced2p5g10GVco()` is parsed at `dt_parsing.c:240` and read in exactly
one place in the whole tree:
`Serdes6756Class/merlin28_shortfin_config.c:1797`, the **merlin28** driver for
the 6756/6765/6766 family. The merlin16 / 146-class driver that runs on 6764
never looks at it. So 2500Base-X uses the 12.5 GHz VCO here, which is what the
stock log shows. Nothing in the port acts on that property.

### `restore_regs`

`merlin_reg_prog()` remembers the pre-write value of every register it
touches, de-duplicated by (dev, reg), and `merline_speed_set_core()` restores
them all before the next speed pass (`:238..291`). Faithfully ported,
including the consequence that `lpi_enable` (written after pass 1) is undone
by the restore at the start of pass 2 and never re-applied. That is vendor
behaviour, not a bug in the port.

## 4. Exact external-switch sequence implemented

`extsw6764_init()`:

| # | step | vendor source |
|---|---|---|
| 1 | GPIO 24 out, assert reset 100 ms, release, settle 100 ms | `bcm_ethsw_ext.c:564..571` |
| 2 | read device ID, page 0x02 reg 0x30, 4 bytes | `:258` |
| 3 | software reset: write 0x83 to page 0x00 reg 0x79, poll bit 7 | `:262..265` |
| 4 | wait for all 8 ports to leave rx-disable | `:268..280` |
| 5 | check the `P8_SEL_SGMII` strap, page 0x01 reg 0x70 bit 9 | `:290..298` |
| 6 | disable Rx/Tx on all 8 MAC ports | `:300..305` |
| 7 | unmanaged mode + forwarding + retry-limit-dis; BRCM header off; MII dump forward | `:307..312` |
| 8 | IMP override: sw-override, flow control, 1000, FDX, link pass | `:313..314` |
| 9 | switch serdes: page 0xe6 enable, page 0x14 BLK0/Digital/Digital5 writes → force 2.5G fiber, os2 mode, AN off, PLL sequencer on | `:316..330` |
| 10 | port 5 override 0x004a, IMP override 0x008b (2.5G, FDX, link up) | `:331..332` |
| 11 | per port: PBVLAN = 0x100, NO-STP, Rx/Tx enabled | `:369..387` |
| 12 | GPHYs 0..3: BMCR reset, advertise all + pause + repeater-DTE, clear power-down, restart AN | `phy_drv_mii.c:313`, `:185`, `:64`; `bcm_ethsw_phy.c:114..145` |
| 13 | report port-8 and LAN link from page 0x01 reg 0x00 / 0x04 | `mii_shared.h:294..307` |

All switch register access is a pseudo-PHY transaction at MDIO address 0x1e
(`bcm_ethsw_ext.c:167..251`, `mii_shared.h:355..373`).

### The SoC-side `phy_sgmii_init()` is NOT part of this path

`bcm_ethsw_ext.c:504..516` only runs `phy_sgmii_init()` when the extsw DT node
has a `systemport-serdes-cntrl` resource. The stock 6764 DTB's extsw node has
no such resource (`priv->serdes_cntrl` stays NULL at `:541..545`), so the
whole 2.5G interconnect setup on the switch side is the page 0x14 register
block in step 9 above. `serdesRef50mVco6p25` / `serdesSet2p5GFiber`
(`:395..424`) are dead code on this board and are not ported.

## 5. GPIO block

`brcm,bca-gpio` has no upstream 6.6 driver and the minimal 6764 DTS does not
carry the node yet, so `extsw6764.c` looks the node up first and falls back to
physical addresses only if it is absent:

```
stock DTB   periph { ranges = <0 0 0xff800000 0x400000>; }
            gpioc  { reg = <0x500 0x20 0x520 0x20>;
                     reg-names = "gpio-dir", "gpio-data"; ngpios = <0x62>; }
live        ff800500-ff80051f gpio-dir
            ff800520-ff80053f gpio-data
```

GPIO 24 is bank 0 (`gpio >> 5`), bit 24 (`gpio & 0x1f`) —
`gpio-bcm-bca.c:15..17`. Direction and data are separate banks, both indexed
by bank number, so both accesses are at offset 0 in their window.

Polarity: `switch-reset = <&gpioc 24 1>`, i.e. `GPIO_ACTIVE_LOW`.
`bcm_ethsw_ext.c:567..569` sets the *logical* value 1 for "reset active", so
active means driving the pin **low**; released means high. Live stock shows
gpio-24 "SW reset" out hi, which agrees. Overridable with the
`reset_active_low` module parameter.

Both fallbacks are also module parameters (`gpio_dir_phys`, `gpio_data_phys`).

## 6. Markers

Success `0x80..0x9F`:

| marker | meaning |
|---|---|
| 0x85 | extsw probe entered, GPIO banks mapped |
| 0x80 | external switch reset de-asserted |
| 0x81 | device ID read, non-zero and not 0xffffffff |
| 0x82 | switch software reset completed |
| 0x84 | sw_setup done (unmanaged forwarding + port-8 SGMII 2.5G) |
| 0x83 | ports 0..3 enabled (sw_open) |
| 0x8F | switch port 8 (IMP / SGMII uplink) link up |
| 0x90 | at least one LAN GPHY link seen |
| 0x92 | serdes: brcm,serdes1 + brcm,eth-phy-top mapped |
| 0x88 | serdes core powered, PMD + uC reset toggled |
| 0x89 | ucode written into program RAM |
| 0x8A | ucode read-back verify OK |
| 0x8B | uc_active asserted |
| 0x93 | ucode CRC OK and info-table signature OK |
| 0x8C | core configured (PMD setup, core RAM var, datapath reset core) |
| 0x8D | lane configured, PLL/PMD locked |
| 0x91 | 2500Base-X pass complete |
| 0x8E | serdes reports link up |

Failures `0xC0..0xCF`, one per step:

| marker | meaning |
|---|---|
| 0xC0 | serdes: DT node missing and no phys override, or ioremap failed |
| 0xC1 | serdes indirect-access `start_busy` never cleared |
| 0xC2 | `micro_ra_initdone` poll timeout during ucode load |
| 0xC3 | ucode read-back mismatch |
| 0xC4 | `uc_active` never asserted |
| 0xC5 | `uc_dsc_ready_for_cmd` timeout, or `uc_dsc_error_found` set |
| 0xC6 | ucode CRC mismatch, or bad info-table signature |
| 0xC7 | PLL lock timeout |
| 0xC8 | serdes link never came up |
| 0xC9 | GPIO block map / DT failure |
| 0xCA | switch device ID 0x0 or 0xffffffff |
| 0xCB | switch software reset never cleared |
| 0xCC | pseudo-PHY op timeout |
| 0xCD | a switch port never left rx-disable |
| 0xCE | `P8_SEL_SGMII` strap disagrees with the configured interconnect (logged, not fatal — matches the vendor, which only warns) |
| 0xCF | neither port-8 nor any LAN port came up |

Note 0x8D is emitted at the end of **both** speed passes, so on a healthy boot
the order is `…0x8C 0x8D` (1 G exercise pass) then `0x8C 0x8D 0x91` (2.5 G
pass). If it stops at the first `0x8D`, pass 2 is where it died.

Every register poll, MDIO poll and PHY poll has a bounded iteration count and
returns an error; there is no unbounded spin anywhere. Where the vendor spins
forever (`sw_hw_ready`, the software-reset wait) the port bounds it at ~1 s.

## 7. Deviations from the vendor, and why

1. **Polarity is re-applied after the 2.5 G pass.** In the vendor flow
   `phy_serdes_polarity_config()` runs once, right after
   `merlin16_serdes_init()` returns (`phy_drv_146class_serdes.c:414..417`),
   and is then followed by a *second* full init whose
   `serdes_access_config()` power cycle plausibly clears 0xd0e3/0xd0d3 again;
   it is never written after the final speed set. The board needs both pairs
   inverted, so the port writes them last as well. The writes are idempotent.
   Turn the inversions off entirely with `tx_polarity_inverse=0
   rx_polarity_inverse=0`.
2. **`merlin16_serdes_init()` runs once, not twice.** The vendor calls it
   from `phy_dsl_serdes_init()` → `dsl_serdes_power_set(1)` →
   `merlin_core_power_op()` and then again directly at
   `phy_drv_146class_serdes.c:193`, so on stock the firmware is loaded and
   the 1 G pass runs twice. That is driver-model ordering, not a documented
   hardware requirement, and it costs ~0.7 s. If the single init does not
   work on hardware, `insmod serdes6764.ko double_init=1` reproduces the
   vendor's exact double init.
3. **`start_busy` is actually checked.** The vendor's
   `serdes_indirect_access_control_status()` (`serdes_access_6764.h:157..160`)
   is a stub that always returns 0, even though the error message it guards
   prints `busy=%d`. The port polls the bit for 1 ms and fails with marker
   0xC1. `strict_busy=0` restores the vendor's ignore-it behaviour if the
   check misfires.
4. **`fatal_log()` / `BUG()` replaced by error returns.** The vendor calls
   `BUG()` on a failed `uc_active` or PLL lock. Here every such path returns
   an errno and emits a failure marker.
5. **The register-table interpreter is trimmed.** Only `SEQ_TYPE_REG`,
   `SEQ_TYPE_NEST_SEQ` and the one function callback used by the tables on
   this path (`merlin_chk_pll_lock`) are implemented; the `timeout_100ns`
   string special-case and the generic 0–4 argument function dispatch are
   not, because no table on this path uses them.
6. **`en_datapath_reset_lane` is not ported.** It belongs to
   `phy_drv_shortfin.c`, not to the 146-class path.

## 8. Not verified, and how to check

* **Nothing has been on hardware.** Everything below is read from the vendor
  source and the stock DTB; the only thing actually demonstrated is that the
  modules compile clean and their symbols resolve.
* **The RAM-variable writes may be no-ops.** `merlin_cfg_core_ram_var()` and
  `merlin_cfg_lane_ram_var()` write only `micro_ra_wrdata_lsw` (0xd206), while
  the ucode load left the RAM interface in 32-bit auto-increment mode
  (`wrdatasize = 2`), where a word normally commits on writing the *msw*
  register (0xd207). The vendor does exactly this and its link works, so the
  port mirrors it rather than "fixing" it. To check on hardware: read back
  program RAM at `0x20000200` / `0x20000300` after the 2.5 G pass and see
  whether `vco_rate` really is 28.
* **`sd_acc_wait()` polling `start_busy` is an assumption.** The vendor never
  reads that bit. If the hardware does not self-clear it, every access will
  log marker 0xC1 — set `strict_busy=0` and the port behaves exactly like the
  vendor (fixed 10 µs settle, no check).
* **The 12 µs / 20 µs / 100 ms delays in `merlin_wait_uc_active()`** are
  copied from `timeout_ns(12000)` / `timeout_ns(20000)` / `msleep(100)`; the
  vendor's `timeout_ns()` (`phy_drv_merlin16.h:46..54`) treats its argument as
  nanoseconds, so `timeout_ns(12000)` is 12 µs, not 12 ms. Read that way the
  comment in the vendor source ("wait 50us comclks") does not match its own
  code; the code was followed, not the comment.
* **Whether the external GPHYs need more than `mii_init`.** The vendor kernel
  runs `phy_drv_egphy.c:471..495`, which also does an AFE workaround
  (`_phy_afe`), auto-MDIX force and wirespeed enable via Broadcom shadow
  registers. Those are 53134-internal PHY tweaks that are not needed to get a
  link and are not ported. If a LAN port links but has a high error rate,
  that is the first thing to add.
* **`REG_SPDSTS` decoding for a 2.5G-capable port.** `mii_shared.h:294..307`
  has both a 2-bit-per-port `REG_SPDSTS` (0x04) and a 3-bit-per-port
  `REG_NEW_SPDSTS` (0x94) "for 6756, 6765". Which one the 53134 populates is
  unverified; the port reads the classic one, and it only affects a log line.
* **The `EN_SW_RST` constant is unused on purpose.** The vendor writes the
  literal `0x83` at `bcm_ethsw_ext.c:262`, which is
  `SOFTWARE_RESET | 0x03`, not `SOFTWARE_RESET | EN_SW_RST`. The commented-out
  code just above it would have written `EN_SW_RST`. The literal was kept.
* **`sw_hw_ready()` before `sw_setup()`.** The vendor waits for the hardware
  to enable the ports in `extsw_probe()`, then disables them all again in
  `sw_setup()`, then re-enables them in `sw_open()`. Looks redundant;
  reproduced as-is.
* **`bcm96764_mark()` re-entrancy.** The marker channel is a single 8-bit
  field in the reset-reason register, so a marker emitted by the other agent's
  SoC driver at the same time will overwrite ours. Load the modules
  sequentially, not in parallel.

## 9. Build

```
make -C kernel-6.6/src/linux-6.6.93 \
     O=kernel-6.6/build \
     M=port66/enet66b ARCH=arm \
     CROSS_COMPILE=gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi- \
     modules
```

or just `make` in this directory, which wraps exactly that. Result:
`serdes6764.ko`, `extsw6764.ko`, `enet66b_mdio.ko`. Builds clean with
`KBUILD_EXTRA_WARN=1`.

Once `port66/enet66` exports `sf2_mdio_read()` / `sf2_mdio_write()`:

```
make ENET66B_STANDALONE_MDIO=0 \
     KBUILD_EXTRA_SYMBOLS=port66/enet66/Module.symvers
```

`enet66b_mdio.ko` is then neither built nor needed. Without the extra symbols
file modpost fails on those two symbols, which is the intended signal that
the SoC driver does not export them yet.

Regenerating the microcode header (only needed if the GPL tree moves):
`make ucode`, or `./gen_ucode.sh`. It re-emits the array literal from
`Serdes146Class/merlin16_shortfin_ucode_image.h`
(md5 `873e6087672041dba75d2006384340d5`, byte-identical to the copy under
`merlin_shortfin/`) — nothing is hand-typed, and the generated file records
the md5 it came from.

## 10. Insmod order

```
1. pmc            (enet66)  power up the switch / serdes domains
2. sf2 + gphy     (enet66)  SF2 core, MDIO master, internal GPHY
3. enet66b_mdio             only while enet66 does not export sf2_mdio_*
4. serdes6764               core 0 lane 0 -> 2500Base-X   (markers 0x92,0x88..0x8E)
5. extsw6764                BCM53134 behind it            (markers 0x85,0x80..0x90)
6. sysport open   (enet66)  bring the netdev up, then test with a cable on LAN2
```

Serdes before switch: the switch's port 8 is the far end of the 2.5 G link, so
the SoC side has to be transmitting before the 53134's serdes is asked to
lock. The reverse order also works in principle because both ends are forced
rather than auto-negotiated, but this is the order the vendor uses
(`phy_drv_146class_serdes` init runs from the enet driver's PHY init, ahead of
`bcm_ethsw_ext_open`).

If `enet66` already provides the SF2 MDIO master, skip step 3 and rebuild with
`ENET66B_STANDALONE_MDIO=0`.

Both modules auto-run their bring-up at load (`autoinit=1`); pass
`autoinit=0` to load them inert and call `serdes6764_init_2p5g()` /
`extsw6764_init()` from the SoC driver instead. Both stay loaded even when the
bring-up fails, so the register state can be inspected afterwards.

Useful parameters while bisecting on the device:

```
serdes6764.ko  serdes_base_phys=0x80282000 ethtop_base_phys=0x80280000
               strict_busy=0 acc_delay_us=10 double_init=1 autoinit=0
extsw6764.ko   gpio_dir_phys=0xff800500 gpio_data_phys=0xff800520
               reset_gpio=24 reset_active_low=1 ext_sw_sgmii=6 autoinit=0
enet66b_mdio.ko mdio_base_phys=0x80286000 clock_divider=12
```

The `*_phys` parameters are only consulted when the matching DT node is
absent, so they are safe to leave set once the DT grows the nodes.
