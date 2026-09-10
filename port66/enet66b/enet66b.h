/* SPDX-License-Identifier: GPL-2.0 */
/*
 * enet66b - LAN-side link bring-up for the Broadcom BCM6764 (Cudy WR3600)
 *           ported from the vendor U-Boot 2019.07 GPL sources.
 *
 * This header declares (a) the MDIO API the serdes / external-switch modules
 * need from the SoC-side driver and (b) the stage-marker channel.
 *
 * MDIO transport
 * --------------
 * All MDIO on this SoC goes through the SF2 MDIO window (DT "brcm,mdio-sf2",
 * reg <0x286000 0x10> under ubus-bus => phys 0x80286000).  Register layout,
 * from drivers/net/bcmbca/bcm_ethsw.h:51..62 and
 * drivers/net/bcmbca/phy/mdio_drv_common.c:50..73 :
 *
 *   +0x00 mdio_cmd:  [15:0] data/addr, [20:16] reg/dev addr,
 *                    [25:21] phy/port addr, [27:26] opcode,
 *                    [28] fail, [29] busy
 *   +0x04 mdio_cfg:  [0] clause (0 = c45, 1 = c22), [11:4] clk divider,
 *                    [12] suppress preamble, [13] free-run clk enable
 *
 * c22 opcodes: 1 = write, 2 = read.
 * c45 opcodes: 0 = address, 1 = write, 2 = read-inc, 3 = read.
 *
 * The SoC-side driver (port66/enet66) is expected to export these four
 * symbols.  Until it does, build with ENET66B_STANDALONE_MDIO (the default
 * in Kbuild) and enet66b_mdio.ko provides them from sf2_mdio_local.c.
 */

#ifndef _ENET66B_H_
#define _ENET66B_H_

#include <linux/types.h>

/* ---------------------------------------------------------------- MDIO -- */

/*
 * Clause-22 access.  Returns the 16-bit value (0..0xffff) on success,
 * negative errno on bus error / timeout.
 */
int sf2_mdio_read(int phy_addr, int reg);
int sf2_mdio_write(int phy_addr, int reg, u16 val);

/*
 * Clause-45 access.  prtad = port address, devad = MMD device address.
 * Returns the 16-bit value on success, negative errno otherwise.
 *
 * Not used by the current bring-up path: the Merlin16 serdes is reached
 * through the memory-mapped indirect-access window, not over MDIO (see
 * serdes6764.c).  Declared because the API contract asked for it.
 */
int sf2_mdio_c45_read(int prtad, int devad, u16 reg);
int sf2_mdio_c45_write(int prtad, int devad, u16 reg, u16 val);

/* ------------------------------------------------------------- markers -- */

/*
 * 8-bit stage marker channel exported by arch/arm/mach-bcm/bcm96764.c.
 * Survives a watchdog reset; the values below are the enet66b map.
 */
extern void bcm96764_mark(u8 stage);

/* success path, 0x80..0x9f */
#define E66B_MK_EXTSW_PROBE		0x85	/* extsw probe entered, GPIO mapped   */
#define E66B_MK_EXTSW_RESET_OFF		0x80	/* switch reset de-asserted           */
#define E66B_MK_EXTSW_ID		0x81	/* device ID read, sane               */
#define E66B_MK_EXTSW_SWRESET		0x82	/* software reset completed           */
#define E66B_MK_EXTSW_SETUP		0x84	/* unmanaged fwd + port-8 SGMII 2.5G  */
#define E66B_MK_EXTSW_PORTS		0x83	/* ports 0..3 enabled                 */
#define E66B_MK_EXTSW_P8_LINK		0x8F	/* switch port 8 (IMP) link up        */
#define E66B_MK_EXTSW_GPHY_LINK		0x90	/* at least one LAN GPHY link seen    */

#define E66B_MK_SD_PROBE		0x92	/* serdes probe: regs mapped          */
#define E66B_MK_SD_CORE_RESET		0x88	/* core powered, PMD+uC reset toggled */
#define E66B_MK_SD_UCODE_LOADED		0x89	/* ucode written to program RAM       */
#define E66B_MK_SD_UCODE_VERIFIED	0x8A	/* ucode read-back matches            */
#define E66B_MK_SD_UC_ACTIVE		0x8B	/* uc_active + micro ready for cmd    */
#define E66B_MK_SD_UCODE_CRC		0x93	/* ucode CRC + info table signature   */
#define E66B_MK_SD_CORE_CFG		0x8C	/* core configured (1G exercise pass) */
#define E66B_MK_SD_LANE_CFG		0x8D	/* lane configured, PLL/PMD locked    */
#define E66B_MK_SD_2P5G			0x91	/* 2500Base-X pass complete           */
#define E66B_MK_SD_LINK			0x8E	/* serdes reports link up             */

/* failure path, 0xc0..0xcf */
#define E66B_MK_ERR_SD_MAP		0xC0	/* DT node missing / ioremap failed   */
#define E66B_MK_ERR_SD_ACC		0xC1	/* indirect-access start_busy stuck   */
#define E66B_MK_ERR_SD_UCODE_LOAD	0xC2	/* micro_ra_initdone poll timeout     */
#define E66B_MK_ERR_SD_UCODE_VERIFY	0xC3	/* ucode read-back mismatch           */
#define E66B_MK_ERR_SD_UC_ACTIVE	0xC4	/* uc_active timeout                  */
#define E66B_MK_ERR_SD_DSC		0xC5	/* uc_dsc not ready / dsc error       */
#define E66B_MK_ERR_SD_CRC		0xC6	/* ucode CRC / info table bad         */
#define E66B_MK_ERR_SD_PLL		0xC7	/* PLL lock timeout                   */
#define E66B_MK_ERR_SD_LINK		0xC8	/* serdes link never came up          */

#define E66B_MK_ERR_EXTSW_GPIO		0xC9	/* GPIO block map / DT failure        */
#define E66B_MK_ERR_EXTSW_ID		0xCA	/* device ID 0x0 or 0xffffffff        */
#define E66B_MK_ERR_EXTSW_SWRESET	0xCB	/* software reset never cleared       */
#define E66B_MK_ERR_EXTSW_PSEUDO	0xCC	/* pseudo-PHY op timeout              */
#define E66B_MK_ERR_EXTSW_HWREADY	0xCD	/* port rx-enable wait timeout        */
#define E66B_MK_ERR_EXTSW_STRAP		0xCE	/* P8_SEL_SGMII strap mismatch (warn) */
#define E66B_MK_ERR_EXTSW_LINK		0xCF	/* no port-8 / LAN link seen          */

/* --------------------------------------------------------- module API --- */

/*
 * serdes6764.ko
 *  serdes6764_init_2p5g() runs the full Merlin16 bring-up for core 0 lane 0
 *  and leaves the lane in forced 2500Base-X.  Idempotent-ish: a second call
 *  redoes the speed pass only.
 *  serdes6764_link_up() returns 1 when the PCS reports link, 0 when not,
 *  negative errno on a bus error.
 */
int serdes6764_init_2p5g(void);
int serdes6764_link_up(void);

/*
 * extsw6764.ko
 *  extsw6764_init() lifts the BCM53134 out of reset, identifies it, software
 *  resets it, configures port 8 for 2.5G SGMII, enables ports 0..3 in
 *  unmanaged forwarding mode and powers up the four LAN GPHYs.
 */
int extsw6764_init(void);

#endif /* _ENET66B_H_ */
