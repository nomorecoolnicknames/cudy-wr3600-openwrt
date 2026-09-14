/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Broadcom BCM6764 (Cudy WR3600) Ethernet bring-up driver for Linux 6.6.
 *
 * Shared definitions for the three compilation units of enet6764.ko:
 *   pmc6764.c    - PMC / PMB keyhole + BPCM power-up of the switch block
 *   sf2_6764.c   - SF2 switch core, MDIO bus, internal EGPHY power-up
 *   sysport6764.c- SYSTEMPORT v2.1 MAC + netdev, and the module entry point
 *
 * Every non-obvious register value below carries the reference it came from.
 * Reference roots (vendor GPL, known to work on this exact board):
 *   UB  = gpl/openwrt/21.02/package/extra/bcm/src/bcm-bootloader/bootloaders/
 *         u-boot-2019.07/
 *   KD  = gpl/openwrt/21.02/package/extra/bcm/src/bcmdrivers/opensource/
 *
 * ---------------------------------------------------------------------------
 * STAGE MARKER MAP  (bcm96764_mark(), arch/arm/mach-bcm/bcm96764.c)
 * ---------------------------------------------------------------------------
 * Success path (0x60..0x6F), each written once, in this order:
 *   0x60  pmc probe done: "procmon" window mapped, PMB config register sane
 *   0x61  switch block powered: BPCM zone status pwr_on_state read back as 1
 *   0x62  SF2 software reset completed (SOFTWARE_RESET bit self-cleared)
 *   0x63  SF2 register file sane: switch_mode read back with FORWARDING_EN set
 *   0x64  internal EGPHY powered: sphy-ctrl shows RESET clear + PHYAD == 8
 *   0x65  MDIO read of PHY 8 ID1 returned a plausible ID (not 0x0000/0xffff)
 *   0x66  switch ports enabled (PBVLAN = CPU-only, port state = NO_STP)
 *   0x67  sysport init done: RDMA and TDMA both reported ready
 *   0x68  netdev "eth0" registered
 *   0x69  first TX descriptor consumed by hardware
 *   0x6A  first RX packet handed to the stack
 *
 * Failure path (0xE0..0xED, 0xEF -- 0xEE is taken by the kernel panic hook):
 *   0xE0  pmc: "procmon" resource missing or ioremap failed
 *   0xE1  pmc: PMB config register reads as all-zero / all-ones
 *   0xE2  pmc: PMB keyhole transaction timed out or reported bus timeout
 *   0xE3  pmc: switch BPCM zone never reported pwr_on_state
 *   0xE4  sf2: a reg resource is missing or ioremap failed
 *   0xE5  sf2: SOFTWARE_RESET never self-cleared
 *   0xE6  sf2: switch core register file stuck at 0x00000000 / 0xffffffff
 *   0xE7  sf2: MDIO command stayed BUSY
 *   0xE8  sf2: PHY ID1 read back as 0x0000 or 0xffff
 *   0xE9  sysport: a reg resource is missing or ioremap failed
 *   0xEA  sysport: DMA buffer allocation failed / not addressable in 32 bits
 *   0xEB  sysport: RDMA did not come out of reset
 *   0xEC  sysport: TDMA did not come out of reset
 *   0xED  sysport: register_netdev() failed
 *   0xEF  sysport: TX descriptor was never consumed (runtime, non-fatal)
 */

#ifndef _ENET6764_H
#define _ENET6764_H

#include <linux/device.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/types.h>

/* Exported by the platform code, arch/arm/mach-bcm/bcm96764.c. Writes an
 * 8-bit "last stage reached" code to a register that survives reset. This is
 * the only observability channel on this board -- it has no UART.
 */
extern void bcm96764_mark(u8 stage);

/* ------------------------------------------------------------------ */
/* stage markers                                                      */
/* ------------------------------------------------------------------ */
#define MK_PMC_PROBE		0x60
#define MK_SWITCH_POWERED	0x61
#define MK_SF2_RESET		0x62
#define MK_SF2_SANE		0x63
#define MK_GPHY_POWERED		0x64
#define MK_PHYID_OK		0x65
#define MK_PORTS_ENABLED	0x66
#define MK_SYSPORT_INIT		0x67
#define MK_NETDEV_OK		0x68
#define MK_FIRST_TX		0x69
#define MK_FIRST_RX		0x6A

#define MK_ERR_PMC_MAP		0xE0
#define MK_ERR_PMC_CONFIG	0xE1
#define MK_ERR_PMC_KEYHOLE	0xE2
#define MK_ERR_PMC_ZONE		0xE3
#define MK_ERR_SF2_MAP		0xE4
#define MK_ERR_SF2_RESET	0xE5
#define MK_ERR_SF2_STUCK	0xE6
#define MK_ERR_MDIO		0xE7
#define MK_ERR_PHYID		0xE8
#define MK_ERR_SP_MAP		0xE9
#define MK_ERR_SP_DMA		0xEA
#define MK_ERR_RDMA		0xEB
#define MK_ERR_TDMA		0xEC
#define MK_ERR_NETDEV		0xED
#define MK_ERR_TX_STUCK		0xEF

/* ================================================================== */
/* PMC / PMB / BPCM                                                    */
/* ================================================================== */

/*
 * BCM6764 uses PMC_IMPL_3_X (KD/misc/pmc/impl1/6764/pmc_drv_cfg.h:38), which
 * means every BPCM access goes through a "keyhole" in the procmon block --
 * NOT through the older per-bus PMBM window.
 *
 * struct Procmon (KD/misc/pmc/impl1/6764/pmc.h:315-321):
 *   PmmReg pmm            @ 0x000
 *   uint32 unused11[22]   @ 0x008
 *   SSBMaster ssb         @ 0x060
 *   uint32 unused12[36]   @ 0x070
 *   PmbBus pmb            @ 0x100
 * struct PmbBus (pmc.h:205-215):
 *   config  @ 0x100, arbiter @ 0x104, timeout @ 0x108, unused @ 0x10c,
 *   keyhole[4] @ 0x110..0x14f
 * struct keyholeReg (pmc.h:191-203):
 *   control @ +0x0, wr_data @ +0x4, mutex @ +0x8, rd_data @ +0xc
 */
#define PMB_BASE		0x100
#define PMB_CONFIG		(PMB_BASE + 0x00)
#define PMB_KEYHOLE(i)		(PMB_BASE + 0x10 + (i) * 0x10)
#define KH_CONTROL		0x00
#define KH_WR_DATA		0x04
#define KH_MUTEX		0x08
#define KH_RD_DATA		0x0c

/* keyhole control bits, pmc.h:193-199 */
#define PMC_PMBM_START		(1u << 31)
#define PMC_PMBM_TIMEOUT	(1u << 30)
#define PMC_PMBM_SLAVE_ERR	(1u << 29)
#define PMC_PMBM_BUSY		(1u << 28)
#define PMC_PMBM_BUS_SHIFT	20
#define PMC_PMBM_READ		(0u << 24)
#define PMC_PMBM_WRITE		(1u << 24)

/* pmc.h:207-208 -- register-stride field inside PmbBus.config */
#define PMB_NUM_REGS_SHIFT	20
#define PMB_NUM_REGS_MASK	0x3ff

/* KD/misc/pmc/impl1/6764/pmc_addr.h:38,68-73 */
#define PMB_BUS_ID_SHIFT	12
#define PMB_ADDR_SWITCH		(8 | (0 << PMB_BUS_ID_SHIFT))	/* == PMB_ADDR_CNP */
#define PMB_ZONES_SWITCH	4

/*
 * WLAN BPCMs, KD/misc/pmc/impl1/6764/pmc_addr.h:75-81 (GPL copy
 * bcm-bootloader/bootloaders/armtf/plat/bcm/include/pmc_addr_6764.h):
 *   PMB_ADDR_WLAN0 = 9  on PMB bus 1, one zone
 *   PMB_ADDR_WLAN1 = 10 on PMB bus 1, one zone
 * 6764 defines no WLANx_PHYn BPCMs (the -1 defaults in pmc_wlan.c apply), so
 * a WLAN unit is exactly one BPCM.
 */
#define PMB_ADDR_WLAN0		(9  | (1 << PMB_BUS_ID_SHIFT))
#define PMB_ADDR_WLAN1		(10 | (1 << PMB_BUS_ID_SHIFT))
#define PMB_ZONES_WLAN		1

/*
 * BPCM register word offsets. struct BPCM_REGS, KD/misc/pmc/impl1/6764/BPCM.h
 * :508-521, addressed in 32-bit words (BPCMRegOffset() = byte offset >> 2):
 *   id_reg 0, capabilities 1, link_address 2, rsvd 3, dpg_zones 4,
 *   sr_control 5, rsvd 6..7, client_specific 8..31, zones[] from word 32.
 * struct BPCM_ZONE (BPCM.h:412-420) is 8 words:
 *   control +0, config1 +1, config2 +2, status +3, timer_control +4, ...
 */
#define BPCM_W_CAPABILITIES	1
#define BPCM_W_SR_CONTROL	5
#define BPCM_W_ZONE(z)		(32 + (z) * 8)
#define BPCM_W_ZONE_CTRL(z)	(BPCM_W_ZONE(z) + 0)
#define BPCM_W_ZONE_STATUS(z)	(BPCM_W_ZONE(z) + 3)

/* BPCM_CAPABILITES_REG, BPCM.h:80-90 */
#define BPCM_CAP_NUM_ZONES_MASK	0x7f

/* BPCM_PWR_ZONE_N_CONTROL bits, BPCM.h:336-358 */
#define ZONE_CTRL_DPG_CTL_EN	(1u << 8)
#define ZONE_CTRL_PWR_DN_REQ	(1u << 9)
#define ZONE_CTRL_PWR_UP_REQ	(1u << 10)
#define ZONE_CTRL_MEM_PWR_CTL_EN (1u << 11)
#define ZONE_CTRL_BLK_RESET_ASSERT (1u << 12)

/* BPCM_PWR_ZONE_N_STATUS bits, BPCM.h:390-410 */
#define ZONE_STS_PWR_ON_STATE	(1u << 15)

/* pmc_switch.c:130-146 (U-Boot copy, guarded by IS_BCMCHIP(6764)):
 * the SYSTEMPORT sits on zone 3 of the switch BPCM; its soft reset is
 * sr_control bit 3, pulsed high then low.
 */
#define BPCM_SR_SYSPORT_BIT	(1u << 3)

int pmc6764_read_bpcm(int dev_addr, int word, u32 *val);
int pmc6764_write_bpcm(int dev_addr, int word, u32 val);
int pmc6764_switch_power_up(void);
int pmc6764_wlan_power_up(int unit);
int pmc6764_wlan_power_down(int unit);
int pmc6764_sysport_reset(void);
bool pmc6764_ready(void);

/* ================================================================== */
/* SF2 switch core                                                     */
/* ================================================================== */

/*
 * Byte offsets inside the "switchcore-base" window (DT: 0x200000 len 0x72724,
 * physical 0x80200000). Verified against struct EthernetSwitchCore in
 * port66/ethsw.h; the struct is laid out for SF2_REG_SHIFT == 2, i.e. one
 * 53xx-style register slot is 8 bytes wide (mac_drv_sf2.c:41-46).
 *
 *  port_traffic_ctrl[9] u64  ethsw.h:178   -> 0x00000, stride 8
 *  switch_mode          u32  ethsw.h:184   -> 0x00058  (page 0 reg 0x0b)
 *  switch_ctrl          u32  ethsw.h:189   -> 0x00110
 *  software_reset       u64  ethsw.h:218   -> 0x003c8  (page 0 reg 0x79,
 *                                             matches SOFTWARE_RESET_CTRL
 *                                             in mii_shared.h:240)
 *  brcm_hdr_ctrl        u32  ethsw.h:287   -> 0x01018  (page 2 reg 3)
 *  port_vlan_ctrl[36]   u32  ethsw.h:2111  -> 0x18800, 4 words per port
 *  imp_port_state       u32  ethsw.h:4581  -> 0x72080
 */
#define SF2_PORT_TRAFFIC_CTRL(i)	(0x00000 + (i) * 8)
#define SF2_SWITCH_MODE			0x00058
#define SF2_SWITCH_CTRL			0x00110
#define SF2_SOFTWARE_RESET		0x003c8
#define SF2_BRCM_HDR_CTRL		0x01018
#define SF2_PORT_VLAN_CTRL(i)		(0x18800 + (i) * 16)
#define SF2_IMP_PORT_STATE		0x72080

/* "switchreg-base" window (DT: 0x274000 len 0x20). The upper half of a
 * >32-bit switch register is staged here: write hi first then lo to the
 * register, read lo from the register then hi from here.
 * mac_drv_sf2.c:39-40, 205-207, 229-247.
 */
#define SF2_DIRECT_DATA_WR		0x08
#define SF2_DIRECT_DATA_RD		0x0c

/* mii_shared.h:229-242 */
#define PORT_CTRL_PORT_STATUS_S		5
#define PORT_CTRL_PORT_STATUS_M		(7 << PORT_CTRL_PORT_STATUS_S)
#define PORT_CTRL_NO_STP		(0 << PORT_CTRL_PORT_STATUS_S)
#define PORT_CTRL_SWITCH_RESERVE	(7 << 2)
#define PORT_CTRL_TX_DISABLE		0x2
#define PORT_CTRL_RX_DISABLE		0x1
#define PORT_CTRL_RXTX_DISABLE		(PORT_CTRL_TX_DISABLE | PORT_CTRL_RX_DISABLE)
#define SF2_SOFTWARE_RESET_BIT		(1 << 7)	/* SOFTWARE_RESET */
#define SF2_EN_SW_RST			(1 << 4)	/* EN_SW_RST */

/* ethsw.h:181-183, 190-191 */
#define ETHSW_SM_RETRY_LIMIT_DIS	0x04
#define ETHSW_SM_FORWARDING_EN		0x02
#define ETHSW_SM_MANAGED_MODE		0x01
#define ETHSW_SC_MII_DUMP_FORWARDING_EN	0x40
#define ETHSW_SC_MII2_VOL_SEL		0x02

/* ethsw.h:4582-4597 */
#define ETHSW_IPS_XGMII_MODE		0x100
#define ETHSW_IPS_USE_REG_CONTENTS	0x80
#define ETHSW_IPS_SW_PORT_SPEED_10G	0x40
#define ETHSW_IPS_TXFLOW_PAUSE_CAPABLE	0x20
#define ETHSW_IPS_RXFLOW_PAUSE_CAPABLE	0x10
#define ETHSW_IPS_DUPLEX_MODE		0x02
#define ETHSW_IPS_LINK_PASS		0x01

/* ethsw.h:4659 -- port-based VLAN bitmap that permits CPU traffic only */
#define PBMAP_MIPS			0x100

/* bcm_ethsw_impl1.c:21 -- the init/open loops cover ports 0..7 (the IMP port
 * is port 8 and is configured through imp_port_state instead).
 */
#define SF2_MAX_PORTS			8
#define SF2_IMP_PORT			8
#define PORT_CTRL_IMP_RX_ALL_EN		0x1c	/* RX_UCST_EN|RX_MCST_EN|RX_BCST_EN */

/* ================================================================== */
/* SF2 WAN/LAN split (triaging/shim/sf2-vlan/REPORT.md)                */
/* ================================================================== */

/*
 * The stock firmware separates WAN from LAN with three switch registers,
 * programmed by ethswctl (SIOCSWANPORT -> port_sw_port_role_set(),
 * impl7/sw_common.c:1551):
 *   WAN_PORT_SEL  (page0 0x26 -> core 0x130): bit set = port has WAN role
 *                 (frames to/from it go only through the IMP); bit 9 is
 *                 EN_MAN_TO_WAN (bcmmii.h:299) so the CPU may transmit to it
 *   DIS_LEARN     (page0 0x3c -> core 0x1e0): learning-off bitmap, same bits
 *   BRCM_HDR_RX_DIS/TX_DIS (page2 0x60/0x62 -> core 0x1300/0x1310): a
 *                 cleared port bit enables the in-band Broadcom tag in that
 *                 direction (b53_common.c:566-622)
 * Stock dump (obs/stock-regdump-2026-09-07.txt): DIS_LEARN = 0x01 (WAN P0).
 */
#define SF2_WAN_PORT_SEL		0x00130
#define SF2_EN_MAN_TO_WAN		(1u << 9)
#define SF2_BRCM_HDR_RX_DIS		0x01300
#define SF2_BRCM_HDR_TX_DIS		0x01310
#define SF2_BRCM_HDR_PORTS_MASK		0x1ff

/* Root SF2 ports of the split map.  Defaults are the WR3600 (R77) wiring:
 * WAN is the internal GPHY (P0), LAN is the serdes port feeding the external
 * 53134 (P5).  The WR3600H (R69) disables the internal GPHY and puts its
 * 2.5G WAN on port_sgmii1 (P6, serdes core 1 -> external cascade PHY), so the
 * WAN port is a module parameter; LAN is the same P5 on both boards. */
#define SP_SPLIT_WAN_PORT_DEFAULT	0
#define SP_SPLIT_LAN_PORT		5
extern unsigned int enet6764_wan_port;
#define SP_SPLIT_WAN_PORT		enet6764_wan_port
#define SP_MAX_NETDEVS			2

enum sp_role {
	SP_ROLE_LAN = 0,
	SP_ROLE_WAN,
};

/* 4-byte in-band Broadcom tag after DA+SA. Egress (CPU->switch) is
 * "20 00 <map>" (opcode 1 = directed egress). The ingress encoding must be
 * confirmed on hardware with rx_diag (risk R1); both candidates are decoded:
 *   b53    byte0[7:5] == 0, byte3[4:0] == source port number
 *   type2  byte0..1 == 0x888a, byte2..3 == source-port bitmap (hypothesis)
 */
#define SP_TAG_LEN			4
#define SP_TAG_EGRESS_OPCODE		0x20
#define SP_TAG_SRC_PORT_MASK		0x1f
#define SP_TAG_TYPE2_HI			0x88
#define SP_TAG_TYPE2_LO			0x8a

enum sp_tag_fmt {
	SP_TAG_FMT_B53 = 1,
	SP_TAG_FMT_TYPE2 = 2,
};

/* module parameters owned by sysport6764.c, read by sf2_6764.c */
extern int enet6764_split;
extern unsigned int enet6764_wan_port_sel;

/* ================================================================== */
/* MDIO (the "switchmdio-base" window, DT: 0x286000 len 0x10)          */
/* ================================================================== */

/* struct sw_mdio, UB/drivers/net/bcmbca/bcm_ethsw.h:63-67 */
#define SF2_MDIO_CMD			0x00
#define SF2_MDIO_CFG			0x04

/* bcm_ethsw.h:51-62 */
#define ETHSW_MDIO_BUSY			(1 << 29)
#define ETHSW_MDIO_FAIL			(1 << 28)
#define ETHSW_MDIO_CMD_SHIFT		26
#define ETHSW_MDIO_CMD_C22_READ		2
#define ETHSW_MDIO_CMD_C22_WRITE	1
#define ETHSW_MDIO_C22_PHY_ADDR_SHIFT	21
#define ETHSW_MDIO_C22_PHY_ADDR_MASK	(0x1f << ETHSW_MDIO_C22_PHY_ADDR_SHIFT)
#define ETHSW_MDIO_C22_PHY_REG_SHIFT	16
#define ETHSW_MDIO_C22_PHY_REG_MASK	(0x1f << ETHSW_MDIO_C22_PHY_REG_SHIFT)
#define ETHSW_MDIO_PHY_DATA_MASK	0xffff

/* Clause-45 on the same controller (vendor mdio_drv_common.c:50-65): the CFG
 * register selects the clause (bit0: 0 = clause 45, 1 = clause 22) and a C45
 * access is two commands - an ADDRESS phase carrying the register number in
 * the data field, then READ/WRITE.  The device address goes where C22 puts
 * the register number (bits 20:16).  Needed for the WR3600H cascade PHY. */
#define ETHSW_MDIO_CFG_CLAUSE22		(1u << 0)
#define ETHSW_MDIO_CMD_C45_ADDRESS	0
#define ETHSW_MDIO_CMD_C45_WRITE	1
#define ETHSW_MDIO_CMD_C45_READ		3
#define ETHSW_MDIO_C45_DEV_SHIFT	ETHSW_MDIO_C22_PHY_REG_SHIFT
#define BCM_PHY_ID_M			0x1f

/* ================================================================== */
/* Internal single GPHY control ("sphy-ctrl", DT: 0x281024 len 4)      */
/* ================================================================== */

/* arch-bcm6764/ethsw.h:110-123 (copy at port66/ethsw.h) */
#define ETHSW_SPHY_CTRL_IDDQ_BIAS	(1u << 0)
#define ETHSW_SPHY_CTRL_EXT_PWR_DOWN	(1u << 1)
#define ETHSW_SPHY_CTRL_IDDQ_GLOBAL_PWR	(1u << 3)
#define ETHSW_SPHY_CTRL_RESET		(1u << 5)
#define ETHSW_SPHY_CTRL_PHYAD_SHIFT	8
#define ETHSW_SPHY_CTRL_PHYAD_MASK	(0x1fu << ETHSW_SPHY_CTRL_PHYAD_SHIFT)

/* ================================================================== */
/* PHY advertisement encoding                                          */
/* ================================================================== */

/* bcm_ethsw.h:11-25. phy_advertise_caps() takes a packed "phy id" that
 * carries both the MDIO address and the requested capabilities.
 */
#define PHY_ADV_CAP_CFG_S		12
#define ADVERTISE_10HD			(1 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_10FD			(2 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_100HD			(4 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_100FD			(8 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_1000HD		(16 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_1000FD		(32 << PHY_ADV_CAP_CFG_S)
#define ADVERTISE_ALL_GMII		(ADVERTISE_10HD | ADVERTISE_10FD | \
					 ADVERTISE_100HD | ADVERTISE_100FD | \
					 ADVERTISE_1000HD | ADVERTISE_1000FD)
#define PHY_ADV_CFG_VALID		(1 << 18)
#define MAC_CONN_S			21
#define MAC_CONN_VALID			(1 << 22)
#define MAC_MAC_IF			(1 << MAC_CONN_S)
#define MAC_CONNECTION			(1 << MAC_CONN_S)
#define PHYID_LSBYTE_M			0xff

/* mii_shared.h:64,67,117-126 and bcm_ethsw.h:43-49 */
#define MII_ANAR_REG			0x04
#define MII_K1CTL_REG			0x09
#define ANAR_TXFD			0x0100
#define ANAR_TXHD			0x0080
#define ANAR_10FD			0x0040
#define ANAR_10HD			0x0020
#define K1CTL_1000BT_FDX		0x0200
#define K1CTL_1000BT_HDX		0x0100
#define K1CTL_REPEATER_DTE		0x0400

/* ================================================================== */
/* SYSTEMPORT v2.1 register offsets                                    */
/* ================================================================== */

/*
 * BCM6764 selects SYSPORT_V2_1 (bcmbca_sysport_v2.h:4-6). Offsets below are
 * the byte offsets of the fields of struct sys_port_{rbuf,rdma,tdma,topctrl}
 * in bcmbca_sysport_v2.h:44-56 / 92-131 / 145-151 / 221-277, relative to the
 * four DT windows "systemport-{rbuf,rdma,tdma,topctrl}-base".
 */

/* RBUF window (DT 0x340400 len 0x2c) */
#define RBUF_CONTROL			0x00
#define RBUF_PACKET_READY_THR		0x04
#define RBUF_CTRL_RSB_MODE_M		0x3
#define RBUF_CTRL_4B_ALIGN_M		(1u << 2)
#define RBUF_CTRL_BTAG_STRIP_M		(1u << 3)
#define RBUF_CTRL_BAD_PKT_DISCARD_M	(1u << 4)

/* RDMA window (DT 0x342000 len 0x1288) */
#define RDMA_DESCRIPTOR			0x0000	/* on-chip descriptor RAM */
#define RDMA_CONTROL			0x1080
#define RDMA_STATUS			0x1084
#define RDMA_LOCRAM_DESCRING_SIZE(q)	(0x10b0 + (q) * 4)
#define RDMA_PKTBUF_SIZE(q)		(0x10d0 + (q) * 4)
#define RDMA_PINDEX(q)			(0x10f0 + (q) * 4)
#define RDMA_CINDEX(q)			(0x1110 + (q) * 4)
#define RDMA_DDR_DESC_RING_START(i)	(0x1170 + (i) * 4)
#define RDMA_DDR_DESC_RING_SIZE(q)	(0x11b0 + (q) * 4)
#define RDMA_CTRL_RDMA_EN_M		(1u << 0)
#define RDMA_RING_EN			(1u << 17)	/* sysport_v2.h:97 */

/* TDMA window (DT 0x344000 len 0xe60) */
#define TDMA_WRITE_PORT_LO(r)		(0x0000 + (r) * 8 + 0)
#define TDMA_WRITE_PORT_HI(r)		(0x0000 + (r) * 8 + 4)
#define TDMA_DESC_RING_CONTROL(r)	(0x0200 + (r) * 4)
#define TDMA_DESC_RING_MAX_THRESHOLD(r)	(0x0380 + (r) * 4)
#define TDMA_DESC_RING_INTR_CONTROL(r)	(0x0400 + (r) * 4)
#define TDMA_DESC_RING_PC_INDEX(r)	(0x0480 + (r) * 4)
#define TDMA_DESC_RING_MAPPING(r)	(0x0500 + (r) * 4)
#define TDMA_DDR_DESC_RING_START(i)	(0x0600 + (i) * 4)
#define TDMA_DDR_DESC_RING_SIZE(r)	(0x0700 + (r) * 4)
#define TDMA_DDR_DESC_RING_CTRL(r)	(0x0780 + (r) * 4)
#define TDMA_DDR_DESC_RING_PUSH_TIMER(r) (0x0800 + (r) * 4)
#define TDMA_CONTROL			0x0904
#define TDMA_STATUS			0x0908
#define TDMA_TIER1_ARBITER_CTRL(i)	(0x0910 + (i) * 4)
#define TDMA_TIER1_ARBITER_QUEUE_EN(i)	(0x0930 + (i) * 4)
#define TDMA_TIER2_ARBITER_CTRL		0x0950

#define TDMA_DESC_RING_CONTROL_RING_EN	(1u << 1)
#define TDMA_CONTROL_TDMA_EN_M		(1u << 0)
#define TDMA_CONTROL_TSB_EN_M		(1u << 1)
#define TDMA_CONTROL_RING_CFG_M		(1u << 19)
#define TDMA_CONTROL_ACB_EN_M		(1u << 27)
#define TDMA_CONTROL_TPD_16B_EN		(1u << 29)

/* TOPCTRL window (DT 0x340000 len 0x5c) */
#define TOPCTRL_RX_FLUSH_CNTL		0x04
#define TOPCTRL_TX_FLUSH_CNTL		0x08

/* Ring sizing, bcmbca_sysport_v2.h:8-17 with CONFIG_BCM6764 */
#define SP_RX_DESC_LOG2			5
#define SP_TX_DESC_LOG2			0
#define SP_PKT_LEN_LOG2			11
#define SP_NUM_RX_BUFS			(1 << SP_RX_DESC_LOG2)	/* 32 */
#define SP_NUM_TX_BUFS			(1 << SP_TX_DESC_LOG2)	/* 1  */
#define SP_DMA_BUFSIZE			2048
#define SP_MAX_PKT_LEN			1536	/* run #71: no jumbo, was SP_DMA_BUFSIZE */
#define SP_ENET_ZLEN			60	/* bcmbca_sysport_v2.h:29 */

/*
 * Packet descriptor, struct PktDesc (bcmbca_sysport_v2.h:36-41):
 *   word0 = address
 *   word1 = { address_hi:8; status:10; length:14 }  little-endian
 * so on a little-endian build address_hi occupies bits 7:0, status bits
 * 17:8 and length bits 31:18.
 */
#define SP_DESC_STRIDE			8
#define SP_DESC_ADDR_HI_MASK		0xffu
#define SP_DESC_LEN_SHIFT		18
#define SP_DESC_LEN_MASK		0x3fffu

/* TX descriptor word 1, bcmbca_sysport_v2.c:470: SOP|EOP in the status field
 * plus APPEND_CRC, and the length in bits 31:18.
 */
#define SP_TXDESC_W1(len)	(((u32)(len) << SP_DESC_LEN_SHIFT) | (3u << 16) | (1u << 11))

/* ================================================================== */
/* internal interfaces between the three compilation units             */
/* ================================================================== */

struct sf2_6764;

struct sf2_6764 *sf2_6764_get(void);
int sf2_6764_init(struct sf2_6764 *sf2);	/* mirrors bcm_ethsw_init()  */
int sf2_6764_open(struct sf2_6764 *sf2);	/* mirrors bcm_ethsw_open()  */
void sf2_6764_close(struct sf2_6764 *sf2);	/* mirrors bcm_ethsw_close() */
int sf2_6764_mdio_read(struct sf2_6764 *sf2, int phy, int reg);
int sf2_6764_mdio_write(struct sf2_6764 *sf2, int phy, int reg, u16 val);

extern struct platform_driver pmc6764_driver;
extern struct platform_driver sf2_6764_driver;
extern struct platform_driver sysport6764_driver;

#endif /* _ENET6764_H */
