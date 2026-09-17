// SPDX-License-Identifier: GPL-2.0
/*
 * BCM6764 SF2 switch core, MDIO master and internal single EGPHY.
 *
 * Port of the U-Boot reference that is known to work on this board:
 *   UB/drivers/net/bcmbca/bcm_ethsw_impl1.c  (sf2_eth_probe, bcm_ethsw_init,
 *                                             bcm_ethsw_open, bcm_ethsw_close)
 *   UB/drivers/net/bcmbca/bcm_ethsw_phy.c    (MDIO, gphy_powerup,
 *                                             phy_advertise_caps)
 * with UB = gpl/.../u-boot-2019.07/. Copies of both live in port66/.
 *
 * Init order is the reference order and must not be rearranged:
 *   PMC switch power-up -> SF2 software reset -> GPHY power-up (with the
 *   25 ms workaround) -> phy_advertise_caps -> port disable + switch mode +
 *   IMP port state. Port enable and PBVLAN happen later, in sf2_6764_open(),
 *   exactly as U-Boot splits init() and open().
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#include "enet6764.h"

struct sf2_6764 {
	struct device	*dev;
	void __iomem	*core;		/* switchcore-base */
	void __iomem	*sreg;		/* switchreg-base  */
	void __iomem	*mdio;		/* switchmdio-base */
	void __iomem	*sphy;		/* sphy-ctrl	   */
	void __iomem	*phytest;	/* phy-test-ctrl   */
	u32		phy_base;
	u32		phy_wkard_timeout;
	struct mutex	lock;		/* serialises core + MDIO access */

	int		nphys;
	u32		phy_ids[SF2_MAX_PORTS];

	/* saved boot-strap state, restored on close
	 * (extsw_register_save_restore(), bcm_ethsw_impl1.c:153-183)
	 */
	bool		saved;
	u32		saved_port_ctrl[SF2_MAX_PORTS];
	u32		saved_pbvlan[SF2_MAX_PORTS];
};

static struct sf2_6764 *g_sf2;

/* SoC-side SF2 port whose MAC is fed by the Merlin serdes (port_sgmii0 = 5 in
 * the stock DTB). The serdes link is forced to 2500Base-X by port66/enet66b,
 * so the port's MAC state must be forced too: U-Boot does this per link event
 * in mac_drv_sf2.c:port_sf2mac_cfg_set() (HIGH_SPEED_STATE branch):
 *   REG_PORT_STATE_LNK 0x01 | REG_PORT_STATE_2500 0x0c | REG_PORT_STATE_OVERRIDE 0x40 |
 *   REG_PORT_STATE_FDX 0x02, keeping the flow-control bits (0x30).
 * Register: SWITCH_CORE_STS_OVERRIDE_GMII_P<n> = 0x72000 + n*0x10 (ethsw.h; the IMP
 * override 0x72080 is the same array's entry 8). -1 disables the override. */
/* SF2 low-power state seen at probe (before/after the switch software
 * reset), exported so the no-UART init can report it: page0 0xDE
 * LOW_POWER_CTRL (core 0x6f0) and page0 0x40 LOW_POWER_EXP1 (core 0x200,
 * [8:0] SLEEP_SYSCLK_PORT, [24:16] SLEEP_MACCLK_PORT). */
static unsigned int lp_ctrl_pre, lp_exp1_pre, lp_ctrl_post, lp_exp1_post;
/* More post-software-reset state (before we write anything): does the
 * reset really clear the stock (OpenWrt 21.02) switch config? */
static unsigned int vlan0_post, gmng_post, hdr_post, ovr5_post, lnksts_post;
/* Lookup-failure handling as left by the software reset: NEW_CTRL (page0
 * 0x21 "port forward": bit7 MCST, bit6 UCST, bit0 IP_MCST select the
 * ULF/MLF/IPMC maps instead of PBVLAN flooding) and the three maps. */
static unsigned int newctrl_post, ulf_post, mlf_post, ipmc_post;
/* ACB (aggregate congestion buffer, "switchacb-base" 0x80274800 in the stock
 * swblks node) lives outside the switch core and is NOT touched by the core
 * software reset. The stock driver enables it with per-queue/per-port XOFF
 * thresholds and warns that queues can stay "congested for ever"; after a
 * warm reboot from stock a stale XOFF state would block every egress port
 * (runs #31..#39: IMP accepts frames, nothing ever leaves). U-Boot never
 * touches ACB (cold-boot default). We disable it. */
static unsigned long acb_base_phys = 0x80274800UL;
module_param(acb_base_phys, ulong, 0444);
static unsigned int acb_ctrl_pre, acb_port5_pre;
module_param(acb_ctrl_pre, uint, 0444);
module_param(acb_port5_pre, uint, 0444);
#define ACB_CONTROL		0x000
#define ACB_PORT_CONFIG(p)	(0x208 + (p) * 4)
#define ACB_EN			0x1

static void sf2_6764_acb_disable(struct sf2_6764 *sf2)
{
	void __iomem *acb = ioremap(acb_base_phys, 0x230);
	int p;

	if (!acb) {
		dev_err(sf2->dev, "ACB ioremap failed\n");
		return;
	}
	acb_ctrl_pre = readl(acb + ACB_CONTROL);
	acb_port5_pre = readl(acb + ACB_PORT_CONFIG(5));
	writel(acb_ctrl_pre & ~ACB_EN, acb + ACB_CONTROL);
	for (p = 0; p <= 8; p++)
		writel(0, acb + ACB_PORT_CONFIG(p));
	dev_info(sf2->dev, "ACB control %08x -> %08x, port5 cfg was %08x\n",
		 acb_ctrl_pre, readl(acb + ACB_CONTROL), acb_port5_pre);
	iounmap(acb);
}
module_param(newctrl_post, uint, 0444);
module_param(ulf_post, uint, 0444);
module_param(mlf_post, uint, 0444);
module_param(ipmc_post, uint, 0444);
#define SF2_NEW_CTRL			0x00108
#define SF2_ULF_DROP_MAP		0x00190
#define SF2_MLF_DROP_MAP		0x001a0
#define SF2_MLF_IPMC_FWD_MAP		0x001b0
#define NEW_CTRL_FWD_MCST		0x80
#define NEW_CTRL_FWD_UCST		0x40
#define NEW_CTRL_FWD_IP_MCST		0x01
module_param(vlan0_post, uint, 0444);
module_param(gmng_post, uint, 0444);
module_param(hdr_post, uint, 0444);
module_param(ovr5_post, uint, 0444);
module_param(lnksts_post, uint, 0444);
#define SF2_VLAN_CTRL(n)		(0x1a000 + (n) * 8)	/* 0..3; 4 = 0x1a028, 5 = 0x1a030 */
#define SF2_VLAN_CTRL4			0x1a028
#define SF2_VLAN_CTRL5			0x1a030
#define SF2_DEFAULT_1Q_TAG(n)		(0x1a080 + (n) * 0x10)	/* IMP = 0x1a100 */
#define SF2_DIS_LEARN			0x001e0
#define SF2_GMNGCFG			0x01000
#define SF2_LNKSTS			0x00800
module_param(lp_ctrl_pre, uint, 0444);
module_param(lp_exp1_pre, uint, 0444);
module_param(lp_ctrl_post, uint, 0444);
module_param(lp_exp1_post, uint, 0444);
#define SF2_LOW_POWER_CTRL		0x006f0
#define SF2_LOW_POWER_EXP1		0x00200
#define LP_CTRL_SLEEP_BITS		(0x8000 | 0x1000 | 0x0800 | 0x0040 | 0x0020 | 0x0010 | 0x0003)
#define LP_EXP1_SLEEP_BITS		(0x1ffu << 16 | 0x1ffu)

static int serdes_port = 5;
module_param(serdes_port, int, 0444);
MODULE_PARM_DESC(serdes_port, "SF2 port fed by the forced 2.5G serdes (-1 = none)");
#define SF2_STS_OVERRIDE_P(n)	(0x72000 + (n) * 0x10)

static void sf2_wr32(struct sf2_6764 *sf2, u32 off, u32 val);

/* Live P0 (WAN GPHY) MAC-state override. -1 keeps the built-in 1G value;
 * write any 0x00..0x7f value to /sys/module/enet6764/parameters/p0_ovr to
 * try another speed/state while the box is running (vendor uses 0x4b = 1G,
 * 0x47 = 100M, 0x43 = 10M, 0x42 = no link; bit7 keeps flow control off). */
static int p0_ovr = -1;
static int p0_ovr_set(const char *val, const struct kernel_param *kp)
{
	int ret = kstrtoint(val, 0, &p0_ovr);

	if (ret)
		return ret;
	if (g_sf2 && p0_ovr >= 0) {
		sf2_wr32(g_sf2, SF2_STS_OVERRIDE_P(0), (u32)p0_ovr);
		pr_info("enet6764: p0 override -> 0x%02x\n", p0_ovr);
	}
	return 0;
}
static const struct kernel_param_ops p0_ovr_ops = {
	.set = p0_ovr_set,
	.get = param_get_int,
};
module_param_cb(p0_ovr, &p0_ovr_ops, &p0_ovr, 0644);
MODULE_PARM_DESC(p0_ovr, "live override for SF2 port 0 (WAN GPHY); -1 = built-in");

struct sf2_6764 *sf2_6764_get(void)
{
	return g_sf2;
}

/* Drive an SF2 port's MAC-state override from an out-of-band link event.
 *
 * A port fed by a cascade PHY (WR3600H WAN: P6 <- serdes core 1 <- external
 * 2.5G copper PHY) gets no in-band status, so whoever does know the copper
 * link has to write the MAC state here or the port stays dead.  Same encoding
 * as U-Boot's port_sf2mac_cfg_set() (UB mac_drv_sf2.c): OVERRIDE | speed |
 * FDX | LNK, flow control left off.
 */
int sf2_6764_force_port_state(int port, int mbps, bool link)
{
	u32 ov = 0x40;			/* REG_PORT_STATE_OVERRIDE */

	if (!g_sf2 || port < 0 || port > 7)
		return -EINVAL;

	if (link) {
		switch (mbps) {
		case 2500: ov |= 0x0c; break;
		case 1000: ov |= 0x08; break;
		case 100:  ov |= 0x04; break;
		case 10:   break;	/* speed field 0 */
		default:   return -EINVAL;
		}
		ov |= 0x02 | 0x01;	/* FDX | LNK */
	}

	sf2_wr32(g_sf2, SF2_STS_OVERRIDE_P(port), ov);
	return 0;
}
EXPORT_SYMBOL_GPL(sf2_6764_force_port_state);

/* ------------------------------------------------------------------ */
/* switch core register access                                        */
/* ------------------------------------------------------------------ */

/*
 * Registers that the reference declares as uint64_t (port_traffic_ctrl,
 * software_reset) are 8 bytes apart because the SF2 memory map uses an
 * 8-byte slot per 53xx-style register (SF2_REG_SHIFT == 2). Their upper half
 * is staged through the switchreg-base scratch pair, and the order matters:
 * write hi first then lo, read lo first then hi
 * (mac_drv_sf2.c:186-247). Both registers only carry meaningful bits in the
 * low half, but we keep the protocol so the access is byte-for-byte what the
 * working reference issues.
 */
static u64 sf2_rd64(struct sf2_6764 *sf2, u32 off)
{
	u32 lo = readl(sf2->core + off);
	u32 hi = readl(sf2->sreg + SF2_DIRECT_DATA_RD);

	return ((u64)hi << 32) | lo;
}

static void sf2_wr64(struct sf2_6764 *sf2, u32 off, u64 val)
{
	writel((u32)(val >> 32), sf2->sreg + SF2_DIRECT_DATA_WR);
	writel((u32)val, sf2->core + off);
}

static u32 sf2_rd32(struct sf2_6764 *sf2, u32 off)
{
	return readl(sf2->core + off);
}

static void sf2_wr32(struct sf2_6764 *sf2, u32 off, u32 val)
{
	writel(val, sf2->core + off);
}

/* ------------------------------------------------------------------ */
/* MDIO                                                               */
/* ------------------------------------------------------------------ */

/*
 * bcm_ethsw_phy.c:16-71. Command layout: BUSY bit 29, FAIL bit 28,
 * op at bit 26, PHY address at bit 21, register at bit 16, data in 15:0.
 * The reference gives up after 10 x udelay(1); we allow 1 ms and return an
 * error instead of silently yielding 0.
 */
#define MDIO_BUSY_POLLS		1000

static int sf2_mdio_cmd(struct sf2_6764 *sf2, u32 cmd, u32 *out)
{
	u32 v;
	int i;

	writel(cmd | ETHSW_MDIO_BUSY, sf2->mdio + SF2_MDIO_CMD);

	for (i = 0; i < MDIO_BUSY_POLLS; i++) {
		udelay(1);
		v = readl(sf2->mdio + SF2_MDIO_CMD);
		if (!(v & ETHSW_MDIO_BUSY)) {
			if (out)
				*out = v;
			return 0;
		}
	}

	dev_err(sf2->dev, "MDIO command 0x%08x stayed busy\n", cmd);
	bcm96764_mark(MK_ERR_MDIO);
	return -ETIMEDOUT;
}

static int __sf2_mdio_read(struct sf2_6764 *sf2, int phy, int reg)
{
	u32 cmd, val;
	int ret;

	cmd = ((phy & BCM_PHY_ID_M) << ETHSW_MDIO_C22_PHY_ADDR_SHIFT) |
	      ((reg & 0x1f) << ETHSW_MDIO_C22_PHY_REG_SHIFT) |
	      (ETHSW_MDIO_CMD_C22_READ << ETHSW_MDIO_CMD_SHIFT);

	ret = sf2_mdio_cmd(sf2, cmd, &val);
	if (ret)
		return ret;

	/* bcm_ethsw_phy.c:36-45: the reference issues the read twice "to
	 * ensure it is reliable"; the second result is the one used.
	 */
	ret = sf2_mdio_cmd(sf2, cmd, &val);
	if (ret)
		return ret;

	return val & ETHSW_MDIO_PHY_DATA_MASK;
}

static int __sf2_mdio_write(struct sf2_6764 *sf2, int phy, int reg, u16 data)
{
	u32 cmd;

	cmd = ((phy & BCM_PHY_ID_M) << ETHSW_MDIO_C22_PHY_ADDR_SHIFT) |
	      ((reg & 0x1f) << ETHSW_MDIO_C22_PHY_REG_SHIFT) |
	      (ETHSW_MDIO_CMD_C22_WRITE << ETHSW_MDIO_CMD_SHIFT) |
	      (data & ETHSW_MDIO_PHY_DATA_MASK);

	return sf2_mdio_cmd(sf2, cmd, NULL);
}

/* ---------------------------------------------------------------- C45 ----
 * The cascade 2.5G PHY of the WR3600H (R69) is a Clause-45 part at MDIO 0x18.
 * The controller does C45 natively; only the clause bit in CFG has to be
 * flipped, and it MUST be put back, or every C22 user on this bus (internal
 * GPHY, the 53134 switch) would start talking the wrong protocol.
 */
static int __sf2_mdio_c45(struct sf2_6764 *sf2, int op, int phy, int dev,
			  int reg, u16 data, u32 *out)
{
	u32 cfg, cmd;
	int ret;

	cfg = readl(sf2->mdio + SF2_MDIO_CFG);
	writel(cfg & ~ETHSW_MDIO_CFG_CLAUSE22, sf2->mdio + SF2_MDIO_CFG);

	/* address phase: which register inside the device */
	cmd = ((phy & BCM_PHY_ID_M) << ETHSW_MDIO_C22_PHY_ADDR_SHIFT) |
	      ((dev & 0x1f) << ETHSW_MDIO_C45_DEV_SHIFT) |
	      (ETHSW_MDIO_CMD_C45_ADDRESS << ETHSW_MDIO_CMD_SHIFT) |
	      ((u32)reg & ETHSW_MDIO_PHY_DATA_MASK);
	ret = sf2_mdio_cmd(sf2, cmd, NULL);
	if (ret)
		goto out;

	cmd = ((phy & BCM_PHY_ID_M) << ETHSW_MDIO_C22_PHY_ADDR_SHIFT) |
	      ((dev & 0x1f) << ETHSW_MDIO_C45_DEV_SHIFT) |
	      (op << ETHSW_MDIO_CMD_SHIFT);
	if (op == ETHSW_MDIO_CMD_C45_WRITE)
		cmd |= data & ETHSW_MDIO_PHY_DATA_MASK;
	ret = sf2_mdio_cmd(sf2, cmd, out);
out:
	writel(cfg, sf2->mdio + SF2_MDIO_CFG);
	return ret;
}

/* Returns the 16-bit value, or a negative errno. */
int sf2_mdio_c45_read(int phy, int dev, int reg)
{
	struct sf2_6764 *sf2 = g_sf2;
	u32 val = 0;
	int ret;

	if (!sf2)
		return -ENODEV;
	mutex_lock(&sf2->lock);
	ret = __sf2_mdio_c45(sf2, ETHSW_MDIO_CMD_C45_READ, phy, dev, reg, 0,
			     &val);
	mutex_unlock(&sf2->lock);
	return ret ? ret : (int)(val & ETHSW_MDIO_PHY_DATA_MASK);
}
EXPORT_SYMBOL_GPL(sf2_mdio_c45_read);

int sf2_mdio_c45_write(int phy, int dev, int reg, u16 val)
{
	struct sf2_6764 *sf2 = g_sf2;
	int ret;

	if (!sf2)
		return -ENODEV;
	mutex_lock(&sf2->lock);
	ret = __sf2_mdio_c45(sf2, ETHSW_MDIO_CMD_C45_WRITE, phy, dev, reg, val,
			     NULL);
	mutex_unlock(&sf2->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf2_mdio_c45_write);

int sf2_6764_mdio_read(struct sf2_6764 *sf2, int phy, int reg)
{
	int ret;

	mutex_lock(&sf2->lock);
	ret = __sf2_mdio_read(sf2, phy, reg);
	mutex_unlock(&sf2->lock);
	return ret;
}

int sf2_6764_mdio_write(struct sf2_6764 *sf2, int phy, int reg, u16 val)
{
	int ret;

	mutex_lock(&sf2->lock);
	ret = __sf2_mdio_write(sf2, phy, reg, val);
	mutex_unlock(&sf2->lock);
	return ret;
}

/* Flat MDIO API for the LAN-side modules (port66/enet66b): serdes/ext switch
 * share the SF2 MDIO master. Returns -ENODEV before the switch has probed. */
int sf2_mdio_read(int phy_addr, int reg)
{
	if (!g_sf2)
		return -ENODEV;
	return sf2_6764_mdio_read(g_sf2, phy_addr, reg);
}
EXPORT_SYMBOL_GPL(sf2_mdio_read);

int sf2_mdio_write(int phy_addr, int reg, u16 val)
{
	if (!g_sf2)
		return -ENODEV;
	return sf2_6764_mdio_write(g_sf2, phy_addr, reg, val);
}
EXPORT_SYMBOL_GPL(sf2_mdio_write);

/* ------------------------------------------------------------------ */
/* PHY advertisement                                                  */
/* ------------------------------------------------------------------ */

/* bcm_ethsw_phy.c:114-145. phy_id is the packed value built in
 * sf2_eth_probe() (bcm_ethsw_impl1.c:319): MDIO address in the low bits,
 * capability bits from PHY_ADV_CAP_CFG_S, plus PHY_ADV_CFG_VALID.
 */
static void sf2_phy_advertise_caps(struct sf2_6764 *sf2, u32 phy_id)
{
	bool connected, adv_valid;
	int cap;

	/* IsPhyConnected() / IsPhyAdvCapConfigValid(), bcm_ethsw.h:40-41 */
	connected = (phy_id & MAC_CONN_VALID)
		    ? ((phy_id & MAC_CONNECTION) != MAC_MAC_IF)
		    : ((phy_id & PHYID_LSBYTE_M) != 0xff);
	adv_valid = !!(phy_id & PHY_ADV_CFG_VALID);

	if (connected && adv_valid) {
		cap = __sf2_mdio_read(sf2, phy_id, MII_ANAR_REG);
		if (cap < 0)
			return;
		cap &= ~(ANAR_TXFD | ANAR_TXHD | ANAR_10FD | ANAR_10HD);
		if (phy_id & ADVERTISE_10HD)
			cap |= ANAR_10HD;
		if (phy_id & ADVERTISE_10FD)
			cap |= ANAR_10FD;
		if (phy_id & ADVERTISE_100HD)
			cap |= ANAR_TXHD;
		if (phy_id & ADVERTISE_100FD)
			cap |= ANAR_TXFD;
		__sf2_mdio_write(sf2, phy_id, MII_ANAR_REG, cap);

		cap = __sf2_mdio_read(sf2, phy_id, MII_K1CTL_REG);
		if (cap < 0)
			return;
		cap &= ~(K1CTL_1000BT_FDX | K1CTL_1000BT_HDX);
		if (phy_id & ADVERTISE_1000HD)
			cap |= K1CTL_1000BT_HDX;
		if (phy_id & ADVERTISE_1000FD)
			cap |= K1CTL_1000BT_FDX;
		__sf2_mdio_write(sf2, phy_id, MII_K1CTL_REG, cap);
	}

	/* "Always enable repeater mode", bcm_ethsw_phy.c:141-144 */
	cap = __sf2_mdio_read(sf2, phy_id, MII_K1CTL_REG);
	if (cap < 0)
		return;
	__sf2_mdio_write(sf2, phy_id, MII_K1CTL_REG, cap | K1CTL_REPEATER_DTE);
}

/* ------------------------------------------------------------------ */
/* internal EGPHY power-up                                            */
/* ------------------------------------------------------------------ */

static void sphy_delay(u32 usecs)
{
	/* The DT asks for phy_wkard_timeout = 25000 us. udelay() is not the
	 * right tool for 25 ms; every caller here runs in process context.
	 */
	if (usecs >= 1000)
		msleep(DIV_ROUND_UP(usecs, 1000));
	else
		usleep_range(usecs, usecs * 2);
}

/* sphy_init_power_workaround(), bcm_ethsw_phy.c:236-268. Mandatory on this
 * board: the stock DTB sets phy_wkard_timeout = 0x61a8 (25000).
 */
static void sphy_init_power_workaround(struct sf2_6764 *sf2, u32 timeout)
{
	u32 v;

	writel(readl(sf2->sphy) | ETHSW_SPHY_CTRL_RESET, sf2->sphy);
	sphy_delay(timeout);

	writel(1, sf2->phytest);

	v = readl(sf2->sphy);
	v &= ~ETHSW_SPHY_CTRL_IDDQ_BIAS;
	v &= ~ETHSW_SPHY_CTRL_IDDQ_GLOBAL_PWR;
	writel(v, sf2->sphy);
	sphy_delay(timeout);

	writel(readl(sf2->sphy) | ETHSW_SPHY_CTRL_IDDQ_BIAS, sf2->sphy);
	writel(readl(sf2->sphy) | ETHSW_SPHY_CTRL_IDDQ_GLOBAL_PWR, sf2->sphy);
	sphy_delay(timeout);

	v = readl(sf2->sphy);
	v &= ~ETHSW_SPHY_CTRL_RESET;
	writel(v, sf2->sphy);
	sphy_delay(timeout);

	writel(0, sf2->phytest);
}

/* sgphy_powerup(), bcm_ethsw_phy.c:147-174 */
static void sgphy_powerup(struct sf2_6764 *sf2, int phy_id)
{
	u32 v;

	v = readl(sf2->sphy);
	v &= ~(ETHSW_SPHY_CTRL_IDDQ_BIAS | ETHSW_SPHY_CTRL_EXT_PWR_DOWN |
	       ETHSW_SPHY_CTRL_PHYAD_MASK);
	v |= ETHSW_SPHY_CTRL_RESET |
	     ((u32)phy_id << ETHSW_SPHY_CTRL_PHYAD_SHIFT);
	writel(v, sf2->sphy);

	udelay(1);
	v &= ~ETHSW_SPHY_CTRL_IDDQ_GLOBAL_PWR;
	writel(v, sf2->sphy);

	usleep_range(1000, 2000);

	v = readl(sf2->sphy);
	v &= ~ETHSW_SPHY_CTRL_RESET;
	writel(v, sf2->sphy);

	usleep_range(1000, 2000);
}

/* gphy_powerup(), bcm_ethsw_phy.c:296-327, with qphy_ctrl == NULL because the
 * 6764 DT only provides sphy-ctrl.
 */
static int sf2_gphy_powerup(struct sf2_6764 *sf2)
{
	u32 v;
	int id1;

	if (!sf2->sphy || !sf2->phytest) {
		dev_err(sf2->dev, "sphy-ctrl / phy-test-ctrl missing\n");
		return -ENODEV;
	}

	if (sf2->phy_wkard_timeout)
		sphy_init_power_workaround(sf2, sf2->phy_wkard_timeout);

	sgphy_powerup(sf2, sf2->phy_base);

	v = readl(sf2->sphy);
	dev_info(sf2->dev, "sphy-ctrl 0x%08x after power-up\n", v);
	if ((v & ETHSW_SPHY_CTRL_RESET) ||
	    ((v & ETHSW_SPHY_CTRL_PHYAD_MASK) >> ETHSW_SPHY_CTRL_PHYAD_SHIFT)
	    != sf2->phy_base) {
		dev_err(sf2->dev, "GPHY did not come out of reset\n");
		return -EIO;
	}
	bcm96764_mark(MK_GPHY_POWERED);

	/* "dummy read to workaround first MDIO read/write issue after power
	 * on", bcm_ethsw_phy.c:315-317
	 */
	__sf2_mdio_read(sf2, sf2->phy_base, 0x02);

	id1 = __sf2_mdio_read(sf2, sf2->phy_base, MII_PHYSID1);
	if (id1 < 0)
		return id1;
	if (id1 == 0x0000 || id1 == 0xffff) {
		dev_err(sf2->dev, "PHY %u ID1 reads 0x%04x, MDIO is dead\n",
			sf2->phy_base, id1);
		bcm96764_mark(MK_ERR_PHYID);
		return -EIO;
	}

	dev_info(sf2->dev, "PHY %u ID1 0x%04x%s\n", sf2->phy_base, id1,
		 id1 == 0x0143 ? " (Broadcom OUI 00:10:18)" : "");
	bcm96764_mark(MK_PHYID_OK);
	return 0;
}


/* ------------------------------------------------------------------ */
/* internal EGPHY AFE/PLL calibration                                  */
/* ------------------------------------------------------------------ */

/* Indirect register access, phy_drv_brcm.c:
 *   EXP  : address 0x17 = 0x0f00 | reg, value at 0x15
 *   MISC : shadow18[0] |= 0x800 -> reg 0x18, then EXP address
 *          (chnl << 13) | reg and the value at 0x15
 */
static void sf2_exp_write(struct sf2_6764 *sf2, int reg, u16 val)
{
	__sf2_mdio_write(sf2, sf2->phy_base, 0x17, 0x0f00 | (reg & 0xff));
	__sf2_mdio_write(sf2, sf2->phy_base, 0x15, val);
}

static int sf2_exp_read(struct sf2_6764 *sf2, int reg)
{
	__sf2_mdio_write(sf2, sf2->phy_base, 0x17, 0x0f00 | (reg & 0xff));
	return __sf2_mdio_read(sf2, sf2->phy_base, 0x15);
}

static void sf2_misc_write(struct sf2_6764 *sf2, int reg, int chnl, u16 val)
{
	int phy = sf2->phy_base;
	u16 tmp = __sf2_mdio_read(sf2, phy, 0x18);

	__sf2_mdio_write(sf2, phy, 0x18, tmp | 0x800);
	__sf2_mdio_write(sf2, phy, 0x17, (chnl << 13) | (reg & 0x1fff));
	__sf2_mdio_write(sf2, phy, 0x15, val);
}

static int sf2_misc_read(struct sf2_6764 *sf2, int reg, int chnl)
{
	int phy = sf2->phy_base;
	u16 tmp = __sf2_mdio_read(sf2, phy, 0x18);

	__sf2_mdio_write(sf2, phy, 0x18, tmp | 0x800);
	__sf2_mdio_write(sf2, phy, 0x17, (chnl << 13) | (reg & 0x1fff));
	return __sf2_mdio_read(sf2, phy, 0x15);
}

/* dsl_phy_afe_pll_setup() -> _phy_run_cal() + _phy_afe_cfg() from
 * bcmdrivers/opensource/phy/phy_drv_dsl_phy.c, CONFIG_BCM96764 variant, with
 * the register values cross-checked against the live stock firmware (which
 * brings the same PHY up at 1 Gbps).
 *
 * Without this the internal EGPHY answers MDIO but never sees the link
 * partner: bmsr reports link=0 and lpa reads 0, so the WAN port stays dead
 * even though the PHY itself is powered and out of reset.
 */
static void sf2_gphy_afe(struct sf2_6764 *sf2)
{
	int phy = sf2->phy_base;
	u16 expa9, rcalcode, rcalnewcodelp, rcalnewcode11, txcfgch0, txcfg2;

	/* reset the PHY, then the AFE and the PLL */
	__sf2_mdio_write(sf2, phy, 0x00, 0x9140);
	msleep(20);
	sf2_exp_write(sf2, 0x03, 0x0006);
	udelay(300);
	sf2_exp_write(sf2, 0x03, 0x0000);
	msleep(20);

	/* _phy_run_cal(): RCAL then RCCAL, then the bias settings */
	sf2_misc_write(sf2, 0x39, 3, 0x0038);
	sf2_misc_write(sf2, 0x39, 3, 0x003b);
	msleep(1);
	sf2_misc_write(sf2, 0x39, 3, 0x003f);
	msleep(1);
	sf2_misc_write(sf2, 0x39, 1, 0x1c82);
	sf2_misc_write(sf2, 0x39, 1, 0x9e82);
	msleep(1);
	sf2_misc_write(sf2, 0x39, 1, 0x9f82);
	msleep(1);
	sf2_misc_write(sf2, 0x39, 1, 0x9e86);
	msleep(1);
	sf2_misc_write(sf2, 0x39, 1, 0x9f86);
	msleep(1);
	sf2_misc_write(sf2, 0x38, 2, 0xefe2);

	expa9 = sf2_exp_read(sf2, 0xa9);
	rcalcode = (expa9 & 0x007e) >> 1;
	rcalnewcodelp = rcalcode + 16;
	rcalnewcode11 = rcalcode + 10;
	if (rcalnewcodelp > 0x3f)
		rcalnewcodelp = 0x3f;
	if (rcalnewcode11 > 0x3f)
		rcalnewcode11 = 0x3f;

	sf2_misc_write(sf2, 0x39, 3, (rcalnewcodelp << 8) + 0x00f8);
	sf2_misc_write(sf2, 0x38, 1, 0xe3e4);

	/* _phy_afe_cfg() */
	sf2_misc_write(sf2, 0x3b, 0, 0x8002);
	sf2_misc_write(sf2, 0x3c, 3, 0xf882);
	sf2_misc_write(sf2, 0x3d, 0, 0x3201);
	sf2_misc_write(sf2, 0x3a, 2, 0x0c00);
	sf2_misc_write(sf2, 0x3a, 1, 0x0020);
	sf2_misc_write(sf2, 0x3b, 2, 0x0000);
	sf2_misc_write(sf2, 0x3b, 3, 0x0000);
	sf2_misc_write(sf2, 0x3c, 0, 0x0000);
	sf2_misc_write(sf2, 0x3c, 1, 0x0000);
	sf2_misc_write(sf2, 0x3a, 3, 0x0800);
	msleep(1);
	sf2_misc_write(sf2, 0x3a, 1, 0x0000);

	txcfgch0 = sf2_misc_read(sf2, 0x3d, 1);
	txcfgch0 = (txcfgch0 & ~0x0fe0) | 0x0020 |
		   ((rcalnewcode11 & 0xfffe) << 5);
	sf2_misc_write(sf2, 0x3d, 1, txcfgch0);
	sf2_misc_write(sf2, 0x3d, 2, txcfgch0);
	txcfg2 = sf2_misc_read(sf2, 0x3d, 0);
	txcfg2 = (txcfg2 & ~0x3000) | 0x3000;
	sf2_misc_write(sf2, 0x3d, 0, txcfg2);

	/* advertise 10/100/1000 and restart autoneg */
	__sf2_mdio_write(sf2, phy, 0x04, 0x01e1);
	__sf2_mdio_write(sf2, phy, 0x09, 0x0300);
	__sf2_mdio_write(sf2, phy, 0x00, 0x1340);

	/* release the R_CAL/RC_CAL engine */
	sf2_exp_write(sf2, 0xb0, 0x0010);
	sf2_exp_write(sf2, 0xb0, 0x0000);
	msleep(2);

	dev_info(sf2->dev, "GPHY AFE/PLL calibrated (rcal 0x%02x, expa9 0x%04x)\n",
		 rcalcode, expa9);
	bcm96764_mark(MK_PHYID_OK);
}

/* ------------------------------------------------------------------ */
/* switch init / open / close                                         */
/* ------------------------------------------------------------------ */

/* bcm_ethsw_init(), bcm_ethsw_impl1.c:49-151, taking the CONFIG_BCM6764
 * branches. pmc_switch_enable_rgmii_zone_clk() is a no-op on this SoC (its
 * body is compiled only for 63138/63148/4908/63158, pmc_switch.c:41-105) and
 * is therefore omitted.
 */
int sf2_6764_init(struct sf2_6764 *sf2)
{
	u32 v;
	int i, ret;

	ret = pmc6764_switch_power_up();
	if (ret)
		return ret;

	mutex_lock(&sf2->lock);

	lp_ctrl_pre = sf2_rd32(sf2, SF2_LOW_POWER_CTRL);
	lp_exp1_pre = sf2_rd32(sf2, SF2_LOW_POWER_EXP1);

	/* Software reset. Reference spins forever (bcm_ethsw_impl1.c:75-78);
	 * we bound the wait at 100 ms and fail cleanly.
	 */
	sf2_wr64(sf2, SF2_SOFTWARE_RESET,
		 sf2_rd64(sf2, SF2_SOFTWARE_RESET) |
		 SF2_SOFTWARE_RESET_BIT | SF2_EN_SW_RST);

	for (i = 0; i < 1000; i++) {
		if (!(sf2_rd64(sf2, SF2_SOFTWARE_RESET) & SF2_SOFTWARE_RESET_BIT))
			break;
		usleep_range(100, 200);
	}
	if (i == 1000) {
		mutex_unlock(&sf2->lock);
		dev_err(sf2->dev, "switch software reset never completed\n");
		bcm96764_mark(MK_ERR_SF2_RESET);
		return -ETIMEDOUT;
	}
	usleep_range(1000, 2000);	/* udelay(1000), impl1.c:79 */
	dev_info(sf2->dev, "switch software reset done after %d poll(s)\n", i);
	bcm96764_mark(MK_SF2_RESET);
	sf2_6764_acb_disable(sf2);
	/* stock: switch-eth-misc CLKRST_CNTRL (0x80280000 + 0xc) bit0 IMP_CLK_SEL
	 * (impl7 sf2_platform.h:107); reference dump shows 1 on the stock. */
	{
		void __iomem *em = ioremap(0x80280000UL, 0x20);

		if (em) {
			writel(readl(em + 0xc) | 0x1, em + 0xc);
			iounmap(em);
		}
	}

	/* Low-power / clock-sleep state: report what the reset left behind and
	 * force every port's sysclk/macclk awake (impl7 sf2_force_mac_up(),
	 * platform_set_clock_normal()). A sleeping P5 MAC clock would explain
	 * TxOctets_P5 == 0 with IMP accepting frames (runs #31..#35). */
	lp_ctrl_post = sf2_rd32(sf2, SF2_LOW_POWER_CTRL);
	lp_exp1_post = sf2_rd32(sf2, SF2_LOW_POWER_EXP1);
	vlan0_post = sf2_rd32(sf2, SF2_VLAN_CTRL(0));
	gmng_post = sf2_rd32(sf2, SF2_GMNGCFG);
	hdr_post = sf2_rd32(sf2, SF2_BRCM_HDR_CTRL);
	ovr5_post = sf2_rd32(sf2, SF2_STS_OVERRIDE_P(5));
	/* Clean slate: no 802.1Q, no VLAN options, PVID 1, learning on. The
	 * stock OpenWrt 21.02 build runs the SF2 with 802.1Q VLANs; if the
	 * software reset leaves that behind, untagged CPU frames would be
	 * dropped by the VLAN lookup (RxGood counted, no egress). */
	sf2_wr32(sf2, SF2_VLAN_CTRL(0), 0);
	sf2_wr32(sf2, SF2_VLAN_CTRL(1), 0);
	sf2_wr32(sf2, SF2_VLAN_CTRL(2), 0);
	sf2_wr32(sf2, SF2_VLAN_CTRL(3), 0);
	sf2_wr32(sf2, SF2_VLAN_CTRL4, 0);
	sf2_wr32(sf2, SF2_VLAN_CTRL5, 0);
	for (i = 0; i <= SF2_IMP_PORT; i++)
		sf2_wr32(sf2, SF2_DEFAULT_1Q_TAG(i), 1);
	sf2_wr32(sf2, SF2_DIS_LEARN, 0);
	/* Lookup failures (unknown DA, broadcast from the CPU): record the
	 * post-reset state, then make them flood per PBVLAN (clear the
	 * "use ULF/MLF/IPMC map" selects) and open the maps anyway. The
	 * stock (managed+tag) build points the maps at the IMP only. */
	newctrl_post = sf2_rd32(sf2, SF2_NEW_CTRL);
	ulf_post = sf2_rd32(sf2, SF2_ULF_DROP_MAP);
	mlf_post = sf2_rd32(sf2, SF2_MLF_DROP_MAP);
	ipmc_post = sf2_rd32(sf2, SF2_MLF_IPMC_FWD_MAP);
	sf2_wr32(sf2, SF2_NEW_CTRL, newctrl_post &
		 ~(NEW_CTRL_FWD_MCST | NEW_CTRL_FWD_UCST | NEW_CTRL_FWD_IP_MCST));
	sf2_wr32(sf2, SF2_ULF_DROP_MAP, 0x1ff);
	sf2_wr32(sf2, SF2_MLF_DROP_MAP, 0x1ff);
	sf2_wr32(sf2, SF2_MLF_IPMC_FWD_MAP, 0x1ff);
	dev_info(sf2->dev, "post-reset new_ctrl %08x ulf %08x mlf %08x ipmc %08x -> new_ctrl %08x\n",
		 newctrl_post, ulf_post, mlf_post, ipmc_post, sf2_rd32(sf2, SF2_NEW_CTRL));
	dev_info(sf2->dev, "post-reset vlan0 %08x gmng %08x hdr %08x ovr5 %08x\n",
		 vlan0_post, gmng_post, hdr_post, ovr5_post);
	sf2_wr32(sf2, SF2_LOW_POWER_CTRL, lp_ctrl_post & ~LP_CTRL_SLEEP_BITS);
	sf2_wr32(sf2, SF2_LOW_POWER_EXP1, lp_exp1_post & ~LP_EXP1_SLEEP_BITS);
	dev_info(sf2->dev, "low-power ctrl %08x->%08x exp1 %08x->%08x (pre-reset %08x/%08x)\n",
		 lp_ctrl_post, sf2_rd32(sf2, SF2_LOW_POWER_CTRL),
		 lp_exp1_post, sf2_rd32(sf2, SF2_LOW_POWER_EXP1),
		 lp_ctrl_pre, lp_exp1_pre);

	mutex_unlock(&sf2->lock);

	ret = sf2_gphy_powerup(sf2);
	if (ret)
		return ret;

	sf2_gphy_afe(sf2);

	mutex_lock(&sf2->lock);

	/* bcm_ethsw_impl1.c:99-103 */
	for (i = 0; i < sf2->nphys; i++)
		sf2_phy_advertise_caps(sf2, sf2->phy_ids[i]);

	/* The 6764 branch of impl1.c:86-97 skips the "wait for hardware to
	 * enable the ports" loop: on this switch the reset leaves ports
	 * disabled, so waiting for RX_DISABLE to clear would hang.
	 */

	/* Disable all MAC TX/RX, impl1.c:110-115 */
	for (i = 0; i < SF2_MAX_PORTS; i++)
		sf2_wr64(sf2, SF2_PORT_TRAFFIC_CTRL(i),
			 (sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(i)) & 0xff) |
			 PORT_CTRL_RXTX_DISABLE);

	/* Unmanaged mode + forwarding, impl1.c:118-124 */
	v = sf2_rd32(sf2, SF2_SWITCH_MODE);
	if (v == 0xffffffff) {
		mutex_unlock(&sf2->lock);
		dev_err(sf2->dev, "switch core reads as all-ones, block dead\n");
		bcm96764_mark(MK_ERR_SF2_STUCK);
		return -EIO;
	}
	/* Stock impl7 _extsw_setup_imp_ports(): managed mode + Broadcom tag on
	 * the IMP port (frames from the CPU carry an explicit egress map, so
	 * no ARL/lookup-failure logic is involved), IMP enabled as the frame
	 * management port, dumb mode cleared. */
	sf2_wr32(sf2, SF2_GMNGCFG, 0x80 | 0x02);	/* ENABLE_MII_PORT | RECEIVE_BPDU */
	v = (v & 0xff) | ETHSW_SM_FORWARDING_EN | ETHSW_SM_RETRY_LIMIT_DIS |
	    ETHSW_SM_MANAGED_MODE;
	sf2_wr32(sf2, SF2_SWITCH_MODE, v);
	sf2_wr32(sf2, SF2_BRCM_HDR_CTRL, 0x01);		/* BRCM_HDR_EN_IMP_PORT */
	sf2_wr32(sf2, SF2_SWITCH_CTRL, 0);		/* clear dumb mode */
	/* lookup failures -> IMP only, no learning on IMP (stock) */
	sf2_wr32(sf2, SF2_NEW_CTRL, (sf2_rd32(sf2, SF2_NEW_CTRL) & 0xff) |
		 NEW_CTRL_FWD_MCST | NEW_CTRL_FWD_UCST | NEW_CTRL_FWD_IP_MCST);
	sf2_wr32(sf2, SF2_ULF_DROP_MAP, 0x100);
	sf2_wr32(sf2, SF2_MLF_DROP_MAP, 0x100);
	sf2_wr32(sf2, SF2_MLF_IPMC_FWD_MAP, 0x100);
	sf2_wr32(sf2, SF2_DIS_LEARN, 0x100);

	/* WAN/LAN split (triaging/shim/sf2-vlan/REPORT.md §2.2). Gated by the
	 * sysport module parameter split=1 so split=0 keeps the proven
	 * single-netdev configuration byte for byte:
	 *   WAN_PORT_SEL marks P0 as WAN, so P0<->P5 traffic must go through
	 *   the CPU and cannot be switched in hardware;
	 *   DIS_LEARN = BIT(P0) turns learning off on the WAN port (stock);
	 *   RX_DIS/TX_DIS: clearing the P0/P5/P8 bits enables the in-band
	 *   Broadcom tag on the WAN, LAN and IMP ports;
	 *   PBVLAN P0 = 0x101, P5 = 0x120 (self + IMP only), IMP = 0x1ff.
	 * The open() loop below writes the same PBVLAN values for every port.
	 */
	if (enet6764_split) {
		u32 rx_dis = SF2_BRCM_HDR_PORTS_MASK &
			     ~((1u << SP_SPLIT_WAN_PORT) |
			       (1u << SP_SPLIT_LAN_PORT) |
			       (1u << SF2_IMP_PORT));

		sf2_wr32(sf2, SF2_WAN_PORT_SEL, enet6764_wan_port_sel);
		sf2_wr32(sf2, SF2_DIS_LEARN, 1u << SP_SPLIT_WAN_PORT);
		sf2_wr32(sf2, SF2_BRCM_HDR_RX_DIS, rx_dis);
		sf2_wr32(sf2, SF2_BRCM_HDR_TX_DIS, rx_dis);
		sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(SP_SPLIT_WAN_PORT),
			 PBMAP_MIPS | (1u << SP_SPLIT_WAN_PORT));
		sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(SP_SPLIT_LAN_PORT),
			 PBMAP_MIPS | (1u << SP_SPLIT_LAN_PORT));
		sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(SF2_IMP_PORT), 0x1ff);
		dev_info(sf2->dev,
			 "WAN/LAN split: wan_port_sel %08x dis_learn %08x rx_dis %08x tx_dis %08x\n",
			 sf2_rd32(sf2, SF2_WAN_PORT_SEL),
			 sf2_rd32(sf2, SF2_DIS_LEARN),
			 sf2_rd32(sf2, SF2_BRCM_HDR_RX_DIS),
			 sf2_rd32(sf2, SF2_BRCM_HDR_TX_DIS));
	}

	/* IMP port state, 6764 branch of impl1.c:126-131 */
	sf2_wr32(sf2, SF2_IMP_PORT_STATE,
		 ETHSW_IPS_XGMII_MODE | ETHSW_IPS_USE_REG_CONTENTS |
		 ETHSW_IPS_TXFLOW_PAUSE_CAPABLE | ETHSW_IPS_RXFLOW_PAUSE_CAPABLE |
		 ETHSW_IPS_DUPLEX_MODE | ETHSW_IPS_LINK_PASS |
		 ETHSW_IPS_SW_PORT_SPEED_10G);

	/* Readback proves the register file accepts writes. */
	v = sf2_rd32(sf2, SF2_SWITCH_MODE);
	dev_info(sf2->dev, "switch_mode 0x%08x imp_port_state 0x%08x\n",
		 v, sf2_rd32(sf2, SF2_IMP_PORT_STATE));
	if (!(v & ETHSW_SM_FORWARDING_EN)) {
		mutex_unlock(&sf2->lock);
		dev_err(sf2->dev, "switch_mode write did not stick\n");
		bcm96764_mark(MK_ERR_SF2_STUCK);
		return -EIO;
	}
	bcm96764_mark(MK_SF2_SANE);

	mutex_unlock(&sf2->lock);
	return 0;
}

/* bcm_ethsw_open(), bcm_ethsw_impl1.c:187-214, together with the "save" half
 * of extsw_register_save_restore() (impl1.c:161-168).
 */
int sf2_6764_open(struct sf2_6764 *sf2)
{
	int i;

	mutex_lock(&sf2->lock);

	for (i = 0; i < SF2_MAX_PORTS; i++) {
		sf2->saved_port_ctrl[i] =
			(u32)sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(i)) & 0xff;
		sf2->saved_pbvlan[i] =
			sf2_rd32(sf2, SF2_PORT_VLAN_CTRL(i)) & 0xffff;
	}
	sf2->saved = true;

	for (i = 0; i < SF2_MAX_PORTS; i++) {
		/* PBVLAN: any port (U-Boot uses CPU-only 0x100; be permissive
		 * while the data path is being brought up). In split mode the
		 * formula already yields the intended 0x101 for WAN P0 and
		 * 0x120 for LAN P5 (self + IMP only, see sf2_6764_init()). */
		sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(i), 0x100 | (1u << i));
		/* NO-STP, TX/RX enabled */
		sf2_wr64(sf2, SF2_PORT_TRAFFIC_CTRL(i),
			 ((sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(i)) & 0xff) &
			  ~(u64)(PORT_CTRL_RXTX_DISABLE | PORT_CTRL_PORT_STATUS_M)) |
			 PORT_CTRL_NO_STP);
	}

	/* IMP port (8) is outside the 0..7 loop: enable its RX/TX and the
	 * unicast/multicast/broadcast receive enables (page 0 reg 0x08,
	 * REG_MII_PORT_CONTROL_RX_{U,M,B}CST_EN = 0x1c; impl7 sf2.c
	 * IMP_PORTS_ENABLE / b53_enable_cpu_port). Without this, frames from
	 * the CPU count in RxOctets_IMP but never egress (run #31: 0xBE). */
	{
		u32 imp = (u32)sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(SF2_IMP_PORT)) & 0xff;

		imp = (imp & ~(PORT_CTRL_RXTX_DISABLE | PORT_CTRL_PORT_STATUS_M)) |
		      PORT_CTRL_IMP_RX_ALL_EN;
		sf2_wr64(sf2, SF2_PORT_TRAFFIC_CTRL(SF2_IMP_PORT), imp);
		/* IMP port-based VLAN: may forward to every port (reset default
		 * should be 0x1ff, impl7 sf2.c "By default all port's pbvlan is
		 * 0x1FF"; make it explicit). */
		sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(SF2_IMP_PORT), 0x1ff);
		dev_info(sf2->dev, "imp port ctrl -> 0x%02x\n",
			 (u32)sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(SF2_IMP_PORT)) & 0xff);
	}

	dev_info(sf2->dev, "ports enabled, port0 ctrl 0x%02x pbvlan 0x%04x\n",
		 (u32)sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(0)) & 0xff,
		 sf2_rd32(sf2, SF2_PORT_VLAN_CTRL(0)) & 0xffff);
	if (enet6764_split)
		dev_info(sf2->dev,
			 "split pbvlan p0 0x%04x p5 0x%04x imp 0x%04x, wan_port_sel %08x\n",
			 sf2_rd32(sf2, SF2_PORT_VLAN_CTRL(SP_SPLIT_WAN_PORT)) & 0xffff,
			 sf2_rd32(sf2, SF2_PORT_VLAN_CTRL(SP_SPLIT_LAN_PORT)) & 0xffff,
			 sf2_rd32(sf2, SF2_PORT_VLAN_CTRL(SF2_IMP_PORT)) & 0xffff,
			 sf2_rd32(sf2, SF2_WAN_PORT_SEL));

	mutex_unlock(&sf2->lock);
	if (serdes_port >= 0 && serdes_port <= 7) {
		u32 ov = sf2_rd32(sf2, SF2_STS_OVERRIDE_P(serdes_port));

		ov = 0x40 | 0x0c | 0x02 | 0x01;	/* override, 2.5G, FDX, link; no flow control */
		sf2_wr32(sf2, SF2_STS_OVERRIDE_P(serdes_port), ov);
		/* WAN GPHY port 0: override per link (1G FDX default); p0_ovr
		 * lets us retry other speeds/states live */
		sf2_wr32(sf2, SF2_STS_OVERRIDE_P(0),
			 p0_ovr >= 0 ? (u32)p0_ovr : (0x40 | 0x08 | 0x02 | 0x01));
		/* WR3600H (R69): the WAN is not the GPHY but port_sgmii1 (P6),
		 * fed by serdes core 1 through the external 2.5G cascade PHY.
		 * Force that MAC the same way as the other serdes port, so the
		 * datapath is ready once the copper side links. */
		if (SP_SPLIT_WAN_PORT != 0 &&
		    SP_SPLIT_WAN_PORT != (unsigned int)serdes_port) {
			sf2_wr32(sf2, SF2_STS_OVERRIDE_P(SP_SPLIT_WAN_PORT),
				 0x40 | 0x0c | 0x02 | 0x01);
			dev_info(sf2->dev,
				 "WAN port %u state override -> 0x%08x (forced 2.5G FDX link)\n",
				 SP_SPLIT_WAN_PORT,
				 sf2_rd32(sf2, SF2_STS_OVERRIDE_P(SP_SPLIT_WAN_PORT)));
		}
		lnksts_post = sf2_rd32(sf2, SF2_LNKSTS);
		dev_info(sf2->dev, "override p%d readback 0x%08x lnksts 0x%08x\n", serdes_port,
			 sf2_rd32(sf2, SF2_STS_OVERRIDE_P(serdes_port)), lnksts_post);
		dev_info(sf2->dev, "port %d state override -> 0x%02x (forced 2.5G FDX link)\n",
			 serdes_port, sf2_rd32(sf2, SF2_STS_OVERRIDE_P(serdes_port)));
	}
	bcm96764_mark(MK_PORTS_ENABLED);
	return 0;
}

/* bcm_ethsw_close() + the "restore" half of extsw_register_save_restore()
 * (impl1.c:170-181, 217-228).
 */
void sf2_6764_close(struct sf2_6764 *sf2)
{
	u32 reg;
	int i;

	mutex_lock(&sf2->lock);
	if (sf2->saved) {
		for (i = 0; i < SF2_MAX_PORTS; i++) {
			reg = (u32)sf2_rd64(sf2, SF2_PORT_TRAFFIC_CTRL(i)) &
			      PORT_CTRL_SWITCH_RESERVE;
			reg |= sf2->saved_port_ctrl[i] & ~PORT_CTRL_SWITCH_RESERVE;
			sf2_wr64(sf2, SF2_PORT_TRAFFIC_CTRL(i), reg);
			sf2_wr32(sf2, SF2_PORT_VLAN_CTRL(i), sf2->saved_pbvlan[i]);
		}
	}
	mutex_unlock(&sf2->lock);
}

/* ------------------------------------------------------------------ */
/* probe                                                              */
/* ------------------------------------------------------------------ */

/* sf2_eth_probe(), bcm_ethsw_impl1.c:302-331: walk ports/<port>/phy-handle,
 * and for every GMII port record MDIO address | ADVERTISE_ALL_GMII |
 * PHY_ADV_CFG_VALID. Serdes ports have phy-mode "serdes" and are skipped,
 * which is what we want -- this driver does not touch the SGMII lanes.
 */
static void sf2_parse_ports(struct sf2_6764 *sf2, struct device_node *np)
{
	struct device_node *ports, *port, *phy;
	const char *mode;
	u32 phy_addr;

	sf2->nphys = 0;

	for_each_child_of_node(np, ports) {
		for_each_child_of_node(ports, port) {
			if (!of_device_is_available(port))
				continue;
			if (of_property_read_string(port, "phy-mode", &mode))
				continue;
			if (strcasecmp(mode, "gmii"))
				continue;

			phy = of_parse_phandle(port, "phy-handle", 0);
			if (!phy)
				continue;
			if (!of_property_read_u32(phy, "reg", &phy_addr) &&
			    sf2->nphys < SF2_MAX_PORTS) {
				sf2->phy_ids[sf2->nphys++] =
					phy_addr | ADVERTISE_ALL_GMII |
					PHY_ADV_CFG_VALID;
				dev_info(sf2->dev,
					 "%pOFn: GMII PHY at MDIO addr %u\n",
					 port, phy_addr);
			}
			of_node_put(phy);
		}
	}
}

static int sf2_6764_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sf2_6764 *sf2;

	if (!pmc6764_ready()) {
		bcm96764_mark(0xF2);	/* sf2 probe deferred: pmc not ready */
		return -EPROBE_DEFER;
	}

	sf2 = devm_kzalloc(dev, sizeof(*sf2), GFP_KERNEL);
	if (!sf2)
		return -ENOMEM;

	sf2->dev = dev;
	mutex_init(&sf2->lock);

	/* Stock DTB node sf2@200000, reg-names
	 * "switchcore-base","switchreg-base","switchmdio-base","sphy-ctrl",
	 * "phy-test-ctrl". No hardcoded fallbacks: the addresses in the node
	 * are offsets inside ubus-bus (ranges 0 0 0x80000000 0x70000000) and
	 * are only correct once the OF core has applied that translation.
	 */
	sf2->core = devm_platform_ioremap_resource_byname(pdev, "switchcore-base");
	if (IS_ERR(sf2->core))
		goto err_map;
	sf2->sreg = devm_platform_ioremap_resource_byname(pdev, "switchreg-base");
	if (IS_ERR(sf2->sreg))
		goto err_map;
	sf2->mdio = devm_platform_ioremap_resource_byname(pdev, "switchmdio-base");
	if (IS_ERR(sf2->mdio))
		goto err_map;
	sf2->sphy = devm_platform_ioremap_resource_byname(pdev, "sphy-ctrl");
	if (IS_ERR(sf2->sphy))
		goto err_map;
	sf2->phytest = devm_platform_ioremap_resource_byname(pdev, "phy-test-ctrl");
	if (IS_ERR(sf2->phytest))
		goto err_map;

	/* impl1.c:289-291 */
	if (of_property_read_u32(dev->of_node, "phy_base", &sf2->phy_base))
		sf2->phy_base = 1;
	sf2->phy_wkard_timeout = 0;
	of_property_read_u32(dev->of_node, "phy_wkard_timeout",
			     &sf2->phy_wkard_timeout);

	dev_info(dev, "sf2 phy_base %u phy power-on workaround timeout %u us\n",
		 sf2->phy_base, sf2->phy_wkard_timeout);

	sf2_parse_ports(sf2, dev->of_node);

	g_sf2 = sf2;
	bcm96764_mark(0x6B);	/* sf2 probe ok */
	return 0;

err_map:
	dev_err(dev, "cannot map one of the sf2 register windows\n");
	bcm96764_mark(MK_ERR_SF2_MAP);
	return -ENXIO;
}

static void sf2_6764_remove(struct platform_device *pdev)
{
	g_sf2 = NULL;
}

static const struct of_device_id sf2_6764_of_match[] = {
	{ .compatible = "brcm,bcmbca-sf2" },	/* stock DTB, node sf2@200000 */
	{ }
};
MODULE_DEVICE_TABLE(of, sf2_6764_of_match);

struct platform_driver sf2_6764_driver = {
	.probe	= sf2_6764_probe,
	.remove_new = sf2_6764_remove,
	.driver	= {
		.name		= "sf2_6764",
		.of_match_table	= sf2_6764_of_match,
	},
};
