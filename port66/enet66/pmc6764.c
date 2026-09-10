// SPDX-License-Identifier: GPL-2.0
/*
 * BCM6764 PMC: BPCM register access over the procmon PMB keyhole, and
 * power-up of the Ethernet switch block.
 *
 * This is a direct port of the PMC_IMPL_3_X path of the vendor kernel driver
 * at bcmdrivers/opensource/misc/pmc/impl1/pmc_drv.c. Line numbers quoted in
 * the comments refer to that file unless stated otherwise.
 *
 * The earlier draft (port66/sysport/pmc6764.c) used the pre-3.x "PMBM[bus]"
 * window with a hardcoded base, rd_data at +8 and op codes 2/1; all of that
 * is wrong for this SoC. Everything here is taken from the 6764 headers.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>

#include "enet6764.h"

struct pmc6764 {
	struct device	*dev;
	void __iomem	*procmon;
	u32		num_regs;	/* PmbBus.config[29:20], the per-device
					 * register stride used to build a PMB
					 * address (pmc_drv.c:316) */
	spinlock_t	lock;		/* serialises keyhole transactions */
};

static struct pmc6764 *g_pmc;

/* We use keyhole 0, matching read_bpcm_reg_direct()/write_bpcm_reg_direct()
 * (pmc_drv.c:365-378), which pass keyhole_idx 0.
 */
#define PMC_KEYHOLE_IDX		0

/* The reference spins on BUSY with no bound (pmc_drv.c:322-323, 356-357).
 * A PMB transaction completes in well under a microsecond; bound it at 1 ms
 * so a dead block cannot wedge the CPU inside a spinlock.
 */
#define PMB_BUSY_POLLS		1000

bool pmc6764_ready(void)
{
	return g_pmc != NULL;
}

static int pmb_wait_done(struct pmc6764 *pmc, void __iomem *kh, u32 *ctl_out)
{
	u32 ctl;
	int i;

	for (i = 0; i < PMB_BUSY_POLLS; i++) {
		ctl = readl(kh + KH_CONTROL);
		if (!(ctl & PMC_PMBM_BUSY)) {
			*ctl_out = ctl;
			return 0;
		}
		udelay(1);
	}
	return -ETIMEDOUT;
}

/*
 * pmc_drv.c:315-317 -- the PMB address is the device index scaled by the bus
 * register stride, OR'ed with the 32-bit word offset inside the device.
 * The bus id lives in bits 13:12 of devAddr (pmc_addr.h:38) and is placed in
 * the control word at bit 20 (pmc.h:197), not in the address.
 */
static u32 pmb_address(struct pmc6764 *pmc, int dev_addr, int word)
{
	return ((u32)(dev_addr & 0xff) * pmc->num_regs) | (u32)word;
}

static int pmb_bus(int dev_addr)
{
	return (dev_addr >> PMB_BUS_ID_SHIFT) & 0x3;	/* pmc_drv.c:303 */
}

int pmc6764_read_bpcm(int dev_addr, int word, u32 *val)
{
	struct pmc6764 *pmc = g_pmc;
	void __iomem *kh;
	unsigned long flags;
	u32 ctl;
	int ret;

	if (!pmc)
		return -ENODEV;

	kh = pmc->procmon + PMB_KEYHOLE(PMC_KEYHOLE_IDX);

	spin_lock_irqsave(&pmc->lock, flags);
	/* pmc_drv.c:319-320 */
	writel(PMC_PMBM_START | (pmb_bus(dev_addr) << PMC_PMBM_BUS_SHIFT) |
	       PMC_PMBM_READ | pmb_address(pmc, dev_addr, word),
	       kh + KH_CONTROL);
	ret = pmb_wait_done(pmc, kh, &ctl);
	if (!ret) {
		if (ctl & PMC_PMBM_TIMEOUT)		/* pmc_drv.c:325 */
			ret = -ETIMEDOUT;
		else
			*val = readl(kh + KH_RD_DATA);	/* pmc_drv.c:328 */
	}
	spin_unlock_irqrestore(&pmc->lock, flags);

	if (ret)
		dev_err(pmc->dev, "BPCM read dev 0x%x word %d failed (%d)\n",
			dev_addr, word, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(pmc6764_read_bpcm);

int pmc6764_write_bpcm(int dev_addr, int word, u32 val)
{
	struct pmc6764 *pmc = g_pmc;
	void __iomem *kh;
	unsigned long flags;
	u32 ctl;
	int ret;

	if (!pmc)
		return -ENODEV;

	kh = pmc->procmon + PMB_KEYHOLE(PMC_KEYHOLE_IDX);

	spin_lock_irqsave(&pmc->lock, flags);
	/* pmc_drv.c:351-353: wr_data first, then the command word. */
	writel(val, kh + KH_WR_DATA);
	writel(PMC_PMBM_START | (pmb_bus(dev_addr) << PMC_PMBM_BUS_SHIFT) |
	       PMC_PMBM_WRITE | pmb_address(pmc, dev_addr, word),
	       kh + KH_CONTROL);
	ret = pmb_wait_done(pmc, kh, &ctl);
	if (!ret && (ctl & PMC_PMBM_TIMEOUT))		/* pmc_drv.c:359 */
		ret = -ETIMEDOUT;
	spin_unlock_irqrestore(&pmc->lock, flags);

	if (ret)
		dev_err(pmc->dev, "BPCM write dev 0x%x word %d failed (%d)\n",
			dev_addr, word, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(pmc6764_write_bpcm);

/* PowerOnZone(), pmc_drv.c:832-863 */
static int pmc6764_power_on_zone(int dev_addr, int zone)
{
	u32 ctrl, sts;
	int ret;

	ret = pmc6764_read_bpcm(dev_addr, BPCM_W_ZONE_CTRL(zone), &ctrl);
	if (ret)
		return ret;
	ret = pmc6764_read_bpcm(dev_addr, BPCM_W_ZONE_STATUS(zone), &sts);
	if (ret)
		return ret;

	if (sts & ZONE_STS_PWR_ON_STATE) {
		dev_info(g_pmc->dev, "BPCM 0x%x zone %d already powered\n",
			 dev_addr, zone);
		return 0;
	}

	ctrl &= ~ZONE_CTRL_PWR_DN_REQ;
	ctrl |= ZONE_CTRL_DPG_CTL_EN | ZONE_CTRL_PWR_UP_REQ |
		ZONE_CTRL_MEM_PWR_CTL_EN | ZONE_CTRL_BLK_RESET_ASSERT;

	return pmc6764_write_bpcm(dev_addr, BPCM_W_ZONE_CTRL(zone), ctrl);
}

/* PowerOnDevice(), pmc_drv.c:775-799: read the capabilities register for the
 * zone count, then bring every zone up.
 */
static int pmc6764_power_on_device(int dev_addr)
{
	u32 caps;
	int zones, z, ret;

	ret = pmc6764_read_bpcm(dev_addr, BPCM_W_CAPABILITIES, &caps);
	if (ret)
		return ret;

	zones = caps & BPCM_CAP_NUM_ZONES_MASK;
	dev_info(g_pmc->dev, "BPCM 0x%x capabilities 0x%08x, %d zone(s)\n",
		 dev_addr, caps, zones);

	if (zones == 0 || zones > 32) {
		dev_err(g_pmc->dev, "BPCM 0x%x reports implausible zone count %d\n",
			dev_addr, zones);
		return -EIO;
	}

	for (z = 0; z < zones; z++) {
		ret = pmc6764_power_on_zone(dev_addr, z);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Wait until a zone reports pwr_on_state. The vendor code never waits; we do,
 * because this readback is what stage marker 0x61 asserts.
 */
static int pmc6764_wait_zone_powered(int dev_addr, int zone)
{
	u32 sts;
	int i, ret;

	for (i = 0; i < 500; i++) {		/* <= 50 ms */
		ret = pmc6764_read_bpcm(dev_addr, BPCM_W_ZONE_STATUS(zone), &sts);
		if (ret)
			return ret;
		if (sts & ZONE_STS_PWR_ON_STATE)
			return 0;
		usleep_range(100, 200);
	}
	dev_err(g_pmc->dev, "BPCM 0x%x zone %d not powered, status 0x%08x\n",
		dev_addr, zone, sts);
	return -ETIMEDOUT;
}

/* pmc_switch_power_up(), pmc_switch.c:96-99 (U-Boot copy), kernel copy pmc_switch.c:109-112 */
/*
 * pmc_wlan_power_up(), KD/misc/pmc/impl1/pmc_wlan.c:72-105 (GPL copy
 * bcmdrivers/opensource/misc/pmc/impl1/pmc_wlan.c). Per WLAN unit the vendor
 * walks its BPCM list, calls PowerOnDevice() and then clears sr_control (all
 * soft resets deasserted). On 6764 the list has a single entry per unit.
 *
 * Two vendor steps are deliberately not replicated here:
 *   - the 947622 A0 RF-clock workaround (different chip),
 *   - ubus_master_remap_port(UBUS_PORT_ID_WIFI{,1}) under
 *     CONFIG_BCM_UBUS_DECODE_REMAP, which points the radio master's DDR
 *     decode window at the BIU (coherent) port. We have no UBUS driver on 6.6
 *     yet; DMA is therefore left with whatever decode the bootloader
 *     programmed, and the radio driver must use non-coherent DMA mappings.
 */
static const int pmc6764_wlan_pmb[] = { PMB_ADDR_WLAN0, PMB_ADDR_WLAN1 };

int pmc6764_wlan_power_up(int unit)
{
	int addr, ret;

	if (!g_pmc)
		return -ENODEV;
	if (unit < 0 || unit >= ARRAY_SIZE(pmc6764_wlan_pmb))
		return -EINVAL;

	addr = pmc6764_wlan_pmb[unit];

	ret = pmc6764_power_on_device(addr);
	if (ret)
		return ret;

	ret = pmc6764_wait_zone_powered(addr, 0);
	if (ret)
		return ret;

	ret = pmc6764_write_bpcm(addr, BPCM_W_SR_CONTROL, 0);
	if (ret)
		return ret;

	dev_info(g_pmc->dev, "WLAN unit %d (BPCM 0x%x) powered up\n", unit, addr);
	return 0;
}
EXPORT_SYMBOL_GPL(pmc6764_wlan_power_up);

int pmc6764_wlan_power_down(int unit)
{
	int addr;

	if (!g_pmc)
		return -ENODEV;
	if (unit < 0 || unit >= ARRAY_SIZE(pmc6764_wlan_pmb))
		return -EINVAL;

	addr = pmc6764_wlan_pmb[unit];

	/* vendor asserts every soft reset before removing power */
	return pmc6764_write_bpcm(addr, BPCM_W_SR_CONTROL, 1);
}
EXPORT_SYMBOL_GPL(pmc6764_wlan_power_down);

int pmc6764_switch_power_up(void)
{
	int ret;

	if (!g_pmc)
		return -ENODEV;

	ret = pmc6764_power_on_device(PMB_ADDR_SWITCH);
	if (ret) {
		bcm96764_mark(MK_ERR_PMC_KEYHOLE);
		return ret;
	}

	ret = pmc6764_wait_zone_powered(PMB_ADDR_SWITCH, 0);
	if (ret) {
		bcm96764_mark(MK_ERR_PMC_ZONE);
		return ret;
	}

	dev_info(g_pmc->dev, "switch block powered up\n");
	bcm96764_mark(MK_SWITCH_POWERED);
	return 0;
}

/*
 * pmc_sysport_reset_system_port(), pmc_switch.c:123-147 (U-Boot copy port66/pmc_switch.c) (guarded by
 * IS_BCMCHIP(6764), so this path is compiled for this SoC in the vendor tree).
 * The SYSTEMPORT hangs off zone 3 of the switch BPCM; its soft reset is
 * sr_control bit 3, pulsed high then low.
 *
 * Not called on the normal init path: U-Boot's sysport probe does not reset
 * the block either, it only does so on remove (bcmbca_sysport_v2.c:644-647).
 * Exposed so the netdev teardown path can use it.
 */
int pmc6764_sysport_reset(void)
{
	u32 reg;
	int ret;

	if (!g_pmc)
		return -ENODEV;

	ret = pmc6764_read_bpcm(PMB_ADDR_SWITCH, BPCM_W_SR_CONTROL, &reg);
	if (ret)
		return ret;

	ret = pmc6764_write_bpcm(PMB_ADDR_SWITCH, BPCM_W_SR_CONTROL,
				 reg | BPCM_SR_SYSPORT_BIT);
	if (ret)
		return ret;

	return pmc6764_write_bpcm(PMB_ADDR_SWITCH, BPCM_W_SR_CONTROL,
				  reg & ~BPCM_SR_SYSPORT_BIT);
}

static int pmc6764_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pmc6764 *pmc;
	u32 config;

	pmc = devm_kzalloc(dev, sizeof(*pmc), GFP_KERNEL);
	if (!pmc)
		return -ENOMEM;

	pmc->dev = dev;
	spin_lock_init(&pmc->lock);

	/* DT: pmc node, reg-names "pmc","procmon","maestro","itcm","dtcm";
	 * "procmon" is 0x320000 under periph (ranges 0 0 0xff800000 0x400000),
	 * i.e. physical 0xffb20000. The vendor kernel maps exactly this
	 * resource by name (pmc_drv_dt.c:167-174).
	 */
	pmc->procmon = devm_platform_ioremap_resource_byname(pdev, "procmon");
	if (IS_ERR(pmc->procmon)) {
		dev_err(dev, "cannot map procmon window\n");
		bcm96764_mark(MK_ERR_PMC_MAP);
		return PTR_ERR(pmc->procmon);
	}

	config = readl(pmc->procmon + PMB_CONFIG);
	pmc->num_regs = (config >> PMB_NUM_REGS_SHIFT) & PMB_NUM_REGS_MASK;

	dev_info(dev, "procmon at %p, PMB config 0x%08x, num_regs %u\n",
		 pmc->procmon, config, pmc->num_regs);

	/* A dead or unmapped block reads as 0x00000000 or 0xffffffff; either
	 * would produce a bogus PMB address stride.
	 */
	if (config == 0 || config == 0xffffffff || pmc->num_regs == 0) {
		dev_err(dev, "PMB config register is not plausible\n");
		bcm96764_mark(MK_ERR_PMC_CONFIG);
		return -EIO;
	}

	g_pmc = pmc;
	bcm96764_mark(MK_PMC_PROBE);
	return 0;
}

static void pmc6764_remove(struct platform_device *pdev)
{
	g_pmc = NULL;
}

static const struct of_device_id pmc6764_of_match[] = {
	{ .compatible = "brcm,bca-pmc-3-2" },	/* stock DTB, node "pmc" */
	{ }
};
MODULE_DEVICE_TABLE(of, pmc6764_of_match);

struct platform_driver pmc6764_driver = {
	.probe	= pmc6764_probe,
	.remove_new = pmc6764_remove,
	.driver	= {
		.name		= "pmc6764",
		.of_match_table	= pmc6764_of_match,
	},
};
