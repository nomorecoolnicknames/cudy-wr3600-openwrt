// SPDX-License-Identifier: GPL-2.0
/*
 * sf2_mdio_local.c - self-contained SF2 MDIO master for the BCM6764.
 *
 * Only built when ENET66B_STANDALONE_MDIO is defined (Kbuild default), so the
 * serdes / external-switch modules can be tested before the SoC-side driver
 * in port66/enet66 exports sf2_mdio_read()/sf2_mdio_write().  Drop the define
 * from Kbuild once the real ones exist.
 *
 * Ported from the vendor U-Boot 2019.07:
 *   drivers/net/bcmbca/phy/mdio_drv_sf2.c      (probe / DT node, clock divider)
 *   drivers/net/bcmbca/phy/mdio_drv_common.c   (cmd + cfg register layout)
 *   drivers/net/bcmbca/bcm_ethsw_phy.c         (the "read twice" quirk)
 *
 * The vendor code uses packed bitfield structs written as one u32; here the
 * same words are built with explicit shifts so endianness and bitfield
 * layout are not left to the compiler.
 */

#ifndef ENET66B_STANDALONE_MDIO
/*
 * Nothing to build: the SoC-side driver in port66/enet66 exports
 * sf2_mdio_read()/sf2_mdio_write()/sf2_mdio_c45_*().  Drop this file from
 * Kbuild, or define ENET66B_STANDALONE_MDIO, to use the copy below instead.
 */
#else

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/mutex.h>

#include "enet66b.h"

/* mdio_cmd, offset 0.  mdio_drv_common.c:50..61 */
#define SF2_MDIO_CMD			0x00
#define  SF2_MDIO_BUSY			BIT(29)
#define  SF2_MDIO_FAIL			BIT(28)
#define  SF2_MDIO_OP_SHIFT		26
#define  SF2_MDIO_PRT_SHIFT		21
#define  SF2_MDIO_DEV_SHIFT		16
#define  SF2_MDIO_DATA_MASK		0xffff

/* mdio_cfg, offset 4.  mdio_drv_common.c:63..73 */
#define SF2_MDIO_CFG			0x04
#define  SF2_MDIO_CFG_CLAUSE		BIT(0)		/* 1 = c22, 0 = c45 */
#define  SF2_MDIO_CFG_DIV_SHIFT		4
#define  SF2_MDIO_CFG_DIV_MASK		(0xffu << 4)
#define  SF2_MDIO_CFG_FREE_RUN		BIT(13)

/* opcodes, mdio_drv_common.c:36..48 */
#define SF2_OP22_WRITE			1
#define SF2_OP22_READ			2
#define SF2_OP45_ADDRESS		0
#define SF2_OP45_WRITE			1
#define SF2_OP45_READ			3

/* mdio_drv_sf2.c:47, DT "clock-divider" default */
#define SF2_MDIO_CLOCK_DIVIDER		12

/*
 * mdio_drv_common.c:24 uses MDIO_BUSY_RETRY = 1000 spins with an optional
 * 1 us delay when the clock divider is > 4 (which it is here: 12).  Same
 * budget, but the loop always terminates.
 */
#define SF2_MDIO_BUSY_RETRY		1000

/*
 * Fallback physical address of the SF2 MDIO window when the device tree has
 * no "brcm,mdio-sf2" node yet.  Only used when the module parameter is set;
 * DT is always preferred.
 */
static unsigned long mdio_base_phys;
module_param(mdio_base_phys, ulong, 0444);
MODULE_PARM_DESC(mdio_base_phys,
		 "physical address of the SF2 MDIO window (0 = take it from the DT node brcm,mdio-sf2)");

static unsigned int clock_divider = SF2_MDIO_CLOCK_DIVIDER;
module_param(clock_divider, uint, 0444);
MODULE_PARM_DESC(clock_divider, "MDIO clock divider (vendor default 12)");

static void __iomem *sf2_mdio;
static DEFINE_MUTEX(sf2_mdio_lock);

static int sf2_mdio_wait(void)
{
	u32 cmd;
	int retry = SF2_MDIO_BUSY_RETRY;

	do {
		cmd = readl(sf2_mdio + SF2_MDIO_CMD);
		if (!(cmd & SF2_MDIO_BUSY))
			break;
		udelay(1);
	} while (--retry);

	if (cmd & SF2_MDIO_BUSY) {
		pr_err_ratelimited("enet66b-mdio: busy stuck, cmd=0x%08x\n", cmd);
		return -ETIMEDOUT;
	}
	if (cmd & SF2_MDIO_FAIL) {
		pr_err_ratelimited("enet66b-mdio: bus fail, cmd=0x%08x\n", cmd);
		return -EIO;
	}
	return 0;
}

static void sf2_mdio_set_clause(bool c22)
{
	u32 cfg = readl(sf2_mdio + SF2_MDIO_CFG);

	if (c22)
		cfg |= SF2_MDIO_CFG_CLAUSE;
	else
		cfg &= ~SF2_MDIO_CFG_CLAUSE;
	writel(cfg, sf2_mdio + SF2_MDIO_CFG);
}

static int sf2_mdio_ready(void)
{
	if (!sf2_mdio) {
		pr_err_ratelimited("enet66b-mdio: not initialised\n");
		return -ENODEV;
	}
	return 0;
}

int sf2_mdio_read(int phy_addr, int reg)
{
	u32 cmd;
	int ret, pass;

	ret = sf2_mdio_ready();
	if (ret)
		return ret;

	mutex_lock(&sf2_mdio_lock);
	sf2_mdio_set_clause(true);

	cmd = ((u32)(phy_addr & 0x1f) << SF2_MDIO_PRT_SHIFT) |
	      ((u32)(reg & 0x1f) << SF2_MDIO_DEV_SHIFT) |
	      ((u32)SF2_OP22_READ << SF2_MDIO_OP_SHIFT);

	/*
	 * bcm_ethsw_phy.c:36 - "Read a second time to ensure it is reliable".
	 * mdio_drv_sf2.c:151 does the same for DSL-based chips.  Keep it.
	 */
	for (pass = 0; pass < 2; pass++) {
		writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
		ret = sf2_mdio_wait();
		if (ret)
			goto out;
	}

	ret = readl(sf2_mdio + SF2_MDIO_CMD) & SF2_MDIO_DATA_MASK;
out:
	mutex_unlock(&sf2_mdio_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf2_mdio_read);

int sf2_mdio_write(int phy_addr, int reg, u16 val)
{
	u32 cmd;
	int ret;

	ret = sf2_mdio_ready();
	if (ret)
		return ret;

	mutex_lock(&sf2_mdio_lock);
	sf2_mdio_set_clause(true);

	cmd = ((u32)(phy_addr & 0x1f) << SF2_MDIO_PRT_SHIFT) |
	      ((u32)(reg & 0x1f) << SF2_MDIO_DEV_SHIFT) |
	      ((u32)SF2_OP22_WRITE << SF2_MDIO_OP_SHIFT) |
	      val;

	writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
	ret = sf2_mdio_wait();

	mutex_unlock(&sf2_mdio_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf2_mdio_write);

/* mdio_drv_common.c:178 - address cycle, then read cycle */
int sf2_mdio_c45_read(int prtad, int devad, u16 reg)
{
	u32 cmd;
	int ret;

	ret = sf2_mdio_ready();
	if (ret)
		return ret;

	mutex_lock(&sf2_mdio_lock);
	sf2_mdio_set_clause(false);

	cmd = ((u32)(prtad & 0x1f) << SF2_MDIO_PRT_SHIFT) |
	      ((u32)(devad & 0x1f) << SF2_MDIO_DEV_SHIFT) |
	      ((u32)SF2_OP45_ADDRESS << SF2_MDIO_OP_SHIFT) | reg;
	writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
	ret = sf2_mdio_wait();
	if (ret)
		goto out;

	cmd = (cmd & ~((u32)3 << SF2_MDIO_OP_SHIFT)) |
	      ((u32)SF2_OP45_READ << SF2_MDIO_OP_SHIFT);
	writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
	ret = sf2_mdio_wait();
	if (ret)
		goto out;

	ret = readl(sf2_mdio + SF2_MDIO_CMD) & SF2_MDIO_DATA_MASK;
out:
	mutex_unlock(&sf2_mdio_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf2_mdio_c45_read);

/* mdio_drv_common.c:207 - address cycle, then write cycle */
int sf2_mdio_c45_write(int prtad, int devad, u16 reg, u16 val)
{
	u32 cmd;
	int ret;

	ret = sf2_mdio_ready();
	if (ret)
		return ret;

	mutex_lock(&sf2_mdio_lock);
	sf2_mdio_set_clause(false);

	cmd = ((u32)(prtad & 0x1f) << SF2_MDIO_PRT_SHIFT) |
	      ((u32)(devad & 0x1f) << SF2_MDIO_DEV_SHIFT) |
	      ((u32)SF2_OP45_ADDRESS << SF2_MDIO_OP_SHIFT) | reg;
	writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
	ret = sf2_mdio_wait();
	if (ret)
		goto out;

	cmd = (cmd & ~(((u32)3 << SF2_MDIO_OP_SHIFT) | SF2_MDIO_DATA_MASK)) |
	      ((u32)SF2_OP45_WRITE << SF2_MDIO_OP_SHIFT) | val;
	writel(cmd | SF2_MDIO_BUSY, sf2_mdio + SF2_MDIO_CMD);
	ret = sf2_mdio_wait();
out:
	mutex_unlock(&sf2_mdio_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sf2_mdio_c45_write);

static int __init sf2_mdio_local_init(void)
{
	struct device_node *np;
	u32 div = clock_divider;
	u32 cfg;

	np = of_find_compatible_node(NULL, NULL, "brcm,mdio-sf2");
	if (np) {
		of_property_read_u32(np, "clock-divider", &div);
		sf2_mdio = of_iomap(np, 0);
		of_node_put(np);
		if (!sf2_mdio) {
			pr_err("enet66b-mdio: of_iomap(brcm,mdio-sf2) failed\n");
			return -ENOMEM;
		}
	} else if (mdio_base_phys) {
		sf2_mdio = ioremap(mdio_base_phys, 0x10);
		if (!sf2_mdio) {
			pr_err("enet66b-mdio: ioremap(0x%lx) failed\n",
			       mdio_base_phys);
			return -ENOMEM;
		}
		pr_warn("enet66b-mdio: no DT node, using mdio_base_phys=0x%lx\n",
			mdio_base_phys);
	} else {
		pr_err("enet66b-mdio: no brcm,mdio-sf2 node and no mdio_base_phys\n");
		return -ENODEV;
	}

	/* mdio_cfg_set(): free-running clock on, program the divider */
	cfg = readl(sf2_mdio + SF2_MDIO_CFG);
	cfg |= SF2_MDIO_CFG_FREE_RUN;
	if (div) {
		cfg &= ~SF2_MDIO_CFG_DIV_MASK;
		cfg |= (div << SF2_MDIO_CFG_DIV_SHIFT) & SF2_MDIO_CFG_DIV_MASK;
	}
	writel(cfg, sf2_mdio + SF2_MDIO_CFG);

	pr_info("enet66b-mdio: ready, cfg=0x%08x (divider %u)\n", cfg, div);
	return 0;
}

static void __exit sf2_mdio_local_exit(void)
{
	if (sf2_mdio) {
		iounmap(sf2_mdio);
		sf2_mdio = NULL;
	}
}

module_init(sf2_mdio_local_init);
module_exit(sf2_mdio_local_exit);

MODULE_DESCRIPTION("BCM6764 SF2 MDIO master (standalone, enet66b)");
MODULE_LICENSE("GPL");

#endif /* ENET66B_STANDALONE_MDIO */
