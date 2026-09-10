// SPDX-License-Identifier: GPL-2.0
/*
 * wlprobe66 - power up the on-chip WLAN cores of the BCM6764 and read back
 * their register windows. This is step one of M4 (virtual PCIe host): before
 * a PCI host bridge is worth building, the two things it depends on have to
 * be shown to work on 6.6:
 *
 *   1. PMC/BPCM power-up of the WLAN units
 *      (vendor: pmc_wlan_power_up(), bcmdrivers/.../misc/pmc/impl1/pmc_wlan.c),
 *   2. CPU access to the radio register windows named by the stock DT nodes
 *      vpcie@0 / vpcie@1, which is exactly the memory the vendor host bridge
 *      hands out as BAR0 (pcie-vcore.c:632-641: bar_1 = of_address_to_resource(np, 0)).
 *
 * DT (stock fdt_96764SV1, kept in our FIT):
 *   vpcie@0: reg = <0x10000000 0x8000000  0xe0000 0x100>, coreid 0, devid 0x603b
 *   vpcie@1: reg = <0x18000000 0x8000000  0xf0000 0x100>, coreid 1, devid 0x6038
 * both under ubus-bus (ranges 0 0 0x80000000 0x70000000), so the translated
 * addresses are 0x90000000 / 0x98000000 (128 MiB each) for the core window and
 * 0x800e0000 / 0x800f0000 for the second (MLO) window.
 *
 * Nothing here writes to the radio. It powers the block and reads.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>

#include <linux/bcma/bcma_driver_chipcommon.h>

#include "../enet66/enet6764.h"
#include "scan.h"			/* kernel tree: drivers/bcma/scan.h, via ccflags -I */

/* stage markers, reset_reason[31:24]; 0xB0..0xBF is free (see enet6764.h map) */
#define MK_WL_ENTER		0xB0
#define MK_WL_NODE		0xB1
#define MK_WL_PMC_PRE		0xB2
#define MK_WL_PMC_OK		0xB3
#define MK_WL_MAP		0xB4
#define MK_WL_READ_PRE		0xB5
#define MK_WL_READ_OK		0xB6
#define MK_WL_EROM_PRE		0xB7
#define MK_WL_EROM_OK		0xB8
#define MK_WL_WRAP_PRE		0xB9
#define MK_WL_WRAP_OK		0xBA
#define MK_WL_ENABLE		0xBB
#define MK_WL_DUMP_PRE		0xBC
#define MK_WL_DUMP_OK		0xBD
#define MK_WL_DONE		0xBF
#define MK_WL_ERR_PMC		0xBE
#define MK_WL_ERR_MAP		0xB1

static int powerup = 1;
module_param(powerup, int, 0444);
MODULE_PARM_DESC(powerup, "run pmc6764_wlan_power_up() before reading (default 1)");

static int words = 32;
module_param(words, int, 0444);
MODULE_PARM_DESC(words, "32-bit words of raw EROM to dump (default 32)");

static int units = 3;
module_param(units, int, 0444);
MODULE_PARM_DESC(units, "bitmask of WLAN units to touch (default 3 = both)");

static int stage = 1;
module_param(stage, int, 0444);
MODULE_PARM_DESC(stage,
	"1 = identification + AI wrapper survey (safe, verified on stock), "
	"2 = additionally walk the EROM (hangs the UBUS on 6.6 as of run #92)");

static uint enable;
module_param(enable, uint, 0444);
MODULE_PARM_DESC(enable,
	"bitmask over the wrapper table: bring those cores out of reset with the "
	"standard AI sequence before the (second) survey");

static uint dump_bp;
module_param(dump_bp, uint, 0444);
MODULE_PARM_DESC(dump_bp,
	"backplane address (unit-0 coordinates) to dump after the survey, 0 = off");

static int dump_words = 16;
module_param(dump_words, int, 0444);
MODULE_PARM_DESC(dump_words, "words to read at dump_bp (default 16)");

static int cc_clken;
module_param(cc_clken, int, 0444);
MODULE_PARM_DESC(cc_clken,
	"before stage 2, set bit 0 (clock enable) in the ChipCommon wrapper ioctl");

/* readback of core window word 0 per unit, for inspection without dmesg */
static u32 chipid[2];
module_param_array(chipid, uint, NULL, 0444);

static void wlprobe_dump(const char *what, void __iomem *base, int off, int n)
{
	char line[8 * 9 + 1];
	int i, j, pos;

	for (i = 0; i < n; i += 8) {
		int cnt = min(8, n - i);

		for (j = 0, pos = 0; j < cnt; j++)
			pos += scnprintf(line + pos, sizeof(line) - pos, " %08x",
					 readl_relaxed(base + off + (i + j) * 4));

		pr_info("wlprobe66:   %s +0x%03x:%s\n", what, off + i * 4, line);
	}
}

/*
 * AI wrapper survey.
 *
 * The wrappers are the only part of the radio backplane that is safe to touch
 * blind: on stock every one of these 16 addresses reads back, while several
 * core register spaces (ChipCommon+0x10, the PMU core at 0x90009000) hang the
 * chip hard enough to reboot it. Addresses come from the EROM read on stock,
 * see WIFI_CORE_MAP.md; they are expressed in the backplane coordinates of
 * unit 0 (base 0x90000000) and rebased per unit here.
 *
 * Register offsets are the bcma AI ones: ioctl 0x408, iostatus 0x40c,
 * resetctl 0x800, resetstatus 0x804 (drivers/bcma/bcma_private.h / scan.c).
 */
#define WL_BP_BASE		0x90000000u

#define AI_IOCTL		0x408
#define AI_IOSTATUS		0x40c
#define AI_RESETCTL		0x800
#define AI_RESETSTATUS		0x804

/* ioctl bits, bcma: SICF_CLOCK_EN / SICF_FGC (drivers/bcma/core.c) */
#define AI_IOCTL_CLK		BIT(0)
#define AI_IOCTL_FGC		BIT(1)

static const struct {
	u32 addr;
	const char *name;
} wl_wrappers[] = {
	{ 0x90100000, "chipcommon mwrap"  },
	{ 0x90101000, "d11 mwrap0"        },
	{ 0x90102000, "d11 mwrap1"        },
	{ 0x90103000, "d11 mwrap2"        },
	{ 0x90104000, "sysbridge mwrap"   },
	{ 0x90105000, "core895 mwrap"     },
	{ 0x90106000, "phy mwrap"         },
	{ 0x90107000, "m2mdma0 mwrap"     },
	{ 0x90108000, "m2mdma1 mwrap"     },
	{ 0x90110000, "d11 swrap1"        },
	{ 0x90111000, "d11 swrap2"        },
	{ 0x90112000, "sysbridge swrap"   },
	{ 0x90113000, "core895 swrap"     },
	{ 0x90114000, "phy swrap"         },
	{ 0x90118000, "interconnect swrap"},
	{ 0x9010f000, "default swrap"     },
};

/* stock reference (radio up), obs/stock-wrappers-2026-09-07.txt: ioctl values */
static const u32 wl_wrap_stock_ioctl[ARRAY_SIZE(wl_wrappers)] = {
	0x00000001, 0x00300935, 0, 0, 0, 0x00000001, 0, 0x00000001,
	0x00000001, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * bcma_core_enable(), drivers/bcma/core.c: clock + forced gated clock on,
 * deassert reset, then drop the forced clock. Only wrapper registers are
 * touched, which run #93 showed to be safe on 6.6 for all 16 wrappers.
 */
static void wlprobe_core_enable(void __iomem *w, const char *name)
{
	u32 ioctl;

	ioctl = readl_relaxed(w + AI_IOCTL);
	writel(ioctl | AI_IOCTL_FGC | AI_IOCTL_CLK, w + AI_IOCTL);
	readl_relaxed(w + AI_IOCTL);

	writel(0, w + AI_RESETCTL);
	readl_relaxed(w + AI_RESETCTL);
	usleep_range(10, 20);

	ioctl = readl_relaxed(w + AI_IOCTL);
	writel((ioctl | AI_IOCTL_CLK) & ~AI_IOCTL_FGC, w + AI_IOCTL);
	readl_relaxed(w + AI_IOCTL);
	usleep_range(10, 20);

	pr_info("wlprobe66:   %-18s enabled: ioctl 0x%08x resetctl 0x%08x rst 0x%08x\n",
		name, readl_relaxed(w + AI_IOCTL),
		readl_relaxed(w + AI_RESETCTL), readl_relaxed(w + AI_RESETSTATUS));
}

static void wlprobe_wrappers(struct resource *core, uint coreid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(wl_wrappers); i++) {
		resource_size_t phys = core->start +
				       (wl_wrappers[i].addr - WL_BP_BASE);
		void __iomem *w;
		u32 ioctl, iost, rctl, rst;

		w = ioremap(phys, PAGE_SIZE);
		if (!w) {
			pr_err("wlprobe66: unit %u %s: ioremap failed\n",
			       coreid, wl_wrappers[i].name);
			continue;
		}

		bcm96764_mark(MK_WL_WRAP_PRE);
		if (enable & (1u << i)) {
			bcm96764_mark(MK_WL_ENABLE);
			wlprobe_core_enable(w, wl_wrappers[i].name);
		}
		ioctl = readl_relaxed(w + AI_IOCTL);
		iost  = readl_relaxed(w + AI_IOSTATUS);
		rctl  = readl_relaxed(w + AI_RESETCTL);
		rst   = readl_relaxed(w + AI_RESETSTATUS);
		bcm96764_mark(MK_WL_WRAP_OK);
		iounmap(w);

		pr_info("wlprobe66:   %pa %-18s ioctl 0x%08x iost 0x%08x resetctl 0x%08x rst 0x%08x%s\n",
			&phys, wl_wrappers[i].name, ioctl, iost, rctl, rst,
			ioctl == wl_wrap_stock_ioctl[i] ? "" : "  <- differs from stock");
	}
}

/*
 * EROM walk. The core window is a bcma-style AXI backplane (ChipCommon word 0
 * reads back with BCMA_CC_ID_TYPE == 1 = AI), so the core map is described by
 * the enumeration ROM whose backplane address lives in ChipCommon+0xFC.
 * Entry format: drivers/bcma/scan.h (SCAN_ER_*, SCAN_CIA_*, SCAN_CIB_*,
 * SCAN_ADDR_*); this is a read-only re-implementation of the parts of
 * bcma_get_next_core() needed to print the table.
 */
static u32 erom_next(void __iomem *erom, int *idx, int max)
{
	if (*idx >= max)
		return SCAN_ER_BAD;
	return readl_relaxed(erom + (*idx)++ * 4);
}

static void wlprobe_erom(void __iomem *erom, int max)
{
	int idx = 0, core = 0;

	while (idx < max) {
		u32 cia, cib, ent;
		int nmp, nsp, nmw, nsw, i;
		int first_addr = 1;

		cia = erom_next(erom, &idx, max);
		if (cia == SCAN_ER_BAD || !(cia & SCAN_ER_VALID))
			break;
		if ((cia & SCAN_ER_TAG) == SCAN_ER_TAG_END)
			break;
		if ((cia & SCAN_ER_TAG) != SCAN_ER_TAG_CI)
			continue;	/* master port / stray address desc */

		cib = erom_next(erom, &idx, max);
		if (cib == SCAN_ER_BAD || !(cib & SCAN_ER_VALID))
			break;

		nmp = (cib & SCAN_CIB_NMP) >> SCAN_CIB_NMP_SHIFT;
		nsp = (cib & SCAN_CIB_NSP) >> SCAN_CIB_NSP_SHIFT;
		nmw = (cib & SCAN_CIB_NMW) >> SCAN_CIB_NMW_SHIFT;
		nsw = (cib & SCAN_CIB_NSW) >> SCAN_CIB_NSW_SHIFT;

		pr_info("wlprobe66:   core %2d: manuf 0x%03x id 0x%03x rev %2d class %d  mp %d sp %d mw %d sw %d\n",
			core,
			(cia & SCAN_CIA_MANUF) >> SCAN_CIA_MANUF_SHIFT,
			(cia & SCAN_CIA_ID) >> SCAN_CIA_ID_SHIFT,
			(cib & SCAN_CIB_REV) >> SCAN_CIB_REV_SHIFT,
			(cia & SCAN_CIA_CLASS) >> SCAN_CIA_CLASS_SHIFT,
			nmp, nsp, nmw, nsw);

		for (i = 0; i < nmp; i++)
			erom_next(erom, &idx, max);	/* master port descriptors */

		/* address descriptors: slave ports, then master/slave wrappers */
		for (i = 0; i < nsp + nmw + nsw + 8; i++) {
			u32 addr, size = 0;

			ent = erom_next(erom, &idx, max);
			if (ent == SCAN_ER_BAD || !(ent & SCAN_ER_VALID) ||
			    (ent & SCAN_ER_TAGX) != SCAN_ER_TAG_ADDR) {
				idx--;			/* push back */
				break;
			}

			addr = ent & SCAN_ADDR_ADDR;
			if (ent & SCAN_ADDR_AG32)
				erom_next(erom, &idx, max);	/* high 32 bits */

			switch (ent & SCAN_ADDR_SZ) {
			case SCAN_ADDR_SZ_SZD:
				size = erom_next(erom, &idx, max);
				if (size & SCAN_SIZE_SG32)
					erom_next(erom, &idx, max);
				size &= SCAN_SIZE_SZ;
				break;
			default:
				size = SCAN_ADDR_SZ_BASE <<
					((ent & SCAN_ADDR_SZ) >> SCAN_ADDR_SZ_SHIFT);
				break;
			}

			pr_info("wlprobe66:     %s port %d addr 0x%08x size 0x%08x%s\n",
				((ent & SCAN_ADDR_TYPE) == SCAN_ADDR_TYPE_SLAVE) ? "slave " :
				((ent & SCAN_ADDR_TYPE) == SCAN_ADDR_TYPE_BRIDGE) ? "bridge" :
				((ent & SCAN_ADDR_TYPE) == SCAN_ADDR_TYPE_MWRAP) ? "mwrap " : "swrap ",
				(ent & SCAN_ADDR_PORT) >> SCAN_ADDR_PORT_SHIFT,
				addr, size, first_addr ? "  <- base" : "");
			first_addr = 0;
		}

		core++;
		if (core > 64)
			break;
	}

	pr_info("wlprobe66:   erom walk stopped after %d core(s), %d word(s)\n", core, idx);
}

static int wlprobe_one(struct device_node *np)
{
	struct resource core, second;
	void __iomem *base, *erom;
	u32 coreid = 0, devid = 0, cc[4], eromptr;
	resource_size_t erom_phys;
	int ret, have_second;

	of_property_read_u32(np, "brcm,coreid", &coreid);
	of_property_read_u32(np, "brcm,devid", &devid);

	if (!(units & (1 << coreid))) {
		pr_info("wlprobe66: %pOFn (coreid %u) skipped by units=0x%x\n",
			np, coreid, units);
		return 0;
	}

	ret = of_address_to_resource(np, 0, &core);
	if (ret) {
		pr_err("wlprobe66: %pOFn has no translatable reg[0]: %d\n", np, ret);
		return ret;
	}
	have_second = of_address_to_resource(np, 1, &second) == 0;

	pr_info("wlprobe66: %pOFn coreid %u devid 0x%04x window %pR\n",
		np, coreid, devid, &core);
	if (have_second)
		pr_info("wlprobe66:   second window %pR\n", &second);

	bcm96764_mark(MK_WL_NODE);

	if (powerup) {
		bcm96764_mark(MK_WL_PMC_PRE);
		ret = pmc6764_wlan_power_up(coreid);
		if (ret) {
			pr_err("wlprobe66: unit %u power-up failed: %d\n", coreid, ret);
			bcm96764_mark(MK_WL_ERR_PMC);
			return ret;
		}
		bcm96764_mark(MK_WL_PMC_OK);
		usleep_range(1000, 2000);
	}

	base = ioremap(core.start, PAGE_SIZE);
	if (!base) {
		pr_err("wlprobe66: cannot map core window at %pa\n", &core.start);
		bcm96764_mark(MK_WL_ERR_MAP);
		return -ENOMEM;
	}
	bcm96764_mark(MK_WL_MAP);

	/*
	 * Run #90 (FACT): on unit 0 the reads at ChipCommon +0x00..+0x0c return
	 * data, +0x10 (OTP status) raises an external abort (0x1008), presumably
	 * because that block has no clock yet. So only the identification words
	 * and the EROM pointer are read here; everything else stays untouched.
	 */
	bcm96764_mark(MK_WL_READ_PRE);
	cc[0] = readl_relaxed(base + 0x00);
	cc[1] = readl_relaxed(base + 0x04);
	cc[2] = readl_relaxed(base + 0x08);
	cc[3] = readl_relaxed(base + 0x0c);
	bcm96764_mark(MK_WL_READ_OK);
	chipid[coreid & 1] = cc[0];

	pr_info("wlprobe66: unit %u chipcommon: id 0x%08x cap 0x%08x corectl 0x%08x bist 0x%08x\n",
		coreid, cc[0], cc[1], cc[2], cc[3]);
	pr_info("wlprobe66: unit %u chip 0x%04x rev %u pkg %u ncores %u type %u\n",
		coreid,
		(cc[0] & BCMA_CC_ID_ID) >> BCMA_CC_ID_ID_SHIFT,
		(cc[0] & BCMA_CC_ID_REV) >> BCMA_CC_ID_REV_SHIFT,
		(cc[0] & BCMA_CC_ID_PKG) >> BCMA_CC_ID_PKG_SHIFT,
		(cc[0] & BCMA_CC_ID_NRCORES) >> BCMA_CC_ID_NRCORES_SHIFT,
		(cc[0] & BCMA_CC_ID_TYPE) >> BCMA_CC_ID_TYPE_SHIFT);

	iounmap(base);

	pr_info("wlprobe66: unit %u AI wrappers:\n", coreid);
	wlprobe_wrappers(&core, coreid);

	if (dump_bp) {
		resource_size_t phys = core.start + (dump_bp - WL_BP_BASE);
		void __iomem *p = ioremap(phys, PAGE_SIZE);

		if (p) {
			pr_info("wlprobe66: unit %u dump of backplane 0x%08x (%pa):\n",
				coreid, dump_bp, &phys);
			bcm96764_mark(MK_WL_DUMP_PRE);
			wlprobe_dump("bp", p, 0, clamp(dump_words, 1, 256));
			bcm96764_mark(MK_WL_DUMP_OK);
			iounmap(p);
		}
	}

	if (stage < 2)
		return 0;

	base = ioremap(core.start, PAGE_SIZE);
	if (!base)
		return -ENOMEM;

	if (cc_clken) {
		void __iomem *w = ioremap(core.start + (0x90100000 - WL_BP_BASE),
					  PAGE_SIZE);

		if (w) {
			u32 v = readl_relaxed(w + AI_IOCTL);

			pr_info("wlprobe66: unit %u cc wrapper ioctl 0x%08x -> 0x%08x\n",
				coreid, v, v | 1);
			writel(v | 1, w + AI_IOCTL);
			readl_relaxed(w + AI_IOCTL);
			iounmap(w);
			usleep_range(1000, 2000);
		}
	}

	bcm96764_mark(MK_WL_EROM_PRE);
	eromptr = readl_relaxed(base + BCMA_CC_EROM);
	iounmap(base);
	pr_info("wlprobe66: unit %u erom pointer 0x%08x\n", coreid, eromptr);

	/*
	 * Run #91 (FACT): both units read the same EROM pointer 0x9010e000, i.e.
	 * the register carries a full SoC address of the core-0 window rather than
	 * the bcma-canonical 0x18000000-based backplane address. Its low bits are
	 * the offset inside the (128 MiB) core window, so each unit's own EROM is
	 * at window.start + (eromptr & (window_size - 1)).
	 */
	erom_phys = core.start + (eromptr & (resource_size(&core) - 1));
	if ((eromptr & ~(resource_size(&core) - 1)) != 0x90000000 &&
	    (eromptr & ~(resource_size(&core) - 1)) != (u32)core.start) {
		pr_err("wlprobe66: erom pointer 0x%08x maps to no known window, not walking\n",
		       eromptr);
		return 0;
	}

	erom = ioremap(erom_phys, PAGE_SIZE);
	if (!erom) {
		pr_err("wlprobe66: cannot map erom at %pa\n", &erom_phys);
		return -ENOMEM;
	}
	pr_info("wlprobe66: unit %u erom at %pa, raw:\n", coreid, &erom_phys);
	wlprobe_dump("erom", erom, 0, words);
	pr_info("wlprobe66: unit %u decoded core map:\n", coreid);
	wlprobe_erom(erom, PAGE_SIZE / 4);
	bcm96764_mark(MK_WL_EROM_OK);
	iounmap(erom);

	return 0;
}

static int __init wlprobe66_init(void)
{
	struct device_node *np;
	int found = 0;

	bcm96764_mark(MK_WL_ENTER);
	pr_info("wlprobe66: powerup=%d words=%d units=0x%x stage=%d cc_clken=%d enable=0x%x\n",
		powerup, words, units, stage, cc_clken, enable);

	if (words < 1 || words > 256)
		words = 32;

	for_each_compatible_node(np, NULL, "brcm,bcm963xx-vpcie") {
		if (!of_device_is_available(np))
			continue;
		found++;
		wlprobe_one(np);
	}

	if (!found)
		pr_err("wlprobe66: no enabled brcm,bcm963xx-vpcie node in DT\n");

	bcm96764_mark(MK_WL_DONE);
	return 0;
}

static void __exit wlprobe66_exit(void)
{
}

module_init(wlprobe66_init);
module_exit(wlprobe66_exit);

MODULE_DESCRIPTION("BCM6764 on-chip WLAN core power-up and register probe");
MODULE_LICENSE("GPL");
