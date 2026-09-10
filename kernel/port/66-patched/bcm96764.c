// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal machine shim for Broadcom BCM6764 / BCM96764 (Cudy WR3600 V1)
 * plus the no-UART "stage marker" channel.
 *
 * Marker channel: the bootstate "reset_reason" register (periph
 * 0xff800000 + 0x2628) survives a SW reset; TPL/U-Boot/stock Linux only
 * RMW bits [23:0], so bits [31:24] are ours. Stock Linux reads them back
 * after the fallback boot via obs/bootmark.ko (/proc/bootmark).
 *
 * Safety: bits [7:0] must read LINUX_RUN|WATCHDOG (0x34) before any SW
 * reset, otherwise TPL treats the image as crashed and re-selects it; bit 0
 * (ACTIVATE) must be 0 or TPL boots the non-committed slot again.
 *
 * Ladder: 0x11 init_early, 0x12 arch_initcall, 0x13 late_initcall,
 *         0x20.. userspace (/init via devmem), 0xEE panic.
 */
#include <linux/io.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/panic.h>
#include <linux/panic_notifier.h>
#include <linux/notifier.h>
#include <linux/sizes.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>

#define BCM96764_RESET_REASON_PHYS	0xff802628UL
#define BCM96764_MARK_MASK		0xff000000U
#define BCM96764_STEADY_STATE		0x34U	/* LINUX_RUN | WATCHDOG */

/* brcm,bcm6345-wdt @ periph+0x480, 50 MHz (stock DTB timeout-sec = 80).
 * U-Boot never arms it; we arm it once so a hang in this kernel becomes a
 * warm reset into the committed stock slot instead of a dead box. */
#define BCM96764_WDT_PHYS		0xff800480UL
#define BCM96764_WDT_HZ			50000000U
#define BCM96764_WDT_SECS		80U
#define WDT_VAL_REG			0x0
#define WDT_CTL_REG			0x4
#define WDT_CTL_START1			0xff00U
#define WDT_CTL_START2			0x00ffU

/* Static section mapping of the whole periph block (UART, WDT, bootstate).
 * Same virtual address as the DEBUG_LL early section, so markers work from
 * __enable_mmu onward; map_io re-creates it in devicemaps_init. */
#define BCM96764_PERIPH_PHYS	0xff800000UL
#define BCM96764_PERIPH_VIRT	0xfc800000UL
#define PERIPH_VIRT(p)	((void __iomem *)(BCM96764_PERIPH_VIRT + ((p) - BCM96764_PERIPH_PHYS)))

static struct map_desc bcm96764_io_desc[] __initdata = {
	{
		.virtual = BCM96764_PERIPH_VIRT,
		.pfn = __phys_to_pfn(BCM96764_PERIPH_PHYS),
		.length = SZ_1M,
		.type = MT_DEVICE,
	},
};

static void __init bcm96764_map_io(void)
{
	iotable_init(bcm96764_io_desc, ARRAY_SIZE(bcm96764_io_desc));
}

static void __iomem *bcm96764_rr = PERIPH_VIRT(BCM96764_RESET_REASON_PHYS);

static void bcm96764_mark_io(void __iomem *rr, u8 stage)
{
	u32 v = readl_relaxed(rr);
	int i;

	v = (v & ~BCM96764_MARK_MASK) | ((u32)stage << 24);
	for (i = 0; i < 16; i++) {
		writel_relaxed(v, rr);
		dsb(sy);
		if (readl_relaxed(rr) == v)
			break;
	}
}

void bcm96764_mark(u8 stage)
{
	if (bcm96764_rr)
		bcm96764_mark_io(bcm96764_rr, stage);
}
EXPORT_SYMBOL_GPL(bcm96764_mark);

static void __init bcm96764_init_early(void)
{
	void __iomem *rr = bcm96764_rr;
	void __iomem *wdt = PERIPH_VIRT(BCM96764_WDT_PHYS);
	u32 v;

	/* keep [23:8] (old reason / img id / failed count / bit22),
	 * clear ACTIVATE, declare steady state so TPL never falls back to us */
	v = (readl_relaxed(rr) & 0x00ffff00U) | BCM96764_STEADY_STATE;
	writel_relaxed(v, rr);
	dsb(sy);
	bcm96764_mark_io(rr, 0x1C);

	panic_timeout = 5;	/* panic -> SW reset -> stock slot, marker kept */

	/* arm the hardware watchdog: hang -> reset -> stock slot, marker kept */
	writel_relaxed(BCM96764_WDT_HZ * BCM96764_WDT_SECS, wdt + WDT_VAL_REG);
	writel_relaxed(WDT_CTL_START1, wdt + WDT_CTL_REG);
	writel_relaxed(WDT_CTL_START2, wdt + WDT_CTL_REG);
	dsb(sy);
}

static int bcm96764_panic(struct notifier_block *nb, unsigned long ev, void *p)
{
	bcm96764_mark(0xEE);
	return NOTIFY_DONE;
}

static struct notifier_block bcm96764_panic_nb = {
	.notifier_call = bcm96764_panic,
	.priority = INT_MAX,
};

/* Keep the hardware watchdog fed while the kernel is alive. It was armed once
 * in init_early and never restarted; the effective period turned out to be
 * ~40 s (runs #60..#65 were cut mid-init), so re-arm it every 5 s. A hard
 * hang still resets the box within one period. */
static struct timer_list bcm96764_wdt_timer;

/* Safety deadline: stop kicking after this many seconds after boot, so a
 * userspace that came up but cannot be reached (no SSH) still falls back to
 * the committed stock slot via the watchdog instead of needing a power cycle.
 * Extend from userspace by writing seconds to /proc/bcm96764_wdt_kick_secs. */
static unsigned long bcm96764_wdt_kick_secs = 600;

static void bcm96764_wdt_kick(struct timer_list *t)
{
	void __iomem *wdt = PERIPH_VIRT(BCM96764_WDT_PHYS);

	if (time_after(jiffies, INITIAL_JIFFIES + bcm96764_wdt_kick_secs * HZ)) {
		pr_warn("bcm96764: watchdog kick deadline reached, letting the WDT reset\n");
		return;
	}

	writel_relaxed(BCM96764_WDT_HZ * BCM96764_WDT_SECS, wdt + WDT_VAL_REG);
	writel_relaxed(WDT_CTL_START1, wdt + WDT_CTL_REG);
	writel_relaxed(WDT_CTL_START2, wdt + WDT_CTL_REG);
	dsb(sy);
	mod_timer(&bcm96764_wdt_timer, jiffies + 5 * HZ);
}

#include <linux/proc_fs.h>
#include <linux/uaccess.h>
static ssize_t bcm96764_wdt_secs_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
	char tmp[16];
	unsigned long v;

	if (len >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, len))
		return -EFAULT;
	tmp[len] = 0;
	if (kstrtoul(tmp, 0, &v))
		return -EINVAL;
	bcm96764_wdt_kick_secs = v;
	if (!timer_pending(&bcm96764_wdt_timer))
		mod_timer(&bcm96764_wdt_timer, jiffies + HZ);
	pr_info("bcm96764: watchdog kick deadline set to %lu s after boot\n", v);
	return len;
}
static const struct proc_ops bcm96764_wdt_secs_ops = {
	.proc_write = bcm96764_wdt_secs_write,
};

static int __init bcm96764_mark_arch_init(void)
{
	proc_create("bcm96764_wdt_kick_secs", 0200, NULL, &bcm96764_wdt_secs_ops);
	atomic_notifier_chain_register(&panic_notifier_list, &bcm96764_panic_nb);
	timer_setup(&bcm96764_wdt_timer, bcm96764_wdt_kick, 0);
	mod_timer(&bcm96764_wdt_timer, jiffies + 5 * HZ);
	bcm96764_mark(0x1D);
	pr_info("bcm96764: marker channel up, reset_reason=%08x\n",
		readl_relaxed(bcm96764_rr));
	return 0;
}
arch_initcall(bcm96764_mark_arch_init);

static int __init bcm96764_mark_late_init(void)
{
	bcm96764_mark(0x1E);
	return 0;
}
late_initcall_sync(bcm96764_mark_late_init);

static const char *const bcm96764_dt_compat[] __initconst = {
	"brcm,bcm96764",
	NULL,
};

DT_MACHINE_START(BCM96764, "Broadcom BCM96764 (minimal bring-up)")
	.l2c_aux_val	= 0,
	.l2c_aux_mask	= ~0,
	.dt_compat	= bcm96764_dt_compat,
	.map_io		= bcm96764_map_io,
	.init_early	= bcm96764_init_early,
MACHINE_END
