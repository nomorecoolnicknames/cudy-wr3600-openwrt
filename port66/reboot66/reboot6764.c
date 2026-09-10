// SPDX-License-Identifier: GPL-2.0-only
/*
 * reboot6764 - restart handler for BCM6764 (Cudy WR3600).
 *
 * Vanilla 6.6 has no reset driver for this SoC. The PSCI SYSTEM_RESET path
 * hangs the board (ATF never returns and never resets), and the vendor reset
 * is the on-chip watchdog at periph+0x480 (DT "brcm,bcm96xxx-wdt").
 *
 * Facts established on hardware (netcon-final.log):
 *  - arch/arm/mach-bcm/bcm96764.c keeps the WDT alive: every 5 s it writes
 *    VAL=50MHz*80 (=0xEE6B2800) + 0xff00/0x00ff. When its deadline expires it
 *    stops kicking and the WDT resets the SoC ("letting the WDT reset").
 *  - machine_restart() runs with IRQs off and secondaries stopped, so that
 *    kicker cannot overwrite our programming.
 *  - Tiny VALs (50 ticks / 2 ms) never fire; VAL from the kicker (80 s) does.
 *    Observed reset ~43 s after an 80 s programming => WDT clock ~93.75 MHz,
 *    so use a comfortably large value and wait.
 *
 * Sequence: stop (0xee00/0x00ee) -> VAL -> start (0xff00/0x00ff).
 * Return NOTIFY_STOP so the broken PSCI handler never runs; if the WDT still
 * has not fired after 6 s, machine_restart() prints "Reboot failed" and halts
 * (needs a power cycle) - that is the safe failure mode.
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/reboot.h>
#include <linux/delay.h>

#define WDT_VAL_REG	0x0
#define WDT_CTL_REG	0x4
#define WDT_STOP_1	0xee00
#define WDT_STOP_2	0x00ee
#define WDT_START_1	0xff00
#define WDT_START_2	0x00ff

/* Exactly what arch/arm/mach-bcm/bcm96764.c kicks with and what is proven
 * to reset this SoC in netcon-final.log. Small values (50 ticks, 2 ms,
 * 250 M) wedged the WDT without ever firing; do not deviate. */
#define WDT_TIMEOUT_TICKS	4000000000U

static void __iomem *wdt_base;
static struct clk *wdt_clk;

/* selftest=1: program a 5 s timeout, sample VAL twice, stop again.
 * Proves the register block is mapped/writable without resetting the board.
 * (Note: the mach-bcm kicker re-arms VAL every 5 s, so samples may differ.) */
static bool selftest;
module_param(selftest, bool, 0444);
MODULE_PARM_DESC(selftest, "sample the watchdog registers and stop (no reset)");

static int bcm6764_restart(struct notifier_block *nb, unsigned long action,
			   void *data)
{
	if (!wdt_base)
		return NOTIFY_DONE;

	/* The mach-bcm driver (arch/arm/mach-bcm/bcm96764.c) arms the watchdog
	 * from its reboot notifier, i.e. before device_shutdown() - that is what
	 * actually resets the SoC here, because a hung vendor shutdown hook or
	 * the broken PSCI path would otherwise leave the board dead. All this
	 * handler has to do is make sure the PSCI SYSTEM_RESET path never runs:
	 * returning NOTIFY_STOP does that. */
	pr_emerg("reboot6764: restart handler, WDT armed by bcm96764, PSCI suppressed\n");
	return NOTIFY_STOP;
}

static struct notifier_block bcm6764_restart_nb = {
	.notifier_call = bcm6764_restart,
	.priority = 200,
};

static int __init reboot6764_init(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, "brcm,bcm96xxx-wdt");
	if (!np)
		np = of_find_compatible_node(NULL, NULL, "brcm,bcm6345-wdt");
	if (!np)
		return -ENODEV;
	wdt_base = of_iomap(np, 0);
	wdt_clk = of_clk_get(np, 0);
	of_node_put(np);
	if (!wdt_base)
		return -ENOMEM;
	if (!IS_ERR(wdt_clk))
		clk_prepare_enable(wdt_clk);
	else
		wdt_clk = NULL;

	if (selftest) {
		u32 v0, v1, v2;

		writel(WDT_TIMEOUT_TICKS, wdt_base + WDT_VAL_REG);
		writel(WDT_START_1, wdt_base + WDT_CTL_REG);
		writel(WDT_START_2, wdt_base + WDT_CTL_REG);
		v0 = readl(wdt_base + WDT_VAL_REG);
		mdelay(1500);
		v1 = readl(wdt_base + WDT_VAL_REG);
		mdelay(1500);
		v2 = readl(wdt_base + WDT_VAL_REG);
		writel(WDT_STOP_1, wdt_base + WDT_CTL_REG);
		writel(WDT_STOP_2, wdt_base + WDT_CTL_REG);
		pr_info("reboot6764: selftest rate=%lu armed=%lu samples %u %u %u\n",
			wdt_clk ? clk_get_rate(wdt_clk) : 0,
			(unsigned long)WDT_TIMEOUT_TICKS, v0, v1, v2);
	}

	if (register_restart_handler(&bcm6764_restart_nb))
		return -EINVAL;
	pr_info("reboot6764: registered (clk %s)\n", wdt_clk ? "on" : "none");
	return 0;
}

static void __exit reboot6764_exit(void)
{
	unregister_restart_handler(&bcm6764_restart_nb);
	if (wdt_base)
		iounmap(wdt_base);
}

module_init(reboot6764_init);
module_exit(reboot6764_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BCM6764 watchdog-based restart handler");
