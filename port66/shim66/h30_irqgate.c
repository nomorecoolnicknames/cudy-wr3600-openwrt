// SPDX-License-Identifier: GPL-2.0-only
/* Diagnostic only: prevent first request_irq from enabling the two radio
 * banks. Use IRQ_NOAUTOEN so Linux and the GIC agree about disabled state.
 * No radio MMIO. Load after vpcie66, before any vendor module. Reboot to
 * discard this experiment; deliberately no module_exit/unload path. */
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/timer.h>
#include <linux/irqdesc.h>

static unsigned int lines[20];
static bool released[20], ready;

static int release_set(const char *val, const struct kernel_param *kp)
{
	unsigned int irq, i;
	int ret = kstrtouint(val, 0, &irq);

	if (ret || !ready)
		return ret ? ret : -EAGAIN;
	for (i = 0; i < ARRAY_SIZE(lines); i++) {
		if (lines[i] != irq)
			continue;
		if (released[i] || !irq_has_action(irq))
			return -EINVAL;
		pr_info("H30_IRQ release virq=%u hwirq=%lu\n", irq,
			irq_get_irq_data(irq)->hwirq);
		irq_clear_status_flags(irq, IRQ_NOAUTOEN);
		released[i] = true;
		enable_irq(irq);
		pr_info("H30_IRQ release returned virq=%u\n", irq);
		return 0;
	}
	return -ENOENT;
}

static int inspect_set(const char *val, const struct kernel_param *kp)
{
	unsigned int i;

	if (!ready)
		return -EAGAIN;
	for (i = 0; i < ARRAY_SIZE(lines); i++) {
		bool pending = false, active = false, masked = false;
		int p = irq_get_irqchip_state(lines[i], IRQCHIP_STATE_PENDING, &pending);
		int a = irq_get_irqchip_state(lines[i], IRQCHIP_STATE_ACTIVE, &active);
		int m = irq_get_irqchip_state(lines[i], IRQCHIP_STATE_MASKED, &masked);

		pr_info("H30_IRQ virq=%u hwirq=%lu action=%d released=%d pending=%d/%d active=%d/%d masked=%d/%d\n",
			lines[i], irq_get_irq_data(lines[i])->hwirq,
			irq_has_action(lines[i]), released[i], pending, p,
			active, a, masked, m);
	}
	return 0;
}
static const struct kernel_param_ops release_ops = { .set = release_set };
static const struct kernel_param_ops inspect_ops = { .set = inspect_set };
module_param_cb(release, &release_ops, NULL, 0200);
module_param_cb(inspect, &inspect_ops, NULL, 0200);

static struct timer_list watch_timer;
static bool watch;
module_param(watch, bool, 0644);
MODULE_PARM_DESC(watch, "periodic H30_IRQ WATCH dumps (debug, default off)");
static void watch_tick(struct timer_list *timer)
{
	unsigned int i, cpu, attached = 0;

	for (i = 0; i < ARRAY_SIZE(lines); i++) {
		unsigned int total = 0;
		bool masked = false;

		if (!irq_has_action(lines[i]))
			continue;
		attached++;
		for_each_possible_cpu(cpu)
			total += READ_ONCE(*per_cpu_ptr(
				container_of(irq_get_irq_data(lines[i]),
				struct irq_desc, irq_data)->kstat_irqs, cpu));
		irq_get_irqchip_state(lines[i], IRQCHIP_STATE_MASKED, &masked);
		pr_info("H30_IRQ WATCH virq=%u hwirq=%lu count=%u masked=%u released=%u\n",
			lines[i], irq_get_irq_data(lines[i])->hwirq,
			total, masked, released[i]);
	}
	pr_info("H30_IRQ WATCH active-handlers=%u\n", attached);
	mod_timer(timer, jiffies + 10 * HZ);
}

static int __init h30_irqgate_init(void)
{
	struct device_node *np;
	unsigned int n = 0, i;
	unsigned long seen = 0;

	for_each_compatible_node(np, NULL, "brcm,bcm963xx-vpcie") {
		for (i = 0; i < 10; i++) {
			int irq = of_irq_get(np, i);
			struct irq_data *d = irq > 0 ? irq_get_irq_data(irq) : NULL;

			if (!d || n == ARRAY_SIZE(lines) || d->hwirq < 128 ||
			    d->hwirq > 147 || (seen & BIT(d->hwirq - 128)) ||
			    irq_has_action(irq) || !irqd_irq_disabled(d)) {
				of_node_put(np);
				return -EBUSY;
			}
			seen |= BIT(d->hwirq - 128);
			lines[n++] = irq;
		}
	}
	if (n != ARRAY_SIZE(lines) || seen != 0xfffff)
		return -ENODEV;
	for (i = 0; i < n; i++) {
		irq_set_status_flags(lines[i], IRQ_NOAUTOEN);
		pr_info("H30_IRQ armed virq=%u hwirq=%lu\n", lines[i],
			irq_get_irq_data(lines[i])->hwirq);
	}
	ready = true;
	if (watch) {
		timer_setup(&watch_timer, watch_tick, TIMER_PINNED);
		watch_timer.expires = jiffies + 10 * HZ;
		add_timer_on(&watch_timer, 0);
	}
	return 0;
}
module_init(h30_irqgate_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("H30 diagnostic radio IRQ auto-enable gate; reboot to remove");
