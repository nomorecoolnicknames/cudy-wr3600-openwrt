// SPDX-License-Identifier: GPL-2.0-only
/* BCM6764 coherency, exact stock register readback.
 * mode0 reads only; port_mask bits0..3: WIFI0/1, MLO0/1;
 * bits4..6: BIU, PER, SNP (vendor26c readback: all still4/0).
 * Both radios must be
 * DOWN (or absent before attach). Configuration persists until reset.
 * Register provenance: h30_ubus_probe.c and vendor24c/stock-ubus-decode.log.
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>

static unsigned int port_mask;
module_param(port_mask, uint, 0400);

static int __init start(void)
{
	static const u32 addresses[] = {
		0x83060a00, 0x83068a00, 0x83070a00, 0x83078a00,
		0x83020a00, 0x83010a00, 0x83050a00,
	};
	void __iomem *p[ARRAY_SIZE(addresses)] = { NULL };
	u32 ctrl[ARRAY_SIZE(addresses)], cache[ARRAY_SIZE(addresses)];
	struct net_device *dev;
	unsigned int i;
	int ret = 0;
	if (port_mask & ~127U)
		return -EINVAL;
	rtnl_lock();
	if (port_mask) {
		for (i = 0; i < 2; i++) {
			dev = dev_get_by_name(&init_net, i ? "wl1" : "wl0");
			if (dev) {
				bool running = netif_running(dev);
				dev_put(dev);
				if (running) {
					ret = -EBUSY;
					goto out;
				}
			}
		}
	}
	/* Validate every selected port before the first write. */
	for (i = 0; i < ARRAY_SIZE(addresses); i++) {
		p[i] = ioremap(addresses[i], 8);
		if (!p[i]) {
			ret = -ENOMEM;
			goto out;
		}
		ctrl[i] = readl(p[i]);
		cache[i] = readl(p[i] + 4);
		pr_info("H30_UBUS_ALL before bit=%u addr=%08x ctrl=%08x cache=%08x\n", i, addresses[i], ctrl[i], cache[i]);
		if ((port_mask & BIT(i)) &&
		    !((ctrl[i] == 4 && cache[i] == 0) ||
		      (ctrl[i] == 0x24 && cache[i] == 1))) {
			ret = -EINVAL;
			goto out;
		}
	}
	for (i = 0; i < ARRAY_SIZE(addresses); i++) {
		if (!(port_mask & BIT(i)))
			continue;
		writel(1, p[i] + 4);
		writel((ctrl[i] & ~0x30U) | 0x20, p[i]);
		ctrl[i] = readl(p[i]);
		cache[i] = readl(p[i] + 4);
		pr_info("H30_UBUS_ALL after bit=%u addr=%08x ctrl=%08x cache=%08x\n", i, addresses[i], ctrl[i], cache[i]);
		if (ctrl[i] != 0x24 || cache[i] != 1) {
			ret = -EIO;
			goto out;
		}
	}
	pr_info("H30_UBUS_ALL PASS port_mask=%u\n", port_mask);
out:
	for (i = 0; i < ARRAY_SIZE(addresses); i++)
		if (p[i])
			iounmap(p[i]);
	rtnl_unlock();
	return ret;
}
static void __exit finish(void) { }
module_init(start);
module_exit(finish);
MODULE_LICENSE("GPL");
