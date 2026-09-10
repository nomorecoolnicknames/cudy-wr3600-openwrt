// SPDX-License-Identifier: GPL-2.0-only
/* BCM6764 decode configuration snapshot; optional WIFI0 coherency setup.
 * GPL 6764.dtsi: ubus-bus +0x80000000, WIFI0/1 +0x3060000/0x3068000,
 * MLO0/1 +0x3070000/0x3078000. 6764/bcm_ubus_chip.h: decode_cfg@0xa00,
 * ctrl@0, cache_cfg@4. No vendor headers included in this kernel module.
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>

static bool coherent;
module_param(coherent, bool, 0400);

static int enable_wifi0(void)
{
	struct net_device *dev;
	void __iomem *p;
	u32 ctrl, cache;
	int ret = 0;
	rtnl_lock();
	dev = dev_get_by_name(&init_net, "wl0");
	if (!dev || netif_running(dev)) {
		ret = -EBUSY;
		goto out;
	}
	p = ioremap(0x83060a00, 8);
	if (!p) {
		ret = -ENOMEM;
		goto out;
	}
	ctrl = readl(p);
	cache = readl(p + 4);
	/* Narrow experiment against the observed #110 reset configuration. */
	if (ctrl != 4 || cache != 0) {
		ret = -EINVAL;
		goto unmap;
	}
	/* BCM6764 branch of ubus_master_decode_wnd_cfg(cache_bit_en=1):
	 * CCI routing is fixed; select cache_cfg rather than input attributes.
	 * Keep this configuration after module unload, until hardware reset.
	 */
	writel(1, p + 4);
	writel((ctrl & ~0x30U) | 0x20, p);
	ctrl = readl(p);
	cache = readl(p + 4);
	pr_info("H30_UBUS WIFI0 coherency ctrl=%08x cache_cfg=%08x wl0_down=1\n", ctrl, cache);
	if (ctrl != 0x24 || cache != 1)
		ret = -EIO;
unmap:
	iounmap(p);
out:
	if (dev)
		dev_put(dev);
	rtnl_unlock();
	return ret;
}

static int __init start(void)
{
	unsigned int i;
	int ret;
	if (coherent) {
		ret = enable_wifi0();
		if (ret)
			return ret;
	}
	for (i = 0; i < 4; i++) {
		phys_addr_t pa = 0x83060a00 + i * 0x8000;
		void __iomem *p = ioremap(pa, 0x100);
		if (!p)
			return -ENOMEM;
		pr_info("H30_UBUS port=%u pa=%pa ctrl=%08x cache_cfg=%08x win0=%08x/%08x/%08x\n",
			i + 12, &pa, readl(p), readl(p + 4),
			readl(p + 16), readl(p + 20), readl(p + 24));
		iounmap(p);
	}
	return 0;
}
static void __exit finish(void) { }
module_init(start);
module_exit(finish);
MODULE_LICENSE("GPL");
