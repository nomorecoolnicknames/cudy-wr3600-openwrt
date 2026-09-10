// SPDX-License-Identifier: GPL-2.0-only
/* Read-only live exercise of the exact lookup/put bridge used by wl. */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include "shim_netdev.h"

extern void bcm_dev_put(struct net_device *dev);

static int __init start(void)
{
	struct net_device *native, *old;
	struct {
		struct list_head list;
		struct net_device *native;
		void *old;
	} prefix;
	u32 wlif = 0, wl = 0, wlc = 0;
	int ret = -EINVAL;

	native = dev_get_by_name(&init_net, "wl0");
	if (!native)
		return -ENODEV;
	old = bcm_shim_dev_get_by_name_legacy(&init_net, "wl0");
	if (!old)
		goto out;
	static_assert(offsetof(typeof(prefix), native) == 8);
	static_assert(offsetof(typeof(prefix), old) == 12);
	if (copy_from_kernel_nofault(&prefix, netdev_priv(native), sizeof(prefix)) ||
	    prefix.native != native || (void *)old != prefix.old || old == native)
		goto put_old;
	if (copy_from_kernel_nofault(&wlif, (u8 *)old + 1408, 4) || !wlif ||
	    copy_from_kernel_nofault(&wl, (void *)(unsigned long)(wlif + 8), 4) || !wl ||
	    copy_from_kernel_nofault(&wlc, (void *)(unsigned long)(wl + 8), 4) || !wlc)
		goto put_old;
	dev_info(&native->dev,
		 "H30_LOOKUP_LIVE PASS native=%px old=%px priv1408=%08x wl=%08x wlc=%08x\n",
		 native, old, wlif, wl, wlc);
	ret = 0;
put_old:
	bcm_dev_put(old);
out:
	dev_put(native);
	return ret;
}

static void __exit stop(void) { }
module_init(start);
module_exit(stop);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded legacy netdev lookup and paired put hardware probe");
