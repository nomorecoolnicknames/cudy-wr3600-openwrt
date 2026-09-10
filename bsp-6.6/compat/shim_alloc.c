// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <net/cfg80211.h>
#include "shim_gfp.h"
#include "shim_wiphy.h"
#include "shim_skb.h"

/* The exported ARM assembly primitives don't open the PAN access window.
 * Old inline callers predate that contract. Use the native checked helpers
 * so range checks, exception fixups and PAN restoration all stay intact. */
unsigned long bcm419_arm_copy_from_user(void *to, const void __user *from,
				       unsigned long n)
{
	return copy_from_user(to, from, n);
}
EXPORT_SYMBOL(bcm419_arm_copy_from_user);

unsigned long bcm419_arm_copy_to_user(void __user *to, const void *from,
				     unsigned long n)
{
	return copy_to_user(to, from, n);
}
EXPORT_SYMBOL(bcm419_arm_copy_to_user);

int shim_alloc_init(void)
{
	void *p;
	if (shim_gfp419(0x6000c0) != GFP_KERNEL ||
	    shim_gfp419(0x6080c0) != (GFP_KERNEL | __GFP_ZERO) ||
	    shim_gfp419(0x488020) != (GFP_ATOMIC | __GFP_ZERO))
		return -EINVAL;
	p = kmalloc(512, shim_gfp419(0x6080c0));
	if (!p)
		return -ENOMEM;
	if (memchr_inv(p, 0, 512)) {
		kfree(p);
		return -EINVAL;
	}
	kfree(p);
	pr_info("bcm_shim: GFP419 mapping and zero allocation PASS\n");
	return 0;
}

void *bcm419___kmalloc(size_t size, unsigned int flags)
{
	return __kmalloc(size, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419___kmalloc);

void *bcm419_kmem_cache_alloc(struct kmem_cache *cache, unsigned int flags)
{
	return kmem_cache_alloc(cache, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419_kmem_cache_alloc);

void *bcm419_kmemdup(const void *src, size_t len, unsigned int flags)
{
	return kmemdup(src, len, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419_kmemdup);

struct sk_buff *bcm419___alloc_skb(unsigned int size, unsigned int gfp,
				int flags, int node)
{
	return __alloc_skb(size, shim_gfp419(gfp), flags, node);
}
EXPORT_SYMBOL(bcm419___alloc_skb);

struct sk_buff *bcm419___netdev_alloc_skb(struct net_device *dev,
				unsigned int len, unsigned int flags)
{
	/* All two blob call sites (linux_pktget, wl_monitor) edit 4.19
	 * fields inline immediately after return. */
	return (void *)bcm419_legacy_netdev_alloc_skb((void *)dev, len, flags);
}
EXPORT_SYMBOL(bcm419___netdev_alloc_skb);

struct sk_buff *bcm419_skb_clone(struct sk_buff *skb, unsigned int flags)
{
	if (shim_skb_is_legacy(skb))
		return (void *)bcm419_legacy_skb_clone((void *)skb, flags);
	return skb_clone(skb, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419_skb_clone);

struct sk_buff *bcm419_skb_copy(const struct sk_buff *skb, unsigned int flags)
{
	if (shim_skb_is_legacy(skb))
		return (void *)bcm419_legacy_skb_copy((void *)skb, flags);
	return skb_copy(skb, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419_skb_copy);

struct sk_buff *bcm419___pskb_copy_fclone(struct sk_buff *skb, int headroom,
				unsigned int flags, bool fclone)
{
	if (shim_skb_is_legacy(skb))
		return (void *)shim_skb_copy_headroom((void *)skb, headroom, shim_gfp419(flags));
	return __pskb_copy_fclone(skb, headroom, shim_gfp419(flags), fclone);
}
EXPORT_SYMBOL(bcm419___pskb_copy_fclone);

/* Native API inserted portid before vendor_event_idx. Legacy events
 * multicast (portid=0), matching the old function's behavior. */
struct sk_buff *bcm419___cfg80211_alloc_event_skb(struct wiphy *wiphy,
		struct wireless_dev *wdev, enum nl80211_commands cmd,
		enum nl80211_attrs attr, int event, int len, unsigned int flags)
{
	struct wiphy *native = shim_wiphy_native((void *)wiphy);
	struct wireless_dev *native_wdev = wdev ? shim_wdev_native((void *)wdev) : NULL;

	if (!native || (wdev && !native_wdev))
		return NULL;
	return __cfg80211_alloc_event_skb(native, native_wdev, cmd, attr, 0, event,
					len, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419___cfg80211_alloc_event_skb);

/* Reply/event skbs are native netlink buffers. Only the radio objects and
 * allocation flags cross the ABI here; do not wrap these in skb419 views. */
struct sk_buff *bcm419___cfg80211_alloc_reply_skb(struct wiphy *wiphy,
		enum nl80211_commands cmd, enum nl80211_attrs attr, int len)
{
	struct wiphy *native = shim_wiphy_native((void *)wiphy);

	return native ? __cfg80211_alloc_reply_skb(native, cmd, attr, len) : NULL;
}
EXPORT_SYMBOL(bcm419___cfg80211_alloc_reply_skb);

void bcm419___cfg80211_send_event_skb(struct sk_buff *skb, unsigned int flags)
{
	__cfg80211_send_event_skb(skb, shim_gfp419(flags));
}
EXPORT_SYMBOL(bcm419___cfg80211_send_event_skb);
