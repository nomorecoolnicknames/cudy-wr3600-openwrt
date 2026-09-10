// SPDX-License-Identifier: GPL-2.0-only
/* Blob packet buffers use owned 4.19 views; netlink allocations use native
 * skbs. Address membership decides before any descriptor is dereferenced. */
#include <linux/module.h>
#include <linux/skbuff.h>
#include "shim_skb.h"

#define DISPATCH_DATA(name) \
void *bcm419_mixed_##name(struct sk_buff *skb, unsigned int len) \
{ \
	if (shim_skb_is_legacy(skb)) \
		return bcm419_##name((void *)skb, len); \
	return name(skb, len); \
} \
EXPORT_SYMBOL(bcm419_mixed_##name)
DISPATCH_DATA(skb_put);
DISPATCH_DATA(skb_push);
DISPATCH_DATA(skb_pull);

void bcm419_mixed_skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (shim_skb_is_legacy(skb))
		bcm419_skb_trim((void *)skb, len);
	else
		skb_trim(skb, len);
}
EXPORT_SYMBOL(bcm419_mixed_skb_trim);
int bcm419_mixed____pskb_trim(struct sk_buff *skb, unsigned int len)
{
	if (shim_skb_is_legacy(skb))
		return bcm419____pskb_trim((void *)skb, len);
	return ___pskb_trim(skb, len);
}
EXPORT_SYMBOL(bcm419_mixed____pskb_trim);

/* Reproduce the exact H30 failure: linux_pktget grows old tail@372/len@44,
 * dma_rxfill calls skb_pull then reads data@40. Also exercise a native
 * netlink-shaped buffer through the same mixed entry point. */
#include "shim_skb_layout.h"
extern struct sk_buff *bcm419___netdev_alloc_skb(struct net_device *, unsigned int, unsigned int);
extern struct sk_buff *bcm419_skb_clone(struct sk_buff *, unsigned int);
static bool skb_dispatch_selftest;
module_param(skb_dispatch_selftest, bool, 0400);
int shim_skb_dispatch_init(void)
{
	struct sk_buff *old = NULL, *clone = NULL, *native = NULL;
	void *data, *tail, *pulled;
	u32 len = 256;
	int ret = -EINVAL;
	if (!skb_dispatch_selftest)
		return 0;
#define DTEST(x) do { if (!(x)) { pr_err("SKB419_DISPATCH FAIL line=%d\n", __LINE__); goto out; } } while (0)
	DTEST(!shim_skb_is_legacy(NULL));
	DTEST(!shim_skb_is_legacy((void *)1));
	old = bcm419___netdev_alloc_skb(NULL, 256, 0x6000c0);
	DTEST(old && shim_skb_is_legacy(old));
	memcpy(&data, (u8 *)old + SK419_off_sk_buff_data, sizeof(data));
	memcpy(&tail, (u8 *)old + SK419_off_sk_buff_tail, sizeof(tail));
	DTEST(data && data == tail);
	tail = (u8 *)tail + len;
	memcpy((u8 *)old + SK419_off_sk_buff_tail, &tail, sizeof(tail));
	memcpy((u8 *)old + SK419_off_sk_buff_len, &len, sizeof(len));
	pulled = bcm419_mixed_skb_pull(old, 32);
	DTEST(pulled == (u8 *)data + 32);
	memset(pulled, 0x5a, 224);
	clone = bcm419_skb_clone(old, 0x6000c0);
	DTEST(clone && shim_skb_is_legacy(clone));
	bcm419_kfree_skb((void *)clone); clone = NULL;
	DTEST(!bcm419_mixed____pskb_trim(old, 64));
	DTEST(bcm419_mixed_skb_put(old, 8));
	native = alloc_skb(256, GFP_KERNEL);
	DTEST(native && !shim_skb_is_legacy(native));
	skb_put(native, 64);
	data = native->data;
	DTEST(bcm419_mixed_skb_pull(native, 8) == (u8 *)data + 8);
	DTEST(native->len == 56);
	bcm419_kfree_skb((void *)old);
	DTEST(!shim_skb_is_legacy(old)); old = NULL;
	pr_info("SKB419_DISPATCH PASS legacy-inline-rxfill native-netlink clone-free registry-remove\n");
	ret = 0;
out:
	if (clone) bcm419_kfree_skb((void *)clone);
	if (old && shim_skb_is_legacy(old)) bcm419_kfree_skb((void *)old);
	dev_kfree_skb_any(native);
	return ret;
#undef DTEST
}
