// SPDX-License-Identifier: GPL-2.0-only
/* H30 bounded live experiment: gbpm slot 10, ordinary owned legacy skbs.
 * hnd nbuff_pktpoolget requests an all-or-nothing singly linked batch.
 * recycle_flags stays zero: linux_pktfree uses the generic bulk free path.
 * Active provider pins itself; callers have no RCU/unload synchronization.
 */
#include <linux/module.h>
#include <linux/init.h>
#include "shim_skb.h"
#include "shim_skb_layout.h"
#include "wl_compat.h"

static bool enable;
module_param(enable, bool, 0400);
static bool disable_xpm;
module_param(disable_xpm, bool, 0400);
extern int wlcsm_nvram_k_set(char *name, char *value);
static atomic_t calls = ATOMIC_INIT(0);
static atomic_t batches = ATOMIC_INIT(0);
static atomic_t failures = ATOMIC_INIT(0);

#define FIELD(s, field, type) (*(type *)((u8 *)(s) + SK419_off_sk_buff_##field))

static unsigned int free_chain(struct skb419_view *p)
{
	unsigned int n = 0;
	while (p) {
		struct skb419_view *next = FIELD(p, next, struct skb419_view *);
		FIELD(p, next, struct skb419_view *) = NULL;
		bcm419_kfree_skb(p);
		p = next;
		n++;
	}
	return n;
}

static struct skb419_view *alloc_chain(u32 num, u32 len, int fail_at,
				     unsigned int *rolled_back)
{
	struct skb419_view *head = NULL, *tail = NULL, *p;
	u32 i;
	if (!num || num > 64 || !len || len > 16384)
		return NULL;
	for (i = 0; i < num; i++) {
		if (i == fail_at)
			goto fail;
		/* Same raw 4.19 atomic GFP as hnd linux_pktget. */
		p = bcm419_legacy_netdev_alloc_skb(NULL, len, 0x488020);
		if (!p)
			goto fail;
		if (!bcm419_skb_put(p, len)) {
			bcm419_kfree_skb(p);
			goto fail;
		}
		if (tail)
			FIELD(tail, next, struct skb419_view *) = p;
		else
			head = p;
		tail = p;
	}
	return head;
fail:
	i = free_chain(head);
	if (rolled_back)
		*rolled_back = i;
	return NULL;
}

static void *provide(u32 num, u32 len, u32 prio)
{
	struct skb419_view *p;
	int n = atomic_inc_return(&calls);
	(void)prio;
	p = alloc_chain(num, len, -1, NULL);
	if (p)
		atomic_inc(&batches);
	else
		atomic_inc(&failures);
	if (n <= 4 || !(n % 256))
		pr_info("H30_BPM call=%d num=%u len=%u ok=%d batches=%d failures=%d\n",
			n, num, len, !!p, atomic_read(&batches), atomic_read(&failures));
	return p;
}

static int __init h30_bpm_init(void)
{
	struct skb419_view *head, *p;
	unsigned int n = 0, rollback = 0;
	bool valid = true;
	head = alloc_chain(4, 512, -1, NULL);
	if (!head)
		return -ENOMEM;
	for (p = head; p; p = FIELD(p, next, struct skb419_view *)) {
		n++;
		if (FIELD(p, len, u32) != 512 ||
		    FIELD(p, recycle_flags, u32) != 0 ||
		    FIELD(p, tail, u8 *) - FIELD(p, data, u8 *) != 512 ||
		    FIELD(p, data, u8 *) < FIELD(p, head, u8 *) ||
		    FIELD(p, tail, u8 *) > FIELD(p, end, u8 *))
			valid = false;
	}
	if (free_chain(head) != 4 || n != 4 || !valid)
		return -EINVAL;
	head = alloc_chain(4, 512, 2, &rollback);
	if (head || rollback != 2) {
		free_chain(head);
		return -EINVAL;
	}
	if (alloc_chain(0, 512, -1, NULL) || alloc_chain(65, 512, -1, NULL) ||
	    alloc_chain(1, 0, -1, NULL) || alloc_chain(1, 16385, -1, NULL))
		return -EINVAL;
	pr_info("H30_BPM_SELFTEST PASS chain=4 rollback=2 bounds=4 enable=%d\n", enable);
	if (enable) {
		/* Only before hnd/wl attach; changing this on an attached radio
		 * does not change its already initialized DMA mode. */
		if (disable_xpm && wlcsm_nvram_k_set("wl_pp_xpm", "0"))
			return -ENOMEM;
		__module_get(THIS_MODULE);
		WRITE_ONCE(gbpm_g.slot[WL_GBPM_ALLOC_MULT_BUF_SKB], provide);
		pr_info("H30_BPM ACTIVE slot=10 pinned=1 ordinary_skb=1 disable_xpm=%d\n", disable_xpm);
	}
	return 0;
}

static void __exit h30_bpm_exit(void)
{
	pr_info("H30_BPM fixture unload\n");
}
module_init(h30_bpm_init);
module_exit(h30_bpm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("H30 live legacy RX buffer allocation experiment");
