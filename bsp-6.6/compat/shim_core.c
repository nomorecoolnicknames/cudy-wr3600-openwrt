// SPDX-License-Identifier: GPL-2.0-only
/*
 * shim_core.c — lane C skeleton: renames/inlines and signature adapters
 * for generic kernel symbols (UND_SYMBOLS_419_TO_66.md §3 subset + verified
 * hnd/igs/bcmmcast gaps).
 *
 * Every wrapper below cites the 6.6.93 source file+line its recipe came
 * from. All exports are EXPORT_SYMBOL (never _GPL): wl.ko is Proprietary.
 *
 * Verified ABSENT from kernel-6.6/build/Module.symvers (2026-09-07, 6064
 * entries), so no duplicate-export risk. NOTE warn_slowpath_fmt is
 * deliberately NOT exported (kernel already exports the name with a
 * different prototype — see comment at its site).
 *   printk(del_timer_sync/del_timer/kfree_skb/netif_rx_ni/__list_add_valid/
 *   __list_del_entry_valid/prandom_u32/warn_slowpath_null/nla_parse/PDE_DATA/
 *   consume_skb/skb_queue_purge/__dev_kfree_skb_any/usleep_range/
 *   preempt_schedule/__rcu_read_lock/__rcu_read_unlock/dev_queue_xmit/
 *   bcm_dev_hold/bcm_dev_put)
 * REMOVED vs skeleton v1: sqrt_int (hnd.ko exports it — duplicate risk).
 * Callee for each wrapper verified present in Module.symvers (vprintk,
 * try_to_del_timer_sync, timer_delete(_sync), kfree_skb_reason, netif_rx,
 * get_random_u32, warn_slowpath_fmt, __nla_parse, int_sqrt,
 * napi_consume_skb, skb_queue_purge_reason, dev_kfree_skb_any_reason,
 * usleep_range_state, __dev_queue_xmit).
 *
 * TODO(lane C): cfg80211 adapters with struct translation (§4) live in
 * shim_cfg80211.c; call-site audit for del_timer_sync→try_to_del_timer_sync
 * semantic delta (no sleep-wait on running handler, returns -1 instead).
 */
/* The 6.6 headers define static inlines with the same names as our
 * 4.19-compat globals. Rename the inlines at include time, then define
 * globals that forward to them — bodies stay upstream-identical.
 * The #defines MUST precede ALL kernel includes: module.h already pulls
 * rcupdate.h (rcu inlines) and netdevice.h pulls delay.h (usleep_range)
 * through long chains. Internal header users are renamed consistently,
 * so semantics don't change. #undefs come after the last include. */
#define __rcu_read_lock		__rcu_read_lock_inl
#define __rcu_read_unlock	__rcu_read_unlock_inl
#define usleep_range		usleep_range_inl
#define del_timer_sync		del_timer_sync_inl
#define del_timer		del_timer_inl
#define kfree_skb		kfree_skb_inl
#define consume_skb		consume_skb_inl
#define skb_queue_purge		skb_queue_purge_inl
#define dev_queue_xmit		dev_queue_xmit_inl
#define __list_add_valid		__list_add_valid_inl
#define __list_del_entry_valid		__list_del_entry_valid_inl
#define nla_parse		nla_parse_inl
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stdarg.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/bug.h>
#include <linux/panic.h>
#include <net/netlink.h>
#include <linux/proc_fs.h>
#include <linux/preempt.h>
#include <linux/math.h>
#include <linux/printk.h>
#include <linux/string.h>
#undef __rcu_read_lock
#undef __rcu_read_unlock
#undef usleep_range
#undef del_timer_sync
#undef del_timer
#undef kfree_skb
#undef consume_skb
#undef skb_queue_purge
#undef dev_queue_xmit
#undef __list_add_valid
#undef __list_del_entry_valid
#undef nla_parse
/* printk is a macro in this config (printk_index_wrap around _printk).
 * Undef it so the 4.19-compat global below can take the name. In-TU
 * pr_* calls then route through our printk() -> vprintk(), equivalent. */
#ifdef printk
#undef printk
#endif
#include "shim.h"
#include "shim_dma.h"
#include "shim_netdev.h"
#include "shim_skb.h"
/* NOTE: do NOT #include "shim_wiphy.h" here — it pulls <net/cfg80211.h>,
 * whose static inline cfg80211_find_ie_match() collides with our 4.19
 * global of the same name defined below. A bare prototype is enough. */
extern int shim_wiphy_init(void);
extern void shim_wiphy_exit(void);

/* --- module param: lets load_wifi.sh stamp a stage marker at load time --- */
static int mark = MK_SHIM_LOAD;
module_param(mark, int, 0444);
MODULE_PARM_DESC(mark, "stage marker written to bootmark register on load");

extern void bcm96764_mark(u8 stage);

/* --- printk: 4.19 exported printk(); 6.6 has it as macro -> _printk --- */
asmlinkage __visible int printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);
	return r;
}
EXPORT_SYMBOL(printk);

/* --- del_timer_sync: removed in 6.5+, timer.h:198 is now a static inline
 * calling timer_delete_sync(). Our out-of-tree copy must be a real symbol.
 * Preserve synchronization: returning before a running callback completes
 * allows legacy callers to free its storage while it is still in use.
 * 6.6: include/linux/timer.h:198-200, kernel/time/timer.c:1442. --- */
int del_timer_sync(struct timer_list *timer)
{
	return timer_delete_sync(timer);
}
EXPORT_SYMBOL(del_timer_sync);

/* --- del_timer: 6.6 timer.h:211 static inline -> timer_delete().
 * 6.6: include/linux/timer.h:211-214, timer_delete EXPORT_SYMBOL. --- */
int del_timer(struct timer_list *timer)
{
	return timer_delete(timer);
}
EXPORT_SYMBOL(del_timer);

/* --- kfree_skb: 4.19 function; 6.6 static inline -> kfree_skb_reason().
 * 6.6: net/core/skbuff.c:1105 EXPORT_SYMBOL(kfree_skb_reason). --- */
void kfree_skb(struct sk_buff *skb)
{
	if (shim_skb_is_legacy(skb))
		bcm419_kfree_skb((void *)skb);
	else
		kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
}
EXPORT_SYMBOL(kfree_skb);

/* --- __dev_kfree_skb_any: 4.19 function; 6.6 folded into
 * dev_kfree_skb_any_reason() inline. net/core/dev.c:3230. --- */
void __dev_kfree_skb_any(struct sk_buff *skb, enum skb_drop_reason reason)
{
	if (shim_skb_is_legacy(skb))
		bcm419___dev_kfree_skb_any((void *)skb, reason);
	else
		dev_kfree_skb_any_reason(skb, reason);
}
EXPORT_SYMBOL(__dev_kfree_skb_any);

/* --- netif_rx_ni: removed; 6.6 netif_rx() is BH-safe itself.
 * net/core/dev.c: netif_rx EXPORT_SYMBOL. --- */
int netif_rx_ni(struct sk_buff *skb)
{
	return netif_rx(skb);
}
EXPORT_SYMBOL(netif_rx_ni);

/* --- dev_queue_xmit: 4.19 function; 6.6 static inline
 * (include/linux/netdevice.h:3110-3112) -> __dev_queue_xmit(skb, NULL).
 * __dev_queue_xmit is EXPORT_SYMBOL. --- */
int dev_queue_xmit(struct sk_buff *skb)
{
	return __dev_queue_xmit(skb, NULL);
}
EXPORT_SYMBOL(dev_queue_xmit);

/* --- __list_add_valid / __list_del_entry_valid: 4.19 list debugging
 * helpers; 6.6 renamed to __list_add_valid_or_report/__list_del_entry_valid_or_report
 * with different prototype. Reimplement on top of __list_add/
 * __list_del_entry (both static inlines in include/linux/list.h, always
 * available — no export needed). --- */
bool __list_add_valid(struct list_head *new, struct list_head *prev,
		      struct list_head *next)
{
	/* 4.19 semantics: a pure check - the caller inserts. FACT: wl.ko
	 * imports this symbol (nm -u radio/wl.ko), so the previous version,
	 * which called __list_add() here as well, inserted every node twice
	 * and corrupted the vendor driver's lists (review S1-8). */
	return prev->next == next && next->prev == prev;
}
EXPORT_SYMBOL(__list_add_valid);

bool __list_del_entry_valid(struct list_head *entry)
{
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;

	if (!prev || !next)
		return false;
	if (prev == LIST_POISON1 || next == LIST_POISON2)
		return false;
	if (prev->next != entry || next->prev != entry)
		return false;
	/* Same as above: validate only, the caller unlinks. */
	return true;
}
EXPORT_SYMBOL(__list_del_entry_valid);

/* --- prandom_u32: removed; 6.6 get_random_u32() (EXPORT_SYMBOL). --- */
u32 prandom_u32(void)
{
	return get_random_u32();
}
EXPORT_SYMBOL(prandom_u32);

/* --- sqrt_int: REMOVED (was here in skeleton v1). FACT: hnd.ko EXPORTS
 * sqrt_int (it is in hnd's 853 __ksymtab entries) and wl.ko is its only
 * importer — and wl loads AFTER hnd. A shim export would collide at hnd
 * insmod ("exports duplicate symbol"). int_sqrt stays available in the
 * kernel for future in-shim use. --- */

/* --- warn_slowpath_null: removed. 6.6 kernel/panic.c:697 has
 * warn_slowpath_fmt(file, line, taint, fmt, ...) EXPORT_SYMBOL.
 * NULL fmt prints file/line with "cut here" — matches old behaviour. --- */
void warn_slowpath_null(const char *file, int line)
{
	warn_slowpath_fmt(file, line, TAINT_WARN, NULL);
}
EXPORT_SYMBOL(warn_slowpath_null);

/* --- warn_slowpath_fmt: 4.19 (file,line,fmt...) vs 6.6
 * (file,line,taint,fmt...) — kernel/panic.c:697, EXPORT_SYMBOL at :718.
 * FACT: warn_slowpath_fmt IS in our Module.symvers, so the shim MUST NOT
 * export this name (duplicate export = insmod failure). Consequence: blob
 * calls land on the kernel implementation with shifted arguments (blob's
 * fmt is read as taint, first vararg as fmt). Impact is limited to WARN
 * paths, but a format/args mismatch can crash vsnprintf — lane C/E must
 * handle this before M3 by binary-patching wl.ko/hnd.ko relocations for
 * this symbol to a renamed shim entry (wl_warn_slowpath_fmt_419), the
 * same rel-patch technique lane E uses for vermagic (tools/modvermagic.py
 * domain). Until then: DO NOT export; document.
 * TODO(lane C+E): rel-patch + renamed wrapper, audit first wl WARN. --- */

/* --- nla_parse: 4.19 5-arg; 6.6 inline is 6-arg (+extack).
 * Body copied from include/net/netlink.h:662-668: strict validation,
 * extack NULL — exactly what the 4.19 wrapper did internally. --- */
int nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
	      int len, const struct nla_policy *policy)
{
	return __nla_parse(tb, maxtype, head, len, policy,
			   NL_VALIDATE_STRICT, NULL);
}
EXPORT_SYMBOL(nla_parse);

/* --- PDE_DATA: 4.19 function/macro; 6.6 pde_data() static inline
 * (include/linux/proc_fs.h:121). --- */
void *PDE_DATA(const struct inode *inode)
{
	return pde_data(inode);
}
EXPORT_SYMBOL(PDE_DATA);

/* --- consume_skb: 6.6 has it only under CONFIG_TRACEPOINTS
 * (net/core/skbuff.c:1278-1285), which the target config does NOT set
 * (hence the header inline -> kfree_skb, renamed above).
 * 6.6 void napi_consume_skb(skb, budget) with budget=0 means "non-NAPI
 * context" (skbuff.c:1339-1343) and reduces to the 4.19 consume_skb
 * body (unref + free, no tracepoint). CONSTRAINT for lane B:
 * CONFIG_TRACEPOINTS must stay off, or this becomes a duplicate export. --- */
void consume_skb(struct sk_buff *skb)
{
	if (shim_skb_is_legacy(skb))
		bcm419_consume_skb((void *)skb);
	else
		napi_consume_skb(skb, 0);
}
EXPORT_SYMBOL(consume_skb);

/* --- skb_queue_purge: 6.6 inline -> skb_queue_purge_reason()
 * (include/linux/skbuff.h:3201, net/core/skbuff.c:3737). --- */
void skb_queue_purge(struct sk_buff_head *list)
{
	skb_queue_purge_reason(list, SKB_DROP_REASON_QUEUE_PURGE);
}
EXPORT_SYMBOL(skb_queue_purge);

/* --- cfg80211_find_ie_match: 4.19 EXPORT_SYMBOL function
 * (bcm-tree net/wireless/scan.c:483-504, proto in cfg80211.h:4703);
 * 6.6 keeps the NAME as a static inline with widened types
 * (unsigned int len/match_len/match_offset, cfg80211.h:6566) — the blob
 * was built against the 4.19 out-of-line symbol, so provide it with the
 * exact 4.19 signature. Body is the 4.19 loop written out by hand
 * (same walk as for_each_element_id in 4.19: stop at malformed element,
 * return pointer to the id byte): no new includes, no inline collision
 * (this TU never includes <net/cfg80211.h>). ABI note: (u8,ptr,int,ptr,
 * int,int) passes identically to the 6.6 inline form. --- */
const u8 *cfg80211_find_ie_match(u8 eid, const u8 *ies, int len,
				 const u8 *match, int match_len,
				 int match_offset)
{
	/* match_offset can't be smaller than 2, unless match_len is
	 * zero, in which case match_offset must be zero as well.
	 * (4.19 scan.c body, verbatim logic.) */
	if (WARN_ON((match_len && match_offset < 2) ||
		    (!match_len && match_offset)))
		return NULL;

	while (len >= 2) {
		u8 elen = ies[1];

		if (elen + 2 > len)
			break;
		if (ies[0] == eid &&
		    elen >= match_offset - 2 + match_len &&
		    !memcmp(ies + match_offset, match, match_len))
			return ies;
		len -= elen + 2;
		ies += elen + 2;
	}

	return NULL;
}
EXPORT_SYMBOL(cfg80211_find_ie_match);

/* --- usleep_range: 6.6 inline -> usleep_range_state(min,max,
 * TASK_UNINTERRUPTIBLE) (include/linux/delay.h). Forward to the renamed
 * inline — body is upstream's by construction. --- */
void usleep_range(unsigned long min, unsigned long max)
{
	usleep_range_inl(min, max);
}
EXPORT_SYMBOL(usleep_range);

/* --- preempt_schedule: compiled out under CONFIG_PREEMPT_NONE (our
 * target: CONFIG_PREEMPT_NONE=y). With preemption disabled the call is a
 * correct no-op: there is nothing to schedule. Do NOT "implement" it by
 * calling schedule() — that would change 4.19 semantics (preempt_schedule
 * never slept when preemption was already disabled, which is the only
 * state a PREEMPT_NONE kernel is ever in). --- */
asmlinkage __visible void preempt_schedule(void)
{
}
EXPORT_SYMBOL(preempt_schedule);

/* --- __rcu_read_lock/unlock: static inlines under !CONFIG_PREEMPT_RCU
 * (include/linux/rcupdate.h:93-101, bodies preempt_disable/enable).
 * Forward to the renamed inlines. --- */
void __rcu_read_lock(void)
{
	__rcu_read_lock_inl();
}
EXPORT_SYMBOL(__rcu_read_lock);

void __rcu_read_unlock(void)
{
	__rcu_read_unlock_inl();
}
EXPORT_SYMBOL(__rcu_read_unlock);

/* --- bcm_dev_hold/bcm_dev_put: BCA aliases for dev_hold/dev_put
 * (6.6: include/linux/netdevice.h:4150-4175 static inlines over
 * netdev_hold/netdev_put, GFP_ATOMIC tracking; pre-6.6 they were plain
 * pcpu_refcnt/dev_refcnt ops modulo CONFIG_PCPU_DEV_REFCNT — the inline
 * covers both, so no #ifdef is needed here).
 *
 * Legacy-aware since the P0 vendor30 netdev-lookup lane: the blob's
 * dev_get_by_name sites are renamed to bcm_shim_dev_get_by_name_legacy
 * (shim_netdev.c), which returns a 4.19 legacy VIEW holding the single
 * lookup ref. That view reaches these two functions — directly as the
 * paired release (0x206c lookup -> 0x2164 put) and as the pkt-fwd fabric's
 * stored netdev (0x6608 hold / 0x6648 put, 0x6674 hold / 0x66c0 / 0x66cc
 * put, NULL-or-fabric by construction). A raw pcpu op on the legacy bytes
 * would be layout gambling; translate to the paired native first.
 *
 * Decision (handoff §6.2): proven mixed wrapper, NOT a scoped rename.
 * - Same UND names stay (BCA-only: the kernel has no bcm_dev_hold/put, so
 *   there is no duplicate-export risk and no kernel caller to disturb —
 *   native callers use dev_hold/dev_put and are untouched by construction).
 * - No extra blob surgery: the six hold/put relocs need no rename, only the
 *   five lookup relocs do (tools/modvermagic.py --rename-lookup).
 * - Provenance (audited on stage-rxpoolfix/wl-h7.ko): every net_device* the
 *   blob can observe post-fix is a legacy view or NULL. Blob-internal
 *   netdev slots (blog r5, RX ctx+8 consumed with the 4.19 layout at
 *   wl_awl_rx_sendup+0x58, fwd entries) are filled only from the lookup
 *   bridge and the alloc redirect; kernel natives enter the blob solely
 *   through translated boundaries (notifier trampoline, ndo wrappers,
 *   cfg80211 wdev translation), and the kernel never writes wl-private
 *   netdev slots. Crash-site ordering reinforces this: any native in a
 *   blob slot Oopses at the first [+1408]/[+892] deref before hold/put.
 * Fallback policy for anything else (defensive, no audited site hits it):
 * NULL is a no-op (0x6674 passes literal 0); a live shim native passed
 * directly is held/put directly; unknown/foreign is warn-once + skip —
 * never touch an unproven pointer (a skipped pair stays balanced, a blind
 * dec would corrupt). --- */
void bcm_dev_hold(struct net_device *dev)
{
	struct net_device *native;

	if (!dev)
		return;
	native = shim_netdev_native((const struct netdev419_view *)dev);
	if (native) {
		dev_hold(native);
		return;
	}
	if (shim_netdev_legacy(dev)) {
		dev_hold(dev);
		return;
	}
	pr_warn_once("bcm_shim: bcm_dev_hold on unknown netdev %pK, skip\n",
		     dev);
}
EXPORT_SYMBOL(bcm_dev_hold);

void bcm_dev_put(struct net_device *dev)
{
	struct net_device *native;

	if (!dev)
		return;
	native = shim_netdev_native((const struct netdev419_view *)dev);
	if (native) {
		dev_put(native);
		return;
	}
	if (shim_netdev_legacy(dev)) {
		dev_put(dev);
		return;
	}
	pr_warn_once("bcm_shim: bcm_dev_put on unknown netdev %pK, skip\n",
		     dev);
}
EXPORT_SYMBOL(bcm_dev_put);

static int __init shim_core_init(void)
{
	int ret;

	ret = shim_alloc_init();
	if (ret)
		return ret;
	bcm96764_mark(MK_SHIM_CORE_OK);
	ret = cfg80211_compat_subinit();
	if (ret)
		return ret;
	ret = wl_compat_subinit();
	if (ret)
		return ret;
	ret = shim_nvram_init();
	if (ret)
		return ret;
	ret = shim_hnd_gaps_init();
	if (ret)
		return ret;
	ret = shim_dma_init();
	if (ret)
		return ret;
	ret = shim_skb_init();
	if (ret) {
		shim_dma_exit();
		return ret;
	}
	ret = shim_netdev_init();
	if (ret) {
		shim_skb_exit();
		shim_dma_exit();
		return ret;
	}
	ret = shim_wiphy_init();
	if (ret) {
		shim_netdev_exit();
		shim_skb_exit();
		shim_dma_exit();
		return ret;
	}
	bcm96764_mark(mark);
	pr_info("bcm_shim: up (mark 0x%02x)\n", mark);
	return 0;
}

static void __exit shim_core_exit(void)
{
	/* Reverse of shim_core_init order. Successful sub-inits leave no
	 * persistent state (selftests free everything), so the skb/netdev/
	 * wiphy exits are no-ops here and only matter on failure paths. */
	shim_wiphy_exit();
	shim_netdev_exit();
	shim_skb_exit();
	shim_dma_exit();
	pr_info("bcm_shim: core wrappers down\n");
}

/* init/exit live here; other shim_*.c files contribute only symbols. */
module_init(shim_core_init);
module_exit(shim_core_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cudy-be3600 port");
MODULE_DESCRIPTION("BCA 4.19 -> 6.6 ABI shim, core kernel wrappers (lane C)");
MODULE_VERSION("0.1-skeleton");
