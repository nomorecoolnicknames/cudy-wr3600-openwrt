// SPDX-License-Identifier: GPL-2.0-only
/* H10/H11: separate legacy/native storage and native registration lifecycle.
 * Not wired to blob imports yet: ndo/cfg80211/skb/notifier
 * boundaries must be translated together. No pretend packet callbacks. */
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/overflow.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/rculist.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include "shim_netdev.h"
#include "shim_netdev_layout.h"
#include "shim_netdev_flags.h"
#include "shim_netdev_stats.h"
#include "shim_skb.h"
#include "shim_gfp.h"
#include "shim_wiphy.h"
#include "shim_dma.h"
#ifdef CONFIG_ARM
#include <asm/memory.h>
/* tools/wl_ioctl_userlimit.py replaces removed get_fs range checks with
 * this native limit. Never silently use that patch on another split. */
static_assert(TASK_SIZE == 0xbf000000UL);
#endif

struct netdev419_view {
	u8 bytes[ND419_size_net_device];
	u8 priv[];
};

struct netdev419_entry {
	struct list_head list;
	struct net_device *native;
	struct netdev419_view *old;
	void *allocation;
	u8 address[MAX_ADDR_LEN];
	void (*old_destructor)(struct netdev419_view *);
	void (*old_drvinfo)(struct netdev419_view *, struct ethtool_drvinfo *);
	bool in_register;
	bool destructor_called;
	const struct ethtool_ops *default_ethtool;
	struct net_device_ops native_ops;
	struct ethtool_ops native_ethtool;
	void (*old_stats)(struct netdev419_view *, struct netdev419_stats *);
	bool extended_stats;
	struct device *parent_ref;
	int (*old_open)(struct netdev419_view *);
	int (*old_stop)(struct netdev419_view *);
	void (*old_uninit)(struct netdev419_view *);
	int (*old_set_mac)(struct netdev419_view *, void *);
	void (*old_set_rx_mode)(struct netdev419_view *);
	int (*old_ioctl)(struct netdev419_view *, struct ifreq *, int);
	netdev_tx_t (*old_xmit)(struct skb419_view *, struct netdev419_view *);
};
static const struct net_device_ops netdev419_real_ops;
static LIST_HEAD(netdev419_views);
static DEFINE_MUTEX(netdev419_mutex);
static bool netdev_selftest;
module_param(netdev_selftest, bool, 0400);
MODULE_PARM_DESC(netdev_selftest, "Test separate legacy/native netdev allocation without radio");
static bool netdev_lifecycle_selftest;
module_param(netdev_lifecycle_selftest, bool, 0400);
MODULE_PARM_DESC(netdev_lifecycle_selftest, "Test native registration/failure/unregister with legacy views");
static bool notify_selftest;
module_param(notify_selftest, bool, 0400);
MODULE_PARM_DESC(notify_selftest, "Test netdevice-notifier trampoline (mock callback, replay events) without radio");
static bool netdev_write_selftest;
module_param(netdev_write_selftest, bool, 0400);
MODULE_PARM_DESC(netdev_write_selftest, "Replay wl_attach netdev writes on a legacy view, verify native stays pristine (H24, no radio)");

/* XMIT handshake (H25): what lifts the -EINVAL gate in the register
 * wrappers. The gate opens IFF every readiness bit is set AND the human
 * unlock flag is on. Default: closed (production keeps the H24 fail-clean
 * -EINVAL; the blob's own cmp/bne path aborts attach). Bits describe the
 * TX path, proven piece by piece, and are established once by silent
 * init-time probes (xmit_probe_ready, no radio, no state change):
 *  IMPORT native->legacy entry (bcm419_tx_import over shim_skb_import;
 *         S7 PASS: plain + vlan_all import, NULL/GSO refused native-held);
 *  WAKE   queue wake through shim_netdev_native + netdev_get_tx_queue
 *         (bcm419_netif_tx_wake_queue; S7 PASS: stopped bit really clears);
 *  QUEUE  shared queue-state view (H10: _tx/pcpu_refcnt asserted through
 *         the native queue API, never raw 4.19 offsets);
 *  NDO    mock->real steady: the installed table carries a real
 *         ndo_start_xmit with the S7 mock's exact shape/contract, plus
 *         steady-state accounting instead of test globals.
 * A missing bit fails safe: the wrappers keep serving the xmit-less table
 * and registration keeps failing -EINVAL (never a half-open TX path). */
#define XMIT_READY_IMPORT	BIT(0)
#define XMIT_READY_WAKE		BIT(1)
#define XMIT_READY_QUEUE	BIT(2)
#define XMIT_READY_NDO		BIT(3)
#define XMIT_READY_ALL		(XMIT_READY_IMPORT | XMIT_READY_WAKE | \
				 XMIT_READY_QUEUE | XMIT_READY_NDO)

static unsigned int xmit_ready;
static bool xmit_handshake;
module_param(xmit_handshake, bool, 0400);
MODULE_PARM_DESC(xmit_handshake, "Production unlock: install real ndo_start_xmit once the TX path is ready (default closed)");
static bool xmit_selftest;
module_param(xmit_selftest, bool, 0400);
MODULE_PARM_DESC(xmit_selftest, "TX-handshake selftest: gate-closed proof + forced-open TX roundtrip (no radio)");

static atomic_t xmit_frames = ATOMIC_INIT(0);
static atomic_t xmit_bytes = ATOMIC_INIT(0);
static atomic_t xmit_drops = ATOMIC_INIT(0);

/* 4.19 GFP_ATOMIC word for the xmit path (softirq-safe, must not sleep):
 * 4.19 GFP_ATOMIC = __GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM
 * = 0x20 | 0x80000 | 0x400000. The word is pinned at runtime against the
 * native GFP_ATOMIC by the selftest (phase A): a silent drift here would
 * sleep inside dev_hard_start_xmit context. */
#define XMIT_GFP419_ATOMIC	0x480020u

static bool xmit_gate_open(void)
{
	return xmit_handshake && xmit_ready == XMIT_READY_ALL;
}

#define OLD_OFF(field) ND419_off_net_device_##field
/* memcpy handles old fields with weaker alignment than native types. */
#define COPY_TO_OLD(old, dev, field) do { \
	static_assert(sizeof((dev)->field) == ND419_width_net_device_##field); \
	memcpy((old)->bytes + OLD_OFF(field), &(dev)->field, sizeof((dev)->field)); \
} while (0)
#define COPY_FROM_OLD(dev, old, field) do { \
	static_assert(sizeof((dev)->field) == ND419_width_net_device_##field); \
	memcpy(&(dev)->field, (old)->bytes + OLD_OFF(field), sizeof((dev)->field)); \
} while (0)

static int flags_to_native(u64 old, u64 *native,
			   const struct netdev419_flag_pair *pairs, size_t n)
{
	size_t i;
	*native = 0;
	for (i = 0; i < n; i++) {
		if (old & pairs[i].old) {
			*native |= pairs[i].native;
			old &= ~pairs[i].old;
		}
	}
	return old ? -EOPNOTSUPP : 0;
}

static u64 flags_to_old(u64 native, const struct netdev419_flag_pair *pairs, size_t n)
{
	u64 old = 0;
	size_t i;
	for (i = 0; i < n; i++)
		if (native & pairs[i].native)
			old |= pairs[i].old;
	return old;
}

static void old_pointer(struct netdev419_view *old, unsigned int offset,
			const void *value)
{
	memcpy(old->bytes + offset, &value, sizeof(value));
}

static void old_empty_addresses(struct netdev419_view *old, unsigned int off)
{
	struct list_head *list = (void *)(old->bytes + off);
	INIT_LIST_HEAD(list);
	/* kzalloc already cleared the old 32-bit count at +8. Native nodes
	 * must never be linked here: old addr offset=8, native addr offset=20. */
}

static void netdev419_initial_view(struct netdev419_entry *entry)
{
	struct net_device *dev = entry->native;
	struct netdev419_view *old = entry->old;
	u32 priv_flags = (u32)dev->priv_flags;

	COPY_TO_OLD(old, dev, name);
	COPY_TO_OLD(old, dev, name_assign_type);
	COPY_TO_OLD(old, dev, flags);
	/* Native widened priv_flags to u64. Initial ether flags fit u32 and
	 * their bit positions are asserted below. Do not overwrite old gflags. */
	memcpy(old->bytes + OLD_OFF(priv_flags), &priv_flags, sizeof(priv_flags));
	COPY_TO_OLD(old, dev, state);
	COPY_TO_OLD(old, dev, type);
	COPY_TO_OLD(old, dev, mtu);
	COPY_TO_OLD(old, dev, min_mtu);
	COPY_TO_OLD(old, dev, max_mtu);
	COPY_TO_OLD(old, dev, hard_header_len);
	COPY_TO_OLD(old, dev, min_header_len);
	COPY_TO_OLD(old, dev, needed_headroom);
	COPY_TO_OLD(old, dev, needed_tailroom);
	COPY_TO_OLD(old, dev, addr_len);
	COPY_TO_OLD(old, dev, addr_assign_type);
	COPY_TO_OLD(old, dev, perm_addr);
	COPY_TO_OLD(old, dev, broadcast);
	COPY_TO_OLD(old, dev, tx_queue_len);
	COPY_TO_OLD(old, dev, num_tx_queues);
	COPY_TO_OLD(old, dev, real_num_tx_queues);
	COPY_TO_OLD(old, dev, num_rx_queues);
	COPY_TO_OLD(old, dev, real_num_rx_queues);
	COPY_TO_OLD(old, dev, nd_net);
	/* Audited inline accesses: old _tx->state uses the same 256-byte
	 * queues and offset76. Old per-CPU dev_put can share native counters.
	 * Do NOT copy native ops/wdev/device/multicast pointers into the view. */
	COPY_TO_OLD(old, dev, _tx);
	COPY_TO_OLD(old, dev, pcpu_refcnt);
	memcpy(entry->address, dev->dev_addr, dev->addr_len);
	old_pointer(old, OLD_OFF(dev_addr), entry->address);
	old_empty_addresses(old, OLD_OFF(uc));
	old_empty_addresses(old, OLD_OFF(mc));
	old_empty_addresses(old, OLD_OFF(dev_addrs));
}

struct netdev419_view *shim_netdev_alloc_ether(int priv_size, const char *name,
					    u8 assign_type, u32 txqs, u32 rxqs)
{
	struct netdev419_entry *entry;
	struct net_device *native;
	void *allocation;
	size_t size;

	if (priv_size < 0 || !name || strnlen(name, IFNAMSIZ) >= IFNAMSIZ ||
	    !txqs || !rxqs ||
	    check_add_overflow((size_t)priv_size,
		(size_t)ND419_size_net_device + NETDEV_ALIGN - 1, &size))
		return NULL;
	allocation = kzalloc(size, GFP_KERNEL);
	if (!allocation)
		return NULL;
	native = alloc_netdev_mqs(sizeof(*entry), name, assign_type, ether_setup, txqs, rxqs);
	if (!native) {
		kfree(allocation);
		return NULL;
	}
	entry = netdev_priv(native);
	entry->native = native;
	entry->allocation = allocation;
	entry->old = PTR_ALIGN(allocation, NETDEV_ALIGN);
	entry->default_ethtool = native->ethtool_ops;
	netdev419_initial_view(entry);
	mutex_lock(&netdev419_mutex);
	list_add_rcu(&entry->list, &netdev419_views);
	mutex_unlock(&netdev419_mutex);
	return entry->old;
}

struct net_device *shim_netdev_native(const struct netdev419_view *old)
{
	struct netdev419_entry *entry;
	struct net_device *native = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &netdev419_views, list) {
		if (entry->old == old) {
			native = entry->native;
			break;
		}
	}
	rcu_read_unlock();
	return native;
}

struct netdev419_view *shim_netdev_legacy(const struct net_device *native)
{
	struct netdev419_entry *entry;
	struct netdev419_view *old = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &netdev419_views, list) {
		if (entry->native == native) {
			old = entry->old;
			break;
		}
	}
	rcu_read_unlock();
	return old;
}

/* Legacy lookup bridge (P0 vendor30 netdev-lookup lane).
 *
 * Root cause: wl.ko's five dev_get_by_name sites (0x206c wl_handle_blog_event,
 * 0x63cd2c/0x63ced4/0x63d18c/0x63d740 cfg/nlwifi paths) resolved to the kernel
 * and received a NATIVE 6.6 net_device. Every site then reads it with 4.19
 * offsets — [dev,#1408] as wlif, [dev,#892] as pcpu_refcnt — and the first
 * crash (vendor30 Oops: dev_get_by_name+46 -> [native+1408]=bf0bd130 garbage
 * -> wl_bsscfg_find -> NULL+8) proved the object confusion. The fix must also
 * carry the reference: bcm_dev_hold/put operate on the native counter, so a
 * bare pointer swap without ref pairing would corrupt the next release.
 *
 * Contract (mirrors the stock 4.19 ref DAG exactly, only the object identity
 * is translated):
 *  - native lookup takes exactly one ref (kernel dev_get_by_name semantics);
 *  - registry hit: that single ref is TRANSFERRED to the caller with the
 *    legacy view. The caller drops it exactly once — bcm_dev_put(old) on the
 *    blog path (0x206c->0x2164) or the blob's inline pcpu dec via old+892 on
 *    the four cfg paths (the legacy slot mirrors the native pcpu pointer, so
 *    both legs reach the same counter). No extra hold is taken here.
 *  - missing name: NULL, no ref (kernel returned NULL).
 *  - foreign interface (loopback, Ethernet, anything without a legacy view):
 *    the lookup ref is dropped HERE and NULL is returned. Handing the native
 *    pointer out as an olddev would re-create the Oops; every one of the five
 *    sites NULL-checks (beq to its fail path), so NULL is the safe answer.
 *    No unsafe synthetic view is invented for foreign interfaces.
 *  - NULL net/name: NULL without touching the stack (the blob never does
 *    this; cheap guard).
 * The passed net (the blob passes init_net at all five sites) selects the
 * namespace; rtnl is not required (dev_get_by_name is RCU internally). The
 * legacy view outlives native unregister by design (explicit free only), so a
 * held bridge ref keeps the native alive exactly as on stock.
 */
struct net_device *bcm_shim_dev_get_by_name_legacy(struct net *net,
						   const char *name)
{
	struct net_device *native;
	struct netdev419_view *old;

	if (!net || !name)
		return NULL;
	native = dev_get_by_name(net, name);
	if (!native)
		return NULL;
	old = shim_netdev_legacy(native);
	if (!old) {
		dev_put(native);
		return NULL;
	}
	return (struct net_device *)old;
}
EXPORT_SYMBOL(bcm_shim_dev_get_by_name_legacy);

static void netdev419_release_view(struct netdev419_entry *entry)
{
	mutex_lock(&netdev419_mutex);
	list_del_rcu(&entry->list);
	mutex_unlock(&netdev419_mutex);
	synchronize_rcu();
	if (entry->parent_ref) {
		put_device(entry->parent_ref);
		entry->parent_ref = NULL;
	}
	if (entry->native->ieee80211_ptr) {
		struct wireless_dev *wd = entry->native->ieee80211_ptr;
		struct wdev419_view *old_wd = shim_wdev_legacy(wd);

		if (old_wd && !wd->registered) {
			wd->netdev = NULL;
			if (shim_wdev_free(old_wd))
				pr_warn("bcm_shim: netdev wdev free refused\n");
			else
				entry->native->ieee80211_ptr = NULL;
		}
	}
	kfree(entry->allocation);
	entry->allocation = NULL;
	entry->old = NULL;
}

int shim_netdev_free(struct netdev419_view *old)
{
	struct netdev419_entry *entry, *found = NULL;
	struct net_device *native;

	mutex_lock(&netdev419_mutex);
	list_for_each_entry(entry, &netdev419_views, list) {
		if (entry->old != old)
			continue;
		if (entry->native->reg_state != NETREG_UNINITIALIZED &&
		    entry->native->reg_state != NETREG_UNREGISTERED &&
		    entry->native->reg_state != NETREG_UNREGISTERING) {
			mutex_unlock(&netdev419_mutex);
			return -EBUSY;
		}
		found = entry;
		break;
	}
	mutex_unlock(&netdev419_mutex);
	if (!found)
		return -ENOENT;
	native = found->native;
	if (native->reg_state == NETREG_UNREGISTERING) {
		/* Native free_netdev defers destruction until RTNL todo completes. */
		if (!rtnl_is_locked())
			return -EPERM;
		native->needs_free_netdev = true;
		old->bytes[OLD_OFF(needs_free_netdev)] = 1;
		free_netdev(native);
		return 0;
	}
	netdev419_release_view(found);
	free_netdev(native); /* frees entry (native private data) too */
	return 0;
}

int shim_netdev_free_unregistered(struct netdev419_view *old)
{
	struct net_device *dev = shim_netdev_native(old);
	if (!dev)
		return -ENOENT;
	if (dev->reg_state != NETREG_UNINITIALIZED)
		return -EBUSY;
	return shim_netdev_free(old);
}

static void netdev419_sync_core(struct netdev419_entry *entry)
{
	struct net_device *dev = entry->native;
	struct netdev419_view *old = entry->old;
	u64 features;

	COPY_TO_OLD(old, dev, name);
	COPY_TO_OLD(old, dev, ifindex);
	COPY_TO_OLD(old, dev, flags);
	COPY_TO_OLD(old, dev, state);
	old->bytes[OLD_OFF(reg_state)] = dev->reg_state;
	old->bytes[OLD_OFF(needs_free_netdev)] = dev->needs_free_netdev;
	features = flags_to_old(dev->features, nd419_feature_flags, ARRAY_SIZE(nd419_feature_flags));
	if (entry->extended_stats)
		features |= ND419_EXTSTATS;
	memcpy(old->bytes + OLD_OFF(features), &features, sizeof(features));
}

static void netdev419_destructor(struct net_device *dev)
{
	struct netdev419_entry *entry = netdev_priv(dev);

	if (!entry->destructor_called) {
		entry->destructor_called = true;
		netdev419_sync_core(entry);
		if (entry->old_destructor)
			entry->old_destructor(entry->old);
	}
	/* register_netdevice calls this even on some errors BEFORE returning.
	 * Keep the view for the caller's explicit free in every failure case.
	 * Normal unregister reaches here after netdev_wait_allrefs_any(). */
	if (!entry->in_register && dev->needs_free_netdev)
		netdev419_release_view(entry);
}

static void netdev419_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct netdev419_entry *entry = netdev_priv(dev);
	entry->old_drvinfo(entry->old, info);
}

static const struct ethtool_ops netdev419_ethtool = {
	.get_drvinfo = netdev419_drvinfo,
};

static void netdev419_stats64(struct net_device *dev, struct rtnl_link_stats64 *native)
{
	struct netdev419_entry *entry = netdev_priv(dev);
	struct netdev419_stats old = {};
	entry->old_stats(entry->old, &old);
#define COPY_STAT(name) native->name = old.name;
	ND419_COMMON_STATS(COPY_STAT)
#undef COPY_STAT
	native->rx_nohandler = old.rx_nohandler;
	/* No legacy equivalent: must not read beyond the old 240-byte buffer. */
	native->rx_otherhost_dropped = 0;
}

static const char netdev419_stat_names[6][ETH_GSTRING_LEN] = {
	"bcm_tx_multicast_packets", "bcm_rx_multicast_bytes", "bcm_tx_multicast_bytes",
	"bcm_rx_broadcast_packets", "bcm_tx_broadcast_packets", "bcm_rx_unknown_packets",
};

static int netdev419_sset_count(struct net_device *dev, int set)
{
	return set == ETH_SS_STATS ? ARRAY_SIZE(netdev419_stat_names) : -EOPNOTSUPP;
}

static void netdev419_stat_strings(struct net_device *dev, u32 set, u8 *data)
{
	if (set == ETH_SS_STATS)
		memcpy(data, netdev419_stat_names, sizeof(netdev419_stat_names));
}

static void netdev419_ethtool_stats(struct net_device *dev, struct ethtool_stats *stats, u64 *data)
{
	struct netdev419_entry *entry = netdev_priv(dev);
	struct netdev419_stats old = {};
	entry->old_stats(entry->old, &old);
	memcpy(data, old.extended, sizeof(old.extended));
}

/* Translate the eight populated slots of wl's 256-byte legacy table.
 * The +64 stats slot already has its H10/H11 translator. */
static int netdev419_prepare_blob(struct netdev419_entry *entry)
{
	struct net_device *dev = entry->native;
	struct netdev419_view *old = entry->old;
	const u8 *table;
	void *parent, *wd;
	unsigned int offset;

	memcpy(&table, old->bytes + OLD_OFF(netdev_ops), sizeof(table));
	if (!table)
		return -EINVAL;
	for (offset = 0; offset < 256; offset += 4) {
		if (offset == 4 || offset == 8 || offset == 12 || offset == 16 ||
		    offset == 32 || offset == 36 || offset == 44 || offset == 64)
			continue;
		if (memchr_inv(table + offset, 0, 4)) {
			pr_err("bcm_shim: unsupported legacy ndo slot %u\n", offset);
			return -EOPNOTSUPP;
		}
	}
#define READ_NDO(field, off) memcpy(&entry->field, table + off, sizeof(entry->field))
	READ_NDO(old_uninit, 4);
	READ_NDO(old_open, 8);
	READ_NDO(old_stop, 12);
	READ_NDO(old_xmit, 16);
	READ_NDO(old_set_rx_mode, 32);
	READ_NDO(old_set_mac, 36);
	READ_NDO(old_ioctl, 44);
#undef READ_NDO
	if (!entry->old_xmit)
		return -EINVAL;
	memcpy(&parent, old->bytes + OLD_OFF(dev), sizeof(parent));
	if (parent && !dev->dev.parent) {
		entry->parent_ref = shim_dma_get_device(parent);
		if (!entry->parent_ref)
			return -ENOENT;
		SET_NETDEV_DEV(dev, entry->parent_ref);
	}
	memcpy(&wd, old->bytes + OLD_OFF(ieee80211_ptr), sizeof(wd));
	if (wd && !dev->ieee80211_ptr) {
		struct wireless_dev *native_wd = shim_wdev_adopt(wd, old, dev);

		if (IS_ERR(native_wd))
			return PTR_ERR(native_wd);
		dev->ieee80211_ptr = native_wd;
	}
	return 0;
}

static int netdev419_prepare(struct netdev419_entry *entry,
			     const struct net_device_ops *ops)
{
	struct net_device *dev = entry->native;
	struct netdev419_view *old = entry->old;
	const u8 *eth_ops;
	const u8 *old_ops;
	const u8 *addr;
	void *parent, *wdev;
	u64 features, translated;
	u32 priv_flags;
	int ret;

	if (!ops || !ops->ndo_start_xmit || dev->reg_state != NETREG_UNINITIALIZED ||
	    entry->destructor_called)
		return -EINVAL;
	if (strnlen(old->bytes, IFNAMSIZ) >= IFNAMSIZ)
		return -EINVAL;
	if (ops == &netdev419_real_ops) {
		ret = netdev419_prepare_blob(entry);
		if (ret) {
			pr_err("bcm_shim: netdev prepare blob rc=%d\n", ret);
			return ret;
		}
	}
	/* Object bridges must establish these native relationships first. */
	memcpy(&parent, old->bytes + OLD_OFF(dev), sizeof(parent));
	memcpy(&wdev, old->bytes + OLD_OFF(ieee80211_ptr), sizeof(wdev));
	if ((parent && !dev->dev.parent) || (wdev && !dev->ieee80211_ptr))
		return -EOPNOTSUPP;
	memcpy(&priv_flags, old->bytes + OLD_OFF(priv_flags), sizeof(priv_flags));
	ret = flags_to_native(priv_flags, &translated, nd419_priv_flags, ARRAY_SIZE(nd419_priv_flags));
	if (ret)
		return ret;
	dev->priv_flags = translated;
	memcpy(&old_ops, old->bytes + OLD_OFF(netdev_ops), sizeof(old_ops));
	entry->old_stats = NULL;
	if (old_ops)
		memcpy(&entry->old_stats, old_ops + ND419_off_net_device_ops_ndo_get_stats64,
		       sizeof(entry->old_stats));
	memcpy(&features, old->bytes + OLD_OFF(features), sizeof(features));
	entry->extended_stats = !!(features & ND419_EXTSTATS);
	if (entry->extended_stats && !entry->old_stats)
		return -EOPNOTSUPP;
#define TRANSLATE_FEATURE(field) do { \
	memcpy(&features, old->bytes + OLD_OFF(field), sizeof(features)); \
	if (entry->old_stats) features &= ~ND419_EXTSTATS; \
	ret = flags_to_native(features, &translated, nd419_feature_flags, ARRAY_SIZE(nd419_feature_flags)); \
	if (ret) return ret; \
	dev->field = translated; \
} while (0)
	TRANSLATE_FEATURE(features);
	TRANSLATE_FEATURE(hw_features);
	TRANSLATE_FEATURE(wanted_features);
	TRANSLATE_FEATURE(vlan_features);
	TRANSLATE_FEATURE(hw_enc_features);
#undef TRANSLATE_FEATURE
	COPY_FROM_OLD(dev, old, name);
	COPY_FROM_OLD(dev, old, name_assign_type);
	COPY_FROM_OLD(dev, old, flags);
	COPY_FROM_OLD(dev, old, mtu);
	COPY_FROM_OLD(dev, old, min_mtu);
	COPY_FROM_OLD(dev, old, max_mtu);
	COPY_FROM_OLD(dev, old, needed_headroom);
	COPY_FROM_OLD(dev, old, needed_tailroom);
	COPY_FROM_OLD(dev, old, tx_queue_len);
	COPY_FROM_OLD(dev, old, watchdog_timeo);
	COPY_FROM_OLD(dev, old, mem_start);
	COPY_FROM_OLD(dev, old, mem_end);
	COPY_FROM_OLD(dev, old, base_addr);
	COPY_FROM_OLD(dev, old, irq);
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
	if (!addr || old->bytes[OLD_OFF(addr_len)] != ETH_ALEN || !is_valid_ether_addr(addr))
		return -EINVAL;
	eth_hw_addr_set(dev, addr);
	COPY_FROM_OLD(dev, old, perm_addr);
	COPY_FROM_OLD(dev, old, addr_assign_type);
	memcpy(&eth_ops, old->bytes + OLD_OFF(ethtool_ops), sizeof(eth_ops));
	entry->native_ethtool = *entry->default_ethtool;
	if (eth_ops) {
		/* Actual main wl table: 232 bytes, only get_drvinfo at +8.
		 * Reject any other populated entry until its signature is audited. */
		if (memchr_inv(eth_ops, 0, 8) || memchr_inv(eth_ops + 12, 0, 232 - 12))
			return -EOPNOTSUPP;
		memcpy(&entry->old_drvinfo, eth_ops + 8, sizeof(entry->old_drvinfo));
		if (!entry->old_drvinfo)
			return -EINVAL;
		entry->native_ethtool = netdev419_ethtool;
	}
	if (entry->extended_stats) {
		entry->native_ethtool.get_sset_count = netdev419_sset_count;
		entry->native_ethtool.get_strings = netdev419_stat_strings;
		entry->native_ethtool.get_ethtool_stats = netdev419_ethtool_stats;
	}
	dev->ethtool_ops = &entry->native_ethtool;
	memcpy(&entry->old_destructor, old->bytes + OLD_OFF(priv_destructor), sizeof(entry->old_destructor));
	dev->needs_free_netdev = !!old->bytes[OLD_OFF(needs_free_netdev)];
	dev->priv_destructor = netdev419_destructor;
	entry->native_ops = *ops;
	if (entry->old_stats)
		entry->native_ops.ndo_get_stats64 = netdev419_stats64;
	if (ops == &netdev419_real_ops) {
		/* Use the native software checksum/segmentation path until
		 * radio offloads are verified. The blob receives plain frames. */
		netdev_features_t offload = NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK |
			NETIF_F_SG | NETIF_F_FRAGLIST;

		dev->features &= ~offload;
		dev->hw_features &= ~offload;
		dev->wanted_features &= ~offload;
		dev->vlan_features &= ~offload;
		dev->hw_enc_features &= ~offload;
	}
	dev->netdev_ops = &entry->native_ops;
	return 0;
}

int shim_netdev_register_locked(struct netdev419_view *old,
			       const struct net_device_ops *ops)
{
	struct net_device *dev = shim_netdev_native(old);
	struct netdev419_entry *entry;
	int ret;

	if (!dev)
		return -ENOENT;
	if (!rtnl_is_locked())
		return -EPERM;
	entry = netdev_priv(dev);
	ret = netdev419_prepare(entry, ops);
	if (ret)
		return ret;
	entry->in_register = true;
	ret = register_netdevice(dev);
	entry->in_register = false;
	if (ret)
		dev->needs_free_netdev = false; /* explicit free of failed registration */
	netdev419_sync_core(entry);
	return ret;
}

int shim_netdev_register(struct netdev419_view *old, const struct net_device_ops *ops)
{
	int ret;
	rtnl_lock();
	ret = shim_netdev_register_locked(old, ops);
	rtnl_unlock();
	return ret;
}

int shim_netdev_unregister_locked(struct netdev419_view *old)
{
	struct net_device *dev = shim_netdev_native(old);

	if (!dev)
		return -ENOENT;
	if (!rtnl_is_locked())
		return -EPERM;
	if (dev->reg_state != NETREG_REGISTERED)
		return -EINVAL;
	unregister_netdevice_queue(dev, NULL);
	netdev419_sync_core(netdev_priv(dev));
	return 0; /* auto-free, if requested, occurs at the caller's rtnl_unlock */
}

int shim_netdev_unregister(struct netdev419_view *old)
{
	int ret;
	rtnl_lock();
	ret = shim_netdev_unregister_locked(old);
	rtnl_unlock();
	return ret;
}

/* Notifier trampoline (S9/M3): wl.ko registers two netdevice notifiers —
 * wl_cfg80211_netdev_notifier_call (.text 0x2d01bc, nb at .data+0x3440) and
 * pktfwd_netdev_notifier_call (.text 0x2244, nb at .data+0x1cc) — through
 * four call sites (two wl_cfg80211_ stubs + two direct pkt fwd bl sites),
 * all redirected here by renaming the two UND symbols (never by exporting
 * the kernel's names: duplicates are -ENOEXEC). Both callbacks index
 * struct net_device with 4.19 offsets (cfg80211: ieee80211_ptr @628;
 * pkt fwd: netdev_ops @460, priv @1408, flags-like @300) and dispatch on
 * 4.19 event numbers (UNREGISTER=6, GOING_DOWN=9), while the kernel always
 * passes NATIVE 6.6 objects (registration replays every live netdev, e.g.
 * lo, with REGISTER=5) under 6.6 numbering (PRE_CHANGEADDR=9 inserted, so
 * GOING_DOWN=10). A native pointer faults the first deref (S9 Oops: ldr
 * r8,[r4,#628] yields garbage 0x10800003, ldr r6,[r8] dies) and event 9
 * would alias PRE_CHANGEADDR to GOING_DOWN (spurious stop_ap) while a
 * real GOING_DOWN=10 is ignored — so neither a same-name export (dup) nor
 * a single-instruction layout patch (fixes the pointer, not the events;
 * and goes stale once blob objects become legacy views) suffices.
 *
 * The trampoline translates BOTH: a registry-hit native dev is replaced
 * by its 4.19 legacy view (disasm-proven: neither callback reads r0/nb or
 * past info+0, so a two-word stack copy {legacy, NULL} suffices) with the
 * event mapped 6.6->4.19. Foreign devs (replay, unrelated interfaces) are
 * NOT forwarded: under 4.19 semantics both callbacks return 0 for them
 * (NULL-ieee80211_ptr early exit or magic mismatch; pkt fwd falls through
 * to 0). Accepted deviation: the cfg80211 NULL path prints two
 * wl_dbg_level&4-gated debug lines that the swallow skips (dmesg-only).
 *
 * The nb->notifier_call swap happens at RUNTIME in the wrappers: the blob
 * nb initializers (R_ARM_ABS32 @.data+0x3440/+0x1cc) and call sites are
 * load-relocated, so no file-level edit can carry the trampoline address;
 * only the UND names are file-level hook points. The slot table is a
 * fixed array with READ/WRITE_ONCE pairing (wmb/rmb): the trampoline runs
 * in arbitrary notifier context and takes no locks; writers are process
 * context (insmod/exit paths only) under a leaf mutex. Unregister drains
 * in-flight calls via the kernel first, then clears the slot and restores
 * the blob pointer. Full-blob translation stays dormant (registry miss =
 * swallow, no crash, own UNREGISTER cleanup / GOING_DOWN stop_ap skipped)
 * until the object-adapter lane switches blob alloc imports to legacy
 * views; MUST NOT be combined with the H7e single-site ldr patch at
 * 0x2d01c8 (patched reader + legacy view reads netdev_ops as wdev) —
 * tools/modvermagic.py --rename-notifier refuses renamed input then.
 */
#define SHIM_NOTIFY_SLOTS 8

struct shim_notify_slot {
	struct notifier_block *nb;
	notifier_fn_t orig;
};

static struct shim_notify_slot shim_notify_slots[SHIM_NOTIFY_SLOTS];
static DEFINE_MUTEX(shim_notify_mutex);
static unsigned int shim_notify_swapped;
static unsigned int shim_notify_restored;

/* 6.6 values pinned: any rebase shifting them must fail loudly here
 * instead of silently mistranslating. 4.19 targets (GOING_DOWN=9,
 * POST_INIT=16) are from the GPL 4.19.246 netdevice.h enum, which has no
 * PRE_CHANGEADDR/PRE_UNINIT (6.6-only events are swallowed: a 4.19 kernel
 * could never deliver them). */
static_assert(NETDEV_REGISTER == 5 && NETDEV_UNREGISTER == 6);
static_assert(NETDEV_PRE_CHANGEADDR == 9 && NETDEV_GOING_DOWN == 10);
static_assert(NETDEV_POST_INIT == 17 && NETDEV_PRE_UNINIT == 18);
static_assert(NOTIFY_DONE == 0);

static bool shim_notify_translate(unsigned long in, unsigned long *out)
{
	if (in >= NETDEV_UP && in <= NETDEV_CHANGEADDR) {
		*out = in; /* 1..8 identical in both kernels */
		return true;
	}
	if (in >= NETDEV_GOING_DOWN && in <= NETDEV_POST_INIT) {
		*out = in - 1; /* 10..17 -> 4.19 9..16 */
		return true;
	}
	return false; /* 0, 9 PRE_CHANGEADDR, 18 PRE_UNINIT, 19+: no meaning */
}

static notifier_fn_t shim_notify_orig(struct notifier_block *nb)
{
	int i;

	for (i = 0; i < SHIM_NOTIFY_SLOTS; i++) {
		if (READ_ONCE(shim_notify_slots[i].nb) == nb && nb) {
			smp_rmb();
			return READ_ONCE(shim_notify_slots[i].orig);
		}
	}
	return NULL;
}

static int shim_notify_trampoline(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = ptr ? netdev_notifier_info_to_dev(ptr) : NULL;
	struct netdev419_view *legacy;
	notifier_fn_t orig;
	struct netdev_notifier_info sub;
	unsigned long mapped;

	if (!nb || !dev)
		return NOTIFY_DONE; /* blob beq-exits on NULL dev the same way */
	orig = shim_notify_orig(nb);
	if (!orig)
		return NOTIFY_DONE;
	legacy = shim_netdev_legacy(dev);
	if (!legacy)
		return NOTIFY_DONE; /* foreign replay/unrelated: blob would no-op */
	if (!shim_notify_translate(event, &mapped))
		return NOTIFY_DONE; /* 6.6-only event: 4.19 never delivered it */
	/* Legacy view IS the 4.19 net_device the blob expects (1408 bytes,
	 * static_asserted in shim_netdev_init). Both callbacks dereference
	 * only info+0 and ignore r0/nb (disasm-proven), so extack stays NULL.
	 */
	sub.dev = (struct net_device *)legacy;
	sub.extack = NULL;
	return orig(nb, mapped, &sub);
}

int bcm_shim_register_netdevice_notifier(struct notifier_block *nb)
{
	int i, free = -1, rc;

	if (!nb || !nb->notifier_call)
		return -EINVAL;
	mutex_lock(&shim_notify_mutex);
	for (i = 0; i < SHIM_NOTIFY_SLOTS; i++) {
		struct notifier_block *cur = READ_ONCE(shim_notify_slots[i].nb);

		if (cur == nb) {
			free = i; /* re-register: keep the saved orig */
			break;
		}
		if (!cur && free < 0)
			free = i;
	}
	if (free < 0) {
		mutex_unlock(&shim_notify_mutex);
		/* Blob registers exactly two nbs; passthrough unprotected is
		 * safer than failing insmod, but must be loud. */
		pr_warn_once("bcm_shim: notify table full, passthrough\n");
		return register_netdevice_notifier(nb);
	}
	if (!READ_ONCE(shim_notify_slots[free].nb)) {
		WRITE_ONCE(shim_notify_slots[free].orig, nb->notifier_call);
		smp_wmb();
		WRITE_ONCE(shim_notify_slots[free].nb, nb);
	}
	WRITE_ONCE(nb->notifier_call, shim_notify_trampoline);
	shim_notify_swapped++;
	mutex_unlock(&shim_notify_mutex);
	rc = register_netdevice_notifier(nb);
	if (rc) {
		/* Keep table/kernel in sync: drop the slot we just took. */
		mutex_lock(&shim_notify_mutex);
		if (READ_ONCE(shim_notify_slots[free].nb) == nb &&
		    READ_ONCE(nb->notifier_call) == shim_notify_trampoline) {
			WRITE_ONCE(nb->notifier_call,
				   READ_ONCE(shim_notify_slots[free].orig));
			smp_wmb();
			WRITE_ONCE(shim_notify_slots[free].nb, NULL);
			smp_wmb();
			WRITE_ONCE(shim_notify_slots[free].orig, NULL);
		}
		mutex_unlock(&shim_notify_mutex);
		return rc;
	}
	return 0;
}
EXPORT_SYMBOL(bcm_shim_register_netdevice_notifier);

int bcm_shim_unregister_netdevice_notifier(struct notifier_block *nb)
{
	int i, rc;

	if (!nb)
		return -EINVAL;
	/* Kernel first: removes from the chain and drains in-flight calls,
	 * so no trampoline instance observes the slot teardown below. */
	rc = unregister_netdevice_notifier(nb);
	mutex_lock(&shim_notify_mutex);
	for (i = 0; i < SHIM_NOTIFY_SLOTS; i++) {
		notifier_fn_t orig;

		if (READ_ONCE(shim_notify_slots[i].nb) != nb)
			continue;
		orig = READ_ONCE(shim_notify_slots[i].orig);
		if (READ_ONCE(nb->notifier_call) == shim_notify_trampoline)
			WRITE_ONCE(nb->notifier_call, orig);
		else
			pr_warn_once("bcm_shim: nb %pK call stomped, skip restore\n",
				     nb);
		smp_wmb();
		WRITE_ONCE(shim_notify_slots[i].nb, NULL);
		smp_wmb();
		WRITE_ONCE(shim_notify_slots[i].orig, NULL);
		shim_notify_restored++;
		break;
	}
	mutex_unlock(&shim_notify_mutex);
	return rc;
}
EXPORT_SYMBOL(bcm_shim_unregister_netdevice_notifier);

/* Alloc/register redirect (H24 netdev-write lane).
 *
 * Root cause (bcmfun24 REPORT §4, compiler-measured in this lane):
 * wl.ko's single netdev source is alloc_netdev_mqs(4, "wl%d", 0,
 * ether_setup, 1, 1) at .text 0x309420 (only R_ARM_CALL on that UND in the
 * whole blob). The import resolves to the kernel, so the blob receives a
 * NATIVE 6.6 object and then writes it with 4.19 offsets: +460 netdev_ops
 * ptr -> native ieee80211_ptr, +464 ethtool_ops -> native dev_addr,
 * +636 dev_addr read -> native proto_down_reason (u32, =0) -> str faults.
 * The same idiom repeats at every register_netdev site (wl0 0x30e9e0,
 * monitor 0x30a49c, _wl_add_if 0x30b228, wl_register_interface 0x313628).
 *
 * Why not rel-patch the write instructions (rejected alternative):
 *  - 6 of the ~15 touched offsets live in the Broadcom bcm_nd_ext private
 *    area (+300/+308/+312/+316/+400, CONFIG_BCM_KF_NETDEV_EXT) with NO
 *    native equivalent — there is nowhere to remap them to short of a
 *    shadow struct, i.e. this adapter with extra steps.
 *  - Pointer stores need semantic translation, not offset remap: the +460
 *    ndo table is 256 B with a different slot layout than native 332 B
 *    (H10 audit), the +636 path must copy 6 MAC bytes (not the pointer),
 *    +920 needs the old-view destructor thunk (H11).
 *  - The site list cannot be proven complete: monitor/secondary ifs,
 *    multicast, ioctl and ~150 sibling ndev+628 sites (notifier REPORT §4)
 *    share the idiom. The alloc redirect is complete by construction: the
 *    blob has exactly one netdev source, so every present and future
 *    [dev,#off] access lands in legacy memory.
 *  - A crash-site-only patch is mutually exclusive with this adapter: a
 *    patched ldr [dev,#464] applied to a legacy view would read
 *    legacy+464 (ethtool_ops) as dev_addr (same conflict class as the H7e
 *    guard in patch_notifier_rename). tools/modvermagic.py --rename-netdev
 *    therefore refuses input carrying such a patch.
 *
 * Contract: alloc returns the legacy view cast to struct net_device *;
 * register resolves it to the native object and runs the H11 prepare path
 * with an xmit-less native ops table, so it fails with -EINVAL before any
 * state is touched (ordering: ops gate is first in netdev419_prepare).
 * -EINVAL is the documented H25 handshake point, not a bug: the blob's own
 * cmp/bne fail path aborts attach cleanly. unregister maps miss (foreign
 * pointer, e.g. the ambiguous [r4,#12] tail-call source at 0x30bca4) to a
 * loud no-op instead of dereferencing.
 */
struct net_device *bcm_shim_alloc_netdev_mqs(int priv_size, const char *name,
					     u8 assign_type,
					     void (*setup)(struct net_device *),
					     u32 txqs, u32 rxqs)
{
	struct netdev419_view *old;

	if (!name || setup != ether_setup) {
		/* The audited blob site passes ("wl%d", NET_NAME_UNKNOWN,
		 * ether_setup, 1, 1). Anything else is an un-audited alloc
		 * variant: fail cleanly (blob's beq-fail path) instead of
		 * handing out a mis-shaped object. */
		pr_warn_once("bcm_shim: netdev alloc guard: name=%pK setup-mismatch=%d\n",
			     name, setup != ether_setup);
		return NULL;
	}
	old = shim_netdev_alloc_ether(priv_size, name, assign_type, txqs, rxqs);
	return (struct net_device *)old;
}
EXPORT_SYMBOL(bcm_shim_alloc_netdev_mqs);

/* Native ops for the blob register path while the gate is closed:
 * deliberately xmit-less, so registration fails clean -EINVAL before any
 * state is touched (ordering: ops gate is first in netdev419_prepare).
 * -EINVAL is the documented H25 handshake point, not a bug: the blob's own
 * cmp/bne fail path aborts attach cleanly. */
static const struct net_device_ops netdev419_blob_ops;

/* Real TX entry for legacy-view devices (gate open only). Shape and
 * contract are the S7 mock's (shim_skb.c rxtx_mock_xmit, S7 PASS),
 * promoted to steady state: same import call, same NETDEV_TX_OK-on-every-
 * leg rule, same retained-on-refuse handling — plus frame/byte/drop
 * accounting instead of test globals. S9 replaces ONLY the counted-sink
 * tail (hand `old` to wl_start's queue); gate, contract and counters stay.
 *
 * Ownership proof (one native reference in, zero out, exactly once):
 *  - !skb cannot happen from the stack; return consumed-code anyway.
 *  - foreign dev (no legacy view, e.g. stack misdelivery): the native
 *    reference is dropped HERE, drops++, OK. Never BUSY: pre-S9 nothing
 *    can drain a stopped queue, so BUSY would wedge the qdisc in retry.
 *  - import refuse (NULL/GSO/unknown-dev inside): bcm419_tx_import keeps
 *    the native reference with the caller by contract (S7), so it is
 *    dropped HERE — exactly wl_start's error leg — drops++, OK.
 *  - import success: the native reference is CONSUMED by import
 *    (native_owner takes it; shim_skb_import succeeds-or-ERR_PTR, never
 *    half). We now own one legacy reference instead: count frame+bytes
 *    (len sampled pre-import from the native side, no legacy access
 *    needed), release it. shim_skb_free fires the destructor only on the
 *    users 1->0 transition and retains ownership on error (warned).
 * Runs in hard-start-xmit context: GFP comes from the pinned 4.19 ATOMIC
 * word (no sleep), no locks taken (RCU lookup only, same as the other
 * borrowed-pointer helpers), no queue stop (nothing fills pre-S9). */
/* RTNL serializes these callbacks. Track the actual task, never infer
 * ownership from rtnl_is_locked() (which may mean another task owns it). */
static struct task_struct *netdev419_rtnl_task;
bool shim_netdev_in_rtnl_callback(void)
{
	return READ_ONCE(netdev419_rtnl_task) == current;
}
static int netdev419_blob_open(struct net_device *dev)
{
	struct netdev419_entry *e = netdev_priv(dev);
	struct task_struct *saved;
	int ret;

	ASSERT_RTNL();
	netdev419_sync_core(e);
	saved = READ_ONCE(netdev419_rtnl_task);
	WRITE_ONCE(netdev419_rtnl_task, current);
	ret = e->old_open ? e->old_open(e->old) : 0;
	WRITE_ONCE(netdev419_rtnl_task, saved);
	pr_info("bcm_shim: ndo_open %s rc=%d\n", dev->name, ret);
	return ret;
}
static int netdev419_blob_stop(struct net_device *dev)
{
	struct netdev419_entry *e = netdev_priv(dev);
	struct task_struct *saved;
	int ret;

	ASSERT_RTNL();
	netdev419_sync_core(e);
	saved = READ_ONCE(netdev419_rtnl_task);
	WRITE_ONCE(netdev419_rtnl_task, current);
	dev_info(&dev->dev, "H30_NDO stop enter\n");
	ret = e->old_stop ? e->old_stop(e->old) : 0;
	dev_info(&dev->dev, "H30_NDO stop exit %d\n", ret);
	WRITE_ONCE(netdev419_rtnl_task, saved);
	return ret;
}
static void netdev419_blob_uninit(struct net_device *dev)
{
	struct netdev419_entry *e = netdev_priv(dev);

	netdev419_sync_core(e);
	if (e->old_uninit)
		e->old_uninit(e->old);
}
static void netdev419_blob_rx_mode(struct net_device *dev)
{
	struct netdev419_entry *e = netdev_priv(dev);
	u32 flags = dev->flags;

	/* Accept the native multicast subscription as all-multicast until
	 * the legacy address-list translator exists. This may receive extra
	 * multicast; it does not omit a requested address or forge a list. */
	if (!netdev_mc_empty(dev))
		flags |= IFF_ALLMULTI;
	memcpy(e->old->bytes + OLD_OFF(flags), &flags, sizeof(flags));
	if (e->old_set_rx_mode)
		e->old_set_rx_mode(e->old);
}
static int netdev419_blob_set_mac(struct net_device *dev, void *addr)
{
	struct netdev419_entry *e = netdev_priv(dev);
	int ret;

	ret = eth_prepare_mac_addr_change(dev, addr);
	if (ret)
		return ret;
	if (!e->old_set_mac)
		return -EOPNOTSUPP;
	ret = e->old_set_mac(e->old, addr);
	if (!ret)
		eth_commit_mac_addr_change(dev, addr);
	return ret;
}
static int netdev419_blob_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct netdev419_entry *e = netdev_priv(dev);

	return e->old_ioctl ? e->old_ioctl(e->old, ifr, cmd) : -EOPNOTSUPP;
}
static int netdev419_blob_private(struct net_device *dev, struct ifreq *ifr,
				 void __user *data, int cmd)
{
	struct ifreq copy = *ifr;

	copy.ifr_data = data;
	return netdev419_blob_ioctl(dev, &copy, cmd);
}
static netdev_tx_t netdev419_real_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
	struct netdev419_view *legacy = dev ? shim_netdev_legacy(dev) : NULL;
	struct netdev419_entry *e = legacy ? netdev_priv(dev) : NULL;
	struct skb419_view *old;
	netdev_tx_t ret;
	unsigned int len;

	if (!skb)
		return NETDEV_TX_OK;
	len = skb->len;
	if (!e || !e->old_xmit)
		goto drop;
	/* Keep one reference until the callback commits ownership. If it
	 * returns BUSY, dropping the legacy view leaves the original skb
	 * alive for the native stack to retry. */
	skb_get(skb);
	old = bcm419_tx_import(skb, XMIT_GFP419_ATOMIC);
	if (!old) {
		consume_skb(skb);
		goto drop;
	}
	ret = e->old_xmit(old, legacy);
	if (ret == NETDEV_TX_BUSY) {
		if (shim_skb_free(old))
			pr_warn("bcm_shim: busy TX legacy release refused\n");
		/* Release the extra reference taken above: the stack keeps its
		 * own and retries the same skb, but without this the +1 from
		 * skb_get() leaked on every BUSY round (review S2-9). */
		consume_skb(skb);
		return NETDEV_TX_BUSY;
	}
	consume_skb(skb);
	atomic_inc(&xmit_frames);
	atomic_add(len, &xmit_bytes);
	return NETDEV_TX_OK;
drop:
	dev_kfree_skb_any(skb);
	atomic_inc(&xmit_drops);
	return NETDEV_TX_OK;
}

static const struct net_device_ops netdev419_real_ops = {
	.ndo_open = netdev419_blob_open,
	.ndo_stop = netdev419_blob_stop,
	.ndo_uninit = netdev419_blob_uninit,
	.ndo_start_xmit = netdev419_real_xmit,
	.ndo_set_rx_mode = netdev419_blob_rx_mode,
	.ndo_set_mac_address = netdev419_blob_set_mac,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_eth_ioctl = netdev419_blob_ioctl,
	.ndo_siocdevprivate = netdev419_blob_private,
};

/* Which table the blob-facing register wrappers install. Closed (default)
 * = xmit-less table = clean -EINVAL. Open = real xmit table, only when
 * the full TX path is ready AND the human unlock flag is on. */
static const struct net_device_ops *netdev419_register_table(void)
{
	if (xmit_gate_open()) {
		pr_info_once("bcm_shim: xmit gate OPEN (ready=%#x handshake=1): real ndo_start_xmit installed\n",
			     xmit_ready);
		return &netdev419_real_ops;
	}
	return &netdev419_blob_ops;
}

int bcm_shim_register_netdev(struct net_device *dev)
{
	struct netdev419_view *old = (struct netdev419_view *)dev;
	struct net_device *native = old ? shim_netdev_native(old) : NULL;

	if (!dev)
		return -EINVAL;
	if (!native)
		return -ENOENT;
	{
		int ret = shim_netdev_register(old, netdev419_register_table());
		pr_info("bcm_shim: register_netdev %s rc=%d gate=%d\n",
			native->name, ret, xmit_gate_open());
		return ret;
	}
}
EXPORT_SYMBOL(bcm_shim_register_netdev);

void bcm_shim_unregister_netdev(struct net_device *dev)
{
	struct netdev419_view *old = (struct netdev419_view *)dev;

	if (!dev || !shim_netdev_native(old)) {
		pr_warn_once("bcm_shim: unregister_netdev miss, skip\n");
		return;
	}
	shim_netdev_unregister(old);
}
EXPORT_SYMBOL(bcm_shim_unregister_netdev);

/* Co-rename targets for the monitor/secondary paths (H25, wl.ko only —
 * hnd.ko carries none of these UND):
 *  register_netdevice: 2x R_ARM_CALL @0x30b3bc (_wl_add_if+744) and
 *    @0x313664 (wl_register_interface+144). Note _wl_add_if ALSO calls
 *    register_netdev @0x30b228: dual-path function (primary + secondary
 *    if), both covered once renamed.
 *  unregister_netdevice_queue: 1x R_ARM_JUMP24 @0x30bca0
 *    (wl_set_multicast_list_workitem+684; sibling JUMP24 @0x30bcb0 in the
 *    same function is unregister_netdev, already renamed in H24).
 * The rename itself (tools/modvermagic.py) is the integrator lane's edit
 * (file boundary): exact proposed sets are in triaging/shim/xmit/REPORT.md
 * §4. Same legacy-view contract as the netdev wrappers: the blob passes a
 * legacy view (alloc redirect covers ALL netdevs by construction, H24 §1),
 * we resolve to native and run the tested prepare path under the SAME
 * xmit gate (monitor ifs get real TX exactly when wl0 does).
 * RTNL: both native helpers ASSERT_RTNL, and _wl_add_if runs under the
 * blob's rtnl_lock (H15 §3) while other paths may not — so dispatch on
 * rtnl_is_locked() instead of assuming either (a blind rtnl_lock() here
 * would self-deadlock the locked callers).
 * head: native queues dev->unreg_list into it for a later
 * unregister_netdevice_many() flush — which the blob does NOT import, so
 * any non-NULL head would strand entries by construction. Flatten to the
 * single (NULL-head) path with a loud once-warn, same as
 * shim_netdev_unregister_locked already does. */
int bcm_shim_register_netdevice(struct net_device *dev)
{
	struct netdev419_view *old = (struct netdev419_view *)dev;
	struct net_device *native = old ? shim_netdev_native(old) : NULL;

	if (!dev)
		return -EINVAL;
	if (!native)
		return -ENOENT;
	if (rtnl_is_locked())
		return shim_netdev_register_locked(old,
						   netdev419_register_table());
	return shim_netdev_register(old, netdev419_register_table());
}
EXPORT_SYMBOL(bcm_shim_register_netdevice);

void bcm_shim_unregister_netdevice_queue(struct net_device *dev,
					 struct list_head *head)
{
	struct netdev419_view *old = (struct netdev419_view *)dev;

	if (!dev || !shim_netdev_native(old)) {
		pr_warn_once("bcm_shim: unregister_netdevice_queue miss, skip\n");
		return;
	}
	if (head)
		pr_warn_once("bcm_shim: unregister_netdevice_queue: batch head flattened (blob has no _many)\n");
	if (rtnl_is_locked())
		shim_netdev_unregister_locked(old);
	else
		shim_netdev_unregister(old);
}
EXPORT_SYMBOL(bcm_shim_unregister_netdevice_queue);

/* Mock the blob's exact probe->attach write idiom on a legacy view.
 * Offsets are the ND419_* constants (4.19 layout); values mirror the
 * disassembled immediates/pointers (see REPORT §2). Must never fault and
 * must never touch the native object. */
static void netdev_write_mock_blob(struct netdev419_view *old,
				   const u8 *mac, void *opaque)
{
	u32 w;
	u8 *addr;
	static u8 mock_ndo[ND419_size_net_device_ops];
	static u8 mock_ethtool[232];
	static u32 mock_priv_word;
	void (*destroy)(struct netdev419_view *) =
		(void (*)(struct netdev419_view *))0xdead0001;

	/* wl_get_driver_info alloc path (r4 = netdev there). */
	memcpy(&mock_priv_word, &opaque, sizeof(opaque));
	memcpy(old->priv, &mock_priv_word, sizeof(mock_priv_word));
	memcpy(&w, old->bytes + 300, sizeof(w));
	w |= 32;
	memcpy(old->bytes + 300, &w, sizeof(w));
	old_pointer(old, 308, opaque);
	old_pointer(old, 312, opaque);
	w = 6;
	memcpy(old->bytes + 316, &w, sizeof(w));
	/* wl_attach main path (r7 = netdev). */
	old_pointer(old, OLD_OFF(netdev_ops), mock_ndo);
	old_pointer(old, OLD_OFF(ethtool_ops), mock_ethtool);
	memcpy(&w, &destroy, sizeof(w));
	memcpy(old->bytes + OLD_OFF(priv_destructor), &w, sizeof(w));
	old->bytes[OLD_OFF(needs_free_netdev)] = 1;
	w = 1558;
	memcpy(old->bytes + OLD_OFF(max_mtu), &w, sizeof(w));
	old_pointer(old, 400, opaque);
	w = (u32)(uintptr_t)opaque;
	memcpy(old->bytes + OLD_OFF(base_addr), &w, sizeof(w));
	memcpy(old->bytes + OLD_OFF(irq), &w, sizeof(w));
	/* features hi-word ORR EXTSTATS (blob: ldr r3,[r7,#116]; orr #2<<25). */
	memcpy(&w, old->bytes + 116, sizeof(w));
	w |= (2U << 25);
	memcpy(old->bytes + 116, &w, sizeof(w));
	old_pointer(old, OLD_OFF(dev), opaque);
	/* Crash idiom: ldr r3,[r7,#636]; str r1,[r3]; strh r2,[r3,#4]. */
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
	memcpy(addr, mac, 4);
	memcpy(addr + 4, mac + 4, 2);
	/* Post-crash reads the fixed blob would reach next. */
	memcpy(&addr, old->bytes + OLD_OFF(ieee80211_ptr), sizeof(addr));
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
}

/* Forward: H11 fixture ops (defined below with the lifecycle fixtures).
 * Reused read-only by phase C; never installed in a vendor interface. */
static const struct net_device_ops netdev419_test_ops;

/* H11 test ctx, moved up: write-selftest Phase C stores a ctx pointer in
 * priv before registering with netdev419_test_ops (whose ndo_init reads
 * it). Must precede netdev_write_selftest_fn. */
struct netdev419_test_ctx {
	struct delayed_work release;
	struct net_device *held;
	int init, uninit, destroy, drvinfo, stats;
	bool fail_init, failed, require_release, released;
	u8 destructor_state;
};

static struct netdev419_test_ctx *netdev419_test_context(struct netdev419_view *old)
{
	struct netdev419_test_ctx *ctx;
	memcpy(&ctx, old->priv, sizeof(ctx));
	return ctx;
}

static int netdev_write_selftest_fn(void)
{
	static u32 mock_parent;
	struct net_device *lo = init_net.loopback_dev;
	struct netdev419_view *old = NULL, *q = NULL;
	struct net_device *native;
	const u8 mac[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 1 };
	u32 state_before;
	u64 priv_flags_before;
	const struct net_device_ops *ops_before;
	void *ieee_before, *rxh_before, *core_before;
	const unsigned char *da_before;
	u8 *addr;
	int rc = -EIO;

	/* Guards first: un-audited variants must fail cleanly. */
	if (bcm_shim_alloc_netdev_mqs(4, "wlg%d", NET_NAME_UNKNOWN,
				      NULL, 1, 1))
		goto out;
	if (bcm_shim_alloc_netdev_mqs(4, "wlg%d", NET_NAME_UNKNOWN,
				      ether_setup, 0, 1))
		goto out;
	if (bcm_shim_register_netdev(NULL) != -EINVAL)
		goto out;
	if (bcm_shim_register_netdev(lo) != -ENOENT)
		goto out;
	bcm_shim_unregister_netdev(NULL); /* loud no-op, must not fault */
	bcm_shim_unregister_netdev(lo);

	/* Phase A: alloc as the blob does, write as the blob does. */
	old = (struct netdev419_view *)bcm_shim_alloc_netdev_mqs(
		4, "wlmock%d", NET_NAME_UNKNOWN, ether_setup, 1, 1);
	if (!old)
		goto out;
	native = shim_netdev_native(old);
	if (!native || shim_netdev_legacy(native) != old)
		goto out;
	state_before = native->state;
	priv_flags_before = native->priv_flags;
	ops_before = native->netdev_ops;
	ieee_before = native->ieee80211_ptr;
	rxh_before = native->rx_handler;
	core_before = native->core_stats;
	da_before = native->dev_addr;
	if (ieee_before || rxh_before || core_before)
		goto out;
	netdev_write_mock_blob(old, mac, &mock_parent);
	/* Legacy holds what the blob wrote ... */
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
	if (memcmp(addr, mac, ETH_ALEN))
		goto out;
	if (old->bytes[OLD_OFF(needs_free_netdev)] != 1)
		goto out;
	/* ... and the native object is pristine. */
	if (native->state != state_before ||
	    native->priv_flags != priv_flags_before ||
	    native->netdev_ops != ops_before ||
	    native->ieee80211_ptr || native->rx_handler ||
	    native->core_stats || native->dev_addr != da_before ||
	    native->reg_state != NETREG_UNINITIALIZED ||
	    !list_empty(&native->mc.list))
		goto out;

	/* Phase B: blob-style register must fail CLEANLY (-EINVAL xmit gate:
	 * netdev419_prepare checks ops first, before any mirror). No crash,
	 * no partial state, explicit free still works. */
	{
		static u8 mock_old_ndo[ND419_size_net_device_ops];

		old_pointer(old, OLD_OFF(netdev_ops), mock_old_ndo);
		if (bcm_shim_register_netdev((struct net_device *)old) != -EINVAL)
			goto out;
		if (native->reg_state != NETREG_UNINITIALIZED ||
		    shim_netdev_native(old) != native)
			goto out;
	}
	bcm_shim_unregister_netdev((struct net_device *)old); /* no-op */
	if (shim_netdev_free_unregistered(old))
		goto out;
	old = NULL;

	/* Phase C: the same alloc-wrapper output DOES register through the
	 * tested H11 path once a real (translated) ops table is supplied:
	 * the stack sees a genuine kernel net_device (real ifindex, mirrored
	 * MAC). This is the proof the register boundary operates on a valid
	 * native object. */
	q = (struct netdev419_view *)bcm_shim_alloc_netdev_mqs(
		sizeof(void *), "wlmock%d", NET_NAME_UNKNOWN, ether_setup, 1, 1);
	if (!q)
		goto out;
	native = shim_netdev_native(q);
	if (!native)
		goto out;
	memcpy(&addr, q->bytes + OLD_OFF(dev_addr), sizeof(addr));
	memcpy(addr, mac, 4);
	memcpy(addr + 4, mac + 4, 2);
	/* netdev419_test_ops.ndo_init/uninit read a ctx POINTER from
	 * priv+1408 (H25 Oops: NULL+0x44 — Phase C never stored one,
	 * unlike H11 test_alloc). Provide a stack ctx, H11-style; its
	 * lifetime covers register→unregister→free below (same function).
	 * require_release stays false, so no delayed work is involved. */
	{
		struct netdev419_test_ctx wctx = {};
		struct netdev419_test_ctx *wctxp = &wctx;

		memcpy(q->priv, &wctxp, sizeof(wctxp));
		if (shim_netdev_register(q, &netdev419_test_ops))
			goto out;
		if (native->reg_state != NETREG_REGISTERED ||
		    q->bytes[OLD_OFF(reg_state)] != NETREG_REGISTERED ||
		    native->ifindex <= 0 ||
		    memcmp(native->dev_addr, mac, ETH_ALEN) ||
		    strcmp(q->bytes, native->name))
			goto out;
		bcm_shim_unregister_netdev((struct net_device *)q);
	/* Unregister retains the view by design (explicit free follows, H11
	 * mode 1): free first, then assert the mapping is gone. The previous
	 * order (assert-then-free) could never pass — caught statically
	 * while the H24 selftest still awaits its HW run. */
	if (shim_netdev_free(q) || shim_netdev_native(q))
		goto out;
	q = NULL;
	} /* end Phase C ctx lifetime: unregister+free done, wctx dead below */

	dev_info(&lo->dev, "NETDEVWRITE_SELFTEST PASS blob-writes-absorbed native-pristine regfail-clean regok-fixture\n");
	rc = 0;
out:
	if (q) {
		struct net_device *d = shim_netdev_native(q);

		if (d && d->reg_state == NETREG_REGISTERED)
			shim_netdev_unregister(q);
		if (shim_netdev_native(q))
			shim_netdev_free(q);
		rc = -EIO;
	}
	if (old) {
		if (shim_netdev_native(old))
			shim_netdev_free_unregistered(old);
		rc = -EIO;
	}
	if (!list_empty(&netdev419_views))
		rc = -EBUSY;
	if (rc)
		pr_err("bcm_shim: NETDEVWRITE_SELFTEST FAIL rc=%d\n", rc);
	return rc;
}

static int netdev419_selftest(void)
{
	struct netdev419_view *a = NULL, *b = NULL;
	struct net_device *native;
	struct netdev_queue *queue;
	int __percpu *refs;
	u32 old_flags = 0xa5a5a5a5;
	int ret = -EIO;

	a = shim_netdev_alloc_ether(4, "h10a%d", NET_NAME_UNKNOWN, 1, 1);
	b = shim_netdev_alloc_ether(64, "h10b%d", NET_NAME_UNKNOWN, 2, 1);
	if (!a || !b)
		goto out;
	native = shim_netdev_native(a);
	if (!native || (void *)native == (void *)a ||
	    shim_netdev_legacy(native) != a ||
	    shim_netdev_native((void *)1) || shim_netdev_legacy((void *)1) ||
	    !IS_ALIGNED((unsigned long)a, NETDEV_ALIGN) ||
	    !IS_ALIGNED((unsigned long)a->priv, NETDEV_ALIGN) ||
	    memchr_inv(a->priv, 0, 4) || memchr_inv(b->priv, 0, 64))
		goto out;
	/* Reproduce blob's +1408 private write and old flags write. Neither
	 * may touch native private metadata or native network flags. */
	memcpy(a->priv, &old_flags, 4);
	memcpy(a->bytes + OLD_OFF(flags), &old_flags, 4);
	if (native->flags != (IFF_BROADCAST | IFF_MULTICAST) ||
	    shim_netdev_legacy(native) != a || memchr_inv(b->priv, 0, 64))
		goto out;
	memcpy(&queue, a->bytes + OLD_OFF(_tx), sizeof(queue));
	memcpy(&refs, a->bytes + OLD_OFF(pcpu_refcnt), sizeof(refs));
	if (queue != native->_tx || refs != native->pcpu_refcnt ||
	    native->mtu != ETH_DATA_LEN)
		goto out;
	/* Exercise the exact old queue state field shared with native API. */
	set_bit(__QUEUE_STATE_DRV_XOFF,
		(unsigned long *)((u8 *)queue + ND419_off_netdev_queue_state));
	if (!netif_tx_queue_stopped(netdev_get_tx_queue(native, 0)))
		goto out;
	netif_tx_start_queue(netdev_get_tx_queue(native, 0));
	if (test_bit(__QUEUE_STATE_DRV_XOFF,
		(unsigned long *)((u8 *)queue + ND419_off_netdev_queue_state)))
		goto out;
	dev_info(&native->dev, "NETDEV419_SELFTEST PASS separate-private=OK queues=shared refs=shared\n");
	ret = 0;
out:
	if (b && shim_netdev_free_unregistered(b))
		ret = -EIO;
	if (a && shim_netdev_free_unregistered(a))
		ret = -EIO;
	if (!list_empty(&netdev419_views))
		ret = -EIO;
	return ret;
}

/* Test fixtures below are used only by netdev_lifecycle_selftest=1.
 * Their native packet sink is never installed in a vendor interface. */
/* (netdev419_test_ctx + netdev419_test_context live above with the
 * write-selftest forward decls — Phase C needs the complete type.) */

static int netdev419_test_init(struct net_device *dev)
{
	struct netdev419_test_ctx *ctx = netdev419_test_context(shim_netdev_legacy(dev));
	ctx->init++;
	return ctx->fail_init ? -EIO : 0;
}

static void netdev419_test_uninit(struct net_device *dev)
{
	netdev419_test_context(shim_netdev_legacy(dev))->uninit++;
}

static netdev_tx_t netdev419_test_sink(struct sk_buff *skb, struct net_device *dev)
{
	consume_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops netdev419_test_ops = {
	.ndo_init = netdev419_test_init,
	.ndo_uninit = netdev419_test_uninit,
	.ndo_start_xmit = netdev419_test_sink,
};

static void netdev419_test_destructor(struct netdev419_view *old)
{
	struct netdev419_test_ctx *ctx = netdev419_test_context(old);
	struct net_device *dev = shim_netdev_native(old);
	ctx->destroy++;
	if (!dev || old->bytes[OLD_OFF(reg_state)] != ctx->destructor_state ||
	    (ctx->require_release && (!READ_ONCE(ctx->released) || netdev_refcnt_read(dev) != 1)))
		ctx->failed = true;
}

static void netdev419_test_drvinfo(struct netdev419_view *old, struct ethtool_drvinfo *info)
{
	struct netdev419_test_ctx *ctx = netdev419_test_context(old);
	ctx->drvinfo++;
	strscpy(info->driver, "netdev419-fixture", sizeof(info->driver));
}

static void netdev419_test_stats419(struct netdev419_view *old, struct netdev419_stats *stats)
{
	int i = 1;
	netdev419_test_context(old)->stats++;
#define SET_STAT(name) stats->name = i++;
	ND419_COMMON_STATS(SET_STAT)
#undef SET_STAT
	for (i = 0; i < 6; i++)
		stats->extended[i] = 0x100 + i;
	stats->rx_nohandler = 0x1122334455667788ULL;
}

static const struct {
	u8 prefix[64];
	void (*get_stats64)(struct netdev419_view *, struct netdev419_stats *);
	u8 suffix[188];
} netdev419_test_ndo419 = { .get_stats64 = netdev419_test_stats419 };

static int netdev419_test_statistics(struct net_device *dev)
{
	struct {
		u64 before;
		struct rtnl_link_stats64 stats;
		u64 after;
	} guard = { .before = 0xabcdef1234567890ULL, .after = 0x9876543210abcdefULL };
	u64 extended[6];
	u8 strings[sizeof(netdev419_stat_names)];
	struct ethtool_stats request = {};
	int i = 1;

	dev->netdev_ops->ndo_get_stats64(dev, &guard.stats);
#define CHECK_STAT(name) if (guard.stats.name != i++) return -EIO;
	ND419_COMMON_STATS(CHECK_STAT)
#undef CHECK_STAT
	if (guard.before != 0xabcdef1234567890ULL || guard.after != 0x9876543210abcdefULL ||
	    guard.stats.rx_nohandler != 0x1122334455667788ULL || guard.stats.rx_otherhost_dropped ||
	    dev->ethtool_ops->get_sset_count(dev, ETH_SS_STATS) != 6)
		return -EIO;
	dev->ethtool_ops->get_strings(dev, ETH_SS_STATS, strings);
	if (memcmp(strings, netdev419_stat_names, sizeof(strings)))
		return -EIO;
	dev->ethtool_ops->get_ethtool_stats(dev, &request, extended);
	for (i = 0; i < 6; i++)
		if (extended[i] != 0x100 + i)
			return -EIO;
	return 0;
}

static void netdev419_test_release(struct work_struct *work)
{
	struct netdev419_test_ctx *ctx = container_of(to_delayed_work(work),
						    struct netdev419_test_ctx, release);
	struct net_device *held = ctx->held;
	ctx->held = NULL;
	WRITE_ONCE(ctx->released, true);
	dev_put(held);
}

struct netdev419_test_notifier {
	struct notifier_block nb;
	struct net_device *target;
	unsigned long event;
};

static int netdev419_test_notify(struct notifier_block *nb, unsigned long event, void *data)
{
	struct netdev419_test_notifier *test = container_of(nb, struct netdev419_test_notifier, nb);
	if (event == test->event && netdev_notifier_info_to_dev(data) == test->target)
		return notifier_from_errno(-EACCES);
	return NOTIFY_DONE;
}

/* HW31 §1 fixture-priv layout (byte offsets, no padding assumptions):
 *  [0, sizeof(void *)) — live ctx-pointer slot. ndo_init/ndo_uninit/
 *  destructor read it through EVERY callback (register -> unregister ->
 *  free), so it must stay valid until the fixture is freed.
 *  [sizeof(void *), sizeof(void *) + 8) — u64 sentinel in FREE tail bytes.
 * The old lookup test wrote the 8-byte sentinel at priv+0, clobbering the
 * 4-byte ctx pointer on ARM (sentinel low word 0x5a5aa5a5 -> ndo_init read
 * ctx+0x44 -> fault at 0x5a5aa5e9, PC netdev419_test_init+0x40). Moving the
 * sentinel write after register would NOT suffice: uninit/destructor still
 * use the ctx slot. test_alloc therefore sizes every fixture allocation
 * for both slots; the lifecycle cases 0-5 leave the tail zeroed (kzalloc). */
#define NETDEV419_TEST_PRIV_SENTINEL_OFF (sizeof(void *))
#define NETDEV419_TEST_PRIV_SIZE (sizeof(void *) + sizeof(u64))

static struct netdev419_view *netdev419_test_alloc(const char *name,
						struct netdev419_test_ctx *ctx, bool auto_free)
{
	struct netdev419_view *old = shim_netdev_alloc_ether(NETDEV419_TEST_PRIV_SIZE, name, NET_NAME_UNKNOWN, 1, 1);
	void (*destroy)(struct netdev419_view *) = netdev419_test_destructor;
	u8 *addr;
	const u8 mac[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 1 };
	if (!old)
		return NULL;
	memcpy(old->priv, &ctx, sizeof(ctx));
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
	memcpy(addr, mac, sizeof(mac));
	memcpy(old->bytes + OLD_OFF(priv_destructor), &destroy, sizeof(destroy));
	old->bytes[OLD_OFF(needs_free_netdev)] = auto_free;
	old_pointer(old, OLD_OFF(netdev_ops), &netdev419_test_ndo419);
	{
		u64 features = ND419_EXTSTATS;
		memcpy(old->bytes + OLD_OFF(features), &features, sizeof(features));
	}
	return old;
}

static void netdev419_test_cleanup(struct netdev419_view *old)
{
	struct net_device *dev = shim_netdev_native(old);
	if (!dev)
		return;
	if (dev->reg_state == NETREG_REGISTERED)
		shim_netdev_unregister(old);
	if (shim_netdev_native(old))
		shim_netdev_free(old);
}

static int netdev419_lifecycle_case(int mode)
{
	/* 0 auto-free + held reference + duplicate name; 1 manual free;
	 * 2 POST_INIT failure; 3 REGISTER failure; 4 ndo_init failure;
	 * 5 deferred free while UNREGISTERING with RTNL held. */
	struct netdev419_test_ctx ctx = {}, duplicate_ctx = {};
	struct netdev419_test_notifier notifier = { .nb.notifier_call = netdev419_test_notify };
	struct netdev419_view *old = NULL, *duplicate = NULL;
	struct net_device *dev;
	struct ethtool_drvinfo info = {};
	u8 ethtool419[232] = {};
	void (*get_info)(struct netdev419_view *, struct ethtool_drvinfo *) = netdev419_test_drvinfo;
	bool notifier_registered = false;
	int ret = -EIO, registered;

	INIT_DELAYED_WORK(&ctx.release, netdev419_test_release);
	ctx.fail_init = mode == 4;
	ctx.destructor_state = mode == 2 ? NETREG_UNINITIALIZED : NETREG_UNREGISTERED;
	old = netdev419_test_alloc("h11view%d", &ctx, mode != 1 && mode != 5);
	if (!old)
		goto out;
	dev = shim_netdev_native(old);
	memcpy(ethtool419 + 8, &get_info, sizeof(get_info));
	old_pointer(old, OLD_OFF(ethtool_ops), ethtool419);
	if (mode == 2 || mode == 3) {
		notifier.target = dev;
		notifier.event = mode == 2 ? NETDEV_POST_INIT : NETDEV_REGISTER;
		if (register_netdevice_notifier(&notifier.nb))
			goto out;
		notifier_registered = true;
	}
	registered = shim_netdev_register(old, &netdev419_test_ops);
	if (mode >= 2 && mode <= 4) {
		int expected = mode == 4 ? -EIO : -EACCES;
		if (registered != expected || shim_netdev_native(old) != dev ||
		    ctx.init != 1 || ctx.destroy != (mode != 4) ||
		    ctx.uninit != (mode != 4) || ctx.failed)
			goto out;
		if (shim_netdev_free(old) || shim_netdev_native(old))
			goto out;
		old = NULL;
		ret = 0;
		goto out;
	}
	if (registered || old->bytes[OLD_OFF(reg_state)] != NETREG_REGISTERED ||
	    strcmp(old->bytes, dev->name))
		goto out;
	dev->ethtool_ops->get_drvinfo(dev, &info);
	if (ctx.drvinfo != 1 || strcmp(info.driver, "netdev419-fixture"))
		goto out;
	if (netdev419_test_statistics(dev))
		goto out;
	if (shim_netdev_free(old) != -EBUSY)
		goto out;
	if (mode == 0) {
		duplicate = netdev419_test_alloc(dev->name, &duplicate_ctx, true);
		if (!duplicate || shim_netdev_register(duplicate, &netdev419_test_ops) != -EEXIST ||
		    duplicate_ctx.init || duplicate_ctx.destroy || !shim_netdev_native(duplicate))
			goto out;
		if (shim_netdev_free(duplicate))
			goto out;
		duplicate = NULL;
		ctx.held = dev_get_by_name(dev_net(dev), dev->name);
		if (ctx.held != dev)
			goto out;
		ctx.require_release = true;
		schedule_delayed_work(&ctx.release, msecs_to_jiffies(100));
	}
	if (mode == 5) {
		rtnl_lock();
		registered = shim_netdev_unregister_locked(old);
		if (!registered && old->bytes[OLD_OFF(reg_state)] != NETREG_UNREGISTERING)
			registered = -EIO;
		if (!registered)
			registered = shim_netdev_free(old);
		rtnl_unlock();
	} else {
		registered = shim_netdev_unregister(old);
	}
	if (registered || ctx.init != 1 || ctx.uninit != 1 || ctx.destroy != 1 || ctx.failed)
		goto out;
	if (mode == 1) {
		if (shim_netdev_native(old) != dev || shim_netdev_free(old))
			goto out;
	}
	if (shim_netdev_native(old))
		goto out;
	old = NULL;
	ret = 0;
out:
	if (notifier_registered)
		unregister_netdevice_notifier(&notifier.nb);
	cancel_delayed_work_sync(&ctx.release);
	if (ctx.held) {
		ctx.released = true;
		dev_put(ctx.held);
	}
	if (duplicate)
		netdev419_test_cleanup(duplicate);
	if (old)
		netdev419_test_cleanup(old);
	return ret;
}

/* Mock-callback probe for the notifier selftest (HW lane, gated by
 * notify_selftest=1). The mock stands in for the blob originals, which
 * cannot run on the build host; it only records what the trampoline
 * decided to forward. Fixture views come from the real registry, and the
 * foreign device is the live loopback — the exact replay class that
 * Oopsed S9. */
struct shim_notify_probe {
	int calls;
	unsigned long last_event;
	const void *last_dev;
	struct notifier_block *last_nb;
};

static struct shim_notify_probe notify_probe;

static int shim_notify_probe_call(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	notify_probe.calls++;
	notify_probe.last_event = event;
	notify_probe.last_nb = nb;
	notify_probe.last_dev = ptr ? netdev_notifier_info_to_dev(ptr) : NULL;
	return NOTIFY_DONE;
}

static int shim_notify_direct(struct notifier_block *nb, unsigned long event,
			      struct net_device *dev)
{
	struct netdev_notifier_info info = { .dev = dev, .extack = NULL };

	return shim_notify_trampoline(nb, event, &info);
}

static int shim_notify_selftest(void)
{
	static const struct {
		unsigned long in;
		bool fwd;
		unsigned long out;
	} vectors[] = {
		{ 0, false, 0 }, { 1, true, 1 }, { 5, true, 5 },
		{ 6, true, 6 }, { 8, true, 8 }, { 9, false, 0 },
		{ 10, true, 9 }, { 11, true, 10 }, { 16, true, 15 },
		{ 17, true, 16 }, { 18, false, 0 }, { 19, false, 0 },
		{ 35, false, 0 }, { 40, false, 0 },
	};
	struct notifier_block nb = { .notifier_call = shim_notify_probe_call };
	struct notifier_block alien = { .notifier_call = shim_notify_probe_call };
	struct netdev419_view *fixture = NULL;
	struct net_device *native, *lo = init_net.loopback_dev;
	struct netdev419_view *legacy;
	unsigned long mapped;
	size_t i;
	int calls, rc = -EIO;

	/* Phase A: pure event translation, no chain, no devices. */
	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		bool ok = shim_notify_translate(vectors[i].in, &mapped);

		if (ok != vectors[i].fwd ||
		    (ok && mapped != vectors[i].out))
			goto out;
	}
	/* Phase B: real registration replays the live chain (lo is foreign
	 * and must be swallowed, never forwarded to the mock). */
	memset(&notify_probe, 0, sizeof(notify_probe));
	if (bcm_shim_register_netdevice_notifier(&nb))
		goto out;
	if (READ_ONCE(nb.notifier_call) != shim_notify_trampoline ||
	    !shim_notify_orig(&nb) || notify_probe.calls)
		goto unregister;
	/* Phase C: foreign loopback through every blob-handled event. */
	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		if (vectors[i].in != 1 && vectors[i].in != 5 &&
		    vectors[i].in != 6 && vectors[i].in != 9 &&
		    vectors[i].in != 10 && vectors[i].in != 17)
			continue;
		if (shim_notify_direct(&nb, vectors[i].in, lo) != NOTIFY_DONE ||
		    notify_probe.calls)
			goto unregister;
	}
	/* Phase D: registry-hit fixture — pointer AND event translated. */
	fixture = shim_netdev_alloc_ether(sizeof(void *), "h11n%d",
					  NET_NAME_UNKNOWN, 1, 1);
	if (!fixture)
		goto unregister;
	native = shim_netdev_native(fixture);
	legacy = fixture;
	if (!native || shim_netdev_legacy(native) != legacy)
		goto unregister;
	calls = notify_probe.calls;
	if (shim_notify_direct(&nb, 5, native) != NOTIFY_DONE ||
	    notify_probe.calls != calls + 1 ||
	    notify_probe.last_event != 5 || notify_probe.last_dev != legacy ||
	    notify_probe.last_nb != &nb)
		goto unregister;
	calls = notify_probe.calls;
	if (shim_notify_direct(&nb, 10, native) != NOTIFY_DONE ||
	    notify_probe.calls != calls + 1 || notify_probe.last_event != 9 ||
	    notify_probe.last_dev != legacy)
		goto unregister;
	calls = notify_probe.calls;
	if (shim_notify_direct(&nb, 17, native) != NOTIFY_DONE ||
	    notify_probe.calls != calls + 1 || notify_probe.last_event != 16)
		goto unregister;
	calls = notify_probe.calls;
	if (shim_notify_direct(&nb, 9, native) != NOTIFY_DONE ||
	    shim_notify_direct(&nb, 18, native) != NOTIFY_DONE ||
	    shim_notify_direct(&nb, 1, lo) != NOTIFY_DONE ||
	    notify_probe.calls != calls)
		goto unregister;
	/* Phase E: unknown nb never forwards, even for a registry dev. */
	calls = notify_probe.calls;
	if (shim_notify_direct(&alien, 6, native) != NOTIFY_DONE ||
	    notify_probe.calls != calls)
		goto unregister;
	/* Phase F: NULL guards. */
	if (shim_notify_trampoline(&nb, 6, NULL) != NOTIFY_DONE ||
	    shim_notify_direct(&nb, 6, NULL) != NOTIFY_DONE ||
	    shim_notify_direct(NULL, 6, native) != NOTIFY_DONE ||
	    notify_probe.calls != calls)
		goto unregister;
	dev_info(&lo->dev, "NOTIFY419_SELFTEST PASS fwd=3(events 5/9/10->5/9/9) swallow=replay+unmapped\n");
	rc = 0;
unregister:
	if (bcm_shim_unregister_netdevice_notifier(&nb) && !rc)
		rc = -EIO;
	if (READ_ONCE(nb.notifier_call) != shim_notify_probe_call ||
	    shim_notify_orig(&nb))
		rc = -EIO;
out:
	if (fixture && shim_netdev_free_unregistered(fixture))
		rc = -EIO;
	if (rc)
		return rc;
	return list_empty(&netdev419_views) ? 0 : -EBUSY;
}

/* bcm_dev_hold/put live in shim_core.c (lane C); the bridge selftest below
 * drives them as the blob would (legacy view in, native counter out). */
extern void bcm_dev_hold(struct net_device *dev);
extern void bcm_dev_put(struct net_device *dev);

/* Lookup-bridge selftest (P0 vendor30 netdev-lookup lane, no radio).
 * Runs under the existing netdev_lifecycle_selftest gate; Codex runs it on
 * hardware with the same `wiphy netdev` groups, no runner changes.
 *
 * Fixture: one registered view ("h11lk%d" via the H11 test alloc path, so
 * priv/destructor/mac handling is the already-proven one), then:
 *  L2 lookup returns EXACTLY old with the blob's +1408 priv bytes intact;
 *  L3 missing name -> NULL, no leak (registry/refcounts stable);
 *  L4 foreign ("lo", live loopback, no legacy view) -> NULL with the lookup
 *     ref already dropped (lo refcount unchanged);
 *  L5 NULL net/name -> NULL, no fault;
 *  L6 bridge lookup takes exactly one native ref; bcm_dev_put(old) drops it
 *     (proves the legacy put reaches the native counter);
 *  L7 balanced extra bcm_dev_hold/put pairs on the legacy view; NULL
 *     hold/put are no-ops; unknown (foreign native) hold/put neither fault
 *     nor move the foreign counter (loud warn, skip policy);
 *  L8 held bridge ref across unregister_locked, then put, then rtnl_unlock:
 *     deterministic (no wait warnings), destructor ran once, view drained by
 *     the core (auto-free), registry empty.
 * Failure convention matches the file: -EIO with a FAIL line; leaks force
 * -EBUSY via the caller's list_empty check. */
static int netdev419_lookup_bridge_test(void)
{
	struct netdev419_test_ctx ctx = {};
	struct netdev419_view *old = NULL;
	struct net_device *dev, *lo = init_net.loopback_dev;
	struct net_device *found;
	struct netdev419_test_ctx *ctx_saved;
	u64 sentinel = 0xa5a55a5a5a5aa5a5ULL, check;
	int base, rc = -EIO;

	old = netdev419_test_alloc("h11lk%d", &ctx, true);
	if (!old)
		return -EIO;
	dev = shim_netdev_native(old);
	if (!dev)
		goto out;
	ctx.destructor_state = NETREG_UNREGISTERED;
	/* HW31 §1: the ctx slot at priv+0 stays live through ALL callbacks;
	 * the sentinel goes into the FREE tail bytes after it. Save the real
	 * ctx pointer now: L2 compares it before/after lookup, proving the
	 * blob-visible +1408 priv bytes survived the bridge intact. */
	ctx_saved = netdev419_test_context(old);
	memcpy(old->priv + NETDEV419_TEST_PRIV_SENTINEL_OFF, &sentinel, sizeof(sentinel));
	if (shim_netdev_register(old, &netdev419_test_ops))
		goto out;

	/* L2: exact view + priv (+1408) preserved. */
	found = bcm_shim_dev_get_by_name_legacy(dev_net(dev), dev->name);
	if (found != (struct net_device *)old)
		goto out;
	if (netdev419_test_context((struct netdev419_view *)found) != ctx_saved ||
	    netdev419_test_context((struct netdev419_view *)found) != &ctx)
		goto put_out;
	memcpy(&check, ((struct netdev419_view *)found)->priv + NETDEV419_TEST_PRIV_SENTINEL_OFF,
	       sizeof(check));
	if (check != sentinel)
		goto put_out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L2 PASS exact-old ctx-pointer-kept sentinel-kept\n");
	base = netdev_refcnt_read(dev);
	/* The L2 lookup above holds one ref: put it now, then re-measure. */
	bcm_dev_put((struct net_device *)old);
	if (netdev_refcnt_read(dev) != base - 1)
		goto out;
	base--;

	/* L3: missing name -> NULL, nothing held. */
	if (bcm_shim_dev_get_by_name_legacy(dev_net(dev), "h11lk-missing"))
		goto out;
	if (netdev_refcnt_read(dev) != base)
		goto out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L3 PASS miss-null no-leak\n");

	/* L4: foreign interface -> NULL, lookup ref already dropped. */
	base = netdev_refcnt_read(lo);
	if (bcm_shim_dev_get_by_name_legacy(dev_net(lo), "lo"))
		goto out;
	if (netdev_refcnt_read(lo) != base)
		goto out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L4 PASS foreign-null ref-dropped\n");

	/* L5: NULL guards. */
	if (bcm_shim_dev_get_by_name_legacy(NULL, dev->name) ||
	    bcm_shim_dev_get_by_name_legacy(dev_net(dev), NULL) ||
	    bcm_shim_dev_get_by_name_legacy(NULL, NULL))
		goto out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L5 PASS null-guards\n");

	/* L6: one lookup == one native ref; legacy put drops it. */
	base = netdev_refcnt_read(dev);
	found = bcm_shim_dev_get_by_name_legacy(dev_net(dev), dev->name);
	if (found != (struct net_device *)old ||
	    netdev_refcnt_read(dev) != base + 1)
		goto put_out;
	bcm_dev_put((struct net_device *)old);
	if (netdev_refcnt_read(dev) != base)
		goto out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L6 PASS ref1-put0\n");

	/* L7: balanced extra pairs; NULL/unknown policy. */
	base = netdev_refcnt_read(dev);
	bcm_dev_hold((struct net_device *)old);
	bcm_dev_hold((struct net_device *)old);
	if (netdev_refcnt_read(dev) != base + 2)
		goto out;
	bcm_dev_put((struct net_device *)old);
	bcm_dev_put((struct net_device *)old);
	if (netdev_refcnt_read(dev) != base)
		goto out;
	bcm_dev_hold(NULL);
	bcm_dev_put(NULL);
	if (netdev_refcnt_read(dev) != base)
		goto out;
	base = netdev_refcnt_read(lo);
	bcm_dev_hold(lo);
	bcm_dev_put(lo);
	if (netdev_refcnt_read(lo) != base)
		goto out;
	dev_info(&lo->dev, "NETDEV419_LOOKUP_BRIDGE_L7 PASS hold2-balanced null-noop unknown-skip\n");

	/* L8: held bridge ref across unregister, then release. rtnl is held
	 * across lookup->unregister_locked->put so the net-todo (which would
	 * otherwise wait on our ref) runs only after the put: deterministic,
	 * no "waiting for h11lk" warnings. Auto-free drains the view at
	 * unlock; both old and dev dangle afterwards — only ctx (our stack)
	 * and the registry may be inspected below. */
	rtnl_lock();
	found = bcm_shim_dev_get_by_name_legacy(dev_net(dev), dev->name);
	if (found != (struct net_device *)old) {
		rtnl_unlock();
		goto out;
	}
	if (shim_netdev_unregister_locked(old)) {
		bcm_dev_put((struct net_device *)old);
		rtnl_unlock();
		goto out;
	}
	if (shim_netdev_native(old) != dev) {
		bcm_dev_put((struct net_device *)old);
		rtnl_unlock();
		goto out;
	}
	bcm_dev_put((struct net_device *)old);
	rtnl_unlock();
	old = NULL;
	dev = NULL;
	found = NULL;
	if (ctx.init != 1 || ctx.uninit != 1 || ctx.destroy != 1 || ctx.failed)
		return -EIO;
	if (!list_empty(&netdev419_views))
		return -EBUSY;
	/* L8 marker: this final PASS is emitted only after the held-ref
	 * unregister_locked -> put -> unlock sequence plus the ctx
	 * init/uninit/destroy accounting above, so it doubles as L8. */
	dev_info(&init_net.loopback_dev->dev,
		 "NETDEV419_LOOKUP_BRIDGE PASS exact-old priv-kept miss-null foreign-null ref1-put0 hold2-balanced unregister-held\n");
	return 0;

put_out:
	bcm_dev_put((struct net_device *)old);
out:
	if (old)
		netdev419_test_cleanup(old);
	return rc;
}

static int netdev419_lifecycle_test(void)
{	u64 native;
	size_t i;
	int mode, ret;
	for (i = 0; i < ARRAY_SIZE(nd419_feature_flags); i++) {
		if (flags_to_native(nd419_feature_flags[i].old, &native,
			nd419_feature_flags, ARRAY_SIZE(nd419_feature_flags)) ||
		    native != nd419_feature_flags[i].native ||
		    flags_to_old(native, nd419_feature_flags, ARRAY_SIZE(nd419_feature_flags)) != nd419_feature_flags[i].old)
			return -EINVAL;
	}
	if (flags_to_native(BIT_ULL(2), &native, nd419_feature_flags,
			    ARRAY_SIZE(nd419_feature_flags)) != -EOPNOTSUPP)
		return -EINVAL;
	for (mode = 0; mode < 6; mode++) {
		ret = netdev419_lifecycle_case(mode);
		dev_info(&init_net.loopback_dev->dev, "NETDEV419_LIFECYCLE_CASE mode=%d rc=%d\n", mode, ret);
		if (ret || !list_empty(&netdev419_views))
			return ret ? ret : -EBUSY;
	}
	ret = netdev419_lookup_bridge_test();
	dev_info(&init_net.loopback_dev->dev, "NETDEV419_LOOKUP_BRIDGE_CASE rc=%d\n", ret);
	if (ret || !list_empty(&netdev419_views))
		return ret ? ret : -EBUSY;
	dev_info(&init_net.loopback_dev->dev, "NETDEV419_LIFECYCLE PASS cases=6 held-ref=checked ethtool=translated\n");
	return 0;
}

/* Silent init-time probes establishing xmit_ready (no radio, no state
 * change, no dmesg spam on success):
 *  IMPORT: shim_skb_import(NULL) must refuse -EINVAL — proves the import
 *    core the real xmit is built on is linked and behaving.
 *  WAKE/QUEUE: the live loopback's tx queue 0 must resolve through the
 *    native queue API with readable stopped-bit and trans_start — the
 *    exact path bcm419_netif_tx_wake_queue and the H10 shared-state view
 *    use (read-only; the queue is never stopped here).
 *  NDO: the real table must actually carry the xmit entry (guards against
 *    table-desync edits silently re-emptying it). */
static void xmit_probe_ready(void)
{
	struct net_device *lo = init_net.loopback_dev;
	struct netdev_queue *txq;
	struct skb419_view *bad;

	bad = shim_skb_import(NULL, GFP_KERNEL);
	if (IS_ERR(bad) && PTR_ERR(bad) == -EINVAL)
		xmit_ready |= XMIT_READY_IMPORT;
	txq = (lo && lo->real_num_tx_queues > 0) ?
		netdev_get_tx_queue(lo, 0) : NULL;
	if (txq) {
		(void)netif_tx_queue_stopped(txq);
		(void)READ_ONCE(txq->trans_start);
		xmit_ready |= XMIT_READY_WAKE | XMIT_READY_QUEUE;
	}
	if (netdev419_real_ops.ndo_start_xmit)
		xmit_ready |= XMIT_READY_NDO;
}

static bool xmit_mock_busy;
static unsigned int xmit_mock_calls;
static netdev_tx_t xmit_mock_blob(struct skb419_view *skb,
				struct netdev419_view *old)
{
	xmit_mock_calls++;
	if (xmit_mock_busy || !shim_netdev_native(old))
		return NETDEV_TX_BUSY;
	if (shim_skb_free(skb))
		pr_err("bcm_shim: mock TX free failed\n");
	return NETDEV_TX_OK;
}

static struct netdev419_view *xmit_test_view(const char *name)
{
	struct netdev419_view *old;
	u8 *addr;
	static const u8 mac[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 7 };

	old = (struct netdev419_view *)bcm_shim_alloc_netdev_mqs(
		sizeof(void *), name, NET_NAME_UNKNOWN, ether_setup, 1, 1);
	if (!old)
		return NULL;
	memcpy(&addr, old->bytes + OLD_OFF(dev_addr), sizeof(addr));
	if (!addr) {
		shim_netdev_free_unregistered(old);
		return NULL;
	}
	memcpy(addr, mac, sizeof(mac));
	{
		static u8 mock_table[256];
		netdev_tx_t (*fn)(struct skb419_view *, struct netdev419_view *) = xmit_mock_blob;

		memset(mock_table, 0, sizeof(mock_table));
		memcpy(mock_table + 16, &fn, sizeof(fn));
		old_pointer(old, OLD_OFF(netdev_ops), mock_table);
	}
	return old;
}

/* Xmit-handshake selftest (xmit_selftest=1, no radio). Drives the REAL
 * blob-facing wrappers (not the internal ops-taking API), so the gate
 * logic itself is under test:
 *  A. gate CLOSED (handshake forced off): both register wrappers fail
 *     -EINVAL with no partial state; miss legs of the queue wrapper are
 *     loud no-ops. The pinned GFP word and the readiness bits are
 *     asserted first — a closed gate must never be blamed on the flag.
 *  B. gate OPEN (handshake forced on, restored on exit): register through
 *     bcm_shim_register_netdev installs the real table; the stack entry
 *     is driven directly with a 22 B native frame (NETDEV_TX_OK, +1
 *     frame/+22 bytes, skb gone on every leg); GSO and foreign-dev legs
 *     drop-with-OK and bump drops; wake clears a really-stopped queue
 *     through the legacy view; unregister+free drains fully.
 *  C. co-rename wrappers on the monitor shape: register_netdevice installs
 *     the real table too, unregister_netdevice_queue(NULL head) drains.
 * Fails safe: any failure restores the saved handshake value. */
static int xmit_selftest_fn(void)
{
	struct netdev419_view *open = NULL, *co = NULL;
	struct net_device *dev, *lo = init_net.loopback_dev;
	struct netdev_queue *txq;
	struct sk_buff *native = NULL;
	bool saved = xmit_handshake;
	int frames, bytes, drops;
	u8 *p;
	int rc, ret = -EIO;

	if (shim_gfp419(XMIT_GFP419_ATOMIC) != GFP_ATOMIC)
		goto out;
	if (xmit_ready != XMIT_READY_ALL)
		goto out;

	/* Phase A: closed. */
	xmit_handshake = false;
	open = xmit_test_view("xmitgate%d");
	if (!open)
		goto out;
	if (bcm_shim_register_netdev((struct net_device *)open) != -EINVAL)
		goto out;
	if (bcm_shim_register_netdevice((struct net_device *)open) != -EINVAL)
		goto out;
	dev = shim_netdev_native(open);
	if (!dev || dev->reg_state != NETREG_UNINITIALIZED)
		goto out;
	if (shim_netdev_free_unregistered(open))
		goto out;
	open = NULL;
	bcm_shim_unregister_netdevice_queue(NULL, NULL);
	bcm_shim_unregister_netdevice_queue(lo, NULL);

	/* Phase B: forced open, real TX roundtrip. */
	xmit_handshake = true;
	open = xmit_test_view("xmit-tx%d");
	if (!open)
		goto out;
	if (bcm_shim_register_netdev((struct net_device *)open))
		goto out;
	dev = shim_netdev_native(open);
	if (!dev || dev->reg_state != NETREG_REGISTERED ||
	    dev->netdev_ops->ndo_start_xmit != netdev419_real_xmit)
		goto out;
	txq = netdev_get_tx_queue(dev, 0);
	if (!txq)
		goto out;
	frames = atomic_read(&xmit_frames);
	bytes = atomic_read(&xmit_bytes);
	drops = atomic_read(&xmit_drops);
	native = alloc_skb(64, GFP_KERNEL);
	if (!native)
		goto out;
	skb_reserve(native, 32);
	p = skb_put(native, 22);
	if (!p)
		goto out;
	memset(p, 0x5c, 22);
	p[12] = 8;
	p[13] = 0;
	skb_reset_mac_header(native);
	native->dev = dev;
	xmit_mock_calls = 0;
	xmit_mock_busy = true;
	rc = dev->netdev_ops->ndo_start_xmit(native, dev);
	if (rc != NETDEV_TX_BUSY || refcount_read(&native->users) != 1 ||
	    xmit_mock_calls != 1 || atomic_read(&xmit_frames) != frames)
		goto out;
	xmit_mock_busy = false;
	rc = dev->netdev_ops->ndo_start_xmit(native, dev);
	native = NULL; /* consumed-or-dropped by xmit on every leg */
	if (rc != NETDEV_TX_OK || xmit_mock_calls != 2)
		goto out;
	if (atomic_read(&xmit_frames) != frames + 1 ||
	    atomic_read(&xmit_bytes) != bytes + 22 ||
	    atomic_read(&xmit_drops) != drops)
		goto out;
	native = alloc_skb(64, GFP_KERNEL);
	if (!native)
		goto out;
	p = skb_put(native, 22);
	if (!p)
		goto out;
	memset(p, 0x5c, 22);
	skb_shinfo(native)->gso_size = 20;
	native->dev = dev;
	rc = netdev419_real_xmit(native, dev);
	native = NULL;
	if (rc != NETDEV_TX_OK ||
	    atomic_read(&xmit_drops) != drops + 1 ||
	    atomic_read(&xmit_frames) != frames + 1)
		goto out;
	native = alloc_skb(64, GFP_KERNEL);
	if (!native)
		goto out;
	p = skb_put(native, 22);
	if (!p)
		goto out;
	memset(p, 0x5c, 22);
	rc = netdev419_real_xmit(native, lo);
	native = NULL;
	if (rc != NETDEV_TX_OK || atomic_read(&xmit_drops) != drops + 2)
		goto out;
	netif_tx_stop_queue(txq);
	if (!netif_tx_queue_stopped(txq))
		goto out;
	bcm419_netif_tx_wake_queue(open, 0);
	if (netif_tx_queue_stopped(txq))
		goto out;
	bcm_shim_unregister_netdev((struct net_device *)open);
	if (shim_netdev_free(open) || shim_netdev_native(open))
		goto out;
	open = NULL;

	/* Phase C: monitor-shape wrappers. */
	co = xmit_test_view("xmit-co%d");
	if (!co)
		goto out;
	if (bcm_shim_register_netdevice((struct net_device *)co))
		goto out;
	dev = shim_netdev_native(co);
	if (!dev || dev->reg_state != NETREG_REGISTERED ||
	    dev->netdev_ops->ndo_start_xmit != netdev419_real_xmit)
		goto out;
	bcm_shim_unregister_netdevice_queue((struct net_device *)co, NULL);
	if (shim_netdev_free(co) || shim_netdev_native(co))
		goto out;
	co = NULL;

	dev_info(&lo->dev, "XMIT419_SELFTEST PASS gate-closed-open blob-dispatch busy-retained tx-ok-frames-drops wake co-register-queue\n");
	ret = 0;
out:
	xmit_handshake = saved;
	if (native)
		dev_kfree_skb_any(native);
	if (co) {
		netdev419_test_cleanup(co);
		ret = -EIO;
	}
	if (open) {
		netdev419_test_cleanup(open);
		ret = -EIO;
	}
	if (!ret && !list_empty(&netdev419_views))
		ret = -EBUSY;
	if (ret)
		pr_err("bcm_shim: XMIT419_SELFTEST FAIL rc=%d ready=%#x\n",
		       ret, xmit_ready);
	return ret;
}

int shim_netdev_init(void)
{
	int ret;
	static_assert(sizeof(struct netdev419_view) == 1408);
	static_assert(NETDEV_ALIGN == 32);
	static_assert(sizeof(struct netdev_queue) == ND419_size_netdev_queue);
	static_assert(offsetof(struct netdev_queue, state) == ND419_off_netdev_queue_state);
	static_assert(offsetof(struct netdev_queue, trans_start) == ND419_off_netdev_queue_trans_start);
	static_assert(offsetof(struct netdev_queue, _xmit_lock) == ND419_off_netdev_queue__xmit_lock);
	static_assert(IFF_XMIT_DST_RELEASE == (1U << 5));
	static_assert(IFF_TX_SKB_SHARING == (1U << 11));
	static_assert(IFF_XMIT_DST_RELEASE_PERM == (1U << 17));
	static_assert(sizeof(struct ethtool_drvinfo) == 196);
	static_assert(sizeof(struct netdev419_stats) == 240);
	static_assert(offsetof(struct netdev419_stats, rx_nohandler) == 232);
	static_assert(sizeof(struct rtnl_link_stats64) == 200);
	static_assert(offsetof(struct rtnl_link_stats64, rx_nohandler) == 184);
	static_assert(sizeof(netdev419_test_ndo419) == 256);
	ret = netdev_selftest ? netdev419_selftest() : 0;
	if (!ret && netdev_write_selftest)
		ret = netdev_write_selftest_fn();
	if (!ret && netdev_lifecycle_selftest)
		ret = netdev419_lifecycle_test();
	if (!ret && notify_selftest)
		ret = shim_notify_selftest();
	xmit_probe_ready();
	pr_info("bcm_shim: xmit handshake ready=%#x (want %#x) handshake=%d gate=%s\n",
		(unsigned int)xmit_ready, (unsigned int)XMIT_READY_ALL,
		xmit_handshake, xmit_gate_open() ? "OPEN" : "CLOSED");
	if (!ret && xmit_selftest)
		ret = xmit_selftest_fn();
	return ret;
}

void shim_netdev_exit(void)
{
	/* Defensive drain for the init-failure path (the selftests free
	 * everything they allocate, so this is a no-op on success).
	 * Idempotent: a second call finds an empty list. Only
	 * NETREG_UNINITIALIZED views are adapter-owned and freed via the
	 * tested shim_netdev_free() (RCU + free_netdev, sleeps — hence the
	 * lock is dropped around the call); anything the core owns is
	 * reported and retained. Single-threaded here (init failure or
	 * module exit), so peek-and-free needs no extra serialization
	 * beyond the list mutex. */
	for (;;) {
		struct netdev419_entry *entry;
		struct netdev419_view *victim = NULL;

		mutex_lock(&netdev419_mutex);
		list_for_each_entry(entry, &netdev419_views, list) {
			if (entry->native->reg_state == NETREG_UNINITIALIZED) {
				victim = entry->old;
				break;
			}
		}
		if (!victim && !list_empty(&netdev419_views))
			pr_warn("bcm_shim: netdev_exit: registered views retained\n");
		mutex_unlock(&netdev419_mutex);
		if (!victim)
			break;
		shim_netdev_free(victim);
	}
}
