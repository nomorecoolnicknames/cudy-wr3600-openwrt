// SPDX-License-Identifier: GPL-2.0-only
/* Owned legacy packet storage. Keep both sk_buff and skb_shared_info in the
 * measured old ABI. Native alloc_skb cannot provide either object to wl/hnd.
 * Imports remain disconnected until all packet boundaries are translated. */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/overflow.h>
#include <linux/hashtable.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/gso.h>
/* B6 translators need the native cfg80211 layouts. This TU defines no
 * 4.19-named cfg80211 globals, so the 6.6 inlines are harmless here
 * (the shim_core.c collision note does not apply). Dormant without
 * CONFIG_CFG80211: only the genl selftest below stays active. */
#if IS_ENABLED(CONFIG_CFG80211)
#include <net/cfg80211.h>
#endif
#include "shim_netdev.h"
#include "shim_netdev_layout.h"
#include "shim_skb.h"
#include "shim_skb_layout.h"
#include "shim_skb_meta.h"
#include "shim_gfp.h"
#include "shim.h"

struct skb419_view { u8 bytes[SK419_size_sk_buff] __aligned(8); };
struct skb419_data {
	unsigned int capacity;
	u8 bytes[] __aligned(64);
};
struct skb419_entry {
	struct hlist_node registry;
	u64 before;
	struct skb419_view view;
	u64 after;
	struct skb419_data *data;
	struct sk_buff *native_meta;
	struct sk_buff *native_owner;
};
#define SK419_GUARD 0x4c6567616379534bULL
static atomic_t skb419_headers = ATOMIC_INIT(0);
static atomic_t skb419_buffers = ATOMIC_INIT(0);
/* Membership is checked by address alone: never probe a foreign native skb
 * with container_of/guard reads. Callers still own a reference throughout
 * dispatch, just as required by the native skb API. */
static DEFINE_HASHTABLE(skb419_registry, 8);
static DEFINE_SPINLOCK(skb419_registry_lock);
bool shim_skb_is_legacy(const void *ptr)
{
	struct skb419_entry *e;
	unsigned long flags;
	bool found = false;
	spin_lock_irqsave(&skb419_registry_lock, flags);
	hash_for_each_possible(skb419_registry, e, registry, (unsigned long)ptr) {
		if (&e->view == ptr) { found = true; break; }
	}
	spin_unlock_irqrestore(&skb419_registry_lock, flags);
	return found;
}
static void skb419_register(struct skb419_entry *e)
{
	unsigned long flags;
	spin_lock_irqsave(&skb419_registry_lock, flags);
	hash_add(skb419_registry, &e->registry, (unsigned long)&e->view);
	spin_unlock_irqrestore(&skb419_registry_lock, flags);
}
static void skb419_unregister(struct skb419_entry *e)
{
	unsigned long flags;
	spin_lock_irqsave(&skb419_registry_lock, flags);
	hash_del(&e->registry);
	spin_unlock_irqrestore(&skb419_registry_lock, flags);
}
static bool skb_bridge_selftest;
module_param(skb_bridge_selftest, bool, 0400);
MODULE_PARM_DESC(skb_bridge_selftest, "Test native/legacy packet conversion and ownership");
static bool skb_selftest;
module_param(skb_selftest, bool, 0400);
MODULE_PARM_DESC(skb_selftest, "Test owned legacy linear packet storage and shared clones");
#define OFF(f) SK419_off_sk_buff_##f
#define LOAD(s,f,v) memcpy(&(v), (s)->bytes + OFF(f), sizeof(v))
#define STORE(s,f,v) do { typeof(v) _value = (v); \
 static_assert(sizeof(_value) == SK419_width_sk_buff_##f); \
 memcpy((s)->bytes + OFF(f), &_value, sizeof(_value)); } while (0)

static struct skb419_entry *skb419_entry(struct skb419_view *skb)
{
	return container_of(skb, struct skb419_entry, view);
}
static u8 *skb419_shinfo(struct skb419_entry *e)
{
	return e->data->bytes + e->data->capacity;
}
static atomic_t *skb419_dataref(struct skb419_entry *e)
{
	return (void *)(skb419_shinfo(e) + SK419_off_skb_shared_info_dataref);
}
static refcount_t *skb419_users(struct skb419_view *skb)
{
	return (void *)(skb->bytes + OFF(users));
}
static bool skb419_bit(struct skb419_view *skb, unsigned int off, u8 mask)
{
	return !!(skb->bytes[off] & mask);
}
static void skb419_setbit(struct skb419_view *skb, unsigned int off, u8 mask, bool set)
{
	skb->bytes[off] = (skb->bytes[off] & ~mask) | (set ? mask : 0);
}
#define BITVAL(s,f) skb419_bit(s, SK419_bitoff_##f, SK419_bitmask_##f)
#define SETBIT(s,f,v) skb419_setbit(s, SK419_bitoff_##f, SK419_bitmask_##f, v)

/* --- GSO lane: Unknown-point resolution + shared-info gates ---
 * triaging/shim/skb-gso/REPORT.md §1. wl.ko/hnd.ko import ZERO GSO helpers
 * (nm survey: no skb_segment/skb_gso_segment/gso_* UND, only alloc/copy/
 * pull/push/put/trim/cb_zero/bpm_tainted). Whatever the blob does with a
 * superframe happens through inline reads/writes at the 4.19 176B
 * shared_info offsets — which is exactly what the legacy views provide.
 * GSO vocabulary is ABI-stable: bits 0-17 (TCPV4..UDP_L4) are identical
 * in both trees' skbuff.h; only 6.6 appends FRAGLIST (bit 18). Offsets
 * do shift (size/segs 8/10 on 4.19 vs 4/6 on 6.6, type stays 24), so the
 * copy below always goes through the native accessors on the 6.6 side
 * and the measured SK419 offsets on the legacy side — never raw. */

/* 4.19 GSO vocabulary ends at UDP_L4 (bit 17). Anything else (6.6-only
 * FRAGLIST, future bits) has no 4.19 meaning and is refused, not mapped. */
#define SKB419_GSO_MASK ((SKB_GSO_UDP_L4 << 1) - 1)
static_assert(SKB419_GSO_MASK == 0x3ffffu);

/* Legacy GSO consistency, single source of truth for validate() (which
 * runs before every free/clone/copy/export). Follows skb_is_gso()
 * semantics exactly: only gso_size decides. Stale segs/known-type hints
 * with zero size are dead metadata the 4.19 stack itself ignores (its own
 * segmenter leaves them on tails) — accepted, nothing copied. Stale
 * UNKNOWN-type bits are foreign even as hints (-EOPNOTSUPP). A nonzero
 * size needs a known 4.19 type (-EOPNOTSUPP otherwise). */
static int skb419_gso_check(u16 size, u16 segs, u32 type)
{
	(void)segs;
	if (!size)
		return (type & ~SKB419_GSO_MASK) ? -EOPNOTSUPP : 0;
	if (!type || (type & ~SKB419_GSO_MASK))
		return -EOPNOTSUPP;
	return 0;
}

/* --- Zerocopy/timestamp decision (REPORT §2, explicit codes, never silent) ---
 * tstamp (skb->tstamp): SUPPORTED both ways (plain ktime_t, same off/width
 *   16/8 in both ABIs, already in META_SCALARS).
 * hwtstamps.hwtstamp: REFUSED (-EOPNOTSUPP). A blob-set stamp belongs to
 *   the 4.19/DMA clock domain; handing it to the 6.6 stack would attribute
 *   foreign HW time to its own clock, and no 6.6 provider exists here.
 *   Zeroing it instead would lie to SO_TIMESTAMPING readers.
 * tskey: REFUSED (-EOPNOTSUPP). Option IDs belong to native sockets the
 *   blob cannot own.
 * tx_flags / ubuf_info (destructor_arg): REFUSED (-EOPNOTSUPP). The
 *   completion callback is a CODE POINTER (4.19 sock_zerocopy_callback or
 *   blob text); invoking it from 6.6 crashes, and the 4.19 sock behind it
 *   does not exist here. Untranslatable by construction. */

/* 4.19 bcm_ext.vlan.cfi_save-style DEI gate pattern reused for the two
 * optional words the 6.6 target lacks (REPORT §4): the legacy view HAS
 * them (measured skb-gso/OFFSETS.md: secmark@252 w4, tc_index@230 w2),
 * native build-h7 has NEITHER (CONFIG_NETWORK_SECMARK,
 * CONFIG_NET_SCHED/NET_XGRESS all unset — 6.6 probe fails to compile).
 * Zero passes through as a no-op; nonzero is refused (-EOPNOTSUPP):
 * silently dropping a TC classifier index or a security mark would
 * misdirect qdisc classification / LSM labeling. The CONFIG branches
 * below re-activate a real copy if the target config ever gains them. */
static int skb419_tc_secmark_out(struct sk_buff *native,
				 struct skb419_view *skb)
{
	u32 secmark;
	u16 tc;

	memcpy(&secmark, skb->bytes + SK419_off_sk_buff_secmark,
	       sizeof(secmark));
#if defined(CONFIG_NETWORK_SECMARK)
	static_assert(sizeof(native->secmark) == SK419_width_sk_buff_secmark);
	native->secmark = secmark;
#else
	if (secmark)
		return -EOPNOTSUPP;
#endif
	memcpy(&tc, skb->bytes + SK419_off_sk_buff_tc_index, sizeof(tc));
#if defined(CONFIG_NET_SCHED) || defined(CONFIG_NET_XGRESS)
	static_assert(sizeof(native->tc_index) == SK419_width_sk_buff_tc_index);
	native->tc_index = tc;
#else
	if (tc)
		return -EOPNOTSUPP;
#endif
	return 0;
}

/* 4.19 BCA vendor tree keeps the DEI/CFI bit of a hwaccel VLAN tag in
 * bcm_ext.vlan.cfi_save (CONFIG_BCM_KF_VLAN_DEI, measured by
 * triaging/shim/skb-h13/probe_meta.py); 6.6 stores the full TCI in vlan_tci
 * with presence in vlan_all. Only the DEI bit is meaningful in that word;
 * anything else is unsupported vendor state. */
static int skb419_vlan_cfi(struct skb419_view *skb, u32 *cfi)
{
	u32 word;
	if (SKMETA_offset_bcm_ext_vlan_cfi_save <
	    OFF(bcm_ext) + SK419_width_bcm_skb_ext_wlan ||
	    SKMETA_offset_bcm_ext_vlan_cfi_save + sizeof(word) >
	    OFF(bcm_ext) + SK419_width_sk_buff_bcm_ext)
		return -EUCLEAN;
	memcpy(&word, skb->bytes + SKMETA_offset_bcm_ext_vlan_cfi_save,
	       sizeof(word));
	if (word & ~SKMETA_vlan_present)
		return -EOPNOTSUPP;
	*cfi = word;
	return 0;
}

/* Checks apply to this internal linear-only ownership contract. Additional
 * refcounted metadata, page frags and recycling require their own adapters;
 * silently freeing only part of such an object would leak/double-free data. */
static int skb419_validate(struct skb419_view *skb)
{
	struct skb419_entry *e = skb419_entry(skb);
	u8 *head, *data, *tail, *end;
	u32 len, nonlin, recycle;
	unsigned long pointer;
	u64 guard;
	const unsigned int refs[] = { OFF(_skb_refdst), OFF(_nfct), OFF(sk),
		OFF(blog_p), OFF(recycle_hook), OFF(sp), OFF(nf_bridge) };
	unsigned int i;

	if (!shim_skb_is_legacy(skb))
		return -EINVAL;
	if (e->before != SK419_GUARD || e->after != SK419_GUARD || !e->data)
		return -EUCLEAN;
	memcpy(&guard, skb419_shinfo(e) + ALIGN(SK419_size_skb_shared_info, 64), sizeof(guard));
	if (guard != SK419_GUARD)
		return -EUCLEAN;
	if (!refcount_read(skb419_users(skb)) ||
	    !(atomic_read(skb419_dataref(e)) & 0xffff))
		return -EUCLEAN;
	LOAD(skb, head, head); LOAD(skb, data, data);
	LOAD(skb, tail, tail); LOAD(skb, end, end);
	LOAD(skb, len, len); LOAD(skb, data_len, nonlin);
	if (head != e->data->bytes || end != skb419_shinfo(e) ||
	    (unsigned long)data < (unsigned long)head ||
	    (unsigned long)tail < (unsigned long)data ||
	    (unsigned long)tail > (unsigned long)end || tail - data != len)
		return -EINVAL;
	if (nonlin || skb419_shinfo(e)[SK419_off_skb_shared_info_nr_frags])
		return -EOPNOTSUPP;
	memcpy(&pointer, skb419_shinfo(e) + SK419_off_skb_shared_info_frag_list, sizeof(pointer));
	if (pointer || BITVAL(skb, head_frag))
		return -EOPNOTSUPP;
	/* Linear shared state, GSO lane: bytes 4-7 (pad/nr_frags/tx_flags)
	 * must be zero — a set tx_flags bit means SKBTX/zerocopy completion
	 * state with no cross-ABI translation (see the decision note above).
	 * GSO words go through skb419_gso_check(); hwtstamps/tskey are
	 * refused explicitly (foreign HW clock / native-only option IDs).
	 * destructor_arg + frags keep the blanket zero-check below: a set
	 * ubuf_info callback pointer there must never cross into 6.6. */
	if (memchr_inv(skb419_shinfo(e) + sizeof(void *), 0,
		SK419_off_skb_shared_info_gso_size - sizeof(void *)) ||
	    memchr_inv(skb419_shinfo(e) + SK419_off_skb_shared_info_destructor_arg,
		0, SK419_size_skb_shared_info - SK419_off_skb_shared_info_destructor_arg))
		return -EOPNOTSUPP;
	{
		u8 *shinfo = skb419_shinfo(e);
		u16 gso_size, gso_segs;
		u32 gso_type, tskey;
		ktime_t hwtstamp;
		int gso_ret;

		memcpy(&gso_size, shinfo + SK419_off_skb_shared_info_gso_size,
		       sizeof(gso_size));
		memcpy(&gso_segs, shinfo + SK419_off_skb_shared_info_gso_segs,
		       sizeof(gso_segs));
		memcpy(&gso_type, shinfo + SK419_off_skb_shared_info_gso_type,
		       sizeof(gso_type));
		gso_ret = skb419_gso_check(gso_size, gso_segs, gso_type);
		if (gso_ret)
			return gso_ret;
		memcpy(&hwtstamp, shinfo + SK419_off_skb_shared_info_hwtstamps,
		       sizeof(hwtstamp));
		if (hwtstamp)
			return -EOPNOTSUPP;
		memcpy(&tskey, shinfo + SK419_off_skb_shared_info_tskey,
		       sizeof(tskey));
		if (tskey)
			return -EOPNOTSUPP;
	}
	/* Only WLAN scratch bytes and the VLAN DEI save word are currently
	 * accepted in the BCA extension. The range guard runs first so a
	 * skewed probe offset cannot underflow the segment lengths below. */
	{
		u32 cfi;
		int cfi_ret = skb419_vlan_cfi(skb, &cfi);
		if (cfi_ret)
			return cfi_ret;
	}
	if (memchr_inv(skb->bytes + OFF(bcm_ext) + SK419_width_bcm_skb_ext_wlan, 0,
		SKMETA_offset_bcm_ext_vlan_cfi_save -
		(OFF(bcm_ext) + SK419_width_bcm_skb_ext_wlan)) ||
	    memchr_inv(skb->bytes + SKMETA_offset_bcm_ext_vlan_cfi_save + sizeof(u32), 0,
		(OFF(bcm_ext) + SK419_width_sk_buff_bcm_ext) -
		(SKMETA_offset_bcm_ext_vlan_cfi_save + sizeof(u32))))
		return -EOPNOTSUPP;
	LOAD(skb, recycle_flags, recycle);
	if (recycle)
		return -EOPNOTSUPP;
	for (i = 0; i < ARRAY_SIZE(refs); i++) {
		memcpy(&pointer, skb->bytes + refs[i], sizeof(pointer));
		if (pointer)
			return -EOPNOTSUPP;
	}
	return 0;
}

struct skb419_view *shim_skb_alloc(unsigned int size, gfp_t gfp)
{
	struct skb419_entry *e;
	struct skb419_data *d;
	u8 *head, *end;
	u32 capacity, truesize;
	size_t total;
	u64 guard = SK419_GUARD;

	if (check_add_overflow(size, 63U, &capacity))
		return NULL;
	capacity &= ~63U;
	if (check_add_overflow((size_t)capacity,
		(size_t)sizeof(*d) + ALIGN(SK419_size_skb_shared_info, 64) + sizeof(guard), &total) ||
	    check_add_overflow(capacity, (u32)(SK419_size_sk_buff + ALIGN(SK419_size_skb_shared_info, 64)), &truesize))
		return NULL;
	e = kzalloc(sizeof(*e), gfp);
	if (!e)
		return NULL;
	d = kmalloc(total, gfp);
	if (!d) {
		kfree(e);
		return NULL;
	}
	d->capacity = capacity;
	e->data = d;
	e->before = e->after = SK419_GUARD;
	head = d->bytes;
	end = head + capacity;
	memset(end, 0, ALIGN(SK419_size_skb_shared_info, 64));
	memcpy(end + ALIGN(SK419_size_skb_shared_info, 64), &guard, sizeof(guard));
	STORE(&e->view, head, head); STORE(&e->view, data, head);
	STORE(&e->view, tail, head); STORE(&e->view, end, end);
	STORE(&e->view, truesize, truesize);
	/* Same unset-header convention as old __alloc_skb. */
	STORE(&e->view, mac_header, (u16)~0U);
	STORE(&e->view, transport_header, (u16)~0U);
	refcount_set(skb419_users(&e->view), 1);
	atomic_set(skb419_dataref(e), 1);
	atomic_inc(&skb419_headers);
	atomic_inc(&skb419_buffers);
	skb419_register(e);
	return &e->view;
}

struct skb419_view *shim_skb_clone(struct skb419_view *skb, gfp_t gfp)
{
	struct skb419_entry *src = skb419_entry(skb), *dst;
	u8 *head, *data;
	u16 hdr_len;
	void *null = NULL;
	if (skb419_validate(skb))
		return NULL;
	dst = kzalloc(sizeof(*dst), gfp);
	if (!dst)
		return NULL;
	if (src->native_meta) {
		dst->native_meta = skb_clone(src->native_meta, gfp);
		if (!dst->native_meta) {
			kfree(dst);
			return NULL;
		}
	}
	dst->before = dst->after = SK419_GUARD;
	dst->data = src->data;
	dst->view = *skb;
	STORE(&dst->view, next, null); STORE(&dst->view, prev, null);
	STORE(&dst->view, sk, null); STORE(&dst->view, destructor, null);
	LOAD(skb, hdr_len, hdr_len);
	if (BITVAL(skb, nohdr)) {
		LOAD(skb, head, head); LOAD(skb, data, data);
		hdr_len = data - head;
	}
	STORE(&dst->view, hdr_len, hdr_len);
	SETBIT(&dst->view, cloned, true); SETBIT(&dst->view, nohdr, false);
	SETBIT(&dst->view, fclone, false);
	refcount_set(skb419_users(&dst->view), 1);
	atomic_inc(skb419_dataref(src));
	SETBIT(skb, cloned, true);
	atomic_inc(&skb419_headers);
	skb419_register(dst);
	return &dst->view;
}

struct skb419_view *shim_skb_copy(struct skb419_view *skb, gfp_t gfp)
{
	struct skb419_view *copy;
	struct skb419_entry *src = skb419_entry(skb), *dst;
	u8 *head, *data, *tail, *new_head, *new_data, *new_tail, *new_end;
	u32 truesize;
	void *null = NULL;
	if (skb419_validate(skb))
		return NULL;
	copy = shim_skb_alloc(src->data->capacity, gfp);
	if (!copy)
		return NULL;
	dst = skb419_entry(copy);
	if (src->native_meta) {
		dst->native_meta = skb_clone(src->native_meta, gfp);
		if (!dst->native_meta) {
			shim_skb_free(copy);
			return NULL;
		}
	}
	LOAD(copy, truesize, truesize);
	LOAD(skb, head, head); LOAD(skb, data, data); LOAD(skb, tail, tail);
	new_head = dst->data->bytes; new_end = skb419_shinfo(dst);
	new_data = new_head + (data - head); new_tail = new_head + (tail - head);
	/* Copy headroom and live bytes, never uninitialized tailroom. */
	memcpy(new_head, head, tail - head);
	*copy = *skb;
	STORE(copy, head, new_head); STORE(copy, data, new_data);
	STORE(copy, tail, new_tail); STORE(copy, end, new_end);
	STORE(copy, next, null); STORE(copy, prev, null);
	STORE(copy, sk, null); STORE(copy, destructor, null);
	STORE(copy, truesize, truesize); STORE(copy, hdr_len, (u16)0);
	SETBIT(copy, cloned, false); SETBIT(copy, nohdr, false); SETBIT(copy, fclone, false);
	refcount_set(skb419_users(copy), 1);
	return copy;
}

/* hnd osl_pktdup_cpy asks for the source headroom. Refuse an unimplemented
 * expansion rather than passing an old descriptor into native pskb_copy. */
struct skb419_view *shim_skb_copy_headroom(struct skb419_view *skb, int headroom, gfp_t gfp)
{
	u8 *head, *data;
	if (skb419_validate(skb))
		return NULL;
	LOAD(skb, head, head); LOAD(skb, data, data);
	if (headroom < 0 || headroom != data - head) {
		pr_warn_once("bcm_shim: legacy pskb_copy headroom expansion unsupported\n");
		return NULL;
	}
	return shim_skb_copy(skb, gfp);
}

int shim_skb_free(struct skb419_view *skb)
{
	struct skb419_entry *e;
	void (*destructor)(struct skb419_view *);
	int ret, remain;
	if (!skb)
		return 0;
	ret = skb419_validate(skb);
	if (ret)
		return ret;
	if (!refcount_dec_and_test(skb419_users(skb)))
		return 0;
	e = skb419_entry(skb);
	LOAD(skb, destructor, destructor);
	if (destructor)
		destructor(skb);
	remain = BITVAL(skb, cloned) ?
		atomic_sub_return(BITVAL(skb, nohdr) ? 0x10001 : 1, skb419_dataref(e)) : 0;
	if (!remain) {
		kfree(e->data);
		atomic_dec(&skb419_buffers);
	}
	dev_kfree_skb_any(e->native_meta);
	dev_kfree_skb_any(e->native_owner);
	skb419_unregister(e);
	e->before = e->after = 0;
	kfree(e);
	atomic_dec(&skb419_headers);
	return 0;
}

/* Metadata resources stay in native descriptors. Never expose native dst,
 * socket, conntrack or extension objects through incompatible old fields. */
#define META_SCALARS(X) \
	X(tstamp) X(mac_len) X(queue_mapping) X(csum) X(csum_start) X(csum_offset) \
	X(priority) X(skb_iif) \
	X(hash) X(mark) X(protocol) X(transport_header) X(network_header) \
	X(mac_header) X(inner_protocol) X(inner_transport_header) \
	X(inner_network_header) X(inner_mac_header)

static void skb419_metadata_in(struct skb419_view *old, const struct sk_buff *native)
{
#define SCALAR(f) STORE(old, f, native->f);
	META_SCALARS(SCALAR)
#undef SCALAR
	/* Optional native words (absent on the build-h7 target): when the
	 * 6.6 config provides them they are real copies into the measured
	 * legacy slots; otherwise the legacy words stay zero from the
	 * kzalloc in shim_skb_alloc, which the export gate accepts. */
#if defined(CONFIG_NETWORK_SECMARK)
	STORE(old, secmark, native->secmark);
#endif
#if defined(CONFIG_NET_SCHED) || defined(CONFIG_NET_XGRESS)
	STORE(old, tc_index, native->tc_index);
#endif
#define FLAG(f) old->bytes[SKMETA_offset_##f] = \
	(old->bytes[SKMETA_offset_##f] & ~SKMETA_mask_##f) | \
	(native->f << SKMETA_shift_##f);
	SKMETA_COMMON(FLAG)
#undef FLAG
}

static int skb419_metadata_out(struct sk_buff *native, struct skb419_view *old)
{
	u16 vlan_tci;
	__be16 vlan_proto;
	u32 cfi_save;
	int cfi_ret = skb419_vlan_cfi(old, &cfi_save);
	int ret;
	if (cfi_ret)
		return cfi_ret;
#define UNSUPPORTED(f) if (old->bytes[SKMETA_offset_##f] & SKMETA_mask_##f) return -EOPNOTSUPP;
	SKMETA_UNSUPPORTED(UNSUPPORTED)
#undef UNSUPPORTED
#define SCALAR(f) LOAD(old, f, native->f);
	META_SCALARS(SCALAR)
#undef SCALAR
#define FLAG(f) native->f = (old->bytes[SKMETA_offset_##f] & SKMETA_mask_##f) >> SKMETA_shift_##f;
	SKMETA_COMMON(FLAG)
#undef FLAG
	/* GSO pass-through (legacy -> native, REPORT §1): validate() above
	 * already enforced size/segs/type consistency and the 4.19 type
	 * mask, so only a present superframe needs copying — through the
	 * native accessors (4.19 size/segs live at 8/10, native at 4/6).
	 * The stack owns GRO/segmentation policy on RX; the shim must not
	 * segment here (that would need a list API and would destroy the
	 * aggregation the stack was built to handle). QinQ note: a second
	 * tag always travels in-frame (both ABIs have a single hwaccel
	 * slot); in-frame bytes are memcpy'd verbatim by the caller, so a
	 * hwaccel outer + in-frame inner (or two in-frame tags) round-trips
	 * without extra fields. */
	{
		u16 gso_size, gso_segs;
		u32 gso_type;

		memcpy(&gso_size,
		       skb419_shinfo(skb419_entry(old)) +
		       SK419_off_skb_shared_info_gso_size, sizeof(gso_size));
		memcpy(&gso_segs,
		       skb419_shinfo(skb419_entry(old)) +
		       SK419_off_skb_shared_info_gso_segs, sizeof(gso_segs));
		memcpy(&gso_type,
		       skb419_shinfo(skb419_entry(old)) +
		       SK419_off_skb_shared_info_gso_type, sizeof(gso_type));
		if (gso_size) {
			skb_shinfo(native)->gso_size = gso_size;
			skb_shinfo(native)->gso_segs = gso_segs;
			skb_shinfo(native)->gso_type = gso_type;
		}
	}
	ret = skb419_tc_secmark_out(native, old);
	if (ret)
		return ret;
	LOAD(old, vlan_tci, vlan_tci); LOAD(old, vlan_proto, vlan_proto);
	__vlan_hwaccel_clear_tag(native);
	if (vlan_tci & SKMETA_vlan_present) {
		if (vlan_proto != htons(ETH_P_8021Q) && vlan_proto != htons(ETH_P_8021AD))
			return -EINVAL;
		/* 4.19 uses the CFI bit as presence; imported native VLAN is already
		 * materialized in the frame, preserving all TCI bits including DEI.
		 * A legacy-side metadata tag restores its true DEI from BCA
		 * cfi_save; native stores the full TCI with presence in vlan_all. */
		__vlan_hwaccel_put_tag(native, vlan_proto,
			(vlan_tci & ~SKMETA_vlan_present) | (cfi_save & SKMETA_vlan_present));
	}
	return 0;
}

struct skb419_view *shim_skb_import(struct sk_buff *native, gfp_t gfp)
{
	struct skb419_view *old;
	struct skb419_entry *e;
	struct sk_buff *work;
	struct netdev419_view *old_dev = NULL;
	u32 headroom, size;
	u8 *data, *tail;
	bool vlan;

	if (!native)
		return ERR_PTR(-EINVAL);
	/* These must be segmented or given callback translation at the caller
	 * before entering this non-GSO packet boundary. No silent truncation.
	 * GSO superframes go through shim_skb_import_gso (native SW
	 * segmentation + per-segment import); zerocopy/timestamp state has
	 * no cross-ABI translation (see the decision note above) and stays
	 * refused here with ownership retained. */
	/* GSO verdict follows skb_is_gso() semantics like the legacy side:
	 * only gso_size decides; stale known-hint words with zero size are
	 * dead metadata. Stale UNKNOWN-type bits are foreign (-EOPNOTSUPP)
	 * even with zero size: silently laundering a 6.6-only superframe
	 * into a "normal" legacy view the blob would DMA is worse than a
	 * loud refusal with ownership retained. */
	if (skb_is_gso(native) ||
	    (skb_shinfo(native)->gso_type & ~SKB419_GSO_MASK) ||
	    skb_shinfo(native)->tx_flags || skb_shinfo(native)->tskey ||
	    skb_zcopy(native) || skb_shinfo(native)->hwtstamps.hwtstamp)
		return ERR_PTR(-EOPNOTSUPP);
	if (native->dev) {
		old_dev = shim_netdev_legacy(native->dev);
		if (!old_dev)
			return ERR_PTR(-EXDEV);
	}
	vlan = skb_vlan_tag_present(native);
	if (vlan && (native->len < ETH_HLEN || !skb_mac_header_was_set(native) ||
		     skb_mac_offset(native)))
		return ERR_PTR(-EINVAL);
	headroom = max_t(u32, skb_headroom(native), vlan ? VLAN_HLEN : 0);
	if (check_add_overflow(headroom, native->len, &size) || size > INT_MAX - VLAN_HLEN)
		return ERR_PTR(-EOVERFLOW);
	/* Native helper safely copies page frags/frag_list and takes native
	 * metadata references; it never exposes native shared_info to the blob. */
	work = skb_copy_expand(native, headroom, 0, gfp);
	if (!work)
		return ERR_PTR(-ENOMEM);
	work->pfmemalloc = native->pfmemalloc;
	work->mac_len = native->mac_len;
	if (vlan) {
		int ret = skb_vlan_push(work, work->vlan_proto, work->vlan_tci);
		if (ret) {
			dev_kfree_skb_any(work);
			return ERR_PTR(ret);
		}
		/* skb_vlan_push materialized the old tag and installed another
		 * metadata tag. Clear that extra tag: exactly one VLAN is wanted. */
		__vlan_hwaccel_clear_tag(work);
	}
	headroom = skb_headroom(work);
	if (check_add_overflow(headroom, work->len, &size)) {
		dev_kfree_skb_any(work);
		return ERR_PTR(-EOVERFLOW);
	}
	old = shim_skb_alloc(size, gfp);
	if (!old) {
		dev_kfree_skb_any(work);
		return ERR_PTR(-ENOMEM);
	}
	e = skb419_entry(old);
	data = e->data->bytes + headroom;
	tail = data + work->len;
	memcpy(e->data->bytes, work->head, size);
	STORE(old, data, data); STORE(old, tail, tail); STORE(old, len, work->len);
	STORE(old, dev, old_dev);
	skb419_metadata_in(old, work);
	/* Native cb is kept in native_meta; old cb is driver scratch of a
	 * different size/ABI. Copying the two would corrupt netlink/stack state. */
	e->native_meta = work;
	e->native_owner = native; /* success: consume caller's reference */
	return old;
}

struct sk_buff *shim_skb_export(struct skb419_view *old, gfp_t gfp)
{
	struct skb419_entry *e;
	struct sk_buff *native;
	struct netdev419_view *old_dev;
	struct net_device *dev = NULL;
	u8 *head, *data, *tail;
	u32 len;
	int ret;

	if (!old)
		return ERR_PTR(-EINVAL);
	ret = skb419_validate(old);
	if (ret)
		return ERR_PTR(ret);
	LOAD(old, dev, old_dev);
	if (old_dev) {
		dev = shim_netdev_native(old_dev);
		if (!dev)
			return ERR_PTR(-EXDEV);
	}
	e = skb419_entry(old);
	LOAD(old, head, head); LOAD(old, data, data); LOAD(old, tail, tail);
	LOAD(old, len, len);
	native = alloc_skb(e->data->capacity, gfp);
	if (!native)
		return ERR_PTR(-ENOMEM);
	skb_reserve(native, data - head);
	skb_put(native, len);
	memcpy(native->head, head, tail - head);
	if (e->native_meta)
		skb_copy_header(native, e->native_meta);
	native->dev = dev;
	ret = skb419_metadata_out(native, old);
	if (ret) {
		dev_kfree_skb_any(native);
		return ERR_PTR(ret);
	}
	return native;
}

static int skb419_mutable(struct skb419_view *skb)
{
	int ret = skb419_validate(skb);
	if (ret)
		return ret;
	return refcount_read(skb419_users(skb)) == 1 ? 0 : -EBUSY;
}

/* A reclaimed RX pool packet can retain an earlier DMA headroom pull.
 * Reset only a validated, exclusively owned linear packet before reposting;
 * never repair an already corrupt descriptor or discard foreign metadata. */
int shim_skb_pool_reset(struct skb419_view *skb, unsigned int headroom,
			unsigned int len)
{
	struct skb419_entry *e;
	u8 *data, *tail;
	int ret = skb419_mutable(skb);
	if (ret)
		return ret;
	e = skb419_entry(skb);
	if (BITVAL(skb, cloned) || atomic_read(skb419_dataref(e)) != 1)
		return -EBUSY;
	if (headroom > e->data->capacity || len > e->data->capacity - headroom)
		return -ENOSPC;
	data = e->data->bytes + headroom;
	tail = data + len;
	STORE(skb, data, data); STORE(skb, tail, tail); STORE(skb, len, len);
	return 0;
}
int shim_skb_reserve(struct skb419_view *skb, unsigned int len)
{
	u8 *data, *tail, *end;
	u32 used;
	int ret = skb419_mutable(skb);
	if (ret) return ret;
	LOAD(skb, len, used); if (used) return -EINVAL;
	LOAD(skb, data, data); LOAD(skb, tail, tail); LOAD(skb, end, end);
	if (len > end - tail) return -ENOSPC;
	data += len; tail += len;
	STORE(skb, data, data); STORE(skb, tail, tail);
	return 0;
}
void *shim_skb_put(struct skb419_view *skb, unsigned int len)
{
	u8 *tail, *end, *result;
	u32 used;
	if (skb419_mutable(skb)) return NULL;
	LOAD(skb, tail, tail); LOAD(skb, end, end); LOAD(skb, len, used);
	if (len > end - tail) return NULL;
	result = tail; tail += len; used += len;
	STORE(skb, tail, tail); STORE(skb, len, used);
	return result;
}
void *shim_skb_push(struct skb419_view *skb, unsigned int len)
{
	u8 *head, *data;
	u32 used;
	if (skb419_mutable(skb)) return NULL;
	LOAD(skb, head, head); LOAD(skb, data, data); LOAD(skb, len, used);
	if (len > data - head) return NULL;
	data -= len; used += len;
	STORE(skb, data, data); STORE(skb, len, used);
	return data;
}
void *shim_skb_pull(struct skb419_view *skb, unsigned int len)
{
	u8 *data;
	u32 used;
	if (skb419_mutable(skb)) return NULL;
	LOAD(skb, data, data); LOAD(skb, len, used);
	if (len > used) return NULL;
	data += len; used -= len;
	STORE(skb, data, data); STORE(skb, len, used);
	return data;
}
int shim_skb_trim(struct skb419_view *skb, unsigned int len)
{
	u8 *data, *tail;
	u32 used;
	int ret = skb419_mutable(skb);
	if (ret) return ret;
	LOAD(skb, len, used);
	if (len >= used) return 0;
	LOAD(skb, data, data); tail = data + len;
	STORE(skb, tail, tail); STORE(skb, len, len);
	return 0;
}

/* --- RXTX S1: legacy-descriptor allocators with 4.19 GFP translation ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S1. Fresh netlink buffers stay
 * native (bcm419___alloc_skb & co. in shim_alloc.c); the entry points below
 * serve call sites whose buffer the blob then edits as a legacy descriptor
 * (wl_monitor radiotap build, dma_rxfill-style pool refill, pktdup-style
 * dups). Every wrapper takes the raw 4.19 GFP word; shim_gfp419() maps it
 * to native flags (same vectors as shim_alloc_init() asserts). NULL views
 * are rejected with a one-time warning: the inner helpers assume validated
 * descriptors and must never see NULL from the blob. */
struct skb419_view *bcm419_legacy_skb_alloc(unsigned int size,
					    unsigned int gfp419)
{
	return shim_skb_alloc(size, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_legacy_skb_alloc);

struct skb419_view *bcm419_legacy_skb_clone(struct skb419_view *skb,
					    unsigned int gfp419)
{
	if (!skb) {
		shim_warn_once("legacy_skb_clone: NULL skb\n");
		return NULL;
	}
	return shim_skb_clone(skb, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_legacy_skb_clone);

struct skb419_view *bcm419_legacy_skb_copy(struct skb419_view *skb,
					   unsigned int gfp419)
{
	if (!skb) {
		shim_warn_once("legacy_skb_copy: NULL skb\n");
		return NULL;
	}
	return shim_skb_copy(skb, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_legacy_skb_copy);

/* Legacy __netdev_alloc_skb: len bytes of payload room behind NET_SKB_PAD
 * headroom (4.19 net/core/skbuff.c pattern: pad, reserve, store dev).
 * The dev pointer is the caller's legacy view, stored as-is for the blob
 * to read back; translation to native happens in shim_skb_export (S6). */
struct skb419_view *bcm419_legacy_netdev_alloc_skb(struct netdev419_view *dev,
						   unsigned int len,
						   unsigned int gfp419)
{
	struct skb419_view *skb;
	u32 size;

	if (check_add_overflow(len, (u32)NET_SKB_PAD, &size))
		return NULL;
	skb = shim_skb_alloc(size, shim_gfp419(gfp419));
	if (!skb)
		return NULL;
	if (shim_skb_reserve(skb, NET_SKB_PAD)) {
		shim_skb_free(skb);
		return NULL;
	}
	STORE(skb, dev, dev);
	return skb;
}
EXPORT_SYMBOL(bcm419_legacy_netdev_alloc_skb);

/* --- RXTX S2: B1 cb_zero + B2 bpm_tainted ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S2, specs §5 B1/B2.
 * Guards here are deliberately lighter than skb419_validate(): 4.19
 * performs these writes unconditionally on any sk_buff, so any present
 * (guard-intact) 384B view is serviceable, cloned or not. */

/* B1: 4.19 bcm_skbuff.c:584 skb_cb_zero(): memset(cb, 0, sizeof(cb)) plus
 * the BCA WLAN extension (struct wlan_ext, 24B at bcm_ext+0). Uses measured
 * widths (cb 80B @280, wlan 24B) instead of the H15 "48B" shorthand: the
 * stock-header fixture (H12 oracle) pins cb at 80B, and the vendor body
 * zeroes the whole array, not a prefix. */
void bcm419_skb_cb_zero(struct skb419_view *skb)
{
	struct skb419_entry *e;

	if (!skb) {
		shim_warn_once("skb_cb_zero: NULL skb\n");
		return;
	}
	e = skb419_entry(skb);
	if (e->before != SK419_GUARD || e->after != SK419_GUARD || !e->data) {
		shim_warn_once("skb_cb_zero: bad descriptor, not zeroed\n");
		return;
	}
	memset(skb->bytes + OFF(cb), 0, SK419_width_sk_buff_cb);
	memset(skb->bytes + OFF(bcm_ext) + SK419_off_bcm_skb_ext_wlan, 0,
	       SK419_width_bcm_skb_ext_wlan);
}
EXPORT_SYMBOL(bcm419_skb_cb_zero);

/* B2: 4.19 bcm_skbuff.h:44 SKB_BPM_TAINTED / bcm_skbuff.c:101
 * skb_bpm_tainted(): recycle_flags &= ~SKB_BPM_PRISTINE, dirty_p = NULL.
 * NOTE the H15 table claims (skb)->bool; the vendor header declares
 * void skb_bpm_tainted(struct sk_buff *) (bcm_skbuff.h:61), so the export
 * below is void. Meaning on 6.6: no BPM pool exists, freeing always takes
 * the copy path, so clearing PRISTINE keeps the descriptor inside the
 * shim_skb_free-able set. Other recycle bits have no 6.6 meaning and are
 * left alone with a one-time warning (a later free will refuse them). */
#define SKB419_BPM_PRISTINE (1u << 5)
void bcm419_skb_bpm_tainted(struct skb419_view *skb)
{
	struct skb419_entry *e;
	u32 recycle;

	if (!skb) {
		shim_warn_once("skb_bpm_tainted: NULL skb\n");
		return;
	}
	e = skb419_entry(skb);
	if (e->before != SK419_GUARD || e->after != SK419_GUARD || !e->data) {
		shim_warn_once("skb_bpm_tainted: bad descriptor\n");
		return;
	}
	LOAD(skb, recycle_flags, recycle);
	recycle &= ~SKB419_BPM_PRISTINE;
	STORE(skb, recycle_flags, recycle);
	memset(skb419_shinfo(e) + SK419_off_skb_shared_info_dirty_p, 0,
	       SK419_width_skb_shared_info_dirty_p);
	if (recycle)
		shim_warn_once("skb_bpm_tainted: recycle residue %#x, no pool\n",
			       recycle);
}
EXPORT_SYMBOL(bcm419_skb_bpm_tainted);

/* --- RXTX S3: legacy free path + B3 bulk ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S3, spec §5 B3. Call sites:
 * hnd linux_pktfree[_slow] (consume_skb/__dev_kfree_skb_any), osl_dev_put
 * + linux_commit_skb_freelist (bulk), osl_pkt_queue_purge (purge),
 * wl_monitor/nlwifi error legs (kfree_skb on legacy buffers). Fresh native
 * buffers keep using the native names in shim_core.c; the bcm419_ family
 * below is the legacy-descriptor side. Destructor-once comes from
 * shim_skb_free (fires only on the users 1->0 transition). */
static void skb419_free_one(struct skb419_view *skb, const char *who)
{
	int ret;

	if (!skb)
		return;
	ret = shim_skb_free(skb);
	if (ret)
		shim_warn_once("%s: refuse %d, ownership retained\n", who, ret);
}

void bcm419_kfree_skb(struct skb419_view *skb)
{
	skb419_free_one(skb, "kfree_skb");
}
EXPORT_SYMBOL(bcm419_kfree_skb);

void bcm419_consume_skb(struct skb419_view *skb)
{
	skb419_free_one(skb, "consume_skb");
}
EXPORT_SYMBOL(bcm419_consume_skb);

void bcm419___dev_kfree_skb_any(struct skb419_view *skb,
				enum skb_drop_reason reason)
{
	(void)reason; /* any context, no drop accounting on legacy views */
	skb419_free_one(skb, "__dev_kfree_skb_any");
}
EXPORT_SYMBOL(bcm419___dev_kfree_skb_any);

/* 4.19 skb_queue_purge splices the list under its spinlock, then frees.
 * The legacy ticket-lock word is NOT the 6.6 qspinlock: taking it from
 * 6.6 would corrupt it, so this splice runs without it. The only in-tree
 * caller (osl_pkt_queue_purge) runs in process context under its own OSL
 * lock; S9 must keep that serialization. Anything else warns once. */
static_assert(offsetof(struct skb419_head, next) == 0);
static_assert(offsetof(struct skb419_head, prev) == 4);
static_assert(offsetof(struct skb419_head, qlen) == SK419_off_sk_buff_head_qlen);
static_assert(offsetof(struct skb419_head, lock) == SK419_off_sk_buff_head_lock);
static_assert(sizeof(struct skb419_head) == SK419_size_sk_buff_head);
void bcm419_skb_queue_purge(struct skb419_head *list)
{
	struct skb419_view *cur, *next;
	void *mark;
	u32 steps, budget;

	if (!list)
		return;
	shim_warn_once("skb_queue_purge: legacy lock not taken, caller serializes\n");
	mark = list;
	cur = list->next;
	budget = list->qlen;
	list->next = list->prev = (struct skb419_view *)list;
	list->qlen = 0;
	steps = 0;
	while (cur && (void *)cur != mark && steps <= budget) {
		LOAD(cur, next, next);
		if (shim_skb_free(cur)) {
			shim_warn_once("skb_queue_purge: refuse, rest detached+retained\n");
			break;
		}
		cur = next;
		steps++;
	}
	if (cur && (void *)cur != mark)
		shim_warn_once("skb_queue_purge: truncated at %u of %u\n",
			       steps, budget);
}
EXPORT_SYMBOL(bcm419_skb_queue_purge);

static void skb419_report_failure(struct skb419_view *skb, unsigned int requested,
				  const char *who);

/* B3: the CONFIG_BCM_BPM_BULK_FREE=y variant (stock .config line 3446):
 * void dev_kfree_skb_thread_bulk(head, tail, len). Arity proven by hnd.ko
 * disasm: osl_dev_put+0x9c and linux_commit_skb_freelist+0x48 both do
 * `add r0, rX, #48; ldm r0, {r0, r1, r2}; bl` (triple from the OSL handle
 * at +48/+52/+56), NOT the (array,count) guess in the H15 table. 4.19
 * splices head..tail onto the free-thread queue once head->users hits
 * zero; without that thread the segment is freed inline. Per-element
 * gating equals 4.19's head gate under its own documented uniform-refcount
 * assumption, and stays clone-safe through dataref. */
void bcm419_dev_kfree_skb_thread_bulk(struct skb419_view *head,
				      struct skb419_view *tail, u32 len)
{
	struct skb419_view *cur = head, *next;
	u32 steps = 0;

	if (!head) {
		shim_warn_once("dev_kfree_skb_thread_bulk: NULL head\n");
		return;
	}
	while (cur && cur != tail && steps < len) {
		LOAD(cur, next, next);
		if (shim_skb_free(cur)) {
			skb419_report_failure(cur, len, "bulk_free");
			shim_warn_once("dev_kfree_skb_thread_bulk: refuse, rest retained\n");
			return;
		}
		cur = next;
		steps++;
	}
	if (cur != tail) {
		shim_warn_once("dev_kfree_skb_thread_bulk: tail unreachable (%u/%u)\n",
			       steps, len);
		return;
	}
	if (shim_skb_free(tail)) {
		skb419_report_failure(tail, len, "bulk_free_tail");
		shim_warn_once("dev_kfree_skb_thread_bulk: tail refuse\n");
	} else if (steps + 1 != len)
		shim_warn_once("dev_kfree_skb_thread_bulk: count %u != %u\n",
			       steps + 1, len);
}
EXPORT_SYMBOL(bcm419_dev_kfree_skb_thread_bulk);

static unsigned int rxtx_destructors;
static struct skb419_view *rxtx_expected;
static bool rxtx_wrong;
static void rxtx_test_destructor(struct skb419_view *skb)
{
	rxtx_destructors++;
	if (rxtx_expected && skb != rxtx_expected)
		rxtx_wrong = true;
}

/* --- RXTX S4: header/data manipulation exports ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S4. Covers every datapath
 * entry name from the §1-§2 tables: skb_push (49 wl + 1 hnd relocs),
 * skb_pull (171 + 2), ___pskb_trim (116 + 1), skb_put (3), skb_trim
 * (16, shared with the nlwifi family). Thin guards over the shim_skb_*
 * core: NULL views and bound/mutability failures warn once and degrade
 * (NULL / no-op / negative errno) instead of skb_over/under_panic.
 * ___pskb_trim is exactly trim here: the owned-linear contract rejects
 * paged/frag data at validate time, so "error -> drop, not free" holds
 * by returning the negative errno with ownership retained. */
/* Opt-in RX bring-up diagnostics. Never print payload/key bytes, and only
 * inspect descriptors whose identity is registered as a live legacy view. */
static bool skb_failure_trace;
module_param(skb_failure_trace, bool, 0600);
static bool skb_failure_stack_done;
static void skb419_report_failure(struct skb419_view *skb, unsigned int requested,
				  const char *who)
{
	u8 *head, *data, *tail, *end;
	u32 used, nonlin, recycle;
	int valid;

	if (!skb_failure_trace || !shim_skb_is_legacy(skb))
		return;
	valid = skb419_validate(skb);
	LOAD(skb, head, head); LOAD(skb, data, data);
	LOAD(skb, tail, tail); LOAD(skb, end, end);
	LOAD(skb, len, used); LOAD(skb, data_len, nonlin);
	LOAD(skb, recycle_flags, recycle);
	pr_warn_ratelimited("SKB419_FAIL %s requested=%u validate=%d users=%u len=%u data_len=%u data_off=%lu tail_off=%lu end_off=%lu recycle=%x\n",
		who, requested, valid, refcount_read(skb419_users(skb)),
		used, nonlin, (unsigned long)data - (unsigned long)head,
		(unsigned long)tail - (unsigned long)head,
		(unsigned long)end - (unsigned long)head, recycle);
	if (!xchg(&skb_failure_stack_done, true))
		dump_stack();
}

static void *skb419_pushpull(struct skb419_view *skb, unsigned int len,
			     const char *who,
			     void *(*op)(struct skb419_view *, unsigned int))
{
	void *ret;

	if (!skb) {
		shim_warn_once("%s: NULL skb\n", who);
		return NULL;
	}
	ret = op(skb, len);
	if (!ret) {
		skb419_report_failure(skb, len, who);
		shim_warn_once("%s: len %u refused\n", who, len);
	}
	return ret;
}

void *bcm419_skb_put(struct skb419_view *skb, unsigned int len)
{
	return skb419_pushpull(skb, len, "skb_put", shim_skb_put);
}
EXPORT_SYMBOL(bcm419_skb_put);

void *bcm419_skb_push(struct skb419_view *skb, unsigned int len)
{
	return skb419_pushpull(skb, len, "skb_push", shim_skb_push);
}
EXPORT_SYMBOL(bcm419_skb_push);

void *bcm419_skb_pull(struct skb419_view *skb, unsigned int len)
{
	return skb419_pushpull(skb, len, "skb_pull", shim_skb_pull);
}
EXPORT_SYMBOL(bcm419_skb_pull);

void bcm419_skb_trim(struct skb419_view *skb, unsigned int len)
{
	int ret;

	if (!skb) {
		shim_warn_once("skb_trim: NULL skb\n");
		return;
	}
	ret = shim_skb_trim(skb, len);
	if (ret)
		shim_warn_once("skb_trim: len %u refuse %d\n", len, ret);
}
EXPORT_SYMBOL(bcm419_skb_trim);

int bcm419____pskb_trim(struct skb419_view *skb, unsigned int len)
{
	int ret;

	if (!skb) {
		shim_warn_once("___pskb_trim: NULL skb\n");
		return -EINVAL;
	}
	ret = shim_skb_trim(skb, len);
	if (ret)
		shim_warn_once("___pskb_trim: len %u refuse %d\n", len, ret);
	return ret;
}
EXPORT_SYMBOL(bcm419____pskb_trim);

/* --- RXTX S5: B7 VLAN tag entry points ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S5, spec §5 B7 + §4 table.
 * The H13 two-way DEI gate (proven on HW, SKB419_VLAN_GATE PASS) already
 * translates PRESENT<->vlan_all inside shim_skb_export/import; the four
 * entry points below expose the same gate for direct tag reads/writes
 * without duplicating it: get/set go through skb419_vlan_cfi() + the
 * measured vlan_tci/vlan_proto offsets. Guards are S2-light (present
 * 384B view, no full validate): like the blob's inline tag access, tag
 * reads must work on any live descriptor, including cloned ones. */
static bool skb419_view_intact(const struct skb419_view *skb)
{
	struct skb419_entry *e;

	if (!skb)
		return false;
	e = skb419_entry((struct skb419_view *)skb);
	return e->before == SK419_GUARD && e->after == SK419_GUARD && e->data;
}

bool bcm419_vlan_tag_present(const struct skb419_view *skb)
{
	u16 tci;

	if (!skb419_view_intact(skb)) {
		shim_warn_once("vlan_tag_present: bad descriptor\n");
		return false;
	}
	LOAD(skb, vlan_tci, tci);
	return !!(tci & SKMETA_vlan_present);
}
EXPORT_SYMBOL(bcm419_vlan_tag_present);

int bcm419_vlan_tag_get(const struct skb419_view *skb, __be16 *proto,
			u16 *tci)
{
	u16 raw;
	__be16 p;
	u32 cfi;
	int ret;

	if (!skb419_view_intact(skb)) {
		shim_warn_once("vlan_tag_get: bad descriptor\n");
		return -EINVAL;
	}
	if (!proto || !tci) {
		shim_warn_once("vlan_tag_get: NULL out pointer\n");
		return -EINVAL;
	}
	ret = skb419_vlan_cfi((struct skb419_view *)skb, &cfi);
	if (ret) {
		shim_warn_once("vlan_tag_get: cfi refuse %d\n", ret);
		return ret;
	}
	LOAD(skb, vlan_tci, raw);
	LOAD(skb, vlan_proto, p);
	if (!(raw & SKMETA_vlan_present))
		return 0;
	*proto = p;
	*tci = (raw & ~SKMETA_vlan_present) | (cfi & SKMETA_vlan_present);
	return 1;
}
EXPORT_SYMBOL(bcm419_vlan_tag_get);

int bcm419_vlan_tag_set(struct skb419_view *skb, __be16 proto, u16 tci)
{
	u16 raw;
	u32 cfi;
	int ret;

	if (!skb419_view_intact(skb)) {
		shim_warn_once("vlan_tag_set: bad descriptor\n");
		return -EINVAL;
	}
	if (proto != htons(ETH_P_8021Q) && proto != htons(ETH_P_8021AD)) {
		shim_warn_once("vlan_tag_set: proto %#04x refuse\n",
			       ntohs(proto));
		return -EINVAL;
	}
	ret = skb419_vlan_cfi(skb, &cfi);
	if (ret) {
		shim_warn_once("vlan_tag_set: cfi refuse %d\n", ret);
		return ret;
	}
	raw = (tci & ~SKMETA_vlan_present) | SKMETA_vlan_present;
	cfi = tci & SKMETA_vlan_present;
	STORE(skb, vlan_tci, raw);
	STORE(skb, vlan_proto, proto);
	memcpy(skb->bytes + SKMETA_offset_bcm_ext_vlan_cfi_save, &cfi,
	       sizeof(cfi));
	return 0;
}
EXPORT_SYMBOL(bcm419_vlan_tag_set);

void bcm419_vlan_tag_clear(struct skb419_view *skb)
{
	u16 raw = 0;
	__be16 proto = 0;
	u32 cfi = 0;

	if (!skb419_view_intact(skb)) {
		shim_warn_once("vlan_tag_clear: bad descriptor\n");
		return;
	}
	STORE(skb, vlan_tci, raw);
	STORE(skb, vlan_proto, proto);
	memcpy(skb->bytes + SKMETA_offset_bcm_ext_vlan_cfi_save, &cfi,
	       sizeof(cfi));
}
EXPORT_SYMBOL(bcm419_vlan_tag_clear);

/* --- RX re-verify (H30 §7 abз.2): split eth_type_trans/netif_rx imports ---
 *
 * Consumer split (audited blob sequences, triaging/shim/rxtx-h15/REPORT.md):
 *  DATA (wl_sendup*): blob calls mixed_eth_type_trans (pulls the 14B eth
 *    header, sets protocol) THEN mixed_netif_rx. The legacy descriptor stays
 *    blob-owned between the two calls; each boundary translates independently.
 *  MONITOR (wl_monitor 0x313284…): blob builds radiotap+802.11 internally
 *    (wl_radiotap_rx_* are blob-internal, not UND) and calls netif_rx[_ni]
 *    ONLY — never eth_type_trans. mixed_netif_rx is payload-agnostic, so
 *    monitor frames pass through byte-identical with no Ethernet assumption.
 *  MLME (wl_notify_rx_mgmt_frame, wl_event_handler): no skb at all —
 *    blob calls cfg80211_rx_mgmt(wdev, freq, sig, buf, len) (cfg80211_compat.c
 *    translates the legacy wdev). Nothing to route here.
 * Separation is by ENTRY CONTRACT (the blob's own call sequence, exactly as
 * on stock 4.19 whose eth_type_trans/netif_rx are equally "dumb"), never by
 * payload sniffing. S9 must keep it: monitor via bare mixed_netif_rx,
 * data via the trans+rx pair, combined bcm419_rx_deliver for Ethernet only.
 *
 * Ownership matrix (one legacy reference in, exactly one disposition):
 *  trans/export-refuse (-EXDEV/-EOPNOTSUPP/-EINVAL): legacy RETAINED, blob
 *    still owns it (4.19 eth_type_trans never consumes either). Return 0.
 *  trans success: legacy MUTATED in place (14B pulled, protocol/mac/net
 *    headers mirrored from the temp native), still blob-owned. The temp
 *    native is always dropped here. Returned protocol goes to the blob.
 *  rx/export-refuse: legacy FREED (bcm419_kfree_skb; refuse warns once and
 *    intentionally leaks, never double-frees), NET_RX_DROP returned. This
 *    differs from bcm419_rx_deliver on purpose: 4.19 netif_rx always consumes
 *    (even its error legs free internally), so the blob will never touch the
 *    view again after the call — retaining it would leak silently with no
 *    owner left. A refused free still warns.
 *  rx success: export COPY handed to netif_rx (stack consumes/frees it on
 *    every leg incl. DROP), legacy freed. Blob must not touch it afterwards.
 *
 * cb containment (80B legacy @280 vs 48B native): NO cross-copy in either
 * direction. Import leaves the legacy cb kzalloc-zero for the blob (B1
 * cb_zero or blob's own PKTTAG writes); export of a production RX view
 * (native_meta == NULL) yields a zero native cb for the stack to scribble.
 * The only cb copy is native->native inside skb_copy_header (48B memcpy,
 * net/core/skbuff.c __copy_skb_header) when re-exporting a TX-imported view
 * — same ABI both sides. eth_type_trans touches dev/mac_header/pull/
 * pkt_type/protocol only (net/ethernet/eth.c), never cb. Proven by the
 * RXSPLIT selftest legs below (scribble-each-side + zero checks).
 *
 * protocol/dev: set ONLY by eth_type_trans on the native side at this
 * boundary (export copies the legacy scalar first, trans overwrites it with
 * the parsed ethertype, pkt_type from the dest MAC). mixed_netif_rx performs
 * no parsing — monitor frames keep whatever the blob stored (fresh pool
 * buffers carry zeros, same as stock).
 *
 * recycle/free: shim_skb_free refuses nonzero recycle_flags / live refs /
 * nonlinear (ownership retained + warn). Pool-recycled buffers MUST be
 * tainted (B2, clears PRISTINE at pool checkout, 4.19 BCA lifecycle) and
 * geometry-reset (shim_skb_pool_reset) before reaching RX deliver; anything
 * else fails loud here, never silently laundered. Export-failure legs also
 * feed skb419_report_failure (gated by skb_failure_trace, geometry only, no
 * payload) so HW triage sees WHICH field refused. */
static_assert(sizeof(((struct sk_buff *)0)->cb) == 48);
__be16 bcm419_mixed_eth_type_trans(struct sk_buff *arg, struct net_device *devarg)
{
	struct skb419_view *old = (void *)arg;
	struct netdev419_view *olddev = (void *)devarg;
	struct net_device *dev;
	struct sk_buff *native;
	__be16 protocol;
	if (!shim_skb_is_legacy(arg))
		return eth_type_trans(arg, devarg);
	dev = shim_netdev_native(olddev);
	if (!dev)
		return 0;
	STORE(old, dev, olddev);
	native = shim_skb_export(old, GFP_ATOMIC);
	if (IS_ERR(native)) {
		pr_warn_once("bcm_shim: eth_type_trans export refused %ld\n", PTR_ERR(native));
		return 0;
	}
	if (native->len < ETH_HLEN) {
		dev_kfree_skb_any(native);
		return 0;
	}
	protocol = eth_type_trans(native, dev);
	if (!shim_skb_pull(old, ETH_HLEN)) {
		dev_kfree_skb_any(native);
		return 0;
	}
	skb419_metadata_in(old, native);
	dev_kfree_skb_any(native);
	return protocol;
}
EXPORT_SYMBOL(bcm419_mixed_eth_type_trans);
int bcm419_mixed_netif_rx(struct sk_buff *arg)
{
	struct skb419_view *old = (void *)arg;
	struct sk_buff *native;
	if (!shim_skb_is_legacy(arg))
		return netif_rx(arg);
	native = shim_skb_export(old, GFP_ATOMIC);
	if (IS_ERR(native)) {
		pr_warn_once("bcm_shim: netif_rx export refused %ld\n", PTR_ERR(native));
		skb419_report_failure(old, 0, "netif_rx");
		bcm419_kfree_skb(old);
		return NET_RX_DROP;
	}
	bcm419_kfree_skb(old);
	return netif_rx(native);
}
EXPORT_SYMBOL(bcm419_mixed_netif_rx);

/* --- RXTX S6: RX delivery ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S6. Blob reference: wl_sendup*
 * (12x netif_rx + 11x eth_type_trans call sites, §1): the blob hands the
 * stack a native skb with valid dev/protocol/len and ignores the NET_RX_*
 * return (its stats come from wl_get_stats64, H15 Q2). This wrapper
 * sequences the same three steps over a legacy view: shim_skb_export
 * (419->66 incl. B7 VLAN + H13 metadata), eth_type_trans (pulls the 14B
 * eth header, sets protocol), netif_rx (consumes the native skb).
 * Rename wiring (h30/stage.py --skbdispatch, FACT): blob netif_rx AND
 * netif_rx_ni both resolve to bcm419_mixed_netif_rx above (single-arg
 * shape fits both), eth_type_trans to bcm419_mixed_eth_type_trans.
 * shim_core.c's plain netif_rx_ni forwarder serves native callers only and
 * must never receive a legacy view. Monitor frames arrive here exclusively
 * through the bare mixed_netif_rx leg (no trans), never through this
 * combined Ethernet-only wrapper.
 * trans_start/queue-state note: RX never touches the TX queue; the
 * shared _tx/pcpu_refcnt views asserted here are the shim_netdev ones
 * (H10), verified in the selftest via netdev_get_tx_queue(), never by
 * raw 4.19 offsets (H15 §2 B8 rule). */
int bcm419_rx_deliver(struct skb419_view *old, unsigned int gfp419)
{
	struct sk_buff *native;
	struct net_device *dev;
	u32 len;
	int rc;

	if (!old) {
		shim_warn_once("rx_deliver: NULL skb\n");
		return -EINVAL;
	}
	native = shim_skb_export(old, shim_gfp419(gfp419));
	if (IS_ERR(native)) {
		rc = PTR_ERR(native);
		shim_warn_once("rx_deliver: export refuse %d, retained\n",
			       rc);
		skb419_report_failure(old, 0, "rx_deliver");
		return rc;
	}
	dev = native->dev;
	if (!dev) {
		shim_warn_once("rx_deliver: no dev, dropping\n");
		dev_kfree_skb_any(native);
		shim_skb_free(old);
		return -ENODEV;
	}
	len = native->len;
	if (len < ETH_HLEN) {
		shim_warn_once("rx_deliver: runt %u, dropping\n", len);
		dev_kfree_skb_any(native);
		shim_skb_free(old);
		return -EINVAL;
	}
	/* Sets native->protocol, mac/network headers; consumes nothing. */
	eth_type_trans(native, dev);
	rc = netif_rx(native); /* consumes native */
	if (shim_skb_free(old))
		shim_warn_once("rx_deliver: legacy free refuse\n");
	return rc;
}
EXPORT_SYMBOL(bcm419_rx_deliver);

/* --- RXTX S7: TX entry + queue wake ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S7, spec §5 B8 (partial:
 * full ndo table wiring stays S9; here the import + wake primitives
 * with a mock ndo proving the queue/state path). Blob reference:
 * wl_start (0x30c820, r1 = net_device, priv at +1408) -> wl_xlate_to_skb
 * -> pktq/spktq -> osl_dma_map. trans_start/xmit_lock/carrier are NOT
 * UND: the blob touches them inline through net_device fields, so the
 * selftest asserts the shared queue via netdev_get_tx_queue(), exactly
 * like the H10 selftest. */
struct skb419_view *bcm419_tx_import(struct sk_buff *native,
				     unsigned int gfp419)
{
	struct skb419_view *old;

	if (!native) {
		shim_warn_once("tx_import: NULL native\n");
		return NULL;
	}
	old = shim_skb_import(native, shim_gfp419(gfp419));
	if (IS_ERR(old)) {
		shim_warn_once("tx_import: refuse %ld, native retained\n",
			       PTR_ERR(old));
		return NULL;
	}
	return old;
}
EXPORT_SYMBOL(bcm419_tx_import);

void bcm419_netif_tx_wake_queue(struct netdev419_view *old,
				unsigned int qidx)
{
	struct net_device *dev;
	struct netdev_queue *txq;

	if (!old) {
		shim_warn_once("tx_wake_queue: NULL dev\n");
		return;
	}
	dev = shim_netdev_native(old);
	if (!dev) {
		shim_warn_once("tx_wake_queue: unknown dev\n");
		return;
	}
	if (qidx >= dev->real_num_tx_queues) {
		shim_warn_once("tx_wake_queue: qidx %u >= %u\n", qidx,
			       dev->real_num_tx_queues);
		return;
	}
	txq = netdev_get_tx_queue(dev, qidx);
	netif_tx_wake_queue(txq);
}
EXPORT_SYMBOL(bcm419_netif_tx_wake_queue);

/* --- RXTX EAPOL: WPA-handshake-scoped TX entry (H30 §7) ---
 * Production EAPOL frames travel stack -> netdev419_real_xmit (shim_netdev.c,
 * xmit gate) -> bcm419_tx_import: the installed ndo serves ALL ethertypes
 * once open (ARP/DHCP need the same path right after WPA), so a per-ethertype
 * filter cannot live in the ndo without touching shim_netdev.c — and must
 * not: silently dropping non-EAPOL inside xmit would wedge the qdisc.
 * This wrapper is the auditable EAPOL-only front for S9 bring-up and tests:
 * it proves the exact bytes the 4-way handshake needs survive import, with
 * the same contract as bcm419_tx_import (success consumes the native
 * reference; every refuse retains it and returns NULL).
 * Shape gate (fail-safe, fail-loud): NULL / runt (< ETH_HLEN + 4B 802.1X
 * version/type/length header) / ethertype != 0x888E (ETH_P_PAE) refuse before
 * touching import. The ethertype peek uses skb_copy_bits (frag-safe); a
 * VLAN-tagged EAPOL reads as 0x8100 here and refuses — the AP datapath
 * carries EAPOL untagged, and laundering a tagged frame past the gate by
 * parsing deeper would defeat the scope. GSO/zerocopy/timestamp/unknown-dev
 * refuses come from bcm419_tx_import unchanged (an EAPOL superframe is
 * nonsense; EAPOL is never segmented). gfp419 is the raw 4.19 word
 * (shim_gfp419); the xmit-context pin (0x480020 == GFP_ATOMIC) is asserted
 * by the selftest below, same as the xmit lane's phase A. */
#define BCM419_EAPOL_MIN (ETH_HLEN + 4)
struct skb419_view *bcm419_tx_eapol(struct sk_buff *native,
				    unsigned int gfp419)
{
	struct skb419_view *old;
	__be16 etype = 0;

	if (!native) {
		shim_warn_once("tx_eapol: NULL native\n");
		return NULL;
	}
	if (native->len < BCM419_EAPOL_MIN) {
		shim_warn_once("tx_eapol: runt %u, native retained\n",
			       native->len);
		return NULL;
	}
	if (skb_copy_bits(native, ETH_HLEN - 2, &etype, sizeof(etype)) ||
	    etype != htons(ETH_P_PAE)) {
		shim_warn_once("tx_eapol: not 0x888E, native retained\n");
		return NULL;
	}
	old = bcm419_tx_import(native, gfp419);
	if (!old)
		shim_warn_once("tx_eapol: import refused, native retained\n");
	return old;
}
EXPORT_SYMBOL(bcm419_tx_eapol);

/* --- GSO lane: segmenting TX entry + queue drain ---
 * triaging/shim/skb-gso/REPORT.md §1. Stock 4.19 segmented before wl_start
 * (the wl netdev never advertised GSO, and wl.ko imports no segmenter),
 * so the blob and the radio firmware only ever see MTU-sized frames.
 * Passing a 64K native superframe straight into a legacy view would hand
 * the firmware a TSO descriptor it cannot execute — hence segmentation
 * here, at the boundary, with the native 6.6 engine (not a hand-rolled
 * TCP/IP surgery that would have to track seq/tsval per RFC). features=0
 * means pure software segmentation: checksums are completed into the
 * segments, no HW offload is assumed. Ownership follows the
 * validate_xmit_skb pattern: segmenter failure retains the native
 * reference; success consumes the head (consume_skb) and each segment is
 * consumed by its own shim_skb_import. A non-GSO input with known-only
 * hints takes the plain single-import path (the segmenter may also return
 * NULL for "nothing to split" — same path; a stale-unknown-hint input
 * lands there too and is refused by shim_skb_import with the reference
 * retained). The S7 bcm419_tx_import keeps refusing GSO so its
 * contract (and selftest leg) is unchanged; S9 must call the entry below
 * for any skb that may carry GSO. */
static void skb419_list_append(struct skb419_head *list,
			       struct skb419_view *view,
			       struct skb419_view **tail)
{
	STORE(view, next, (struct skb419_view *)list);
	STORE(view, prev, *tail);
	if (*tail == (struct skb419_view *)list)
		list->next = view;
	else
		STORE(*tail, next, view);
	list->prev = view;
	*tail = view;
	list->qlen++;
}

/* Forward: defined after import_gso (drain is also a public entry). */
void bcm419_skb_queue_drain(struct skb419_head *list);

int shim_skb_import_gso(struct sk_buff *native, gfp_t gfp,
			struct skb419_head *list)
{
	struct sk_buff *segs, *cur, *next;
	struct skb419_view *tail;
	int count = 0;

	if (!native || !list)
		return -EINVAL;
	list->next = list->prev = (struct skb419_view *)list;
	list->qlen = 0;
	list->lock = 0;
	tail = (struct skb419_view *)list;
	if (!skb_is_gso(native) &&
	    !(skb_shinfo(native)->gso_type & ~SKB419_GSO_MASK)) {
		struct skb419_view *one = shim_skb_import(native, gfp);

		if (IS_ERR(one))
			return PTR_ERR(one);
		skb419_list_append(list, one, &tail);
		return 1;
	}
	/* Same entry the stack itself uses (validate_xmit_skb): full engine
	 * incl. frag_list/BY_FRAGS; may return NULL for "nothing to split". */
	segs = skb_gso_segment(native, 0);
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (!segs) {
		struct skb419_view *one = shim_skb_import(native, gfp);

		if (IS_ERR(one))
			return PTR_ERR(one);
		skb419_list_append(list, one, &tail);
		return 1;
	}
	for (cur = segs; cur; cur = next) {
		struct skb419_view *old;

		next = cur->next;
		cur->next = NULL;
		old = shim_skb_import(cur, gfp);
		if (IS_ERR(old)) {
			int ret = PTR_ERR(old);

			cur->next = next;
			kfree_skb_list(cur);
			bcm419_skb_queue_drain(list);
			return ret;
		}
		skb419_list_append(list, old, &tail);
		count++;
	}
	/* Commit ownership only after every segment imported successfully.
	 * Every negative return retains the caller's native reference. */
	consume_skb(native);
	return count;
}

int bcm419_tx_import_gso(struct sk_buff *native, unsigned int gfp419,
			 struct skb419_head *list)
{
	int ret;

	if (!native || !list) {
		shim_warn_once("tx_import_gso: NULL arg\n");
		return -EINVAL;
	}
	ret = shim_skb_import_gso(native, shim_gfp419(gfp419), list);
	if (ret < 0)
		shim_warn_once("tx_import_gso: refuse %d\n", ret);
	return ret;
}
EXPORT_SYMBOL(bcm419_tx_import_gso);

/* Drain a legacy queue filled by shim_skb_import_gso (S9 error legs,
 * selftest teardown). Same safety shape as bcm419_skb_queue_purge: the
 * legacy ticket-lock word is carried, never taken; a refused view warns
 * once and stays owned by the caller (intentional leak, never double
 * free); NULL is a safe no-op. */
void bcm419_skb_queue_drain(struct skb419_head *list)
{
	struct skb419_view *cur, *next;
	void *mark;
	u32 steps, budget;

	if (!list)
		return;
	shim_warn_once("skb_queue_drain: legacy lock not taken, caller serializes\n");
	mark = list;
	cur = list->next;
	budget = list->qlen;
	list->next = list->prev = (struct skb419_view *)list;
	list->qlen = 0;
	steps = 0;
	while (cur && (void *)cur != mark && steps <= budget) {
		LOAD(cur, next, next);
		if (shim_skb_free(cur)) {
			shim_warn_once("skb_queue_drain: refuse, rest retained\n");
			break;
		}
		cur = next;
		steps++;
	}
	if (cur && (void *)cur != mark)
		shim_warn_once("skb_queue_drain: truncated at %u of %u\n",
			       steps, budget);
}
EXPORT_SYMBOL(bcm419_skb_queue_drain);

#if IS_ENABLED(CONFIG_CFG80211)
/* --- RXTX S8: B6 cfg80211-upcall converters ---
 * triaging/shim/rxtx-h15/REPORT.md §6 step S8, spec §5 B6. Direction is
 * the reverse of cfg80211_compat.c (there: 6.6 core -> 419 blob table;
 * here: 419-ABI upcall args -> 6.6 core). Sizes pinned for ARM32 below:
 * the blob reads/writes the 419 layouts, so any drift breaks S9. */
static_assert(sizeof(struct cfg80211_chandef419) == 16);
static_assert(sizeof(struct ssid419) == 33);
static_assert(sizeof(struct fils_resp419) ==
	      sizeof(struct cfg80211_fils_resp_params));
static_assert(offsetof(struct cfg80211_external_auth419, bssid) == 4);
static_assert(offsetof(struct cfg80211_external_auth419, ssid) == 10);
static_assert(offsetof(struct cfg80211_external_auth419, key_mgmt_suite) ==
	      44);
static_assert(offsetof(struct cfg80211_external_auth419, status) == 48);
static_assert(offsetof(struct cfg80211_external_auth419, mld_addr) == 50);
static_assert(sizeof(struct cfg80211_external_auth419) == 56);

static void chandef419_to_native(const struct cfg80211_chandef419 *src,
				 struct cfg80211_chan_def *dst)
{
	dst->chan = src->chan;
	dst->width = src->width;
	dst->center_freq1 = src->center_freq1;
	dst->center_freq2 = src->center_freq2;
	memset(&dst->edmg, 0, sizeof(dst->edmg));
	dst->freq1_offset = 0;
}

static void connect419_to_native(const struct cfg80211_connect_resp419 *src,
				 struct cfg80211_connect_resp_params *dst)
{
	static_assert(sizeof(src->fils) == sizeof(dst->fils));

	memset(dst, 0, sizeof(*dst));
	dst->status = src->status;
	dst->req_ie = src->req_ie;
	dst->req_ie_len = src->req_ie_len;
	dst->resp_ie = src->resp_ie;
	dst->resp_ie_len = src->resp_ie_len;
	memcpy(&dst->fils, &src->fils, sizeof(dst->fils));
	dst->timeout_reason = src->timeout_reason;
	dst->links[0].bssid = src->bssid;
	dst->links[0].bss = src->bss;
	dst->links[0].status = (u16)src->status;
}

static void roam419_to_native(const struct cfg80211_roam_info419 *src,
			      struct cfg80211_roam_info *dst)
{
	static_assert(sizeof(src->fils) == sizeof(dst->fils));

	memset(dst, 0, sizeof(*dst));
	dst->req_ie = src->req_ie;
	dst->req_ie_len = src->req_ie_len;
	dst->resp_ie = src->resp_ie;
	dst->resp_ie_len = src->resp_ie_len;
	memcpy(&dst->fils, &src->fils, sizeof(dst->fils));
	dst->links[0].bssid = src->bssid;
	dst->links[0].bss = src->bss;
	dst->links[0].channel = src->channel;
}

static void extauth419_to_native(const struct cfg80211_external_auth419 *src,
				 struct cfg80211_external_auth_params *dst)
{
	static_assert(sizeof(src->ssid) == sizeof(dst->ssid));

	memset(dst, 0, sizeof(*dst));
	dst->action = src->action;
	memcpy(dst->bssid, src->bssid, ETH_ALEN);
	memcpy(&dst->ssid, &src->ssid, sizeof(dst->ssid));
	dst->key_mgmt_suite = src->key_mgmt_suite;
	dst->status = src->status;
	dst->pmkid = NULL; /* 419 has none; user space treats NULL as absent */
	memcpy(dst->mld_addr, src->mld_addr, ETH_ALEN);
}

static struct net_device *bcm419_cfg80211_dev(struct netdev419_view *old,
					      const char *who)
{
	struct net_device *dev;

	if (!old) {
		shim_warn_once("%s: NULL dev\n", who);
		return NULL;
	}
	dev = shim_netdev_native(old);
	if (!dev)
		shim_warn_once("%s: unknown dev\n", who);
	return dev;
}

/* 4.19 (dev, chandef) -> 6.6 (dev, chandef, link_id=0, punct=0).
 * Sleepable context only (wdev_lock); UND_SYMBOLS §4 item 1. */
void bcm419_cfg80211_ch_switch_notify(struct netdev419_view *old,
				      struct cfg80211_chandef419 *chandef)
{
	struct net_device *dev = bcm419_cfg80211_dev(old, "ch_switch_notify");
	struct cfg80211_chan_def native;

	if (!dev || !chandef) {
		if (!chandef)
			shim_warn_once("ch_switch_notify: NULL chandef\n");
		return;
	}
	if (!chandef->chan) {
		shim_warn_once("ch_switch_notify: NULL channel\n");
		return;
	}
	chandef419_to_native(chandef, &native);
	cfg80211_ch_switch_notify(dev, &native, 0, 0);
}
EXPORT_SYMBOL(bcm419_cfg80211_ch_switch_notify);

/* Flat bssid/bss -> links[0]; UND_SYMBOLS §4 item 3. */
void bcm419_cfg80211_connect_done(struct netdev419_view *old,
				  struct cfg80211_connect_resp419 *params,
				  unsigned int gfp419)
{
	struct net_device *dev = bcm419_cfg80211_dev(old, "connect_done");
	struct cfg80211_connect_resp_params native;

	if (!dev || !params) {
		if (!params)
			shim_warn_once("connect_done: NULL params\n");
		return;
	}
	connect419_to_native(params, &native);
	cfg80211_connect_done(dev, &native, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_cfg80211_connect_done);

/* Flat channel/bssid/bss -> links[0]; UND_SYMBOLS §4 item 4. */
void bcm419_cfg80211_roamed(struct netdev419_view *old,
			    struct cfg80211_roam_info419 *info,
			    unsigned int gfp419)
{
	struct net_device *dev = bcm419_cfg80211_dev(old, "roamed");
	struct cfg80211_roam_info native;

	if (!dev || !info) {
		if (!info)
			shim_warn_once("roamed: NULL info\n");
		return;
	}
	roam419_to_native(info, &native);
	cfg80211_roamed(dev, &native, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_cfg80211_roamed);

/* Short chandef -> zero-extended chandef; UND_SYMBOLS §4 item 5. */
void bcm419_cfg80211_cac_event(struct netdev419_view *old,
			       struct cfg80211_chandef419 *chandef,
			       enum nl80211_radar_event event,
			       unsigned int gfp419)
{
	struct net_device *dev = bcm419_cfg80211_dev(old, "cac_event");
	struct cfg80211_chan_def native;

	if (!dev || !chandef) {
		if (!chandef)
			shim_warn_once("cac_event: NULL chandef\n");
		return;
	}
	if (!chandef->chan) {
		shim_warn_once("cac_event: NULL channel\n");
		return;
	}
	chandef419_to_native(chandef, &native);
	cfg80211_cac_event(dev, &native, event, shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_cfg80211_cac_event);

/* 419 (no pmkid) -> 66 (pmkid=NULL); UND_SYMBOLS §4 item 6. */
int bcm419_cfg80211_external_auth_request(struct netdev419_view *old,
					  struct cfg80211_external_auth419 *params,
					  unsigned int gfp419)
{
	struct net_device *dev = bcm419_cfg80211_dev(old, "external_auth");
	struct cfg80211_external_auth_params native;

	if (!dev)
		return -ENODEV;
	if (!params) {
		shim_warn_once("external_auth: NULL params\n");
		return -EINVAL;
	}
	extauth419_to_native(params, &native);
	return cfg80211_external_auth_request(dev, &native,
					      shim_gfp419(gfp419));
}
EXPORT_SYMBOL(bcm419_cfg80211_external_auth_request);
#endif /* IS_ENABLED(CONFIG_CFG80211) */

/* RXTX S1-S4 selftests: flag-gated like skb_selftest/skb_bridge_selftest
 * (H12/H13 style). HW lane runs them with rxtx_selftest=1; each section
 * below is tagged with its step. Counters must return to baseline. */
static bool rxtx_selftest;
module_param(rxtx_selftest, bool, 0400);
MODULE_PARM_DESC(rxtx_selftest, "Test rxtx S1-S4 legacy datapath adapters");

/* GSO lane selftest: flag-gated like the H12/H13/RXTX gates (HW lane runs
 * it with skb_gso_selftest=1). No hardware touched; all cases use crafted
 * native/legacy buffers and assert counters return to baseline. */
static bool skb_gso_selftest;
module_param(skb_gso_selftest, bool, 0400);
MODULE_PARM_DESC(skb_gso_selftest, "Test GSO/QinQ/secmark conversion and segmentation");

/* Shared TX-sink for the S6/S7 test netdevs: registration requires a
 * native ndo_start_xmit (netdev419_prepare), but RX delivery never calls
 * it. S7 installs its own recording sink; this one just drops. */
static netdev_tx_t rxtx_dummy_sink(struct sk_buff *skb,
				   struct net_device *dev)
{
	(void)dev;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops rxtx_dummy_ops = {
	.ndo_start_xmit = rxtx_dummy_sink,
};

/* Minimal registered ether dev for datapath selftests. The legacy view
 * must carry a valid MAC before register: ether_setup leaves dev_addr
 * all-zero (6.6.93 net/ethernet/eth.c never touches it; dev_addr_init
 * installs a zero entry) and netdev419_initial_view copies those zeros,
 * so netdev419_prepare would reject the view with -EINVAL at its dev_addr
 * gate (shim_netdev.c:409). Stamp the H11-proven locally-administered
 * unicast MAC through the legacy pointer, exactly like
 * netdev419_test_alloc; addr_len is already ETH_ALEN from ether_setup.
 * Test-only poking via measured layout offsets; production views (blob
 * devices) are untouched. Register failures are logged with rc: no more
 * silent -EINVAL (H16 S6 FAIL line=1363 x2). */
static struct netdev419_view *rxtx_test_register(const char *name,
					const struct net_device_ops *ops)
{
	struct netdev419_view *old;
	u8 *addr;
	static const u8 mac[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 1 };
	int rc;

	old = shim_netdev_alloc_ether(0, name, NET_NAME_UNKNOWN, 1, 1);
	if (!old) {
		dev_err(&init_net.loopback_dev->dev,
			"SKB419_RXTX_REG FAIL alloc name=%s\n", name);
		return NULL;
	}
	memcpy(&addr, (u8 *)old + ND419_off_net_device_dev_addr,
	       sizeof(addr));
	if (!addr) {
		dev_err(&init_net.loopback_dev->dev,
			"SKB419_RXTX_REG FAIL null dev_addr name=%s\n", name);
		shim_netdev_free_unregistered(old);
		return NULL;
	}
	memcpy(addr, mac, sizeof(mac));
	rc = shim_netdev_register(old, ops);
	if (rc) {
		dev_err(&init_net.loopback_dev->dev,
			"SKB419_RXTX_REG FAIL register name=%s rc=%d\n",
			name, rc);
		shim_netdev_free_unregistered(old);
		return NULL;
	}
	return old;
}

static void rxtx_test_release(struct netdev419_view *old)
{
	if (!old)
		return;
	if (shim_netdev_native(old)->reg_state == NETREG_REGISTERED)
		shim_netdev_unregister(old);
	if (shim_netdev_native(old))
		shim_netdev_free(old);
}

/* RXTX S6 selftest: mock RX delivery legacy -> native -> stack without
 * the blob. Ethertype 0x88B5 (local experimental, no ptype handler)
 * makes the stack drop deterministically after a successful delivery;
 * the assertion is the NET_RX_SUCCESS return plus intact queue infra. */
static int rxtx_test_s6(void)
{
	struct netdev419_view *old = NULL;
	struct skb419_view *a = NULL;
	struct net_device *dev;
	struct netdev_queue *txq;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	u8 *p;
	int rc;
	int ret = -EINVAL;
#define S6CHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_S6 failed line=%d\n", __LINE__); \
	goto s6out; } } while (0)

	old = rxtx_test_register("rxtx-rx%d", &rxtx_dummy_ops); S6CHECK(old);
	dev = shim_netdev_native(old); S6CHECK(dev);
	/* netif_rx drops when !netif_running (6.6.93 enqueue_to_backlog):
	 * the test dev must be UP. ndo_open is optional in __dev_open
	 * (only called `if (ops->ndo_open)`), so the dummy ops (xmit-only)
	 * is fine; ASSERT_RTNL requires the lock. H18 diagnosis. */
	rtnl_lock();
	rc = dev_open(dev, NULL);
	rtnl_unlock();
	if (rc)
		dev_err(&init_net.loopback_dev->dev,
			"SKB419_RXTX_S6 dev_open failed rc=%d\n", rc);
	S6CHECK(!rc);
	txq = netdev_get_tx_queue(dev, 0); S6CHECK(txq);
	/* Plain frame delivery. */
	a = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); S6CHECK(a);
	p = shim_skb_put(a, 64); S6CHECK(p);
	memset(p, 0x11, 64);
	memcpy(p, dev->dev_addr, ETH_ALEN);
	memcpy(p + ETH_ALEN, dev->dev_addr, ETH_ALEN);
	p[12] = 0x88; p[13] = 0xB5;
	rc = bcm419_rx_deliver(a, 0x6000c0); a = NULL;
	S6CHECK(rc == NET_RX_SUCCESS);
	S6CHECK(netdev_get_tx_queue(dev, 0) == txq);
	(void)READ_ONCE(txq->trans_start);
	/* VLAN-tagged frame delivery (DEI inside, H13 gate). */
	a = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); S6CHECK(a);
	p = shim_skb_put(a, 64); S6CHECK(p);
	memset(p, 0x22, 64);
	memcpy(p, dev->dev_addr, ETH_ALEN);
	memcpy(p + ETH_ALEN, dev->dev_addr, ETH_ALEN);
	p[12] = 0x88; p[13] = 0xB5;
	S6CHECK(!bcm419_vlan_tag_set(a, htons(ETH_P_8021Q), 0xb123));
	rc = bcm419_rx_deliver(a, 0x6000c0); a = NULL;
	S6CHECK(rc == NET_RX_SUCCESS);
	S6CHECK(netdev_get_tx_queue(dev, 0) == txq);
	/* Error legs: NULL, runt, unknown dev (retained). */
	S6CHECK(bcm419_rx_deliver(NULL, 0x6000c0) == -EINVAL);
	a = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); S6CHECK(a);
	p = shim_skb_put(a, 10); S6CHECK(p);
	memset(p, 0x33, 10);
	rc = bcm419_rx_deliver(a, 0x6000c0); a = NULL;
	S6CHECK(rc == -EINVAL);
	a = bcm419_legacy_skb_alloc(128, 0x6000c0); S6CHECK(a);
	S6CHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 64); S6CHECK(p);
	memset(p, 0x44, 64); p[12] = 0x88; p[13] = 0xB5;
	STORE(a, dev, (struct netdev419_view *)0x1234);
	rc = bcm419_rx_deliver(a, 0x6000c0);
	S6CHECK(rc == -EXDEV);
	S6CHECK(!shim_skb_free(a)); a = NULL;
	S6CHECK(atomic_read(&skb419_headers) == headers);
	S6CHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S6 PASS rx-deliver-success runt-exdev-retained queue-shared\n");
	ret = 0;
s6out:
	if (a)
		shim_skb_free(a);
	if (old && shim_netdev_native(old)) {
		/* Mirror the dev_open above: safe no-op if never opened. */
		rtnl_lock();
		dev_close(shim_netdev_native(old));
		rtnl_unlock();
	}
	rxtx_test_release(old);
	return ret;
#undef S6CHECK
}

/* RXTX RXSPLIT selftest (H30 §7 re-verify): the blob's real RX sequences,
 * synthetic, no radio. DATA goes through the paired
 * mixed_eth_type_trans + mixed_netif_rx entries (the wl_sendup* order);
 * MGMT/monitor goes through bare mixed_netif_rx (the audited wl_monitor
 * order — never trans); cb is scribbled on each side to prove containment.
 * Marker: SKB419_RXTX_RXSPLIT PASS. */
static int rxtx_test_rxsplit(void)
{
	struct netdev419_view *old = NULL;
	struct skb419_view *a = NULL, *twin = NULL;
	struct sk_buff *out = NULL;
	struct net_device *dev;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	__be16 proto;
	u8 *p;
	u32 len;
	u8 bytes[64];
	unsigned int i;
	int rc;
	int ret = -EINVAL;
#define RSCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_RXSPLIT failed line=%d\n", __LINE__); \
	goto rsout; } } while (0)

	old = rxtx_test_register("rxtx-rs%d", &rxtx_dummy_ops); RSCHECK(old);
	dev = shim_netdev_native(old); RSCHECK(dev);
	rtnl_lock();
	rc = dev_open(dev, NULL);
	rtnl_unlock();
	RSCHECK(!rc);
	/* DATA: blob pair order (trans then rx) on an Ethernet frame with a
	 * scribbled legacy cb. */
	a = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); RSCHECK(a);
	p = shim_skb_put(a, 64); RSCHECK(p);
	memset(p, 0x11, 64);
	memcpy(p, dev->dev_addr, ETH_ALEN);
	memcpy(p + ETH_ALEN, dev->dev_addr, ETH_ALEN);
	p[12] = 0x88; p[13] = 0xB5;
	memset(a->bytes + OFF(cb), 0xa5, SK419_width_sk_buff_cb);
	proto = bcm419_mixed_eth_type_trans((struct sk_buff *)a,
					    (struct net_device *)old);
	RSCHECK(proto == htons(0x88B5));
	/* HW31 §2: the blob stores the trans return itself (bl trans;
	 * strh r0,[r1] into skb+0x10c — 4 sites in
	 * hw31-prep/eth-type-caller-stores.txt). Native eth_type_trans
	 * returns the ethertype without assigning the caller view and the
	 * wrapper keeps that contract, so the fixture reproduces the
	 * caller-side store before checking the field. */
	STORE(a, protocol, proto);
	LOAD(a, len, len); RSCHECK(len == 50);
	LOAD(a, protocol, proto); RSCHECK(proto == htons(0x88B5));
	rc = bcm419_mixed_netif_rx((struct sk_buff *)a); a = NULL;
	RSCHECK(rc == NET_RX_SUCCESS);
	/* CB containment, legacy -> native: blob scratch never reaches the
	 * stack (production RX views carry no native_meta, cb stays zero). */
	a = bcm419_legacy_skb_alloc(256, 0x6000c0); RSCHECK(a);
	RSCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 22); RSCHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	memset(a->bytes + OFF(cb), 0xa5, SK419_width_sk_buff_cb);
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); RSCHECK(!IS_ERR(out));
	RSCHECK(!memchr_inv(out->cb, 0, sizeof(out->cb)));
	dev_kfree_skb_any(out); out = NULL;
	RSCHECK(!shim_skb_free(a)); a = NULL;
	/* CB containment, native -> legacy: stack scratch never reaches the
	 * blob descriptor (import never copies cb either way). */
	out = alloc_skb(64, GFP_KERNEL); RSCHECK(out);
	skb_reserve(out, 32);
	p = skb_put(out, 22); RSCHECK(p);
	memset(p, 0x5c, 22);
	memset(out->cb, 0xe7, sizeof(out->cb));
	out->dev = NULL;
	{
		struct skb419_view *imp = shim_skb_import(out, GFP_KERNEL);
		RSCHECK(!IS_ERR(imp));
		out = NULL;
		a = imp;
	}
	RSCHECK(!memchr_inv(a->bytes + OFF(cb), 0, SK419_width_sk_buff_cb));
	RSCHECK(!shim_skb_free(a)); a = NULL;
	/* MGMT/monitor: radiotap + 802.11 bytes through bare mixed_netif_rx.
	 * No trans call (matches the audited wl_monitor sequence); export of
	 * the twin proves byte-identity for non-Ethernet shapes. */
	for (i = 0; i < sizeof(bytes); i++)
		bytes[i] = 0x60 + (i & 0x3f);
	bytes[0] = 0x00; bytes[1] = 0x00; /* radiotap it_version/pad */
	bytes[2] = 0x08; bytes[3] = 0x00; /* it_len = 8 */
	bytes[8] = 0x80; bytes[9] = 0x00; /* 802.11 fc: beacon-ish */
	a = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); RSCHECK(a);
	p = shim_skb_put(a, 64); RSCHECK(p);
	memcpy(p, bytes, sizeof(bytes));
	twin = bcm419_legacy_netdev_alloc_skb(old, 64, 0x6000c0); RSCHECK(twin);
	p = shim_skb_put(twin, 64); RSCHECK(p);
	memcpy(p, bytes, sizeof(bytes));
	STORE(twin, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(twin, GFP_KERNEL); RSCHECK(!IS_ERR(out));
	RSCHECK(out->len == 64);
	RSCHECK(!memcmp(out->data, bytes, sizeof(bytes)));
	dev_kfree_skb_any(out); out = NULL;
	RSCHECK(!shim_skb_free(twin)); twin = NULL;
	rc = bcm419_mixed_netif_rx((struct sk_buff *)a); a = NULL;
	RSCHECK(rc == NET_RX_SUCCESS);
	/* Trans-refuse leg keeps blob ownership (miss dev, retained). */
	a = bcm419_legacy_skb_alloc(128, 0x6000c0); RSCHECK(a);
	RSCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 64); RSCHECK(p);
	memset(p, 0x44, 64); p[12] = 0x88; p[13] = 0xB5;
	STORE(a, dev, (struct netdev419_view *)0x1234);
	proto = bcm419_mixed_eth_type_trans((struct sk_buff *)a,
					    (struct net_device *)0x1234);
	RSCHECK(proto == 0);
	LOAD(a, len, len); RSCHECK(len == 64);
	RSCHECK(!shim_skb_free(a)); a = NULL;
	RSCHECK(atomic_read(&skb419_headers) == headers);
	RSCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_RXSPLIT PASS data-pair-protocol-pulled cb-contained-zero monitor-bare-identical trans-refuse-retained\n");
	ret = 0;
rsout:
	if (out)
		dev_kfree_skb_any(out);
	if (twin)
		shim_skb_free(twin);
	if (a)
		shim_skb_free(a);
	if (old && shim_netdev_native(old)) {
		rtnl_lock();
		dev_close(shim_netdev_native(old));
		rtnl_unlock();
	}
	rxtx_test_release(old);
	return ret;
#undef RSCHECK
}

/* RXTX S7 selftest: mock ndo_start_xmit proving the TX-entry path
 * (native -> legacy import + queue/state handling) without the blob.
 * The recording sink captures what the legacy side saw; the wake
 * wrapper is exercised against a really stopped queue. */
static struct {
	bool called;
	u32 len;
	bool vlan_frame;
	u8 first;
} rxtx_tx_got;

static netdev_tx_t rxtx_mock_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	struct skb419_view *old;
	u8 *data;
	u32 len;

	(void)dev;
	rxtx_tx_got.called = true;
	old = bcm419_tx_import(skb, 0x6000c0);
	if (!old) {
		/* Refused: the native reference is retained by contract,
		 * so the mock drops it here like wl_start's error leg. */
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	LOAD(old, len, len);
	LOAD(old, data, data);
	rxtx_tx_got.len = len;
	rxtx_tx_got.first = data[0];
	rxtx_tx_got.vlan_frame = len >= 16 && data[12] == 0x81 &&
				 data[13] == 0;
	shim_skb_free(old);
	return NETDEV_TX_OK;
}

static const struct net_device_ops rxtx_mock_ops = {
	.ndo_start_xmit = rxtx_mock_xmit,
};

static int rxtx_test_s7(void)
{
	struct netdev419_view *old = NULL;
	struct net_device *dev;
	struct netdev_queue *txq;
	struct sk_buff *native = NULL;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	u8 *p;
	int ret = -EINVAL;
#define S7CHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_S7 failed line=%d\n", __LINE__); \
	goto s7out; } } while (0)

	old = rxtx_test_register("rxtx-tx%d", &rxtx_mock_ops); S7CHECK(old);
	dev = shim_netdev_native(old); S7CHECK(dev);
	txq = netdev_get_tx_queue(dev, 0); S7CHECK(txq);
	/* Wake wrapper against a really stopped queue. */
	netif_tx_stop_queue(txq);
	S7CHECK(netif_tx_queue_stopped(txq));
	bcm419_netif_tx_wake_queue(old, 0);
	S7CHECK(!netif_tx_queue_stopped(txq));
	(void)READ_ONCE(txq->trans_start);
	bcm419_netif_tx_wake_queue(NULL, 0);
	bcm419_netif_tx_wake_queue(old, 99);
	S7CHECK(!netif_tx_queue_stopped(txq));
	/* Untagged TX: legacy sees the same 22 bytes. */
	native = alloc_skb(64, GFP_KERNEL); S7CHECK(native);
	skb_reserve(native, 32);
	p = skb_put(native, 22); S7CHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	skb_reset_mac_header(native);
	native->dev = dev;
	memset(&rxtx_tx_got, 0, sizeof(rxtx_tx_got));
	S7CHECK(rxtx_mock_xmit(native, dev) == NETDEV_TX_OK);
	native = NULL;
	S7CHECK(rxtx_tx_got.called && rxtx_tx_got.len == 22 &&
		!rxtx_tx_got.vlan_frame && rxtx_tx_got.first == 0x5c);
	/* vlan_all TX: legacy sees the tag materialized in-frame. */
	native = alloc_skb(64, GFP_KERNEL); S7CHECK(native);
	skb_reserve(native, 32);
	p = skb_put(native, 22); S7CHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	skb_reset_mac_header(native);
	native->dev = dev;
	__vlan_hwaccel_put_tag(native, htons(ETH_P_8021Q), 0xb123);
	memset(&rxtx_tx_got, 0, sizeof(rxtx_tx_got));
	S7CHECK(rxtx_mock_xmit(native, dev) == NETDEV_TX_OK);
	native = NULL;
	S7CHECK(rxtx_tx_got.called && rxtx_tx_got.len == 26 &&
		rxtx_tx_got.vlan_frame && rxtx_tx_got.first == 0x5c);
	S7CHECK(netdev_get_tx_queue(dev, 0) == txq);
	/* Error legs: NULL refuses, GSO refuses with native retained. */
	S7CHECK(!bcm419_tx_import(NULL, 0x6000c0));
	native = alloc_skb(64, GFP_KERNEL); S7CHECK(native);
	p = skb_put(native, 22); S7CHECK(p);
	memset(p, 0x5c, 22);
	skb_shinfo(native)->gso_size = 20;
	S7CHECK(!bcm419_tx_import(native, 0x6000c0));
	S7CHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	S7CHECK(atomic_read(&skb419_headers) == headers);
	S7CHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S7 PASS tx-import-plain-vlan wake-queue null-gso-refused\n");
	ret = 0;
s7out:
	if (native)
		dev_kfree_skb_any(native);
	rxtx_test_release(old);
	return ret;
#undef S7CHECK
}

/* RXTX EAPOL selftest (H30 §7): the WPA-handshake frame class through the
 * EAPOL-scoped entry. The mock side here (bcm419_tx_eapol + the S7 mock
 * consumer shape) is contract-identical to the real ndo
 * (netdev419_real_xmit, shim_netdev.c): the same bcm419_tx_import call,
 * the same refused-retained legs, the same xmit-context GFP word pinned
 * below — the only delta S9 owns is handing `old` to wl_start instead of
 * freeing it here. Marker: SKB419_RXTX_EAPOL PASS. */
static int rxtx_test_eapol(void)
{
	struct netdev419_view *old = NULL;
	struct net_device *dev;
	struct skb419_view *imp = NULL;
	struct sk_buff *native = NULL;
	struct netdev419_view *gotdev;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	u8 *p, *d;
	u32 len;
	int ret = -EINVAL;
#define EACHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_EAPOL failed line=%d\n", __LINE__); \
	goto eaout; } } while (0)

	/* Same xmit-context pin as the xmit lane's phase A: the 4.19 ATOMIC
	 * word must map to non-sleeping native GFP (hard-start-xmit). */
	EACHECK(shim_gfp419(0x480020) == GFP_ATOMIC);
	old = rxtx_test_register("rxtx-ea%d", &rxtx_dummy_ops); EACHECK(old);
	dev = shim_netdev_native(old); EACHECK(dev);
	/* Well-formed EAPOL-Key through the scoped entry with the xmit word:
	 * legacy view carries dev + intact ethertype + full length. */
	native = alloc_skb(128, GFP_KERNEL); EACHECK(native);
	skb_reserve(native, 32);
	p = skb_put(native, 64); EACHECK(p);
	memset(p, 0, 64);
	memcpy(p, dev->dev_addr, ETH_ALEN);
	memcpy(p + ETH_ALEN, dev->dev_addr, ETH_ALEN);
	p[12] = 0x88; p[13] = 0x8E;
	p[14] = 0x02; p[15] = 0x03; p[16] = 0x00; p[17] = 0x5F; /* 802.1X ver/type/len */
	skb_reset_mac_header(native);
	native->dev = dev;
	imp = bcm419_tx_eapol(native, 0x480020);
	EACHECK(imp);
	native = NULL; /* consumed by import */
	LOAD(imp, len, len); EACHECK(len == 64);
	LOAD(imp, data, d); EACHECK(d[12] == 0x88 && d[13] == 0x8E);
	EACHECK(d[14] == 0x02 && d[15] == 0x03);
	LOAD(imp, dev, gotdev); EACHECK(gotdev == old);
	EACHECK(!shim_skb_free(imp)); imp = NULL;
	/* Mock parity: the S7 mock consumer shape handles the same EAPOL
	 * frame identically (import inside, same length/first-byte view) —
	 * the import half of mock and real ndo is one shared function. */
	native = alloc_skb(128, GFP_KERNEL); EACHECK(native);
	skb_reserve(native, 32);
	p = skb_put(native, 64); EACHECK(p);
	memset(p, 0x5c, 64); p[12] = 0x88; p[13] = 0x8E;
	skb_reset_mac_header(native);
	native->dev = dev;
	memset(&rxtx_tx_got, 0, sizeof(rxtx_tx_got));
	EACHECK(rxtx_mock_xmit(native, dev) == NETDEV_TX_OK);
	native = NULL;
	EACHECK(rxtx_tx_got.called && rxtx_tx_got.len == 64 &&
		!rxtx_tx_got.vlan_frame && rxtx_tx_got.first == 0x5c);
	/* Refuse legs: every one retains the native reference (users == 1),
	 * which the caller then drops — same as wl_start's error leg. */
	native = alloc_skb(64, GFP_KERNEL); EACHECK(native);
	p = skb_put(native, 22); EACHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0; /* IPv4, not EAPOL */
	native->dev = dev;
	EACHECK(!bcm419_tx_eapol(native, 0x6000c0));
	EACHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	native = alloc_skb(32, GFP_KERNEL); EACHECK(native);
	p = skb_put(native, 10); EACHECK(p); /* runt */
	memset(p, 0x5c, 10);
	native->dev = dev;
	EACHECK(!bcm419_tx_eapol(native, 0x6000c0));
	EACHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	native = alloc_skb(128, GFP_KERNEL); EACHECK(native);
	p = skb_put(native, 64); EACHECK(p);
	memset(p, 0x5c, 64); p[12] = 0x88; p[13] = 0x8E;
	native->dev = dev;
	skb_shinfo(native)->gso_size = 20; /* EAPOL superframe: nonsense */
	EACHECK(!bcm419_tx_eapol(native, 0x6000c0));
	EACHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	native = alloc_skb(128, GFP_KERNEL); EACHECK(native);
	p = skb_put(native, 64); EACHECK(p);
	memset(p, 0x5c, 64); p[12] = 0x81; p[13] = 0; /* Q-tagged outer */
	p[16] = 0x88; p[17] = 0x8E;
	native->dev = dev;
	EACHECK(!bcm419_tx_eapol(native, 0x6000c0));
	EACHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	native = alloc_skb(128, GFP_KERNEL); EACHECK(native);
	p = skb_put(native, 64); EACHECK(p);
	memset(p, 0x5c, 64); p[12] = 0x88; p[13] = 0x8E;
	p[14] = 0x02; p[15] = 0x03;
	native->dev = init_net.loopback_dev; /* foreign dev */
	EACHECK(!bcm419_tx_eapol(native, 0x6000c0));
	EACHECK(refcount_read(&native->users) == 1);
	dev_kfree_skb_any(native); native = NULL;
	EACHECK(!bcm419_tx_eapol(NULL, 0x6000c0));
	EACHECK(atomic_read(&skb419_headers) == headers);
	EACHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_EAPOL PASS eapol-import-shape nonrunt-gso-tagged-foreign-refused gfp-atomic-pinned mock-parity\n");
	ret = 0;
eaout:
	if (native)
		dev_kfree_skb_any(native);
	if (imp)
		shim_skb_free(imp);
	rxtx_test_release(old);
	return ret;
#undef EACHECK
}

/* RXTX S8 selftest: genl put/parse roundtrip on a private test family
 * (H15 §3: genlmsg_put/nla_put are direct-kernel (a)-names; no shim
 * wrapper needed, only proof they compose) plus B6 translator unit
 * tests. Real unicast needs a user-space listener, so it stays an S9/HW
 * item; event SKBs keep flowing through bcm419___cfg80211_alloc_event_skb
 * (shim_alloc.c, portid=0) with no duplicate here. */
static struct genl_family rxtx_test_family = {
	.hdrsize = 0,
	.name = "bcm419-rxtx",
	.version = 1,
	.maxattr = 2,
	.module = THIS_MODULE,
};

static const struct nla_policy rxtx_test_policy[3] = {
	[1] = { .type = NLA_U32 },
	[2] = { .type = NLA_NUL_STRING, .len = 16 },
};

static int rxtx_test_s8_genl(void)
{
	struct sk_buff *skb = NULL, *tiny = NULL;
	struct nlattr *tb[3];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	void *hdr;
	int attrlen;
	int ret = -EINVAL;
#define S8GCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_S8_GENL failed line=%d\n", __LINE__); \
	goto s8gout; } } while (0)

	skb = nlmsg_new(128, GFP_KERNEL); S8GCHECK(skb);
	hdr = genlmsg_put(skb, 0, 1, &rxtx_test_family, 0, 1); S8GCHECK(hdr);
	S8GCHECK(!nla_put_u32(skb, 1, 0x12345678));
	S8GCHECK(!nla_put_string(skb, 2, "rxtx"));
	genlmsg_end(skb, hdr);
	nlh = nlmsg_hdr(skb);
	gnlh = nlmsg_data(nlh);
	S8GCHECK(gnlh->cmd == 1 && gnlh->version == 1);
	attrlen = nlmsg_attrlen(nlh, GENL_HDRLEN);
	S8GCHECK(!__nla_parse(tb, 2, nlmsg_attrdata(nlh, GENL_HDRLEN),
			      attrlen, rxtx_test_policy,
			      NL_VALIDATE_STRICT, NULL));
	S8GCHECK(tb[1] && nla_get_u32(tb[1]) == 0x12345678);
	S8GCHECK(tb[2] && !nla_strcmp(tb[2], "rxtx"));
	nlmsg_free(skb); skb = NULL;
	/* Error legs: header does not fit, attr does not fit. NOTE: slab
	 * rounds nlmsg_new() up, so a bare nlmsg_new(0) still has hundreds
	 * of tailroom bytes and genlmsg_put would succeed — eat the slack
	 * explicitly to model a true nospace condition (H19 diagnosis). */
	tiny = nlmsg_new(0, GFP_KERNEL); S8GCHECK(tiny);
	skb_put(tiny, skb_tailroom(tiny));
	S8GCHECK(!genlmsg_put(tiny, 0, 1, &rxtx_test_family, 0, 1));
	nlmsg_free(tiny); tiny = NULL;
	tiny = nlmsg_new(64, GFP_KERNEL); S8GCHECK(tiny);
	hdr = genlmsg_put(tiny, 0, 1, &rxtx_test_family, 0, 1); S8GCHECK(hdr);
	/* Same slab class as the header leg (H20 :1638): nlmsg_new(64)
	 * gets rounded up, so the 128 B attr would fit. Eat the rest of
	 * the tailroom after the header to model a true nospace attr. */
	skb_put(tiny, skb_tailroom(tiny));
	{
		u8 big[128];

		memset(big, 0xa5, sizeof(big));
		S8GCHECK(nla_put(tiny, 1, sizeof(big), big));
	}
	genlmsg_cancel(tiny, hdr);
	nlmsg_free(tiny); tiny = NULL;
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S8_GENL PASS put-parse-roundtrip nospace-refused\n");
	ret = 0;
s8gout:
	if (skb)
		nlmsg_free(skb);
	if (tiny)
		nlmsg_free(tiny);
	return ret;
#undef S8GCHECK
}

#if IS_ENABLED(CONFIG_CFG80211)
static int rxtx_test_s8_b6(void)
{
	struct cfg80211_chandef419 c419 = {
		.chan = (struct ieee80211_channel *)0x4190,
		.width = NL80211_CHAN_WIDTH_20,
		.center_freq1 = 2412,
		.center_freq2 = 0,
	};
	struct cfg80211_chan_def c66;
	struct cfg80211_connect_resp419 p419;
	struct cfg80211_connect_resp_params p66;
	struct cfg80211_roam_info419 r419;
	struct cfg80211_roam_info r66;
	struct cfg80211_external_auth419 e419;
	struct cfg80211_external_auth_params e66;
	static const u8 bssid[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 7 };
	static const u8 mld[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 8 };
	int ret = -EINVAL;
#define S8BCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_S8_B6 failed line=%d\n", __LINE__); \
	goto s8bout; } } while (0)

	chandef419_to_native(&c419, &c66);
	S8BCHECK(c66.chan == c419.chan && c66.width == NL80211_CHAN_WIDTH_20 &&
		 c66.center_freq1 == 2412 && c66.center_freq2 == 0 &&
		 c66.edmg.channels == 0 && c66.freq1_offset == 0);
	memset(&p419, 0, sizeof(p419));
	p419.status = 1;
	p419.bssid = bssid;
	p419.bss = (struct cfg80211_bss *)0x4191;
	p419.timeout_reason = NL80211_TIMEOUT_ASSOC;
	connect419_to_native(&p419, &p66);
	S8BCHECK(p66.status == 1 && p66.links[0].bssid == bssid &&
		 p66.links[0].bss == (struct cfg80211_bss *)0x4191 &&
		 p66.links[0].status == 1 && !p66.valid_links &&
		 !p66.ap_mld_addr && !p66.links[1].bssid && !p66.links[1].bss &&
		 p66.timeout_reason == NL80211_TIMEOUT_ASSOC);
	memset(&r419, 0, sizeof(r419));
	r419.channel = (struct ieee80211_channel *)0x4192;
	r419.bssid = bssid;
	roam419_to_native(&r419, &r66);
	S8BCHECK(r66.links[0].channel == r419.channel &&
		 r66.links[0].bssid == bssid && !r66.valid_links &&
		 !r66.ap_mld_addr && !r66.links[0].addr);
	memset(&e419, 0, sizeof(e419));
	e419.action = NL80211_EXTERNAL_AUTH_START;
	memcpy(e419.bssid, bssid, ETH_ALEN);
	memcpy(e419.ssid.ssid, "t", 1);
	e419.ssid.ssid_len = 1;
	e419.key_mgmt_suite = 0xfac04;
	e419.status = 1;
	memcpy(e419.mld_addr, mld, ETH_ALEN);
	extauth419_to_native(&e419, &e66);
	S8BCHECK(e66.action == NL80211_EXTERNAL_AUTH_START &&
		 !memcmp(e66.bssid, bssid, ETH_ALEN) &&
		 e66.ssid.ssid_len == 1 && e66.key_mgmt_suite == 0xfac04 &&
		 e66.status == 1 && !e66.pmkid &&
		 !memcmp(e66.mld_addr, mld, ETH_ALEN));
	/* Wrapper guards: no native call, no crash. */
	bcm419_cfg80211_ch_switch_notify(NULL, NULL);
	bcm419_cfg80211_connect_done(NULL, NULL, 0x6000c0);
	bcm419_cfg80211_roamed(NULL, NULL, 0x6000c0);
	bcm419_cfg80211_cac_event(NULL, NULL, NL80211_RADAR_CAC_FINISHED,
				  0x6000c0);
	S8BCHECK(bcm419_cfg80211_external_auth_request(NULL, NULL,
						       0x6000c0) == -ENODEV);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S8_B6 PASS chandef-links-cac-extauth null-guarded\n");
	ret = 0;
s8bout:
	return ret;
#undef S8BCHECK
}
#endif /* IS_ENABLED(CONFIG_CFG80211) */

static int rxtx_test_s8(void)
{
	int ret = rxtx_test_s8_genl();

	if (ret)
		return ret;
#if IS_ENABLED(CONFIG_CFG80211)
	return rxtx_test_s8_b6();
#else
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S8_B6 SKIP no-cfg80211\n");
	return 0;
#endif
}

/* RXTX S5 selftest: B7 entry points over the H13 DEI gate. Exact TCI
 * 0xb123 carries DEI=1, which the naive (tci & ~PRESENT) translation
 * would lose as 0xa123; the gate must keep it both ways. In-frame
 * 0x8100 must pass through untouched (stack untags it itself). */
static int rxtx_test_s5(void)
{
	struct skb419_view *a = NULL;
	struct sk_buff *native = NULL, *out = NULL;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	__be16 proto;
	u16 tci;
	u8 *p;
	int present;
	int ret = -EINVAL;
#define S5CHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX_S5 failed line=%d\n", __LINE__); \
	goto s5out; } } while (0)
#define S5FREE_OLD(s) do { if (s) { S5CHECK(!shim_skb_free(s)); s = NULL; } } while (0)
#define S5FREE_NATIVE(s) do { if (s) { dev_kfree_skb_any(s); s = NULL; } } while (0)

	a = bcm419_legacy_skb_alloc(256, 0x6000c0); S5CHECK(a);
	S5CHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 22); S5CHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	/* No tag initially; NULL/bad outs refuse. */
	S5CHECK(!bcm419_vlan_tag_present(a));
	S5CHECK(!bcm419_vlan_tag_get(a, &proto, &tci));
	S5CHECK(bcm419_vlan_tag_get(a, NULL, &tci) == -EINVAL);
	S5CHECK(bcm419_vlan_tag_get(a, &proto, NULL) == -EINVAL);
	S5CHECK(bcm419_vlan_tag_get(NULL, &proto, &tci) == -EINVAL);
	S5CHECK(!bcm419_vlan_tag_present(NULL));
	S5CHECK(bcm419_vlan_tag_set(NULL, htons(ETH_P_8021Q), 1) == -EINVAL);
	S5CHECK(bcm419_vlan_tag_set(a, htons(ETH_P_IP), 1) == -EINVAL);
	bcm419_vlan_tag_clear(NULL);
	/* Set DEI-carrying tag, read back intact. */
	S5CHECK(!bcm419_vlan_tag_set(a, htons(ETH_P_8021Q), 0xb123));
	S5CHECK(bcm419_vlan_tag_present(a));
	present = bcm419_vlan_tag_get(a, &proto, &tci);
	S5CHECK(present == 1 && proto == htons(ETH_P_8021Q) && tci == 0xb123);
	/* Export: native hwaccel tag keeps DEI, frame stays untagged. */
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); S5CHECK(!IS_ERR(out));
	S5CHECK(skb_vlan_tag_present(out) && out->vlan_tci == 0xb123);
	S5CHECK(out->len == 22 && out->data[12] == 8 && out->data[13] == 0);
	S5FREE_NATIVE(out);
	/* Clear removes both words. */
	bcm419_vlan_tag_clear(a);
	S5CHECK(!bcm419_vlan_tag_present(a));
	S5CHECK(!bcm419_vlan_tag_get(a, &proto, &tci));
	S5FREE_OLD(a);
	/* In-frame 0x8100 with no hwaccel tag passes through untouched. */
	a = bcm419_legacy_skb_alloc(256, 0x6000c0); S5CHECK(a);
	S5CHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 26); S5CHECK(p);
	memset(p, 0x5c, 26); p[12] = 0x81; p[13] = 0; p[16] = 8; p[17] = 0;
	S5CHECK(!bcm419_vlan_tag_present(a));
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); S5CHECK(!IS_ERR(out));
	S5CHECK(!skb_vlan_tag_present(out) && out->len == 26);
	S5CHECK(out->data[12] == 0x81 && out->data[13] == 0);
	S5FREE_NATIVE(out);
	S5FREE_OLD(a);
	/* Native tagged -> import materializes; legacy hwaccel tag stays clear. */
	native = alloc_skb(22, GFP_KERNEL); S5CHECK(native);
	p = skb_put(native, 22); memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	skb_reset_mac_header(native);
	__vlan_hwaccel_put_tag(native, htons(ETH_P_8021Q), 0xb123);
	{
		struct skb419_view *imp = shim_skb_import(native, GFP_KERNEL);
		S5CHECK(!IS_ERR(imp));
		native = NULL;
		a = imp;
	}
	S5CHECK(!bcm419_vlan_tag_present(a));
	LOAD(a, data, p); S5CHECK(p[12] == 0x81 && p[13] == 0);
	S5CHECK((p[14] & 0x10) == 0x10); /* DEI bit kept in frame */
	S5FREE_OLD(a);
	S5CHECK(atomic_read(&skb419_headers) == headers);
	S5CHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S5 PASS vlan-dei-roundtrip in-frame-untouched bad-proto-refused\n");
	ret = 0;
s5out:
	S5FREE_NATIVE(out);
	S5FREE_NATIVE(native);
	if (a)
		shim_skb_free(a);
	return ret;
#undef S5FREE_NATIVE
#undef S5FREE_OLD
#undef S5CHECK
}

static int skb419_run_rxtx_test(void)
{
	struct skb419_view *a = NULL, *b = NULL, *c = NULL;
	struct netdev419_view *olddev = NULL;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	u8 *p;
	u32 i;
	int ret = -EINVAL;
#define TCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_RXTX failed line=%d\n", __LINE__); \
	goto out; } } while (0)
#define TDROP(ptr) do { TCHECK(!shim_skb_free(ptr)); (ptr) = NULL; } while (0)

	/* S1: GFP419 vectors (same as shim_alloc_init asserts) through the
	 * legacy allocators; __GFP_ZERO must reach the legacy data area. */
	a = bcm419_legacy_skb_alloc(128, 0x6000c0); TCHECK(a);
	b = bcm419_legacy_skb_clone(a, 0x488020); TCHECK(b);
	c = bcm419_legacy_skb_copy(a, 0x6080c0); TCHECK(c);
	p = shim_skb_put(c, 64); TCHECK(p);
	for (i = 0; i < 64; i++) TCHECK(p[i] == 0);
	TCHECK(!bcm419_legacy_skb_clone(NULL, 0x6000c0));
	TCHECK(!bcm419_legacy_skb_copy(NULL, 0x6000c0));
	TDROP(a); TDROP(b); TDROP(c);
	/* S1: monitor-style netdev alloc: empty, padded, dev stored. */
	olddev = shim_netdev_alloc_ether(0, "rxtx-t1", NET_NAME_UNKNOWN, 1, 1);
	TCHECK(olddev);
	a = bcm419_legacy_netdev_alloc_skb(olddev, 64, 0x6000c0); TCHECK(a);
	{
		struct netdev419_view *gotdev;
		u8 *head, *data;
		u32 len;
		LOAD(a, len, len); TCHECK(len == 0);
		LOAD(a, head, head); LOAD(a, data, data);
		TCHECK(data - head == NET_SKB_PAD);
		LOAD(a, dev, gotdev); TCHECK(gotdev == olddev);
	}
	p = shim_skb_put(a, 64); TCHECK(p);
	TDROP(a);
	TCHECK(!shim_netdev_free_unregistered(olddev)); olddev = NULL;
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S1 PASS gfp419-alloc-clone-copy-zero netdev-pad\n");

	/* S2: cb_zero clears the full measured cb + WLAN ext; NULL is safe. */
	a = bcm419_legacy_skb_alloc(128, 0x6000c0); TCHECK(a);
	memset(a->bytes + SK419_off_sk_buff_cb, 0xa5, SK419_width_sk_buff_cb);
	memset(a->bytes + SK419_off_sk_buff_bcm_ext + SK419_off_bcm_skb_ext_wlan,
	       0x5a, SK419_width_bcm_skb_ext_wlan);
	bcm419_skb_cb_zero(a);
	TCHECK(!memchr_inv(a->bytes + SK419_off_sk_buff_cb, 0,
			   SK419_width_sk_buff_cb));
	TCHECK(!memchr_inv(a->bytes + SK419_off_sk_buff_bcm_ext +
			   SK419_off_bcm_skb_ext_wlan, 0,
			   SK419_width_bcm_skb_ext_wlan));
	bcm419_skb_cb_zero(NULL);
	/* S2: taint clears PRISTINE + dirty_p, keeps residue visible. */
	{
		u32 recycle = SKB419_BPM_PRISTINE;
		u8 *shinfo = skb419_shinfo(skb419_entry(a));
		STORE(a, recycle_flags, recycle);
		memset(shinfo + SK419_off_skb_shared_info_dirty_p, 0x77,
		       SK419_width_skb_shared_info_dirty_p);
		bcm419_skb_bpm_tainted(a);
		LOAD(a, recycle_flags, recycle); TCHECK(recycle == 0);
		TCHECK(!memchr_inv(shinfo + SK419_off_skb_shared_info_dirty_p,
				   0, SK419_width_skb_shared_info_dirty_p));
		recycle = SKB419_BPM_PRISTINE | 0x40u;
		STORE(a, recycle_flags, recycle);
		bcm419_skb_bpm_tainted(a);
		LOAD(a, recycle_flags, recycle); TCHECK(recycle == 0x40u);
		recycle = 0;
		STORE(a, recycle_flags, recycle);
	}
	bcm419_skb_bpm_tainted(NULL);
	TDROP(a);
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S2 PASS cb80-wlan24-zero taint-pristine\n");

	/* S3: NULL-safe frees; destructor fires exactly once per wrapper. */
	rxtx_destructors = 0; rxtx_wrong = false; rxtx_expected = NULL;
	bcm419_kfree_skb(NULL);
	bcm419_consume_skb(NULL);
	bcm419___dev_kfree_skb_any(NULL, SKB_DROP_REASON_NOT_SPECIFIED);
	bcm419_skb_queue_purge(NULL);
	bcm419_dev_kfree_skb_thread_bulk(NULL, NULL, 0);
	{
		void (*destructor)(struct skb419_view *) = rxtx_test_destructor;
		struct skb419_head q;
		struct skb419_view *m = NULL, *tail = NULL;
		unsigned int n;

		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		STORE(a, destructor, destructor); rxtx_expected = a;
		bcm419_kfree_skb(a); a = NULL;
		TCHECK(rxtx_destructors == 1 && !rxtx_wrong);
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		STORE(a, destructor, destructor); rxtx_expected = a;
		bcm419_consume_skb(a); a = NULL;
		TCHECK(rxtx_destructors == 2 && !rxtx_wrong);
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		STORE(a, destructor, destructor); rxtx_expected = a;
		bcm419___dev_kfree_skb_any(a, SKB_DROP_REASON_NOT_SPECIFIED);
		a = NULL;
		TCHECK(rxtx_destructors == 3 && !rxtx_wrong);
		/* S3: purge splices 3, re-inits the head, counters back. */
		rxtx_expected = NULL;
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		m = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(m);
		tail = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(tail);
		STORE(a, destructor, destructor);
		STORE(m, destructor, destructor);
		STORE(tail, destructor, destructor);
		STORE(a, next, m); STORE(m, next, tail);
		STORE(tail, next, (struct skb419_view *)&q);
		q.next = a; q.prev = tail; q.qlen = 3; q.lock = 0;
		n = rxtx_destructors;
		bcm419_skb_queue_purge(&q);
		a = m = tail = NULL;
		TCHECK(rxtx_destructors == n + 3 && !rxtx_wrong);
		TCHECK((void *)q.next == (void *)&q &&
		       (void *)q.prev == (void *)&q && q.qlen == 0);
		/* S3: bulk frees head..tail with an exact count. */
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		m = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(m);
		tail = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(tail);
		STORE(a, destructor, destructor);
		STORE(m, destructor, destructor);
		STORE(tail, destructor, destructor);
		STORE(a, next, m); STORE(m, next, tail);
		n = rxtx_destructors;
		bcm419_dev_kfree_skb_thread_bulk(a, tail, 3);
		a = m = tail = NULL;
		TCHECK(rxtx_destructors == n + 3 && !rxtx_wrong);
		/* S3: shared head is retained (no destructor), then freed. */
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		STORE(a, destructor, destructor);
		refcount_inc(skb419_users(a));
		n = rxtx_destructors;
		bcm419_dev_kfree_skb_thread_bulk(a, a, 1);
		TCHECK(rxtx_destructors == n && !skb419_validate(a));
		TDROP(a);
		TCHECK(rxtx_destructors == n + 1 && !rxtx_wrong);
		/* S3: count mismatch still frees the walked segment. */
		a = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(a);
		m = bcm419_legacy_skb_alloc(64, 0x6000c0); TCHECK(m);
		STORE(a, next, m);
		STORE(m, next, (struct skb419_view *)NULL);
		STORE(m, destructor, destructor);
		STORE(a, destructor, destructor);
		n = rxtx_destructors;
		bcm419_dev_kfree_skb_thread_bulk(a, m, 5);
		a = m = NULL;
		TCHECK(rxtx_destructors == n + 2 && !rxtx_wrong);
	}
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S3 PASS null-safe destructor-once purge-3 bulk-3 shared-retain\n");

	/* S4: datapath manipulation through the bcm419_ names, exact bytes. */
	a = bcm419_legacy_skb_alloc(256, 0x6000c0); TCHECK(a);
	TCHECK(!shim_skb_reserve(a, 64));
	p = bcm419_skb_put(a, 32); TCHECK(p);
	for (i = 0; i < 32; i++) p[i] = i;
	p = bcm419_skb_push(a, 8); TCHECK(p);
	memset(p, 0xa6, 8);
	p = bcm419_skb_put(a, 7); TCHECK(p);
	memset(p, 0xb7, 7);
	p = bcm419_skb_pull(a, 3); TCHECK(p);
	TCHECK(p[0] == 0xa6 && p[5] == 0);
	bcm419_skb_trim(a, 42);
	TCHECK(!bcm419____pskb_trim(a, 42));
	{
		u8 *data;
		u32 len;
		LOAD(a, len, len); TCHECK(len == 42);
		LOAD(a, data, data);
		for (i = 0; i < 5; i++) TCHECK(data[i] == 0xa6);
		for (i = 0; i < 32; i++) TCHECK(data[5 + i] == i);
		for (i = 37; i < 42; i++) TCHECK(data[i] == 0xb7);
	}
	/* S4: bounds degrade to NULL/no-op/errno, NULL is safe. */
	TCHECK(!bcm419_skb_put(a, UINT_MAX));
	TCHECK(!bcm419_skb_push(a, UINT_MAX));
	TCHECK(!bcm419_skb_pull(a, UINT_MAX));
	TCHECK(!bcm419_skb_pull(a, 43));
	bcm419_skb_trim(a, UINT_MAX);
	{
		u32 len;
		LOAD(a, len, len); TCHECK(len == 42);
	}
	TCHECK(!bcm419_skb_put(NULL, 8));
	TCHECK(!bcm419_skb_push(NULL, 8));
	TCHECK(!bcm419_skb_pull(NULL, 8));
	bcm419_skb_trim(NULL, 8);
	TCHECK(bcm419____pskb_trim(NULL, 8) == -EINVAL);
	/* S4: shared headers refuse mutation, recover after release. */
	refcount_inc(skb419_users(a));
	TCHECK(!bcm419_skb_push(a, 1));
	TCHECK(bcm419____pskb_trim(a, 1) == -EBUSY);
	refcount_dec(skb419_users(a));
	p = bcm419_skb_push(a, 1); TCHECK(p);
	TCHECK(!bcm419____pskb_trim(a, 43));
	TDROP(a);
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_RXTX_S4 PASS exact-bytes bounds-null shared-ebusy\n");

	/* S5: B7 VLAN entry points (own function above, same gate). */
	TCHECK(!rxtx_test_s5());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);

	/* S6: mock RX delivery on a registered test netdev. */
	TCHECK(!rxtx_test_s6());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);

	/* S7: mock TX entry + queue wake. */
	TCHECK(!rxtx_test_s7());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);

	/* RXSPLIT (H30 §7): blob RX sequences synthetic — data pair,
	 * cb containment both ways, monitor bare passthrough. */
	TCHECK(!rxtx_test_rxsplit());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);

	/* EAPOL (H30 §7): handshake frame class, mock side of the real ndo. */
	TCHECK(!rxtx_test_eapol());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);

	/* S8: genl roundtrip + B6 converters. */
	TCHECK(!rxtx_test_s8());
	TCHECK(atomic_read(&skb419_headers) == headers);
	TCHECK(atomic_read(&skb419_buffers) == buffers);
	ret = 0;
out:
	if (a) shim_skb_free(a);
	if (b) shim_skb_free(b);
	if (c) shim_skb_free(c);
	if (olddev) shim_netdev_free_unregistered(olddev);
	return ret;
#undef TDROP
#undef TCHECK
}

/* This function was compiled against STOCK headers; its independent field
 * accesses and skb_cloned/header_cloned calculations are the ABI oracle. */
extern unsigned int skb419_legacy_fixture(struct skb419_view *, unsigned int);
static unsigned int skb419_destructors;
static struct skb419_view *skb419_expected_destructor;
static bool skb419_wrong_destructor;
static void skb419_test_destructor(struct skb419_view *skb)
{
	skb419_destructors++;
	if (skb != skb419_expected_destructor)
		skb419_wrong_destructor = true;
}

static int skb419_run_selftest(void)
{
	struct skb419_view *a = NULL, *b = NULL, *c = NULL;
	u8 *adata, *bdata, *cdata, *tail, *wrong;
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	void (*destructor)(struct skb419_view *) = skb419_test_destructor;
	int ret = -EINVAL;
	u16 hdrlen;
#define REQUIRE(test) do { if (!(test)) { \
	ret = -EINVAL; dev_err(&init_net.loopback_dev->dev, "SKB419_SELFTEST failed line=%d\n", __LINE__); \
	goto out; } } while (0)
#define DROP(p) do { int _rc = shim_skb_free(p); REQUIRE(!_rc); (p) = NULL; } while (0)
	skb419_destructors = 0;
	skb419_wrong_destructor = false;
	REQUIRE(!shim_skb_alloc(UINT_MAX, GFP_KERNEL));
	a = shim_skb_alloc(0, GFP_KERNEL); REQUIRE(a); DROP(a);
	{
		struct skb419_view saved;
		unsigned int i;
		u8 *head;
		u32 used;
		a = shim_skb_alloc(2112, GFP_KERNEL); REQUIRE(a);
		REQUIRE(!shim_skb_reserve(a, 64));
		REQUIRE(shim_skb_put(a, 2048));
		LOAD(a, head, head);
		for (i = 0; i < 100; i++) {
			REQUIRE(shim_skb_pull(a, 216));
			REQUIRE(!shim_skb_pool_reset(a, 64, 2048));
			LOAD(a, data, adata); LOAD(a, tail, tail); LOAD(a, len, used);
			REQUIRE(adata == head + 64 && tail == head + 2112 && used == 2048);
		}
		saved = *a;
		REQUIRE(shim_skb_pool_reset(a, 64, 2049) == -ENOSPC);
		REQUIRE(shim_skb_pool_reset(a, UINT_MAX, 2048) == -ENOSPC);
		REQUIRE(!memcmp(&saved, a, sizeof(saved)));
		b = shim_skb_clone(a, GFP_KERNEL); REQUIRE(b);
		saved = *a;
		REQUIRE(shim_skb_pool_reset(a, 64, 2048) == -EBUSY);
		REQUIRE(!memcmp(&saved, a, sizeof(saved)));
		DROP(b); DROP(a);
		pr_info("SKB419_POOL_RESET PASS cycles=100 bounds=2 shared-refused=1\n");
	}
	a = shim_skb_alloc(257, GFP_KERNEL); REQUIRE(a);
	REQUIRE(!skb419_legacy_fixture(a, 0));
	REQUIRE(!skb419_legacy_fixture(a, 1));
	REQUIRE(!skb419_validate(a));
	REQUIRE(skb419_legacy_fixture(a, 3) == 2);
	REQUIRE(!shim_skb_free(a)); /* retained descriptor reference */
	REQUIRE(refcount_read(skb419_users(a)) == 1);
	STORE(a, destructor, destructor);
	skb419_expected_destructor = a;
	b = shim_skb_clone(a, GFP_KERNEL); REQUIRE(b);
	c = shim_skb_copy(a, GFP_KERNEL); REQUIRE(c);
	REQUIRE(!skb419_legacy_fixture(b, 1) && !skb419_legacy_fixture(c, 1));
	REQUIRE(skb419_legacy_fixture(a, 4) == 3);
	REQUIRE(skb419_legacy_fixture(b, 4) == 3);
	REQUIRE(skb419_legacy_fixture(c, 4) == 0);
	LOAD(a, data, adata); LOAD(b, data, bdata); LOAD(c, data, cdata);
	REQUIRE(adata == bdata && cdata != adata);
	bdata[0] ^= 0xff;
	REQUIRE(adata[0] == bdata[0] && cdata[0] == 0x5a);
	bdata[0] ^= 0xff;
	REQUIRE(atomic_read(&skb419_headers) == headers + 3);
	REQUIRE(atomic_read(&skb419_buffers) == buffers + 2);
	DROP(a);
	REQUIRE(skb419_destructors == 1 && !skb419_wrong_destructor);
	REQUIRE(!skb419_legacy_fixture(b, 1));
	REQUIRE(!skb419_legacy_fixture(b, 4));
	DROP(b); DROP(c);
	REQUIRE(skb419_destructors == 1);

	/* Old headerless payload references use high 16 bits in dataref. */
	a = shim_skb_alloc(256, GFP_KERNEL); REQUIRE(a);
	REQUIRE(!skb419_legacy_fixture(a, 0));
	REQUIRE(!skb419_legacy_fixture(a, 2));
	b = shim_skb_clone(a, GFP_KERNEL); REQUIRE(b);
	REQUIRE(atomic_read(skb419_dataref(skb419_entry(a))) == 0x10002);
	LOAD(b, hdr_len, hdrlen); REQUIRE(hdrlen == 64);
	REQUIRE(skb419_legacy_fixture(a, 4) == 1);
	REQUIRE(skb419_legacy_fixture(b, 4) == 1);
	DROP(a);
	REQUIRE(atomic_read(skb419_dataref(skb419_entry(b))) == 1);
	REQUIRE(!skb419_legacy_fixture(b, 1)); DROP(b);
	/* Reverse destruction order: clone first, payload owner last. */
	a = shim_skb_alloc(256, GFP_KERNEL); REQUIRE(a);
	REQUIRE(!skb419_legacy_fixture(a, 0));
	REQUIRE(!skb419_legacy_fixture(a, 2));
	b = shim_skb_clone(a, GFP_KERNEL); REQUIRE(b);
	DROP(b);
	REQUIRE(atomic_read(skb419_dataref(skb419_entry(a))) == 0x10001);
	DROP(a);

	/* Unsupported state is rejected with descriptor ownership retained. */
	a = shim_skb_alloc(256, GFP_KERNEL); REQUIRE(a);
	REQUIRE(!skb419_legacy_fixture(a, 0));
	skb419_shinfo(skb419_entry(a))[SK419_off_skb_shared_info_nr_frags] = 1;
	ret = shim_skb_free(a);
	skb419_shinfo(skb419_entry(a))[SK419_off_skb_shared_info_nr_frags] = 0;
	REQUIRE(ret == -EOPNOTSUPP);
	REQUIRE(refcount_read(skb419_users(a)) == 1);
	LOAD(a, tail, tail); wrong = tail + 1; STORE(a, tail, wrong);
	ret = shim_skb_free(a); STORE(a, tail, tail);
	REQUIRE(ret == -EINVAL);
	REQUIRE(refcount_read(skb419_users(a)) == 1);
	DROP(a);
	REQUIRE(atomic_read(&skb419_headers) == headers);
	REQUIRE(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_SELFTEST PASS old-header-fixture shared-clone copy users payload-ref guards cleanup\n");
	ret = 0;
out:
	if (a) shim_skb_free(a);
	if (b) shim_skb_free(b);
	if (c) shim_skb_free(c);
	return ret;
#undef DROP
#undef REQUIRE
}

/* Test implementation included by shim_skb.c; native and stock-header oracles. */
extern unsigned int skb419_bridge_legacy_fixture(struct skb419_view *, unsigned int);
static unsigned int bridge_destructors;
static struct sk_buff *bridge_expected_owner;
static bool bridge_wrong_owner;
static void skb419_native_test_destructor(struct sk_buff *skb)
{
	bridge_destructors++;
	if (skb != bridge_expected_owner)
		bridge_wrong_owner = true;
}

static int skb419_run_bridge_test(void)
{
	struct sk_buff *src = NULL, *child = NULL, *out = NULL;
	struct skb419_view *a = NULL, *b = NULL, *c = NULL, *error;
	struct netdev419_view *olddev = NULL, *saved_dev;
	struct net_device *dev;
	struct page *page = NULL;
	u8 expected[128], *p;
	u32 len;
	unsigned int i, baseline_h = atomic_read(&skb419_headers);
	unsigned int baseline_b = atomic_read(&skb419_buffers);
	int ret = -EINVAL;
#define CHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_BRIDGE failed line=%d\n", __LINE__); \
	goto done; } } while (0)
#define IMPORT(s,d) do { error = shim_skb_import(s, GFP_KERNEL); \
	CHECK(!IS_ERR(error)); d = error; s = NULL; } while (0)
#define EXPORT(s) do { struct sk_buff *_out = shim_skb_export(s, GFP_KERNEL); \
	CHECK(!IS_ERR(_out)); out = _out; } while (0)
#define FREE_OLD(s) do { CHECK(!shim_skb_free(s)); s = NULL; } while (0)
#define FREE_NATIVE(s) do { dev_kfree_skb_any(s); s = NULL; } while (0)
	bridge_destructors = 0; bridge_wrong_owner = false;
	olddev = shim_netdev_alloc_ether(0, "h13packet", NET_NAME_UNKNOWN, 1, 1);
	CHECK(olddev); dev = shim_netdev_native(olddev); CHECK(dev);
	src = alloc_skb(128, GFP_KERNEL); CHECK(src);
	skb_reserve(src, 64); p = skb_put(src, 26);
	for (i = 0; i < 26; i++) p[i] = i;
	p[12] = 8; p[13] = 0;
	page = alloc_page(GFP_KERNEL); CHECK(page);
	for (i = 0; i < 64; i++) ((u8 *)page_address(page))[19+i] = 0x40+i;
	get_page(page); /* fixture holds one reference; skb takes the other */
	skb_add_rx_frag(src, 0, page, 19, 64, PAGE_SIZE);
	child = alloc_skb(15, GFP_KERNEL); CHECK(child);
	p = skb_put(child, 15); for (i = 0; i < 15; i++) p[i] = 0xe0+i;
	skb_shinfo(src)->frag_list = child;
	src->len += child->len; src->data_len += child->len; src->truesize += child->truesize;
	child = NULL;
	CHECK(src->len == 105 && skb_is_nonlinear(src));
	CHECK(!skb_copy_bits(src, 0, expected, 105));
	src->dev = dev; src->protocol = htons(ETH_P_IP); src->mac_len = ETH_HLEN;
	skb_reset_mac_header(src); skb_set_network_header(src, 14); skb_set_transport_header(src, 34);
	src->mark = 0x13579bdf; src->priority = 5; src->hash = 0x89abcdef;
	src->ip_summed = CHECKSUM_COMPLETE; src->csum_level = 2; src->csum_valid = 1;
	src->encapsulation = 1; src->encap_hdr_csum = 1; src->no_fcs = 1; src->sw_hash = 1;
	src->pkt_type = PACKET_MULTICAST; src->tstamp = 123456789;
	src->queue_mapping = 2; src->csum = (__force __wsum)0x12345678;
	memset(src->cb, 0xe7, sizeof(src->cb));
	src->destructor = skb419_native_test_destructor; bridge_expected_owner = src;
	IMPORT(src, a);
	CHECK(!bridge_destructors && page_ref_count(page) == 2);
	CHECK(!skb419_bridge_legacy_fixture(a, 0));
	LOAD(a, data, p); CHECK(!memcmp(p, expected, 105));
	CHECK(!skb419_bridge_legacy_fixture(a, 1));
	memset(a->bytes + OFF(cb), 0x22, SK419_width_sk_buff_cb);
	EXPORT(a);
	CHECK(out->dev == dev && !skb_is_nonlinear(out) && out->len == 105);
	CHECK(!memcmp(out->data, expected, 105));
	CHECK(out->mark == 0x2468ace0 && out->priority == 2 && out->hash == 0x89abcdef);
	CHECK(out->ip_summed == CHECKSUM_PARTIAL && out->csum_start == 98 && out->csum_offset == 6);
	CHECK(out->csum_level == 1 && !out->csum_valid && !out->encapsulation && !out->no_fcs);
	CHECK(out->queue_mapping == 2 && out->tstamp == 123456789 && out->mac_len == ETH_HLEN);
	for (i = 0; i < sizeof(out->cb); i++) CHECK((u8)out->cb[i] == 0xe7);
	FREE_NATIVE(out);
	b = shim_skb_clone(a, GFP_KERNEL); c = shim_skb_copy(a, GFP_KERNEL); CHECK(b && c);
	FREE_OLD(a);
	CHECK(bridge_destructors == 1 && !bridge_wrong_owner && page_ref_count(page) == 1);
	EXPORT(b); CHECK(!memcmp(out->data, expected, 105)); FREE_NATIVE(out);
	EXPORT(c); CHECK(!memcmp(out->data, expected, 105)); FREE_NATIVE(out);
	FREE_OLD(b); FREE_OLD(c); CHECK(bridge_destructors == 1);
	put_page(page); page = NULL;

	/* Native tagged VLAN includes DEI=1, which old vlan_tci cannot represent
	 * separately from presence. Materialize once into Ethernet bytes. */
	src = alloc_skb(22, GFP_KERNEL); CHECK(src);
	p = skb_put(src, 22); memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	skb_reset_mac_header(src); skb_set_network_header(src, 14);
	src->dev = dev; src->protocol = htons(ETH_P_IP); src->mac_len = ETH_HLEN;
	__vlan_hwaccel_put_tag(src, htons(ETH_P_8021Q), 0xb123);
	src->destructor = skb419_native_test_destructor; bridge_expected_owner = src;
	IMPORT(src, a); CHECK(!skb419_bridge_legacy_fixture(a, 2));
	EXPORT(a); CHECK(!skb_vlan_tag_present(out) && out->protocol == htons(ETH_P_8021Q));
	CHECK(out->len == 26 && out->mac_len == 18 && out->data[14] == 0xb1 && out->data[15] == 0x23);
	CHECK(out->data[12] == 0x81 && out->data[13] == 0 && (out->data[14] & 0x10) == 0x10);
	FREE_NATIVE(out); FREE_OLD(a); CHECK(bridge_destructors == 2 && !bridge_wrong_owner);

	/* Legacy→native VLAN gate: 4.19 PRESENT + BCA cfi_save must yield a
	 * native hwaccel tag with the DEI bit intact; the frame stays untagged
	 * with the inner ethertype back at bytes 12-13. */
	a = shim_skb_alloc(256, GFP_KERNEL); CHECK(a);
	CHECK(!shim_skb_reserve(a, 64)); p = shim_skb_put(a, 22); CHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	CHECK(!skb419_bridge_legacy_fixture(a, 3));
	CHECK(skb419_bridge_legacy_fixture(a, 4) == SKMETA_offset_bcm_ext_vlan_cfi_save);
	CHECK(skb419_bridge_legacy_fixture(a, 5) == 4);
	LOAD(a, data, p); CHECK(p[12] == 8 && p[13] == 0);
	STORE(a, dev, olddev);
	EXPORT(a);
	CHECK(skb_vlan_tag_present(out) && out->vlan_proto == htons(ETH_P_8021Q));
	CHECK(out->vlan_tci == 0xb123 && skb_vlan_tag_get(out) == 0xb123);
	CHECK((out->vlan_tci & 0x1000) && (out->vlan_tci & 0x0fff) == 0x123);
	CHECK(out->dev == dev && out->len == 22 && out->mac_len == ETH_HLEN);
	CHECK(out->protocol == htons(ETH_P_IP));
	CHECK(out->data[12] == 8 && out->data[13] == 0);
	CHECK(!memcmp(out->data, p, 22));
	FREE_NATIVE(out); FREE_OLD(a);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_VLAN_GATE PASS dei-kept-both-ways tag-position-ok\n");

	/* Failure retains native ownership. Unknown device and GSO are explicit. */
	src = alloc_skb(64, GFP_KERNEL); CHECK(src);
	src->destructor = skb419_native_test_destructor; bridge_expected_owner = src;
	src->dev = init_net.loopback_dev;
	error = shim_skb_import(src, GFP_KERNEL); CHECK(IS_ERR(error) && PTR_ERR(error) == -EXDEV);
	CHECK(bridge_destructors == 2 && refcount_read(&src->users) == 1);
	src->dev = NULL; skb_shinfo(src)->gso_size = 20;
	error = shim_skb_import(src, GFP_KERNEL); CHECK(IS_ERR(error) && PTR_ERR(error) == -EOPNOTSUPP);
	skb_shinfo(src)->gso_size = 0; FREE_NATIVE(src); CHECK(bridge_destructors == 3);

	/* Header mutation helpers: bounds, users, exact bytes after push/pull/trim. */
	a = shim_skb_alloc(256, GFP_KERNEL); CHECK(a);
	CHECK(!shim_skb_reserve(a, 64)); p = shim_skb_put(a, 32); CHECK(p);
	for (i = 0; i < 32; i++) p[i] = i;
	CHECK(skb419_legacy_fixture(a, 3) == 2);
	CHECK(!shim_skb_push(a, 1)); CHECK(!shim_skb_free(a));
	p = shim_skb_push(a, 8); CHECK(p); memset(p, 0xa6, 8);
	p = shim_skb_put(a, 7); CHECK(p); memset(p, 0xb7, 7);
	CHECK(shim_skb_pull(a, 3)); CHECK(!shim_skb_trim(a, 42));
	CHECK(!shim_skb_put(a, UINT_MAX) && !shim_skb_push(a, UINT_MAX) && !shim_skb_pull(a, UINT_MAX));
	EXPORT(a); CHECK(out->len == 42);
	for (i = 0; i < 5; i++) CHECK(out->data[i] == 0xa6);
	for (i = 0; i < 32; i++) CHECK(out->data[5+i] == i);
	for (i = 37; i < 42; i++) CHECK(out->data[i] == 0xb7);
	FREE_NATIVE(out);
	LOAD(a, dev, saved_dev); STORE(a, dev, (void *)0x1234);
	out = shim_skb_export(a, GFP_KERNEL);
	STORE(a, dev, saved_dev);
	if (IS_ERR(out)) { ret = PTR_ERR(out); out = NULL; } else ret = 0;
	CHECK(ret == -EXDEV); LOAD(a, len, len); CHECK(len == 42);
	FREE_OLD(a);
	CHECK(atomic_read(&skb419_headers) == baseline_h && atomic_read(&skb419_buffers) == baseline_b);
	CHECK(!shim_netdev_free_unregistered(olddev)); olddev = NULL;
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_BRIDGE PASS nonlinear metadata cb-owner clone-copy vlan-dei mutation failure-ownership\n");
	ret = 0;
done:
	if (out) dev_kfree_skb_any(out);
	if (src) dev_kfree_skb_any(src);
	if (child) dev_kfree_skb_any(child);
	if (a) shim_skb_free(a);
	if (b) shim_skb_free(b);
	if (c) shim_skb_free(c);
	if (page) put_page(page);
	if (olddev) shim_netdev_free_unregistered(olddev);
	return ret;
#undef FREE_NATIVE
#undef FREE_OLD
#undef EXPORT
#undef IMPORT
#undef CHECK
}

/* --- GSO lane selftest (gated by skb_gso_selftest, HW lane runs it) ---
 * T1 export GSO pass-through; T2 export refuse legs (FRAGLIST, corrupt
 * size/type combos, tx_flags/hwtstamp/tskey); T3 import refuse legs incl.
 * the new tskey gate; T4 native TCP superframe -> import_gso -> 3 legacy
 * segments with exact lens/seq/tot_len; T5 QinQ both directions +
 * round-trip; T6 secmark/tc_index gate; T7 import_gso/drain guards. */
static void gso_legacy_words(struct skb419_view *a, u16 size, u16 segs,
			     u32 type)
{
	u8 *s = skb419_shinfo(skb419_entry(a));

	memcpy(s + SK419_off_skb_shared_info_gso_size, &size, sizeof(size));
	memcpy(s + SK419_off_skb_shared_info_gso_segs, &segs, sizeof(segs));
	memcpy(s + SK419_off_skb_shared_info_gso_type, &type, sizeof(type));
}

static int skb419_run_gso_test(void)
{
	struct skb419_view *a = NULL;
	struct sk_buff *native = NULL, *out = NULL;
	/* Zero-init: gout drains both, so a mid-T4/T7 failure frees the
	 * already-imported segments instead of leaking them. Drain is a
	 * no-op on an empty/self-linked list. */
	struct skb419_head q = { NULL, NULL, 0, 0 };
	struct skb419_head q4 = { NULL, NULL, 0, 0 };
	unsigned int headers = atomic_read(&skb419_headers);
	unsigned int buffers = atomic_read(&skb419_buffers);
	u8 *p;
	int ret = -EINVAL;
#define GCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	dev_err(&init_net.loopback_dev->dev, "SKB419_GSO failed line=%d\n", __LINE__); \
	goto gout; } } while (0)
#define GFREE_OLD(s) do { if (s) { GCHECK(!shim_skb_free(s)); s = NULL; } } while (0)
#define GFREE_NATIVE(s) do { if (s) { dev_kfree_skb_any(s); s = NULL; } } while (0)

	/* T1: legacy GSO superframe -> native keeps size/segs/type. */
	a = bcm419_legacy_skb_alloc(512, 0x6000c0); GCHECK(a);
	GCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 100); GCHECK(p);
	memset(p, 0xab, 100); p[12] = 8; p[13] = 0;
	gso_legacy_words(a, 1448, 4, SKB_GSO_TCPV4);
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GCHECK(skb_is_gso(out) && skb_shinfo(out)->gso_size == 1448 &&
	       skb_shinfo(out)->gso_segs == 4 &&
	       skb_shinfo(out)->gso_type == SKB_GSO_TCPV4);
	GCHECK(out->len == 100 && out->data[12] == 8);
	GFREE_NATIVE(out);
	gso_legacy_words(a, 0, 0, 0);
	GFREE_OLD(a);

	/* T2: export refuse legs; clearing the word recovers the view
	 * (ownership was retained, nothing leaked). */
	a = bcm419_legacy_skb_alloc(512, 0x6000c0); GCHECK(a);
	GCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 64); GCHECK(p);
	memset(p, 0xcd, 64);
	STORE(a, dev, (struct netdev419_view *)NULL);
	gso_legacy_words(a, 1448, 4, SKB_GSO_FRAGLIST);
	out = shim_skb_export(a, GFP_KERNEL);
	GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
	out = NULL;
	/* Stale segs/known-type hints with zero size are dead metadata the
	 * 4.19 stack itself ignores — accepted, nothing copied
	 * (skb419_gso_check follows skb_is_gso: only size decides). */
	gso_legacy_words(a, 0, 4, SKB_GSO_TCPV4);
	out = shim_skb_export(a, GFP_KERNEL);
	GCHECK(!IS_ERR(out) && !skb_is_gso(out) && out->len == 64);
	GFREE_NATIVE(out);
	gso_legacy_words(a, 1448, 4, 0); /* size without type */
	out = shim_skb_export(a, GFP_KERNEL);
	GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
	out = NULL;
	gso_legacy_words(a, 0, 0, 0);
	{
		u8 *s = skb419_shinfo(skb419_entry(a));
		u8 flags = 0x02; /* SKBTX_WIFI_STATUS-class: no ubuf mapping */
		__le64 stamp = cpu_to_le64(0x123456789abcdef0ULL);
		u32 tskey = 7;

		memcpy(s + SK419_off_skb_shared_info_tx_flags, &flags, 1);
		out = shim_skb_export(a, GFP_KERNEL);
		GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
		out = NULL;
		flags = 0;
		memcpy(s + SK419_off_skb_shared_info_tx_flags, &flags, 1);
		memcpy(s + SK419_off_skb_shared_info_hwtstamps, &stamp, 8);
		out = shim_skb_export(a, GFP_KERNEL);
		GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
		out = NULL;
		memset(s + SK419_off_skb_shared_info_hwtstamps, 0, 8);
		memcpy(s + SK419_off_skb_shared_info_tskey, &tskey, 4);
		out = shim_skb_export(a, GFP_KERNEL);
		GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
		out = NULL;
		tskey = 0;
		memcpy(s + SK419_off_skb_shared_info_tskey, &tskey, 4);
	}
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GCHECK(!skb_is_gso(out) && out->len == 64);
	GFREE_NATIVE(out);
	GFREE_OLD(a);

	/* T3: native GSO/tskey/tx_flags/hwtstamp refused at import, native
	 * reference retained (users stays 1). */
	native = alloc_skb(128, GFP_KERNEL); GCHECK(native);
	p = skb_put(native, 64); GCHECK(p);
	memset(p, 0xef, 64);
	native->dev = NULL;
	skb_shinfo(native)->gso_size = 20;
	a = shim_skb_import(native, GFP_KERNEL);
	GCHECK(IS_ERR(a) && PTR_ERR(a) == -EOPNOTSUPP);
	GCHECK(refcount_read(&native->users) == 1);
	skb_shinfo(native)->gso_size = 0;
	skb_shinfo(native)->tskey = 5;
	a = shim_skb_import(native, GFP_KERNEL);
	GCHECK(IS_ERR(a) && PTR_ERR(a) == -EOPNOTSUPP);
	skb_shinfo(native)->tskey = 0;
	skb_shinfo(native)->tx_flags = 1;
	a = shim_skb_import(native, GFP_KERNEL);
	GCHECK(IS_ERR(a) && PTR_ERR(a) == -EOPNOTSUPP);
	skb_shinfo(native)->tx_flags = 0;
	skb_shinfo(native)->hwtstamps.hwtstamp = 42;
	a = shim_skb_import(native, GFP_KERNEL);
	GCHECK(IS_ERR(a) && PTR_ERR(a) == -EOPNOTSUPP);
	skb_shinfo(native)->hwtstamps.hwtstamp = 0;
	a = NULL; /* last leg above left ERR_PTR; T4 must not free it */
	GFREE_NATIVE(native);

	/* T4: TCP superframe (14 eth + 20 ip + 20 tcp + 4000 payload,
	 * mss 1448) segments into 1502/1502/1158 with seq 0/1448/2896. */
	native = alloc_skb(9000, GFP_KERNEL); GCHECK(native);
	skb_reserve(native, 64);
	p = skb_put(native, 4054); GCHECK(p);
	memset(p, 0, 54);
	memset(p + 54, 0xa5, 4000);
	{
		unsigned int i;

		for (i = 0; i < 4000; i++)
			p[54 + i] = i & 0xff;
	}
	p[12] = 8; p[13] = 0; /* ethertype IP */
	p[14] = 0x45; p[16] = 4040 >> 8; p[17] = 4040 & 0xff; /* ip */
	p[23] = 6; p[26] = 10; p[27] = 0; p[28] = 0; p[29] = 1;
	p[30] = 10; p[31] = 0; p[32] = 0; p[33] = 2;
	p[34 + 12] = 0x50; /* tcp doff=5 */
	skb_reset_mac_header(native);
	native->mac_len = ETH_HLEN;
	skb_set_network_header(native, 14);
	skb_set_transport_header(native, 34);
	native->ip_summed = CHECKSUM_PARTIAL;
	native->csum_start = skb_headroom(native) + 34;
	native->protocol = htons(ETH_P_IP);
	native->csum_offset = 16;
	native->dev = NULL;
	skb_shinfo(native)->gso_size = 1448;
	skb_shinfo(native)->gso_type = SKB_GSO_TCPV4;
	{
		struct skb419_view *v;
		u32 lens[3] = { 1502, 1502, 1158 };
		u32 seqs[3] = { 0, 1448, 2896 };
		u32 total = 0;
		int i = 0, nseg;

		/* A segment import failure must drain its segments and retain
		 * the original packet for the caller (foreign-device leg). */
		native->dev = init_net.loopback_dev;
		nseg = shim_skb_import_gso(native, GFP_KERNEL, &q4);
		GCHECK(nseg == -EXDEV && !q4.qlen);
		GCHECK(refcount_read(&native->users) == 1);
		native->dev = NULL;
		nseg = shim_skb_import_gso(native, GFP_KERNEL, &q4);
		if (nseg >= 0)
			native = NULL;
		if (nseg != 3 || q4.qlen != 3)
			dev_err(&init_net.loopback_dev->dev,
				"SKB419_GSO segment rc=%d qlen=%u\n", nseg, q4.qlen);
		GCHECK(nseg == 3 && q4.qlen == 3);
		v = q4.next;
		while ((void *)v != (void *)&q4 && i < 3) {
			u8 *d;
			u32 len, seq;
			u16 tot;

			LOAD(v, len, len);
			LOAD(v, data, d);
			GCHECK(len == lens[i]);
			memcpy(&seq, d + 34 + 4, 4);
			GCHECK(ntohl(seq) == seqs[i]);
			if (!i) {
				memcpy(&tot, d + 14 + 2, 2);
				GCHECK(ntohs(tot) == 1488);
			}
			GCHECK(d[12] == 8 && d[13] == 0);
			total += len;
			LOAD(v, next, v);
			i++;
		}
		GCHECK(i == 3 && total == 4162);
		/* Segments are plain frames: each exports GSO-free. */
		v = q4.next;
		while ((void *)v != (void *)&q4) {
			struct sk_buff *s;

			STORE(v, dev, (struct netdev419_view *)NULL);
			s = shim_skb_export(v, GFP_KERNEL);
			GCHECK(!IS_ERR(s) && !skb_is_gso(s));
			dev_kfree_skb_any(s);
			LOAD(v, next, v);
		}
		bcm419_skb_queue_drain(&q4);
		GCHECK(!q4.qlen);
	}

	/* T5: QinQ. Native hwaccel 802.1AD outer + in-frame 802.1Q inner
	 * (DEI=1) -> legacy carries both tags in-frame, in order. */
	native = alloc_skb(128, GFP_KERNEL); GCHECK(native);
	p = skb_put(native, 26); GCHECK(p);
	memset(p, 0x5c, 26);
	p[12] = 0x81; p[13] = 0; p[14] = 0x61; p[15] = 0x23; /* inner DEI */
	p[16] = 8; p[17] = 0;
	skb_reset_mac_header(native);
	native->mac_len = ETH_HLEN;
	native->dev = NULL;
	__vlan_hwaccel_put_tag(native, htons(ETH_P_8021AD), 0x64);
	{
		struct skb419_view *imp = shim_skb_import(native, GFP_KERNEL);

		GCHECK(!IS_ERR(imp));
		native = NULL;
		a = imp;
	}
	GCHECK(!bcm419_vlan_tag_present(a));
	{
		u8 *d;
		u32 len;

		LOAD(a, len, len); GCHECK(len == 30);
		LOAD(a, data, d);
		GCHECK(d[12] == 0x88 && d[13] == 0xa8 && d[14] == 0 &&
		       d[15] == 0x64);
		GCHECK(d[16] == 0x81 && d[17] == 0 && d[18] == 0x61 &&
		       d[19] == 0x23);
		GCHECK(d[20] == 8 && d[21] == 0);
	}
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	/* No legacy metadata tag was ever set (import materialized the
	 * outer tag in-frame, S7 rule), so export passes the 30B frame
	 * through untouched: both tags stay in-frame, no hwaccel tag. */
	GCHECK(!skb_vlan_tag_present(out) && out->len == 30);
	GCHECK(out->data[12] == 0x88 && out->data[13] == 0xa8 &&
	       out->data[14] == 0 && out->data[15] == 0x64);
	GCHECK(out->data[16] == 0x81 && out->data[17] == 0 &&
	       out->data[18] == 0x61 && out->data[19] == 0x23);
	GCHECK(out->data[20] == 8 && out->data[21] == 0);
	GFREE_NATIVE(out);
	GFREE_OLD(a);
	/* Both tags in-frame, no hwaccel: untouched pass-through. */
	a = bcm419_legacy_skb_alloc(256, 0x6000c0); GCHECK(a);
	GCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 30); GCHECK(p);
	memset(p, 0x5c, 30);
	p[12] = 0x81; p[13] = 0; p[14] = 0; p[15] = 10;
	p[16] = 0x81; p[17] = 0; p[18] = 0; p[19] = 20;
	p[20] = 8; p[21] = 0;
	GCHECK(!bcm419_vlan_tag_present(a));
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GCHECK(!skb_vlan_tag_present(out) && out->len == 30);
	GCHECK(out->data[12] == 0x81 && out->data[16] == 0x81 &&
	       out->data[20] == 8);
	GFREE_NATIVE(out);
	GFREE_OLD(a);

	/* T6: secmark/tc_index gate — zero passes, nonzero refuses. */
	a = bcm419_legacy_skb_alloc(256, 0x6000c0); GCHECK(a);
	GCHECK(!shim_skb_reserve(a, 64));
	p = shim_skb_put(a, 22); GCHECK(p);
	memset(p, 0x5c, 22); p[12] = 8; p[13] = 0;
	STORE(a, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GFREE_NATIVE(out);
	{
		u32 secmark = 1;
		u16 tc = 7;

		memcpy(a->bytes + SK419_off_sk_buff_secmark, &secmark, 4);
		out = shim_skb_export(a, GFP_KERNEL);
		GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
		out = NULL;
		secmark = 0;
		memcpy(a->bytes + SK419_off_sk_buff_secmark, &secmark, 4);
		memcpy(a->bytes + SK419_off_sk_buff_tc_index, &tc, 2);
		out = shim_skb_export(a, GFP_KERNEL);
		GCHECK(IS_ERR(out) && PTR_ERR(out) == -EOPNOTSUPP);
		out = NULL;
		tc = 0;
		memcpy(a->bytes + SK419_off_sk_buff_tc_index, &tc, 2);
	}
	out = shim_skb_export(a, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GFREE_NATIVE(out);
	GFREE_OLD(a);
	/* Import leaves both legacy words zero (nothing to carry). */
	native = alloc_skb(64, GFP_KERNEL); GCHECK(native);
	p = skb_put(native, 22); GCHECK(p);
	memset(p, 0x5c, 22);
	native->dev = NULL;
	{
		struct skb419_view *imp = shim_skb_import(native, GFP_KERNEL);
		u32 secmark;
		u16 tc;

		GCHECK(!IS_ERR(imp));
		native = NULL;
		a = imp;
		memcpy(&secmark, a->bytes + SK419_off_sk_buff_secmark, 4);
		memcpy(&tc, a->bytes + SK419_off_sk_buff_tc_index, 2);
		GCHECK(!secmark && !tc);
	}
	GFREE_OLD(a);

	/* T7: import_gso/drain guards. NULL args refuse; non-GSO takes the
	 * single-import path with count 1. */
	GCHECK(shim_skb_import_gso(NULL, GFP_KERNEL, &q) == -EINVAL);
	native = alloc_skb(64, GFP_KERNEL); GCHECK(native);
	p = skb_put(native, 22); GCHECK(p);
	memset(p, 0x5c, 22);
	native->dev = NULL;
	GCHECK(shim_skb_import_gso(native, GFP_KERNEL, NULL) == -EINVAL);
	GCHECK(refcount_read(&native->users) == 1);
	GCHECK(shim_skb_import_gso(native, GFP_KERNEL, &q) == 1);
	native = NULL;
	GCHECK(q.qlen == 1 && q.next == q.prev && q.next);
	STORE(q.next, dev, (struct netdev419_view *)NULL);
	out = shim_skb_export(q.next, GFP_KERNEL); GCHECK(!IS_ERR(out));
	GFREE_NATIVE(out);
	bcm419_skb_queue_drain(&q);
	GCHECK(!q.qlen);
	bcm419_skb_queue_drain(NULL);
	GCHECK(bcm419_tx_import_gso(NULL, 0x6000c0, &q) == -EINVAL);

	GCHECK(atomic_read(&skb419_headers) == headers);
	GCHECK(atomic_read(&skb419_buffers) == buffers);
	dev_info(&init_net.loopback_dev->dev,
		 "SKB419_GSO PASS gso-passthru-refuse segment-3-seq qinq-roundtrip tcsecmark-gate zcopy-tstamp-refuse\n");
	ret = 0;
gout:
	GFREE_NATIVE(out);
	GFREE_NATIVE(native);
	if (a)
		shim_skb_free(a);
	/* Failure-path only (ret != 0; success falls through with empty
	 * lists): free segments a mid-test failure already imported. */
	if (ret) {
		bcm419_skb_queue_drain(&q4);
		bcm419_skb_queue_drain(&q);
	}
	return ret;
#undef GFREE_NATIVE
#undef GFREE_OLD
#undef GCHECK
}

int shim_skb_init(void)
{
	int ret;
	static_assert(SK419_size_sk_buff == 384);
	static_assert(SK419_size_skb_shared_info == 176);
	static_assert(SK419_value_data_uses_offset == 0);
	static_assert(SK419_width_sk_buff_users == sizeof(refcount_t));
	static_assert(SK419_width_skb_shared_info_dataref == sizeof(atomic_t));
	ret = shim_skb_dispatch_init();
	if (ret) return ret;
	ret = skb_selftest ? skb419_run_selftest() : 0;
	if (ret) return ret;
	ret = skb_bridge_selftest ? skb419_run_bridge_test() : 0;
	if (ret) return ret;
	ret = rxtx_selftest ? skb419_run_rxtx_test() : 0;
	if (ret) return ret;
	return skb_gso_selftest ? skb419_run_gso_test() : 0;
}

void shim_skb_exit(void)
{
	/* The registry tracks type, not ownership. The selftests assert
	 * headers/buffers return to baseline, so a live counter here means
	 * a caller leaked a descriptor. Report only — freeing a
	 * foreign-owned view would risk double-free. */
	if (atomic_read(&skb419_headers) || atomic_read(&skb419_buffers))
		pr_warn("bcm_shim: skb_exit: %d headers/%d buffers still alive\n",
			atomic_read(&skb419_headers),
			atomic_read(&skb419_buffers));
}
