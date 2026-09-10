/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wl_compat.c — shim for Broadcom-proprietary UND symbols of stock
 * radio/wl.ko + radio/hnd.ko + radio/wlshared.ko on Linux 6.6.
 *
 * Provenance per symbol (FACT: readelf relocs on the radio blobs: 627 UND
 * in wl.ko / 94 in hnd.ko / 10 in wlshared.ko):
 *
 *  A. GPL ports — bodies ported from gpl/.../linux-brcmbca_bcm96764/bcmkernel
 *     (net/core/{bcm_skbuff,bcm_netdev_path,bcm_skb_free,nbuff,blog}.c,
 *     include/linux/{bcm_skbuff,bcm_netdev_path,gbpm,nbuff,blog}.h).
 *  B. d3lut/d3fwd — minimal in-RAM dictionary. Element layout replicates
 *     bcm_pktfwd.h struct d3lut_elem byte-for-byte because wl.ko derefs
 *     elem+12 (ext.if_handle, word) and elem+19 (ext flags, byte) and
 *     writes elem+24 (ext.virt_net_device). Verified by disassembly
 *     (wl_pktfwd_lut_del+0x.., wl_pktfwd_request+0x968).
 *  C. emfc/igsc/kerSys — arity-observed stubs (ARM call sites) + two tiny
 *     functional registries (dying-gasp handlers).
 *  D. bcmFun — functional id->fn registry with a per-id absent policy
 *     (H24, 2026-09-08, disasm-proven on stock radio/wl.ko):
 *     ids 24/25 (SPDSVC_TRANSMIT/RECEIVE) are get-and-store with a NULL
 *     check at every use (wl_spdsvc_init stores; wl_spdsvc_tx+0xc and
 *     wl_spdsvc_rx+0xc skip on NULL), and the stock provider (closed
 *     spdsvc driver — zero bcmFun_reg(SPDSVC_*) in all of GPL) is absent
 *     on 6.6, so stock get() returns NULL there: get() returns NULL and
 *     wl.ko takes its designed-absent path (tx -1, rx 1). Returning the
 *     generic stub instead would fake "spdsvc present".
 *     ids 35/36/38 are called via blx with NO NULL check (wl.ko
 *     0x1808/0x19bc; GPL bcm_archer.h archer_wlan_{rx_register,
 *     unbind} inlines call hook(&arg) unchecked too), and id 36 is
 *     stored then blx'd with NO check in the RX fast path
 *     (wl_awl_upstream+0x18 and wl_awl_upstream_send_all+...): all three
 *     yield the generic stub (returns 0 = success/continue) when
 *     unregistered. wlshared.ko registers 65,66 live (UPDATE_BRIDGEFDB,
 *     PKTC_DEL_BY_MAC — 2 bcmFun_reg relocs, H24-observed); the registry
 *     passes registered ids through untouched, so those never see stub
 *     or NULL once wlshared is loaded.
 *     id 37 (ARCHER_WLAN_BIND) is an ECHO stub (H37): wl_wfd_bind
 *     (wl.ko 0x7a94) builds archer_wlan_bind_arg_t on its stack
 *     (arg = sp+4; [sp+4]=wl->dev, [sp+8]=pktlist ctx from
 *     wl_pktfwd_request, [sp+12]=0 mode SKB, [sp+16]=
 *     wl_pktfwd_xfer_callback via MOVW/MOVT relocs, [sp+20]=unit —
 *     matches bcm_archer.h field for field) and then requires
 *     hook_ret == unit (cmp r6,r4; bne mismatch → -1 abort). The echo
 *     returns arg->wl_radio_idx (+16), so unit 0 keeps the old stub-0
 *     behaviour and units 1..3 now bind instead of cleanly aborting.
 *     Unregistered-id logging is once-PER-ID (a bitmask): the old single
 *     pr_warn_once hid id 25 behind id 24 in the H24 log.
 *  E. kmalloc_order + pktlist — pktlist_context layout replicates
 *     bcm_pktfwd.h struct pktlist_context (wl.ko's own xfer_fn derefs
 *     ->peer/->unit/->mcast/->ucast[]/->free), table via vzalloc.
 *
 * REMOVED at merge D (2026-09-07): wlcsm_nvram_k_{get,set,getall}
 * (stock bcm_knvram.ko exports them) and kerSysGetMacAddress
 * (shim_nvram.c provides it) — see note at section G.
 *
 * All exports are EXPORT_SYMBOL (never _GPL): wl.ko is Proprietary.
 *
 *  I. proc bridge (H37, 2026-09-08, disasm-proven on stock radio/wl.ko):
 *     the blob creates proc entries with 4.19 ABIs that 6.6 honours
 *     only by accident. wl_attach builds "net/wl%d" and calls
 *     proc_create_data(name, 0444, NULL, fops, wl) where fops is the
 *     static 4.19 file_operations at blob .rodata+0x6d277c
 *     ({ owner NULL, llseek seq_lseek, read seq_read, open wl_proc_open,
 *     release seq_release }; open slot at +52, release at +60 — matches
 *     4.19 fs.h exactly). On 6.6 that pointer is read as struct proc_ops
 *     (which starts with proc_flags, then proc_open at +4): open() would
 *     call seq_lseek(inode, file) and fault, and read() would call
 *     seq_lseek as proc_read on a NULL seq_file. The bridge keeps a
 *     6.6-native struct proc_ops + safe show and offers
 *     wlcompat_proc_repair(name, parent) = remove + re-create with the
 *     native ops (exported-API-only, no PDE surgery), plus the wl0
 *     convenience wrapper. The blob's own show (wl_read_proc) is NOT
 *     reused: it uses single_open's iterator token (v == (void *)1) as
 *     a wl_info pointer ([v,#40] fault) — broken on stock 4.19 too, so
 *     the file is vestigial there and cat'ing it must never be part of
 *     bring-up. pktfwd ("pktfwd_wl/stats|enable", raw read/write fops)
 *     and awl ("wl_awl/stats" via native proc_create_single_data, show
 *     uses seq_file + globals and ignores v — works on 6.6) are
 *     audit-only here; see triaging/shim/bcmfun37/REPORT.md §4.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "wl_compat.h"
#include "shim_skb.h"
#include "shim_gfp.h"
#include "shim_netdev.h"

/* =====================================================================
 * A. GPL ports
 * ===================================================================== */

/*
 * BCA: bcm_netdev_path.c — walk path to root. BCA path uses its own
 * upper-link chain; on vanilla 6.6 the equivalent is the master-upper
 * chain (bond/bridge/vlan roots). A device with no upper is its own root.
 *
 * IMPORTANT (live Oops, 2026-09-09, wl0-scheduler): the blob passes its
 * 4.19 VIEW pointer, while netdev_master_upper_dev_get_rcu() walks the
 * NATIVE 6.6 object. Feeding it a view faults at +0x38 (regs: dev=slab
 * kmalloc-2k view, PC netdev_master_upper_dev_get_rcu+0x38, LR here+0x14
 * via wl_pktfwd_request <- wl_handle_blog_event). Translate view->native
 * first, walk, then translate the root back to the view the blob reads
 * with 4.19 offsets. Unknown objects are never walked (return NULL).
 */
struct net_device *netdev_path_get_root(struct net_device *dev)
{
	struct net_device *native, *root, *upper;
	struct netdev419_view *old;

	if (!dev)
		return NULL;
	native = shim_netdev_native((const struct netdev419_view *)dev);
	if (!native) {
		/* Already native? Only proceed if the registry knows it. */
		if (!shim_netdev_legacy(dev))
			return NULL;	/* foreign object: never walk it */
		native = dev;
	}
	root = native;
	rcu_read_lock();
	while ((upper = netdev_master_upper_dev_get_rcu(root)) != NULL)
		root = upper;
	rcu_read_unlock();
	old = shim_netdev_legacy(root);
	return old ? (struct net_device *)old : root;
}
EXPORT_SYMBOL(netdev_path_get_root);

/*
 * BCA: bcm_skbuff.c skb_cb_zero() — zero cb[] plus the BCA wlan_ext blob.
 * On 6.6 there is no wlan_ext, so only cb[] is cleared.
 */
void skb_cb_zero(struct sk_buff *skb)
{
	if (!skb)
		return;
	memset(skb->cb, 0, sizeof(skb->cb));
}
EXPORT_SYMBOL(skb_cb_zero);

/*
 * BCA: bcm_skbuff.c skb_bpm_tainted() — body is SKB_BPM_TAINTED(skb), a
 * BPM-pool-only macro. No BPM on 6.6: true no-op (GPL prototype is void).
 */
void skb_bpm_tainted(struct sk_buff *skb)
{
	(void)skb;
}
EXPORT_SYMBOL(skb_bpm_tainted);

/*
 * BCA: blog.c blog_clone_wlan(skb2, skb1) — clones the Blog_t for WET/
 * mcast acceleration. No blog on 6.6. Return 0 ("clone failed"): every
 * call site treats 0 as "proceed without acceleration" (sets a stats
 * flag and continues on the slow path). Returning nonzero would claim a
 * blog was attached and risk a blog_p dereference.
 */
int blog_clone_wlan(struct sk_buff *skb2, struct sk_buff *skb1)
{
	(void)skb2;
	(void)skb1;
	pr_warn_once("wl_compat: blog_clone_wlan: no blog on 6.6, slow path\n");
	return 0;
}
EXPORT_SYMBOL(blog_clone_wlan);

/*
 * BCA: nbuff.c nbuff_free_ex(pNBuff, in_thread) — frees skb via
 * dev_kfree_skb_any (or the free-thread when in_thread). On 6.6 there is
 * no FKB pool and no free-thread: synchronous kfree_skb. in_thread is
 * accepted and ignored. NOTE: pbuf must be a real skb; FKB pointers
 * cannot exist on 6.6.
 */
void nbuff_free_ex(void *pbuf, int in_thread)
{
	(void)in_thread;
	if (!pbuf)
		return;
	if (shim_skb_is_legacy(pbuf))
		bcm419_kfree_skb(pbuf);
	else
		kfree_skb((struct sk_buff *)pbuf);
}
EXPORT_SYMBOL(nbuff_free_ex);

/* ---- gbpm_g data + stubs ---- */

static void *wl_gbpm_null_alloc(void)
{
	pr_warn_once("wl_compat: gbpm alloc hook called, no HW pool, NULL\n");
	return NULL;
}

/* Stock gbpm.h: int(uint32_t, void **, uint32_t), GBPM_ERROR=-1.
 * A pointer-returning NULL stub falsely reports success for this hook,
 * leaving the caller's output array uninitialized. No HW pool is bound. */
static int wl_gbpm_no_mult_buf(u32 num, void **buffers, u32 priority)
{
	(void)num;
	(void)buffers;
	(void)priority;
	pr_warn_once("wl_compat: gbpm multi-buffer allocation unavailable\n");
	return -1;
}

static unsigned int wl_gbpm_have_bufs(void)
{
	/* wl.ko (wlc_sbfn_attach) multiplies this into a table size; must
	 * be nonzero. 8192 mirrors a healthy BCA dynamic pool level. */
	return 8192;
}

static unsigned int wl_gbpm_dyn_lvl(void)
{
	return 0;
}

static void wl_gbpm_noop_p1(void *a)
{
	(void)a;
}

static void wl_gbpm_noop_p3(void *a, void *b, unsigned int c)
{
	(void)a;
	(void)b;
	(void)c;
}

static bool wl_gbpm_false_p1(void *a)
{
	(void)a;
	return false;
}

static int wl_gbpm_nosys_p2(void *a, void *b)
{
	(void)a;
	(void)b;
	return -ENOSYS;
}

/*
 * Slot order replicates gbpm.h GBPM_BIND(). Only slots 1,4,5,10,12,22,23
 * are observed in use (hnd.ko: 1/10/12; wl.ko: 23 get_avail_bufs called
 * via blx and its r0 feeds a multiply, hence nonzero).
 */
struct wl_gbpm gbpm_g = {
	.slot = {
		[WL_GBPM_ALLOC_MULT_BUF]	= wl_gbpm_no_mult_buf,
		[WL_GBPM_FREE_MULT_BUF]		= wl_gbpm_noop_p3,
		[WL_GBPM_ALLOC_BUF]		= wl_gbpm_null_alloc,
		[WL_GBPM_FREE_BUF]		= wl_gbpm_noop_p1,
		[WL_GBPM_TOTAL_SKB]		= wl_gbpm_have_bufs,
		[WL_GBPM_AVAIL_SKB]		= wl_gbpm_have_bufs,
		[WL_GBPM_ATTACH_SKB]		= wl_gbpm_noop_p3,
		[WL_GBPM_ATTACH_SKB_NO_SHINFO]	= wl_gbpm_noop_p3,
		[WL_GBPM_ALLOC_SKB]		= wl_gbpm_null_alloc,
		[WL_GBPM_ALLOC_BUF_SKB_ATTACH]	= wl_gbpm_null_alloc,
		[WL_GBPM_ALLOC_MULT_BUF_SKB]	= wl_gbpm_null_alloc,
		[WL_GBPM_ALLOC_MULT_SKB]	= wl_gbpm_null_alloc,
		[WL_GBPM_FREE_SKB]		= wl_gbpm_noop_p1,
		[WL_GBPM_FREE_SKBLIST]		= wl_gbpm_noop_p3,
		[WL_GBPM_INVALIDATE_DIRTYP]	= wl_gbpm_null_alloc,
		[WL_GBPM_RECYCLE_SKB]		= wl_gbpm_noop_p3,
		[WL_GBPM_ATTACH_SKB_HW_BUF]	= wl_gbpm_noop_p3,
		[WL_GBPM_RECYCLE_SKB_HW_BUF]	= wl_gbpm_noop_p3,
		[WL_GBPM_FREE_MULT_SKB_AND_BUF]	= wl_gbpm_noop_p3,
		[WL_GBPM_IS_SKB_WITH_HW_BUF]	= wl_gbpm_false_p1,
		[WL_GBPM_RECYCLE_PNBUFF]	= wl_gbpm_noop_p3,
		[WL_GBPM_GET_DYN_BUF_LVL]	= wl_gbpm_dyn_lvl,
		[WL_GBPM_GET_TOTAL_BUFS]	= wl_gbpm_have_bufs,
		[WL_GBPM_GET_AVAIL_BUFS]	= wl_gbpm_have_bufs,
		[WL_GBPM_GET_MAX_DYN_BUFS]	= wl_gbpm_have_bufs,
		[WL_GBPM_IS_BUF_HW_RECY_CAPABLE] = wl_gbpm_false_p1,
		[WL_GBPM_RECYCLE_HW_BUF]	= wl_gbpm_noop_p3,
		[WL_GBPM_REGISTER_HW_POOL_API]	= wl_gbpm_nosys_p2,
		[28] = NULL, [29] = NULL, [30] = NULL, [31] = NULL,
	}
};
EXPORT_SYMBOL(gbpm_g);

static bool gbpm_abi_selftest;
module_param(gbpm_abi_selftest, bool, 0400);

static int wl_gbpm_abi_selftest(void)
{
	u32 sentinel[2] = { 0x13572468, 0x24681357 };
	void *buffers[2] = { &sentinel[0], &sentinel[1] };
	int (*alloc)(u32, void **, u32) = gbpm_g.slot[WL_GBPM_ALLOC_MULT_BUF];

	if (alloc(2, buffers, 0) != -1 || buffers[0] != &sentinel[0] ||
	    buffers[1] != &sentinel[1] || sentinel[0] != 0x13572468 ||
	    sentinel[1] != 0x24681357 || alloc(0, NULL, 0) != -1) {
		pr_err("GBPM419_ABI_SELFTEST FAIL\n");
		return -EINVAL;
	}
	pr_info("GBPM419_ABI_SELFTEST PASS failure=-1 output-untouched=1\n");
	return 0;
}

/*
 * BCA: bcm_skb_free.c dev_kfree_skb_thread_bulk(head, tail, len) —
 * queues the chain for a free-thread. On 6.6 free synchronously, bounded
 * by len (cap 4096 against a corrupted chain looping forever).
 */
void dev_kfree_skb_thread_bulk(struct sk_buff *head, struct sk_buff *tail,
			       uint32_t len)
{
	struct sk_buff *skb = head, *next;
	uint32_t n = 0;

	if (shim_skb_is_legacy(head)) {
		bcm419_dev_kfree_skb_thread_bulk((void *)head, (void *)tail, len);
		return;
	}

	if (!head)
		return;
	if (len == 0)
		len = 1;
	if (len > 4096)
		len = 4096;
	while (skb && n < len) {
		next = (skb == tail) ? NULL : skb->next;
		skb->next = NULL;
		kfree_skb(skb);
		if (skb == tail)
			break;
		skb = next;
		n++;
	}
}
EXPORT_SYMBOL(dev_kfree_skb_thread_bulk);

/* =====================================================================
 * B. d3lut / d3fwd in-RAM dictionary
 * ===================================================================== */

#define WL_D3LUT_POOLS		5	/* == D3LUT_POOL_TOT (4 WLAN + 1 xdomain) */
#define WL_D3LUT_ELEM_MAX	512	/* == D3LUT_ELEM_MAX per pool */

/*
 * Byte-exact replica of bcm_pktfwd.h struct d3lut_elem (36 bytes):
 *  +0 next ptr, +4 sym[6], +10 key u16, +12 ext.if_handle,
 *  +16 ext.flow (u16), +18 ext.ucast_bmap, +19 ext flags byte,
 *  +20 ext.ssid, +22 ext.rsvd16, +24 ext.virt_net_device, +28 sta_list.
 * wl.ko reads +12/+19 and writes +24 itself after d3lut_ins.
 */
struct wl_d3lut_elem {
	struct wl_d3lut_elem *next;
	uint8_t sym[6];
	uint16_t key_v16;
	void *if_handle;
	uint16_t flow;
	uint8_t ucast_bmap;
	uint8_t flags;
	uint16_t ssid;
	uint16_t rsvd16;
	void *virt_net_device;
	void *sta_next;
	void *sta_prev;
};

struct wl_d3lut {
	spinlock_t lock;
	struct wl_d3lut_elem *head[WL_D3LUT_POOLS];
	uint32_t count[WL_D3LUT_POOLS];
	uint32_t policy[WL_D3LUT_POOLS];
	uint16_t next_idx[WL_D3LUT_POOLS];
	uint8_t incarn[WL_D3LUT_POOLS];
};

static struct wl_d3lut wl_d3lut_table;
void *d3lut_gp;	/* set to &wl_d3lut_table at init (BCA: d3lut_t *d3lut_gp) */
EXPORT_SYMBOL(d3lut_gp);

static unsigned int wl_d3lut_slot(uint32_t pool)
{
	return pool;
}

static struct wl_d3lut *wl_d3lut_use(void *d3lut)
{
	/* BCA asserts d3lut == d3lut_gp; wl.ko caches our pointer at
	 * attach, so honour a non-NULL argument, else the singleton. */
	return d3lut ? (struct wl_d3lut *)d3lut : &wl_d3lut_table;
}

/* Stock dictionary operations use caller serialization. In particular,
 * wl_pktfwd_lut_del locks d3lut_gp at +0 before d3lut_lkup/del. Taking
 * that same lock inside the shim deadlocks APSTA BSS teardown (H30).
 * Keep returned entries protected by the caller across subsequent writes.
 * Source: bcm_pktfwd.c dictionary API; d3lut_clr explicitly documents it. */
void *d3lut_ins(void *d3lut, uint8_t *sym, uint32_t pool, uint32_t policy)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	struct wl_d3lut_elem *e;
	unsigned int s;

	(void)policy; /* stored per-pool by d3lut_policy_set; ins is policy-agnostic here */
	if (!sym || pool >= WL_D3LUT_POOLS)
		return NULL;
	s = wl_d3lut_slot(pool);
	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return NULL;
	memcpy(e->sym, sym, 6);
	lockdep_assert_held(&t->lock);
	if (t->count[s] >= WL_D3LUT_ELEM_MAX) {
		kfree(e);
		return NULL;
	}
	e->key_v16 = (t->next_idx[s] & 0x0FFF) |
		     ((uint16_t)t->incarn[s] << 12) |
		     ((uint16_t)(s & 0x7) << 13);
	if (++t->next_idx[s] >= WL_D3LUT_ELEM_MAX)
		t->next_idx[s] = 0;
	e->next = t->head[s];
	t->head[s] = e;
	t->count[s]++;
	return e;
}
EXPORT_SYMBOL(d3lut_ins);

void *d3lut_lkup(void *d3lut, uint8_t *sym, uint32_t pool)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	struct wl_d3lut_elem *e;
	unsigned int s, first, end;

	if (!sym || (pool != U32_MAX && pool >= WL_D3LUT_POOLS))
		return NULL;
	lockdep_assert_held(&t->lock);
	first = pool == U32_MAX ? 0 : pool;
	end = pool == U32_MAX ? WL_D3LUT_POOLS : pool + 1;
	for (s = first; s < end; s++)
		for (e = t->head[s]; e; e = e->next)
			if (memcmp(e->sym, sym, 6) == 0)
				return e;
	return NULL;
}
EXPORT_SYMBOL(d3lut_lkup);

void *d3lut_del(void *d3lut, uint8_t *sym, uint32_t pool)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	struct wl_d3lut_elem *e, **pp;
	unsigned int s;

	if (!sym || pool >= WL_D3LUT_POOLS)
		return NULL;
	s = wl_d3lut_slot(pool);
	lockdep_assert_held(&t->lock);
	for (pp = &t->head[s]; (e = *pp) != NULL; pp = &e->next) {
		if (memcmp(e->sym, sym, 6) == 0) {
			*pp = e->next;
			t->count[s]--;
			t->incarn[s]++;
			break;
		}
	}
	if (e)
		kfree(e);
	return NULL; /* BCA returns the deleted elem; wl.ko ignores it */
}
EXPORT_SYMBOL(d3lut_del);

void d3lut_clr(void *d3lut, void *ext, bool ignore_ext_match)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	struct wl_d3lut_elem *e, **pp, *tmp;
	unsigned int s;

	lockdep_assert_held(&t->lock);
	for (s = 0; s < WL_D3LUT_POOLS; s++) {
		pp = &t->head[s];
		while ((e = *pp) != NULL) {
			/* Match BCA D3FWD_EXT_CMP (ext.if_handle == ext);
			 * also match virt_net_device (+24): wl.ko stores
			 * its wlif/dev pointer there after d3lut_ins. */
			if (ignore_ext_match || e->if_handle == ext ||
			    e->virt_net_device == ext) {
				*pp = e->next;
				tmp = e;
				t->count[s]--;
				/* kfree is atomic; caller keeps the table lock. */
				e = NULL;
				kfree(tmp);
				continue;
			}
			pp = &e->next;
		}
	}
}
EXPORT_SYMBOL(d3lut_clr);

void d3lut_dump(void *d3lut)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	struct wl_d3lut_elem *e;
	unsigned int s, n;

	pr_info("wl_compat: d3lut dump:\n");
	lockdep_assert_held(&t->lock);
	for (s = 0; s < WL_D3LUT_POOLS; s++) {
		n = 0;
		for (e = t->head[s]; e; e = e->next) {
			if (n < 16)
				pr_info("  pool %u %pM key %04x flags %02x\n",
					s, e->sym, e->key_v16, e->flags);
			n++;
		}
		pr_info("  pool %u: %u entries (policy %u)\n",
			s, t->count[s], t->policy[s]);
	}
}
EXPORT_SYMBOL(d3lut_dump);

void d3lut_policy_set(void *d3lut, uint32_t pool, uint32_t policy)
{
	struct wl_d3lut *t = wl_d3lut_use(d3lut);
	unsigned int s = wl_d3lut_slot(pool);

	if (pool >= WL_D3LUT_POOLS)
		return;
	lockdep_assert_held(&t->lock);
	t->policy[s] = policy;
}
EXPORT_SYMBOL(d3lut_policy_set);

static bool d3lut_selftest;
module_param(d3lut_selftest, bool, 0400);

/* Reproduce the real wl_pktfwd_lut_del lock contract. All dictionary
 * calls run with the externally visible lock held; a recursive acquisition
 * would hang here just as in vendor18. Also distinguish GLOBAL from pool0. */
static int wl_d3lut_selftest(void)
{
	struct wl_d3lut *t;
	struct wl_d3lut_elem *e[WL_D3LUT_POOLS];
	u8 mac[6] = { 2, 0, 0, 0, 0, 0 };
	unsigned int i;
	int ret = -EINVAL;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;
	spin_lock_init(&t->lock);
	spin_lock_bh(&t->lock);
	if (d3lut_lkup(t, mac, U32_MAX))
		goto out;
	for (i = 0; i < WL_D3LUT_POOLS; i++) {
		mac[5] = i;
		d3lut_policy_set(t, i, 0);
		e[i] = d3lut_ins(t, mac, i, 0);
		if (!e[i] || t->count[i] != 1 ||
		    d3lut_lkup(t, mac, i) != e[i] ||
		    d3lut_lkup(t, mac, U32_MAX) != e[i] ||
		    !spin_is_locked(&t->lock))
			goto out;
		e[i]->if_handle = i & 1 ? t : NULL;
	}
	if (d3lut_lkup(t, mac, U32_MAX - 1) ||
	    d3lut_ins(t, mac, WL_D3LUT_POOLS, 0))
		goto out;
	d3lut_clr(t, t, false);
	for (i = 0; i < WL_D3LUT_POOLS; i++) {
		mac[5] = i;
		if (!!d3lut_lkup(t, mac, U32_MAX) != !(i & 1))
			goto out;
		d3lut_del(t, mac, i);
		if (d3lut_lkup(t, mac, U32_MAX) || t->count[i])
			goto out;
	}
	if (!spin_is_locked(&t->lock))
		goto out;
	ret = 0;
out:
	d3lut_clr(t, NULL, true);
	spin_unlock_bh(&t->lock);
	kfree(t);
	pr_info("D3LUT_API_SELFTEST %s caller-lock global-five-pools clear-delete\n",
		ret ? "FAIL" : "PASS");
	return ret;
}

/*
 * BCA: bcm_pktfwd.c d3fwd_wlif_dump() prints wlif->net_device->name.
 * d3fwd_wlif_t layout is wl-side private; only log the pointer.
 */
void d3fwd_wlif_dump(void *d3fwd_wlif)
{
	pr_info("wl_compat: d3fwd_wlif_dump(%p)\n", d3fwd_wlif);
}
EXPORT_SYMBOL(d3fwd_wlif_dump);

/*
 * NOTE: wl_update_d3lut_and_blog() is NOT defined here: stock wlshared.ko
 * already EXPORTs it (verified in its __ksymtab_strings, FACT). A second
 * definition would collide at insmod. wlshared's version is NULL-hook
 * safe on 6.6 (no PKTC hooks registered => slow path).
 */

/* =====================================================================
 * C. emfc / igsc / kerSys stubs
 * ===================================================================== */

int emfc_init(void *a, void *b, void *c, void *d)
{
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	pr_warn_once("wl_compat: emfc (multicast fwd client) disabled\n");
	return 0; /* wl stores r0 as its emf handle; stubs ignore handles */
}
EXPORT_SYMBOL(emfc_init);

void emfc_exit(void *handle)
{
	(void)handle;
}
EXPORT_SYMBOL(emfc_exit);

/*
 * Return 0 = "frame not consumed, continue normal processing".
 * wlc_wmf_packets_handle takes a special branch only for retval 2.
 */
int emfc_input(void *handle, void *a, void *b, void *c, unsigned int d)
{
	(void)handle;
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	pr_warn_once("wl_compat: emfc_input: passing through (no EMF)\n");
	/* P2 (pktfwd-rx audit): stock emf.ko returns 1 (no-action) when EMF
	 * is absent; 0 is WMF_DROP and silently eats IPv4/IPv6 multicast. */
	return 1;
}
EXPORT_SYMBOL(emfc_input);

int emfc_ipv6_input(void *handle, void *a, void *b, void *c,
		    unsigned int d)
{
	(void)handle;
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	pr_warn_once("wl_compat: emfc_ipv6_input: passing through (no EMF)\n");
	return 1;
}
EXPORT_SYMBOL(emfc_ipv6_input);

int emfc_cfg_request_process(void *handle)
{
	(void)handle;
	return 0;
}
EXPORT_SYMBOL(emfc_cfg_request_process);

int igsc_init(void *a, void *b, void *c, void *d, unsigned int e)
{
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	(void)e;
	pr_warn_once("wl_compat: igsc (IGMP snooping client) disabled\n");
	return 0; /* wl stores r0 as its igs handle; stubs ignore handles */
}
EXPORT_SYMBOL(igsc_init);

void igsc_exit(void *handle)
{
	(void)handle;
}
EXPORT_SYMBOL(igsc_exit);

/*
 * Return 0 = "no error, continue teardown": the caller proceeds to
 * igsc_interface_rtport_del only when sdb_interface_del returns 0.
 */
int igsc_sdb_interface_del(void *handle, void *arg)
{
	(void)handle;
	(void)arg;
	return 0;
}
EXPORT_SYMBOL(igsc_sdb_interface_del);

int igsc_interface_rtport_del(void *handle, void *arg)
{
	(void)handle;
	(void)arg;
	return 0;
}
EXPORT_SYMBOL(igsc_interface_rtport_del);

/* ---- dying-gasp handler registry (GPL dgasp_drv heritage, in-RAM) ---- */
#define WL_DGASP_MAX	16

struct wl_dgasp {
	char name[16];
	void *cbfn;
	void *ctx;
	bool used;
};

static struct wl_dgasp wl_dgasp_tab[WL_DGASP_MAX];
static DEFINE_SPINLOCK(wl_dgasp_lock);

/* BCA: dgasp_drv.c void (char *devname, void *cbfn, void *context) */
void kerSysRegisterDyingGaspHandler(char *devname, void *cbfn,
				    void *context)
{
	unsigned long flags;
	int i;

	if (!devname || !cbfn) {
		pr_err("wl_compat: dying-gasp register with NULL dev/cb\n");
		return;
	}
	spin_lock_irqsave(&wl_dgasp_lock, flags);
	for (i = 0; i < WL_DGASP_MAX; i++) {
		if (!wl_dgasp_tab[i].used) {
			strscpy(wl_dgasp_tab[i].name, devname,
				sizeof(wl_dgasp_tab[i].name));
			wl_dgasp_tab[i].cbfn = cbfn;
			wl_dgasp_tab[i].ctx = context;
			wl_dgasp_tab[i].used = true;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_dgasp_lock, flags);
	if (i == WL_DGASP_MAX)
		pr_err("wl_compat: dying-gasp table full for %s\n", devname);
	else
		pr_info("wl_compat: dying-gasp handler for %s registered\n",
			devname);
}
EXPORT_SYMBOL(kerSysRegisterDyingGaspHandler);

void kerSysDeregisterDyingGaspHandler(char *devname)
{
	unsigned long flags;
	int i;

	if (!devname)
		return;
	spin_lock_irqsave(&wl_dgasp_lock, flags);
	for (i = 0; i < WL_DGASP_MAX; i++) {
		if (wl_dgasp_tab[i].used &&
		    strncmp(wl_dgasp_tab[i].name, devname,
			    sizeof(wl_dgasp_tab[i].name)) == 0) {
			wl_dgasp_tab[i].used = false;
			wl_dgasp_tab[i].cbfn = NULL;
			wl_dgasp_tab[i].ctx = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_dgasp_lock, flags);
}
EXPORT_SYMBOL(kerSysDeregisterDyingGaspHandler);

/*
 * BCA: board_wl.c — GPIO LED numbers from board params. No board params
 * on 6.6: report "no LED" (0). wl.ko's wlc_led_attach treats 0 as
 * "LED not configured" and skips — the designed-absent path.
 */
unsigned int kerSysGetWifiLed(unsigned char core)
{
	(void)core;
	return 0;
}
EXPORT_SYMBOL(kerSysGetWifiLed);

void kerSysWifiLed(unsigned int led, unsigned int on)
{
	(void)led;
	(void)on;
}
EXPORT_SYMBOL(kerSysWifiLed);

/* =====================================================================
 * D. bcmFun callback registry (per-id absent policy, H24)
 * ===================================================================== */
#define WL_BCMFUN_MAX	128

/*
 * Id assignments (FACT: bcmkernel/include/linux/bcm_log_mod.h bcmFunId_t,
 * verified by counting the enum from BCM_FUN_ID_RESET_SWITCH=0):
 *  24 BCM_FUN_ID_SPDSVC_TRANSMIT  int (*)(spdsvcHook_transmit_t *)
 *     (spdsvc_defs.h; provider = closed spdsvc driver, absent on 6.6)
 *  25 BCM_FUN_ID_SPDSVC_RECEIVE   int (*)(spdsvcHook_receive_t *)
 *  35 BCM_FUN_ID_ARCHER_WLAN_RX_REGISTER  int (*)(archer_wlan_rx_register_arg_t *)
 *  36 BCM_FUN_ID_ARCHER_WLAN_RX_SEND      void (*)(void *)
 *  37 BCM_FUN_ID_ARCHER_WLAN_BIND         int (*)(archer_wlan_bind_arg_t *)
 *  38 BCM_FUN_ID_ARCHER_WLAN_UNBIND       int (*)(archer_wlan_unbind_arg_t *)
 *  65 BCM_FUN_ID_WLAN_UPDATE_BRIDGEFDB / 66 BCM_FUN_ID_WLAN_PKTC_DEL_BY_MAC
 *     (registered live by stock wlshared.ko; never stubbed once loaded)
 */
#define WL_BCMFUN_SPDSVC_TRANSMIT	24
#define WL_BCMFUN_SPDSVC_RECEIVE	25
#define WL_BCMFUN_ARCHER_RX_REGISTER	35
#define WL_BCMFUN_ARCHER_RX_SEND	36
#define WL_BCMFUN_ARCHER_BIND		37
#define WL_BCMFUN_ARCHER_UNBIND		38

static void *wl_bcmfun_tab[WL_BCMFUN_MAX];
static DEFINE_SPINLOCK(wl_bcmfun_lock);

/* Once-per-id warning mask (128 ids). The old single pr_warn_once hid
 * every id behind the first one (H24 log showed only 24, never 25). */
static unsigned long wl_bcmfun_warned[WL_BCMFUN_MAX / BITS_PER_LONG];

/*
 * True for ids whose EVERY wl.ko use site NULL-checks the stored hook:
 * 24/25 are stored by wl_spdsvc_init (wl.ko 0x76ac/0x76bc) and used only
 * behind `cmp hook,#0 / beq skip` (wl_spdsvc_tx+0xc, wl_spdsvc_rx+0xc),
 * so NULL reproduces the stock spdsvc-absent behaviour exactly
 * (tx returns -1, rx returns 1 — the same values the stub path yields,
 * but without faking "spdsvc present").
 * 36 looks similar (stored at wl_awl_attach+0x110) but its uses blx
 * WITHOUT a check (wl_awl_upstream+0x18, wl_awl_upstream_send_all+...),
 * so it is NOT listed here. 35/37/38 are blx'd without a check.
 */
static bool wl_bcmfun_absent_ok(int fun_id)
{
	return fun_id == WL_BCMFUN_SPDSVC_TRANSMIT ||
	       fun_id == WL_BCMFUN_SPDSVC_RECEIVE;
}

/* Generic hook for ids nobody registered AND nobody NULL-checks.
 * Returns 0, which those call sites interpret as success/continue:
 *  id 35 attach (0 continues attach; nonzero aborts to wl_free),
 *  35 detach (ignored), 36 RX fast path (void use, arg ignored),
 *  38 wfd unbind (ignored).
 * Id 37 has its own echo hook below (wl_wfd_bind compares hook_ret
 * against unit, so a flat 0 only binds radio 0).
 */
static long wl_bcmfun_stub(void)
{
	return 0;
}

/*
 * P0 (live 2026-09-09, EAPOL 4-way timeout): bcmFun_get(35)
 * (BCM_FUN_ID_ARCHER_WLAN_RX_REGISTER, GPL bcm_archer.h:113-123) is
 * called as `hook(&arg)` with NO NULL check, and its return decides the
 * AWL RX mode inside wl_awl_attach: 0 = "Archer RX registered" ->
 * rx.mode=2 (FULL) -> wl_sendup hands every unicast data frame to
 * wl_awl_upstream_send_chain -> hook id 36 (our flat-0 stub) consumes it
 * and netif_rx is never reached. Live symptom: assoc OK (mgmt goes via
 * cfg80211), phone's EAPOL msg2/msg4 counted in rxframe but tcpdump on
 * wl0 sees ZERO RX; hostapd retries msg1 4x then 4WAY timeout (reason 15).
 * Nonzero return takes the designed fail branch (wl_awl_attach+0x1dc:
 * "acceleration failed, disabling", tx.mode=0, rx.mode=0 = PT), after
 * which unicast EAPOL flows wl_intrabss_forward=0 -> eth_type_trans ->
 * netif_rx like every other data frame. -ENODEV is the absent-provider
 * verdict; the hook contract is int(void *arg).
 */
static long wl_bcmfun35_absent(void *arg)
{
	(void)arg;
	return -ENODEV;
}

/*
 * Echo hook for id 37 (ARCHER_WLAN_BIND), H37. Layout replicates
 * bcm_archer.h archer_wlan_bind_arg_t (dev_p, wl_pktlist_context, mode,
 * wl_completeHook, wl_radio_idx — 5 words, radio index at +16):
 * proven twice — by the GPL inline (archer_wlan_bind packs the five
 * args in this order) and by the blob's own stack build at
 * wl_wfd_bind+0x34..0x54 (arg = sp+4; str r6,[sp,#20] puts unit at
 * arg+16; the [sp+16] slot carries wl_pktfwd_xfer_callback via
 * R_ARM_MOVW/MOVT_ABS relocs at 0x7ae0/0x7ae4). wl_wfd_bind then does
 * `cmp unit,hook_ret; beq wl_pktfwd_wfd_ins`, so echoing the index is
 * exactly the "bind accepted" verdict for every unit (a -2 return is
 * the only other designed path: WFD_NOT_SUPPORTED → disable).
 * NULL arg cannot happen (caller passes sp+4) but yields 0, i.e. the
 * old stub behaviour for unit 0.
 */
struct wl_bcmfun37_bind_arg {
	void *dev_p;
	void *wl_pktlist_context;
	uint32_t mode;
	void *wl_completeHook;
	int32_t wl_radio_idx;
};

static long wl_bcmfun37_echo(void *arg)
{
	if (!arg)
		return 0;
	return ((struct wl_bcmfun37_bind_arg *)arg)->wl_radio_idx;
}

void *bcmFun_get(int fun_id)
{
	unsigned long flags;
	void *fn;

	spin_lock_irqsave(&wl_bcmfun_lock, flags);
	if (fun_id >= 0 && fun_id < WL_BCMFUN_MAX && wl_bcmfun_tab[fun_id])
		fn = wl_bcmfun_tab[fun_id];
	else
		fn = NULL;
	spin_unlock_irqrestore(&wl_bcmfun_lock, flags);
	if (fn)
		return fn;
	if (fun_id >= 0 && fun_id < WL_BCMFUN_MAX &&
	    wl_bcmfun_absent_ok(fun_id)) {
		if (!test_and_set_bit(fun_id, wl_bcmfun_warned))
			pr_info("wl_compat: bcmFun_get(%d): unregistered, NULL (spdsvc absent by design)\n",
				fun_id);
		return NULL;
	}
	if (fun_id == WL_BCMFUN_ARCHER_BIND) {
		if (!test_and_set_bit(fun_id, wl_bcmfun_warned))
			pr_warn("wl_compat: bcmFun_get(%d): unregistered, radio_idx echo\n",
				fun_id);
		return wl_bcmfun37_echo;
	}
	if (fun_id == WL_BCMFUN_ARCHER_RX_REGISTER) {
		if (!test_and_set_bit(fun_id, wl_bcmfun_warned))
			pr_warn("wl_compat: bcmFun_get(%d): Archer RX absent, PT mode (-ENODEV)\n",
				fun_id);
		return wl_bcmfun35_absent;
	}
	if (fun_id >= 0 && fun_id < WL_BCMFUN_MAX &&
	    !test_and_set_bit(fun_id, wl_bcmfun_warned))
		pr_warn("wl_compat: bcmFun_get(%d): unregistered, stub\n",
			fun_id);
	else if (fun_id < 0 || fun_id >= WL_BCMFUN_MAX)
		pr_warn_once("wl_compat: bcmFun_get(%d): out of range, stub\n",
			     fun_id);
	return wl_bcmfun_stub;
}
EXPORT_SYMBOL(bcmFun_get);

int bcmFun_reg(int fun_id, void *fun)
{
	unsigned long flags;

	if (fun_id < 0 || fun_id >= WL_BCMFUN_MAX || !fun)
		return -EINVAL;
	spin_lock_irqsave(&wl_bcmfun_lock, flags);
	wl_bcmfun_tab[fun_id] = fun;
	spin_unlock_irqrestore(&wl_bcmfun_lock, flags);
	pr_info("wl_compat: bcmFun_reg(%d, %p)\n", fun_id, fun);
	return 0;
}
EXPORT_SYMBOL(bcmFun_reg);

void bcmFun_dereg(int fun_id)
{
	unsigned long flags;

	if (fun_id < 0 || fun_id >= WL_BCMFUN_MAX)
		return;
	spin_lock_irqsave(&wl_bcmfun_lock, flags);
	wl_bcmfun_tab[fun_id] = NULL;
	spin_unlock_irqrestore(&wl_bcmfun_lock, flags);
}
EXPORT_SYMBOL(bcmFun_dereg);

/* =====================================================================
 * E. kmalloc_order + pktlist
 * ===================================================================== */

/*
 * No GPL definition found anywhere in the tree (provided on stock by
 * bcmlibs/emf/igs runtime). Semantics from 6 wl.ko call sites:
 * kmalloc_order(size, gfp_flags, order) — order is just a size hint
 * (2^order pages >= size at every site). Plain kmalloc is equivalent.
 */
void *kmalloc_order(size_t size, gfp_t flags, unsigned int order)
{
	(void)order;
	return kmalloc(size, shim_gfp419((__force unsigned int)flags));
}
EXPORT_SYMBOL(kmalloc_order);

/* ---- pktlist: layout replica of bcm_pktfwd.h (see header notes) ---- */

struct wl_dll {
	struct wl_dll *next_p;
	struct wl_dll *prev_p;
};

struct wl_pktlist {
	void *head;
	void *tail;
	uint32_t len;
	uint16_t prio_dest;	/* LE: prio:4, dest:12 */
	uint16_t key_v16;	/* pktfwd_key: index:12, incarn:1, domain:3 */
};

struct wl_pktlist_elem {
	struct wl_dll node;
	struct wl_pktlist pktlist;
};

#define WL_PKTLIST_PRIO_MAX	8	/* == PKTLIST_PRIO_MAX */
#define WL_PKTLIST_DEST_MAX	513	/* == PKTLIST_DEST_MAX (512+1 mcast) */
#define WL_PKTLIST_CTX_NAME_SZ	8

struct wl_pktlist_table {
	struct wl_pktlist_elem elem[WL_PKTLIST_PRIO_MAX][WL_PKTLIST_DEST_MAX];
};

/*
 * Field order/sizes replicate struct pktlist_context so that wl.ko's own
 * xfer_fn (which derefs ->peer/->unit/->mcast/->ucast[]/->free) works:
 * lock(4) dispatches(4) table(4) free(8) mcast(8) ucast[8](64)
 * fctable(4) peer(4) xfer_fn(4) keymap_fn(4) list_stats(4) pkts_stats(4)
 * driver(4) driver_name[8] unit(4) instance(8).
 */
struct wl_pktlist_context {
	spinlock_t lock;
	uint32_t dispatches;
	struct wl_pktlist_table *table;
	struct wl_dll free;
	struct wl_dll mcast;
	struct wl_dll ucast[WL_PKTLIST_PRIO_MAX];
	void *fctable;
	struct wl_pktlist_context *peer;
	void (*xfer_fn)(struct wl_pktlist_context *ctx);
	int (*keymap_fn)(uint32_t radio_idx, uint16_t *key,
			 uint16_t *flowid, uint16_t prio, bool k2f);
	uint32_t list_stats;
	uint32_t pkts_stats;
	void *driver;
	char driver_name[WL_PKTLIST_CTX_NAME_SZ];
	uint32_t unit;
	struct wl_dll instance;
} ____cacheline_aligned;

static LIST_HEAD(wl_pktlist_instances);
static DEFINE_SPINLOCK(wl_pktlist_lock);

struct wl_pktlist_track {
	struct list_head node;
	struct wl_pktlist_context *ctx;
};

static void wl_dll_init(struct wl_dll *d)
{
	d->next_p = d;
	d->prev_p = d;
}

static void wl_dll_append(struct wl_dll *head, struct wl_dll *node)
{
	node->next_p = head;
	node->prev_p = head->prev_p;
	head->prev_p->next_p = node;
	head->prev_p = node;
}

/*
 * BCA: bcm_pktfwd.c pktlist_context_init(peer, xfer_fn, keymap_fn,
 * driver, driver_name, unit). Table (~96 KB) via vzalloc: same contents
 * as the GPL kmalloc version, no high-order-atomic pressure on 6.6.
 * Lists are never fed (no Archer/WFD producer on 6.6), so wl.ko's xfer
 * walks find only empty lists — safe no-ops.
 */
void *pktlist_context_init(void *peer, void *xfer_fn, void *keymap_fn,
			   void *driver, const char *driver_name,
			   uint32_t unit)
{
	struct wl_pktlist_context *ctx;
	struct wl_pktlist_track *tr;
	uint32_t prio, dest;
	unsigned long flags;

	if (!driver || !driver_name)
		return NULL;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;
	ctx->table = vzalloc(sizeof(*ctx->table));
	if (!ctx->table) {
		kfree(ctx);
		return NULL;
	}
	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr) {
		vfree(ctx->table);
		kfree(ctx);
		return NULL;
	}
	spin_lock_init(&ctx->lock);
	ctx->dispatches = 0;
	wl_dll_init(&ctx->free);
	wl_dll_init(&ctx->mcast);
	for (prio = 0; prio < WL_PKTLIST_PRIO_MAX; prio++) {
		struct wl_pktlist_elem *e;
		struct wl_pktlist *p;

		wl_dll_init(&ctx->ucast[prio]);
		for (dest = 0; dest < WL_PKTLIST_DEST_MAX; dest++) {
			e = &ctx->table->elem[prio][dest];
			wl_dll_init(&e->node);
			wl_dll_append(&ctx->free, &e->node);
			p = &e->pktlist;
			p->head = NULL;
			p->tail = NULL;
			p->len = 0;
			p->key_v16 = 0xFFFF;
			/* prio/dest tag never reset (BCA PKTLIST_RESET
			 * keeps them); encode once: dest:12 | prio:4 */
			p->prio_dest = ((prio & 0xF) << 12) |
				       (dest & 0xFFF);
		}
	}
	ctx->peer = (struct wl_pktlist_context *)peer;
	ctx->xfer_fn = xfer_fn;
	ctx->keymap_fn = keymap_fn;
	ctx->driver = driver;
	strscpy(ctx->driver_name, driver_name, sizeof(ctx->driver_name));
	ctx->unit = unit;
	wl_dll_init(&ctx->instance);

	tr->ctx = ctx;
	spin_lock_irqsave(&wl_pktlist_lock, flags);
	list_add(&tr->node, &wl_pktlist_instances);
	spin_unlock_irqrestore(&wl_pktlist_lock, flags);

	pr_info("wl_compat: pktlist_context_init(%s unit %u) -> %p\n",
		ctx->driver_name, unit, ctx);
	return ctx;
}
EXPORT_SYMBOL(pktlist_context_init);

void *pktlist_context_fini(void *pktlist_context)
{
	struct wl_pktlist_context *ctx = pktlist_context;
	struct wl_pktlist_track *tr, *tmp;
	unsigned long flags;
	bool found = false;

	if (!ctx)
		return NULL;
	spin_lock_irqsave(&wl_pktlist_lock, flags);
	list_for_each_entry_safe(tr, tmp, &wl_pktlist_instances, node) {
		if (tr->ctx == ctx) {
			list_del(&tr->node);
			kfree(tr);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_pktlist_lock, flags);
	if (!found)
		pr_err("wl_compat: pktlist_context_fini(%p): unknown ctx\n",
		       ctx);
	vfree(ctx->table);
	kfree(ctx);
	return NULL;
}
EXPORT_SYMBOL(pktlist_context_fini);

void pktlist_context_dump_all(void)
{
	struct wl_pktlist_track *tr;
	unsigned long flags;

	pr_info("wl_compat: pktlist_context_dump_all:\n");
	spin_lock_irqsave(&wl_pktlist_lock, flags);
	list_for_each_entry(tr, &wl_pktlist_instances, node) {
		pr_info("  ctx %p name %s unit %u dispatches %u\n",
			tr->ctx, tr->ctx->driver_name, tr->ctx->unit,
			tr->ctx->dispatches);
	}
	spin_unlock_irqrestore(&wl_pktlist_lock, flags);
}
EXPORT_SYMBOL(pktlist_context_dump_all);

/* =====================================================================
 * G. blog extras (found by reloc audit, beyond the 28)
 *
 * NOTE (merge D, 2026-09-07): wlcsm_nvram_k_{get,set,getall} REMOVED —
 * stock bcm_knvram.ko EXPORTS all three (FACT: __ksymtab_strings) and
 * hnd.ko is their only importer; a shim copy would fail knvram insmod
 * with "exports duplicate symbol". nvram is served by stock knvram
 * (lane G). kerSysGetMacAddress REMOVED — provided by shim_nvram.c
 * (module-param MAC); duplicate export in one module is a link error.
 * ===================================================================== */

/*
 * BCA blog.h: Blog_t *blog_get(void) — pool allocator. No pool on 6.6:
 * NULL. wl.ko (wl_spdsvc_tx_helper) NULL-checks and skips the blog path.
 */
void *blog_get(void)
{
	return NULL;
}
EXPORT_SYMBOL(blog_get);

/* BlogAction_t values (BCA blog.h): DONE=0 NORM=1 BLOG=2 DROP=3.
 * No accelerator on 6.6: PKT_NORM (continue normal stack processing).
 */
#define WL_BLOG_PKT_NORM	1

int _blog_emit(void *nbuff, void *dev, uint32_t encap, uint32_t channel,
	       uint32_t phy_hdr, void *fc_args)
{
	(void)nbuff;
	(void)dev;
	(void)encap;
	(void)channel;
	(void)phy_hdr;
	(void)fc_args;
	pr_warn_once("wl_compat: _blog_emit: no blog, normal path\n");
	return WL_BLOG_PKT_NORM;
}
EXPORT_SYMBOL(_blog_emit);

int _blog_sinit(void *skb, void *dev, uint32_t encap, uint32_t channel,
		uint32_t phy_hdr, void *fc_args)
{
	(void)skb;
	(void)dev;
	(void)encap;
	(void)channel;
	(void)phy_hdr;
	(void)fc_args;
	pr_warn_once("wl_compat: _blog_sinit: no blog, normal path\n");
	return WL_BLOG_PKT_NORM;
}
EXPORT_SYMBOL(_blog_sinit);

void blog_notify_async_wait(uint32_t event, void *net,
			    unsigned long param1, unsigned long param2)
{
	(void)event;
	(void)net;
	(void)param1;
	(void)param2;
}
EXPORT_SYMBOL(blog_notify_async_wait);

void blog_inc_wlan_mcast_client_count(struct sk_buff *skb)
{
	(void)skb;
}
EXPORT_SYMBOL(blog_inc_wlan_mcast_client_count);

/* =====================================================================
 * H. nbuff/pktqueue leftovers (same BCA family, reloc-proven in wl.ko)
 * ===================================================================== */

/*
 * BCA nbuff.h: struct sk_buff *fkb_xlate(FkBuff_t *) — translate an FKB
 * into an skb. No FKB pool on 6.6: always NULL. wl.ko (wl_xlate_to_skb)
 * NULL-checks and frees the original via nbuff_free_ex — the designed
 * failure path.
 */
struct sk_buff *fkb_xlate(void *fkb)
{
	(void)fkb;
	pr_warn_once("wl_compat: fkb_xlate: no FKB pool, NULL\n");
	return NULL;
}
EXPORT_SYMBOL(fkb_xlate);

/*
 * BCA bcm_pktfwd.c: void pktqueue_context_dump_all(void) — debug dump of
 * the pktqueue domains. No pktqueue instances on 6.6 (nothing ever
 * enqueues): log-only.
 */
void pktqueue_context_dump_all(void)
{
	pr_info("wl_compat: pktqueue_context_dump_all: no instances\n");
}
EXPORT_SYMBOL(pktqueue_context_dump_all);

/* =====================================================================
 * I. proc bridge: safe 6.6-native ops for blob-created entries (H37)
 *
 * What the blob creates (FACT: relocs + disasm on stock radio/wl.ko,
 * full table in triaging/shim/bcmfun37/REPORT.md §4):
 *  - wl_attach: proc_create_data("net/wl%d", 0444, NULL, fops, wl),
 *    fops = static 4.19 file_operations at blob .rodata+0x6d277c.
 *    Stored at wl+256; removed by wl_free via remove_proc_entry.
 *  - wl_awl_proc_init / wl_awl_attach: proc_mkdir("wl_awl") +
 *    proc_create_single_data("stats", ...) with show =
 *    wl_awl_stats_file_read_proc (uses seq_file + globals, ignores the
 *    single-token v — native-safe on 6.6, no bridge needed).
 *  - wl_pktfwd_sys_init: proc_mkdir("pktfwd_wl") + proc_create x2
 *    ("pktfwd_wl/stats" 0420 raw read, "pktfwd_wl/enable" 0420 raw
 *    read/write fops). Audit-only here (spec in REPORT §4).
 *
 * Why wl0 needs the bridge: on 6.6 the blob's fops pointer is read as
 * struct proc_ops (proc_flags at +0, proc_open at +4, proc_read at +8,
 * proc_read_iter at +12, proc_write at +16, proc_lseek at +24). The
 * blob's word at those slots are owner(NULL), seq_lseek, seq_read, ...
 * so open() would call seq_lseek(inode, file) and fault. 6.6 core
 * cannot be asked to reinterpret the ops (proc_create_data takes
 * proc_ops), and PDE internals are not module-visible, so the repair
 * is remove + re-create with the native ops below (exported API only).
 * Ordering: call wlcompat_proc_repair_wl0() AFTER wl.ko is loaded
 * (wl_attach must have created the entry); on wl.ko unload the blob's
 * own wl_free removes the bridged entry symmetrically. Never open the
 * broken entry before repair (open itself faults).
 * ===================================================================== */

/* Defined in shim_core.c (same module); 6.6 only has the pde_data()
 * static inline, while the blob UND-imports PDE_DATA as a function. */
extern void *PDE_DATA(const struct inode *inode);

#define WLCOMPAT_WL0_SHOW_LINE	"wlcompat-wl0-bridged\n"

/* Safe show: static text + the entry's data pointer for diagnostics.
 * Deliberately NOT the blob's wl_read_proc (it treats single_open's
 * iterator token as wl_info and faults even on stock 4.19). */
static int wlcompat_wl0_show(struct seq_file *m, void *v)
{
	(void)v;
	seq_printf(m, WLCOMPAT_WL0_SHOW_LINE "priv=%px\n", m->private);
	return 0;
}

static int wlcompat_wl0_open(struct inode *inode, struct file *file)
{
	return single_open(file, wlcompat_wl0_show, PDE_DATA(inode));
}

/* Mirrors the kernel's own proc_single_ops shape, with our safe show. */
static const struct proc_ops wlcompat_wl0_proc_ops = {
	.proc_open	= wlcompat_wl0_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/*
 * Retire a blob-created entry (made with 4.19 file_operations) and
 * re-create the same path with native 6.6 proc_ops. data is NULL: the
 * blob's private pointer cannot be recovered without opening the
 * broken entry (which faults), and the safe show ignores it.
 * Returns 0 on success, negative errno when the re-create fails (the
 * old entry is already gone then — the caller must decide whether to
 * retry or leave the path absent).
 */
int wlcompat_proc_repair(const char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry *pde;

	if (!name)
		return -EINVAL;
	remove_proc_entry(name, parent);
	pde = proc_create_data(name, 0444, parent, &wlcompat_wl0_proc_ops,
			       NULL);
	if (!pde) {
		pr_err("wl_compat: proc repair of %s failed\n", name);
		return -ENOMEM;
	}
	pr_info("wl_compat: proc %s re-bridged to native proc_ops\n", name);
	return 0;
}
EXPORT_SYMBOL(wlcompat_proc_repair);

/* Minimum for wl0: run after wl.ko attach created /proc/net/wl0. */
int wlcompat_proc_repair_wl0(void)
{
	return wlcompat_proc_repair("net/wl0", NULL);
}
EXPORT_SYMBOL(wlcompat_proc_repair_wl0);

/* =====================================================================
 * Sub-init: called once from shim_core_init() (shim_core.c owns the
 * single module_init/module_exit pair of bcm_shim.ko). There is no
 * per-file exit: an aborted module_init is not unloadable anyway, and
 * wl.ko-owned pktlist contexts must outlive any unload path.
 * ===================================================================== */

/* Test fixtures below run only with bcmfun24_selftest=1 (no radio, no
 * blobs: pure registry logic, H24 t1-t4; H37 adds t5 echo-37, t6 MAC
 * stitch, t8/t9 proc bridge on throwaway /proc entries). Follows the
 * shim_wiphy.c selftest pattern:
 * PASS prints the marker and returns 0; any FAIL prints and returns
 * -EINVAL so insmod fails loudly. The registry is left as found; the
 * throwaway proc entries are removed before return. */
static bool bcmfun24_selftest;
module_param(bcmfun24_selftest, bool, 0400);
MODULE_PARM_DESC(bcmfun24_selftest, "Verify bcmFun absent/stub/echo policy + proc bridge without radio (H24/H37)");

static long wl_bcmfun_dummy(void)
{
	return 0x5a5a5a5aL;
}

#define BCMFUN24_CHECK(cond, name) do {					\
		ntot++;							\
		if (!(cond)) {						\
			pr_err("wl_compat: BCMFUN37_SELFTEST FAIL "	\
			       "%s (line %d)\n", name, __LINE__);	\
			nfail++;					\
		}							\
	} while (0)

/* memmem for the proc selftests (checks the driver's own output). */
static bool wlcompat_buf_has(const char *buf, size_t n, const char *needle)
{
	size_t nl = strlen(needle);
	size_t i;

	if (nl == 0 || n < nl)
		return false;
	for (i = 0; i + nl <= n; i++) {
		if (memcmp(buf + i, needle, nl) == 0)
			return true;
	}
	return false;
}

/* t8/t9: proc bridge end-to-end on throwaway entries (no radio, no
 * blob). t8 exercises the native adapter directly; t9 rebuilds the
 * blob's broken shape (4.19 fops passed as proc_ops — create succeeds,
 * the entry is never opened) and runs the repair over it. */
static int wlcompat_proc_selftest(void)
{
	int ntot = 0, nfail = 0;
	struct proc_dir_entry *pde;
	struct file *f;
	loff_t pos;
	char buf[96];
	ssize_t n;
	/* Blob-shaped 4.19 fops: owner NULL, llseek seq_lseek, read
	 * seq_read — the wl0 .rodata+0x6d277c skeleton. */
	static const struct file_operations t37b_fops = {
		.llseek	= seq_lseek,
		.read	= seq_read,
	};

	/* t8: adapter entry with a cookie as data. */
	pde = proc_create_data("wlcompat_t37", 0444, NULL,
			       &wlcompat_wl0_proc_ops,
			       (void *)0xabcdef01UL);
	BCMFUN24_CHECK(pde != NULL, "proc-create");
	if (pde) {
		f = filp_open("/proc/wlcompat_t37", O_RDONLY, 0);
		BCMFUN24_CHECK(!IS_ERR(f), "proc-open");
		if (!IS_ERR(f)) {
			pos = 0;
			memset(buf, 0, sizeof(buf));
			n = kernel_read(f, buf, sizeof(buf) - 1, &pos);
			BCMFUN24_CHECK(n > 0 &&
				       (size_t)n < sizeof(buf) &&
				       memcmp(buf, WLCOMPAT_WL0_SHOW_LINE,
					      strlen(WLCOMPAT_WL0_SHOW_LINE)) == 0 &&
				       wlcompat_buf_has(buf, n, "abcdef01"),
				       "proc-read");
			filp_close(f, NULL);
		} else {
			BCMFUN24_CHECK(false, "proc-read");
		}
		remove_proc_entry("wlcompat_t37", NULL);
		f = filp_open("/proc/wlcompat_t37", O_RDONLY, 0);
		BCMFUN24_CHECK(IS_ERR(f), "proc-removed");
		if (!IS_ERR(f))
			filp_close(f, NULL);
	} else {
		BCMFUN24_CHECK(false, "proc-open");
		BCMFUN24_CHECK(false, "proc-read");
		BCMFUN24_CHECK(false, "proc-removed");
	}

	/* t9: broken-shape entry -> repair -> native behaviour. */
	pde = proc_create_data("wlcompat_t37b", 0444, NULL,
			       (const struct proc_ops *)&t37b_fops, NULL);
	BCMFUN24_CHECK(pde != NULL, "repair-create-broken");
	if (pde) {
		/* Never open before repair: proc_open would be
		 * seq_lseek(inode, file). */
		BCMFUN24_CHECK(wlcompat_proc_repair("wlcompat_t37b",
						    NULL) == 0,
			       "repair-rc");
		f = filp_open("/proc/wlcompat_t37b", O_RDONLY, 0);
		BCMFUN24_CHECK(!IS_ERR(f), "repair-open");
		if (!IS_ERR(f)) {
			pos = 0;
			memset(buf, 0, sizeof(buf));
			n = kernel_read(f, buf, sizeof(buf) - 1, &pos);
			BCMFUN24_CHECK(n > 0 &&
				       memcmp(buf, WLCOMPAT_WL0_SHOW_LINE,
					      strlen(WLCOMPAT_WL0_SHOW_LINE)) == 0,
				       "repair-read");
			filp_close(f, NULL);
		} else {
			BCMFUN24_CHECK(false, "repair-read");
		}
		remove_proc_entry("wlcompat_t37b", NULL);
	} else {
		BCMFUN24_CHECK(false, "repair-rc");
		BCMFUN24_CHECK(false, "repair-open");
		BCMFUN24_CHECK(false, "repair-read");
	}

	if (nfail) {
		pr_err("wl_compat: BCMFUN37_SELFTEST FAIL %d/%d (proc)\n",
		       nfail, ntot);
		return -EINVAL;
	}
	pr_info("wl_compat: BCMFUN37_SELFTEST PASS checks=%d (proc)\n", ntot);
	return 0;
}

static int wl_bcmfun24_selftest(void)
{
	int ntot = 0, nfail = 0;
	void *f35, *f36, *f37, *f38, *f, *saved24;
	long (*stub)(void);
	long (*echo37)(void *);
	struct wl_bcmfun37_bind_arg barg;

	/* Compile-time pin of the §D/§I slot arithmetic (H24/H37 audits):
	 * 4.19 file_operations open/release and 6.6 proc_ops open/read_iter,
	 * plus the echo offset inside archer_wlan_bind_arg_t. */
	BUILD_BUG_ON(offsetof(struct file_operations, open) != 52);
	BUILD_BUG_ON(offsetof(struct file_operations, release) != 60);
	BUILD_BUG_ON(offsetof(struct proc_ops, proc_open) != 4);
	BUILD_BUG_ON(offsetof(struct proc_ops, proc_read_iter) != 12);
	BUILD_BUG_ON(offsetof(struct wl_bcmfun37_bind_arg,
			      wl_radio_idx) != 16);

	/* t1: spdsvc ids are absent (NULL) with nothing registered. */
	BCMFUN24_CHECK(bcmFun_get(WL_BCMFUN_SPDSVC_TRANSMIT) == NULL,
		       "get24-NULL");
	BCMFUN24_CHECK(bcmFun_get(WL_BCMFUN_SPDSVC_RECEIVE) == NULL,
		       "get25-NULL");

	/* t2: no-check ids yield the generic stub (35/36/38) or the
	 * radio_idx echo (37); the stub returns 0. */
	f35 = bcmFun_get(WL_BCMFUN_ARCHER_RX_REGISTER);
	f36 = bcmFun_get(WL_BCMFUN_ARCHER_RX_SEND);
	f37 = bcmFun_get(WL_BCMFUN_ARCHER_BIND);
	f38 = bcmFun_get(WL_BCMFUN_ARCHER_UNBIND);
	BCMFUN24_CHECK(f35 == wl_bcmfun_stub, "get35-stub");
	BCMFUN24_CHECK(f36 == wl_bcmfun_stub, "get36-stub");
	BCMFUN24_CHECK(f37 == wl_bcmfun37_echo, "get37-echo");
	BCMFUN24_CHECK(f38 == wl_bcmfun_stub, "get38-stub");
	stub = f35;
	BCMFUN24_CHECK(stub() == 0, "stub-ret0");

	/* t3: reg/dereg roundtrip on an unused id; bad args rejected. */
	BCMFUN24_CHECK(bcmFun_reg(-1, wl_bcmfun_dummy) == -EINVAL,
		       "reg-neg");
	BCMFUN24_CHECK(bcmFun_reg(WL_BCMFUN_MAX, wl_bcmfun_dummy) == -EINVAL,
		       "reg-oob");
	BCMFUN24_CHECK(bcmFun_reg(100, NULL) == -EINVAL, "reg-null");
	BCMFUN24_CHECK(bcmFun_reg(100, wl_bcmfun_dummy) == 0, "reg100");
	f = bcmFun_get(100);
	BCMFUN24_CHECK(f == wl_bcmfun_dummy, "get100-dummy");
	bcmFun_dereg(100);
	BCMFUN24_CHECK(bcmFun_get(100) == wl_bcmfun_stub, "get100-stub");

	/* t4: an explicit registration wins over the absent policy. */
	saved24 = NULL;
	if (bcmFun_get(WL_BCMFUN_SPDSVC_TRANSMIT) != NULL)
		saved24 = bcmFun_get(WL_BCMFUN_SPDSVC_TRANSMIT);
	BCMFUN24_CHECK(bcmFun_reg(WL_BCMFUN_SPDSVC_TRANSMIT,
				  wl_bcmfun_dummy) == 0, "reg24");
	BCMFUN24_CHECK(bcmFun_get(WL_BCMFUN_SPDSVC_TRANSMIT) ==
		       wl_bcmfun_dummy, "get24-dummy");
	bcmFun_dereg(WL_BCMFUN_SPDSVC_TRANSMIT);
	if (saved24)
		BCMFUN24_CHECK(bcmFun_reg(WL_BCMFUN_SPDSVC_TRANSMIT,
					  saved24) == 0, "restore24");
	else
		BCMFUN24_CHECK(bcmFun_get(WL_BCMFUN_SPDSVC_TRANSMIT) == NULL,
			       "get24-NULL-again");

	/* t5: id-37 echo returns the wl_radio_idx carried at arg+16
	 * (H37: wl_wfd_bind stack build + bcm_archer.h). Unit 0 keeps the
	 * old stub-0 verdict; units 1..3 now bind instead of aborting. */
	echo37 = f37;
	memset(&barg, 0, sizeof(barg));
	barg.wl_radio_idx = 0;
	BCMFUN24_CHECK(echo37(&barg) == 0, "echo0");
	barg.wl_radio_idx = 1;
	BCMFUN24_CHECK(echo37(&barg) == 1, "echo1");
	barg.wl_radio_idx = 3;
	BCMFUN24_CHECK(echo37(&barg) == 3, "echo3");
	BCMFUN24_CHECK(echo37(NULL) == 0, "echo-null");
	BCMFUN24_CHECK(bcmFun_get(WL_BCMFUN_ARCHER_BIND) == wl_bcmfun37_echo,
		       "echo-stable");

	/* t6: the 6-byte station-MAC stitch (H37 §3): LE word at pub+8
	 * plus LE halfword at pub+12 is byte-identical to memcpy.
	 * Reference bytes: H24-crash r1 = 0x00181002 for a MAC starting
	 * 02:10:18:00. */
	{
		const uint8_t mac[6] = { 0x02, 0x10, 0x18, 0x00, 0xAA, 0x55 };
		uint32_t word;
		uint16_t half;
		uint8_t out[6];

		memcpy(&word, mac, 4);
		memcpy(&half, mac + 4, 2);
		BCMFUN24_CHECK(word == 0x00181002U, "mac-word");
		memcpy(out, &word, 4);
		memcpy(out + 4, &half, 2);
		BCMFUN24_CHECK(memcmp(out, mac, 6) == 0, "mac-stitch");
	}

	if (nfail) {
		pr_err("wl_compat: BCMFUN37_SELFTEST FAIL %d/%d\n",
		       nfail, ntot);
		return -EINVAL;
	}
	pr_info("wl_compat: BCMFUN37_SELFTEST PASS checks=%d (registry)\n",
		ntot);
	return wlcompat_proc_selftest();
}

int wl_compat_subinit(void)
{
	int ret = 0;

	spin_lock_init(&wl_d3lut_table.lock);
	d3lut_gp = &wl_d3lut_table;
	pr_info("wl_compat: BCA wl.ko shim up (d3lut %p, gbpm %p)\n",
		d3lut_gp, &gbpm_g);
	if (bcmfun24_selftest)
		ret = wl_bcmfun24_selftest();
	if (!ret && d3lut_selftest)
		ret = wl_d3lut_selftest();
	if (!ret && gbpm_abi_selftest)
		ret = wl_gbpm_abi_selftest();
	return ret;
}
