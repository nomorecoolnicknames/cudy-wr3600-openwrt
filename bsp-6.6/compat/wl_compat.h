/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wl_compat.h — declarations for the wl.ko (BCA 4.19) compatibility shim.
 *
 * Covers the Broadcom-proprietary UND symbols of stock radio/wl.ko,
 * radio/hnd.ko and radio/wlshared.ko that exist neither in vanilla 6.6
 * nor in stock hnd.ko exports. See triaging/UND_SYMBOLS_419_TO_66.md §6
 * and triaging/shim/SHIM_B_SUMMARY.md for per-symbol provenance.
 *
 * Every symbol in wl_compat.c is exported with EXPORT_SYMBOL (never _GPL):
 * wl.ko is MODULE_LICENSE("Proprietary") and cannot resolve _GPL exports.
 */
#ifndef _WL_COMPAT_H
#define _WL_COMPAT_H

#include <linux/types.h>

struct net_device;
struct sk_buff;

/* ---- A. GPL ports (bcmkernel / bcm_pktfwd heritage) ---- */
struct net_device *netdev_path_get_root(struct net_device *dev);
void skb_cb_zero(struct sk_buff *skb);
void skb_bpm_tainted(struct sk_buff *skb);
int blog_clone_wlan(struct sk_buff *skb2, struct sk_buff *skb1);
void nbuff_free_ex(void *pbuf, int in_thread);
void dev_kfree_skb_thread_bulk(struct sk_buff *head, struct sk_buff *tail,
			       uint32_t len);

/*
 * gbpm_g: on BCA this is "gbpm_t gbpm_g" (struct of ~28 hook pointers,
 * bcmkernel/include/linux/gbpm.h). wl.ko reads slot #23 (get_avail_bufs)
 * and calls it; hnd.ko uses slots #1 (free_mult_buf), #10
 * (alloc_mult_buf_skb_attach) and #12 (free_skb). Layout below keeps the
 * same slot order; each slot points at a safe stub. 32 slots cover all
 * BIND hooks plus margin.
 */
#define WL_GBPM_SLOTS	32
/* BIND slot indexes (must match gbpm.h GBPM_BIND() order) */
#define WL_GBPM_ALLOC_MULT_BUF		0
#define WL_GBPM_FREE_MULT_BUF		1
#define WL_GBPM_ALLOC_BUF		2
#define WL_GBPM_FREE_BUF		3
#define WL_GBPM_TOTAL_SKB		4
#define WL_GBPM_AVAIL_SKB		5
#define WL_GBPM_ATTACH_SKB		6
#define WL_GBPM_ATTACH_SKB_NO_SHINFO	7
#define WL_GBPM_ALLOC_SKB		8
#define WL_GBPM_ALLOC_BUF_SKB_ATTACH	9
#define WL_GBPM_ALLOC_MULT_BUF_SKB	10
#define WL_GBPM_ALLOC_MULT_SKB		11
#define WL_GBPM_FREE_SKB		12
#define WL_GBPM_FREE_SKBLIST		13
#define WL_GBPM_INVALIDATE_DIRTYP	14
#define WL_GBPM_RECYCLE_SKB		15
#define WL_GBPM_ATTACH_SKB_HW_BUF	16
#define WL_GBPM_RECYCLE_SKB_HW_BUF	17
#define WL_GBPM_FREE_MULT_SKB_AND_BUF	18
#define WL_GBPM_IS_SKB_WITH_HW_BUF	19
#define WL_GBPM_RECYCLE_PNBUFF		20
#define WL_GBPM_GET_DYN_BUF_LVL		21
#define WL_GBPM_GET_TOTAL_BUFS		22
#define WL_GBPM_GET_AVAIL_BUFS		23
#define WL_GBPM_GET_MAX_DYN_BUFS	24
#define WL_GBPM_IS_BUF_HW_RECY_CAPABLE	25
#define WL_GBPM_RECYCLE_HW_BUF		26
#define WL_GBPM_REGISTER_HW_POOL_API	27

struct wl_gbpm {
	void *slot[WL_GBPM_SLOTS];
};
extern struct wl_gbpm gbpm_g;

/* ---- B. D3 LUT / D3FWD in-RAM (opaque handles, layout-compatible) ---- */
extern void *d3lut_gp;	/* singleton table pointer, set at module init */
void *d3lut_ins(void *d3lut, uint8_t *sym, uint32_t pool,
		uint32_t policy);
void *d3lut_del(void *d3lut, uint8_t *sym, uint32_t pool);
void *d3lut_lkup(void *d3lut, uint8_t *sym, uint32_t pool);
void d3lut_clr(void *d3lut, void *ext, bool ignore_ext_match);
void d3lut_dump(void *d3lut);
void d3lut_policy_set(void *d3lut, uint32_t pool, uint32_t policy);
void d3fwd_wlif_dump(void *d3fwd_wlif);
/* wl_update_d3lut_and_blog: provided by stock wlshared.ko, NOT here
 * (duplicate export would fail insmod). */

/* ---- C. EMF client / IGS stubs + board stubs ---- */
int emfc_init(void *a, void *b, void *c, void *d);
void emfc_exit(void *handle);
int emfc_input(void *handle, void *a, void *b, void *c, unsigned int d);
int emfc_ipv6_input(void *handle, void *a, void *b, void *c,
		    unsigned int d);
int emfc_cfg_request_process(void *handle);
int igsc_init(void *a, void *b, void *c, void *d, unsigned int e);
void igsc_exit(void *handle);
int igsc_sdb_interface_del(void *handle, void *arg);
int igsc_interface_rtport_del(void *handle, void *arg);
void kerSysRegisterDyingGaspHandler(char *devname, void *cbfn,
				    void *context);
void kerSysDeregisterDyingGaspHandler(char *devname);
unsigned int kerSysGetWifiLed(unsigned char core);
void kerSysWifiLed(unsigned int led, unsigned int on);

/* ---- D. bcmFun callback registry ---- */
void *bcmFun_get(int fun_id);
int bcmFun_reg(int fun_id, void *fun);
void bcmFun_dereg(int fun_id);

/* ---- E. allocator + pktlist (GPL bcm_pktfwd heritage) ---- */
void *kmalloc_order(size_t size, gfp_t flags, unsigned int order);
void *pktlist_context_init(void *peer, void *xfer_fn, void *keymap_fn,
			   void *driver, const char *driver_name,
			   uint32_t unit);
void *pktlist_context_fini(void *pktlist_context);
void pktlist_context_dump_all(void);

/* ---- F. REMOVED at merge D: wlcsm_nvram_k_{get,set,getall} live in
 * stock bcm_knvram.ko (duplicate export would fail its insmod);
 * kerSysGetMacAddress lives in shim_nvram.c. ---- */

/* ---- G. blog extras + board MAC (reloc audit beyond the 28) ---- */
void *blog_get(void);
int _blog_emit(void *nbuff, void *dev, uint32_t encap, uint32_t channel,
	       uint32_t phy_hdr, void *fc_args);
int _blog_sinit(void *skb, void *dev, uint32_t encap, uint32_t channel,
		uint32_t phy_hdr, void *fc_args);
void blog_notify_async_wait(uint32_t event, void *net,
			    unsigned long param1, unsigned long param2);
void blog_inc_wlan_mcast_client_count(struct sk_buff *skb);
/* kerSysGetMacAddress: provided by shim_nvram.c (NOT here — one
 * definition per module). */

/* ---- H. nbuff/pktqueue leftovers (same BCA family, reloc-proven) ---- */
struct sk_buff *fkb_xlate(void *fkb);
void pktqueue_context_dump_all(void);

#endif /* _WL_COMPAT_H */
