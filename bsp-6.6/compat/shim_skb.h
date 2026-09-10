/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_SKB_H
#define BCM_SHIM_SKB_H
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <uapi/linux/nl80211.h>
struct skb419_view;
struct netdev419_view;
/* Internal API for owned, linear 4.19 packet buffers. Not blob imports yet.
 * The caller owns a descriptor reference; mutations require exclusive ownership.
 * On free error ownership is retained. No native skb may be passed here. */
struct skb419_view *shim_skb_alloc(unsigned int size, gfp_t gfp);
struct skb419_view *shim_skb_clone(struct skb419_view *skb, gfp_t gfp);
struct skb419_view *shim_skb_copy(struct skb419_view *skb, gfp_t gfp);
struct skb419_view *shim_skb_copy_headroom(struct skb419_view *skb, int headroom, gfp_t gfp);
int shim_skb_free(struct skb419_view *skb);
/* import consumes one native reference ONLY on success (ERR_PTR on failure).
 * export returns a native COPY; old reference remains owned by the caller.
 * Native GSO/timestamp/zerocopy and unknown netdevs need further adaptation. */
struct skb419_view *shim_skb_import(struct sk_buff *native, gfp_t gfp);
struct sk_buff *shim_skb_export(struct skb419_view *old, gfp_t gfp);
int shim_skb_reserve(struct skb419_view *old, unsigned int len);
int shim_skb_pool_reset(struct skb419_view *old, unsigned int headroom,
			unsigned int len);
void *shim_skb_put(struct skb419_view *old, unsigned int len);
void *shim_skb_push(struct skb419_view *old, unsigned int len);
void *shim_skb_pull(struct skb419_view *old, unsigned int len);
int shim_skb_trim(struct skb419_view *old, unsigned int len);
bool shim_skb_is_legacy(const void *ptr);
int shim_skb_dispatch_init(void);
int shim_skb_init(void);
/* Leak check only: views are caller-owned (no registry), the selftests
 * assert counters return to baseline. Reports live headers/buffers,
 * never frees foreign-owned descriptors. Idempotent, NULL-safe. */
void shim_skb_exit(void);

/* RXTX S1: legacy-descriptor allocators. gfp419 is the raw 4.19 flag word
 * (translated via shim_gfp419); dev is stored as the caller's legacy view.
 * bcm419_legacy_* names avoid clashing with the native-skb bcm419_* family
 * in shim_alloc.c (same UND short names, different descriptor ABI). */
struct skb419_view *bcm419_legacy_skb_alloc(unsigned int size,
					    unsigned int gfp419);
struct skb419_view *bcm419_legacy_skb_clone(struct skb419_view *skb,
					    unsigned int gfp419);
struct skb419_view *bcm419_legacy_skb_copy(struct skb419_view *skb,
					   unsigned int gfp419);
struct skb419_view *bcm419_legacy_netdev_alloc_skb(struct netdev419_view *dev,
						   unsigned int len,
						   unsigned int gfp419);

/* RXTX S2: B1/B2. 4.19 void(struct sk_buff *) semantics on legacy views. */
void bcm419_skb_cb_zero(struct skb419_view *skb);
void bcm419_skb_bpm_tainted(struct skb419_view *skb);

/* Legacy 4.19 struct sk_buff_head geometry (next@0, prev@4, qlen@8,
 * lock@12, 16 bytes; SK419_off_sk_buff_head_*). The lock word is carried
 * for layout compatibility only and never taken (see purge below). */
struct skb419_head {
	struct skb419_view *next;
	struct skb419_view *prev;
	u32 qlen;
	u32 lock;
};

/* RXTX S3: legacy free path + B3 bulk. The void fns cannot report failure:
 * a refused descriptor warns once and keeps its ownership (intentional
 * leak; S9 must never double-free after a warning). NULL is a safe no-op
 * like the 4.19 originals. */
void bcm419_kfree_skb(struct skb419_view *skb);
void bcm419_consume_skb(struct skb419_view *skb);
void bcm419___dev_kfree_skb_any(struct skb419_view *skb,
				enum skb_drop_reason reason);
void bcm419_skb_queue_purge(struct skb419_head *list);
void bcm419_dev_kfree_skb_thread_bulk(struct skb419_view *head,
				      struct skb419_view *tail, u32 len);

/* RXTX S4: header/data manipulation. 4.19 net/core/skbuff.c semantics
 * (void * push/pull/put, void trim, int ___pskb_trim) on legacy views.
 * Bounds failures warn once and degrade to NULL/no-op instead of the 4.19
 * skb_over/under_panic: S9 must size buffers so these never fire. */
void *bcm419_skb_put(struct skb419_view *skb, unsigned int len);
void *bcm419_skb_push(struct skb419_view *skb, unsigned int len);
void *bcm419_skb_pull(struct skb419_view *skb, unsigned int len);
void bcm419_skb_trim(struct skb419_view *skb, unsigned int len);
int bcm419____pskb_trim(struct skb419_view *skb, unsigned int len);

/* RXTX S5: B7 VLAN import/export as callable entry points. The blob has no
 * *vlan* UND (tag travels in-frame, descriptor field touched inline), so
 * these exist for S9-generated call sites and for tests, not as rel-patch
 * targets. Logic is NOT duplicated: get/set reuse the H13 DEI gate
 * (vlan_tci PRESENT bit + bcm_ext cfi_save) that shim_skb_export/import
 * already use. Full-TCI convention matches native (PCP+DEI+VID in one u16,
 * presence = tag exists); legacy stores PRESENT|(tci & ~PRESENT) in
 * vlan_tci and the true DEI bit in cfi_save. */
bool bcm419_vlan_tag_present(const struct skb419_view *skb);
int bcm419_vlan_tag_get(const struct skb419_view *skb, __be16 *proto,
			u16 *tci);
int bcm419_vlan_tag_set(struct skb419_view *skb, __be16 proto, u16 tci);
void bcm419_vlan_tag_clear(struct skb419_view *skb);

/* RXTX S6: RX delivery legacy -> native -> stack. Mirrors the blob's
 * wl_sendup* tail (export + eth_type_trans + netif_rx, H15 §1): the two
 * kernel calls stay direct (same signatures on 6.6), this wrapper only
 * sequences them over the converted buffer. Consumes the legacy view on
 * any completed export (frees it even when the stack drops); when export
 * itself fails the legacy view is retained and the negative errno is
 * returned. gfp419 is the raw 4.19 flag word (shim_gfp419). */
int bcm419_rx_deliver(struct skb419_view *old, unsigned int gfp419);

/* RXTX S7: TX entry native -> legacy + TX-queue wake. Mirrors the blob's
 * wl_start head (H15 §2: wl_xlate_to_skb stamps dev into pkt+8, then
 * internal queues + DMA): native dev maps to the stored legacy view
 * inside shim_skb_import, native vlan_all materializes into the frame.
 * Import consumes the native reference ONLY on success (ERR_PTR/NULL on
 * failure keeps it with the caller, same contract as shim_skb_import).
 * The wake wrapper resolves the TX queue through shim_netdev_native() +
 * netdev_get_tx_queue() (H15 §2 B8 rule: never a raw 4.19 offset); an
 * unknown dev or out-of-range index warns once and does nothing.
 * gfp419 is the raw 4.19 flag word (shim_gfp419). */
struct skb419_view *bcm419_tx_import(struct sk_buff *native,
				     unsigned int gfp419);
void bcm419_netif_tx_wake_queue(struct netdev419_view *old,
				unsigned int qidx);

/* RXTX EAPOL (H30 §7): WPA-handshake-scoped TX entry. Gates on 802.1X shape
 * (ETH_HLEN + 4B header present, ethertype 0x888E) then delegates to
 * bcm419_tx_import with the identical ownership contract (success consumes
 * the native reference; every refuse retains it, NULL). Production opening
 * is the xmit gate in shim_netdev.c (ready==ALL + explicit xmit_handshake=1
 * module param, default closed) — this wrapper never opens anything; it is
 * the auditable first-TX frame class for S9/tests. */
struct skb419_view *bcm419_tx_eapol(struct sk_buff *native,
				    unsigned int gfp419);

/* GSO lane (triaging/shim/skb-gso/REPORT.md): segmenting TX entry +
 * queue drain. bcm419_tx_import refuses GSO (S9 must call the entry
 * below instead): it runs the native 6.6 segmenter (skb_gso_segment,
 * features=0 — pure software segmentation, checksums completed) and
 * imports every segment as a legacy linear view chained into *list
 * (legacy skb419_head: next/prev/qlen; lock word stays 0, never taken,
 * same rule as bcm419_skb_queue_purge). Returns the segment count (>0)
 * with the native reference consumed. On segmenter failure the native
 * reference is retained and -EOPNOTSUPP (or the segmenter errno) is
 * returned with *list left empty. On import failure past a successful
 * segmentation everything (imported views + remaining native segments)
 * is freed and the negative errno returned — the native reference is
 * then consumed. bcm419_skb_queue_drain frees a filled list (warns once
 * and leaks only the refused view, same ownership rule as the S3 void
 * family). gfp419 is the raw 4.19 word (shim_gfp419). */
int shim_skb_import_gso(struct sk_buff *native, gfp_t gfp,
			struct skb419_head *list);
int bcm419_tx_import_gso(struct sk_buff *native, unsigned int gfp419,
			 struct skb419_head *list);
void bcm419_skb_queue_drain(struct skb419_head *list);

/* RXTX S8: B6 cfg80211-upcall converters (blob 419 -> native 66).
 * The blob was built against the BCA 4.19 tree (see UND_SYMBOLS §4):
 * ch_switch had no link_id/punct, connect/roam carried bssid/bss flat
 * instead of links[], cac chandef had no edmg/freq1_offset, external_auth
 * had no pmkid (stock has CONFIG_BCM_KF_NL80211_EXTAUTH_MLD_ADDR=y, so
 * mld_addr IS present). Translators zero the 6.6-only tails; non-MLO
 * upcalls land in links[0] with valid_links=0, like the kernel's own
 * connect_bss/roamed compat inlines. Dev pointers are legacy views
 * (resolved via shim_netdev_native); params are borrowed, never stored.
 * gfp419 is the raw 4.19 word (shim_gfp419). ch_switch takes no gfp on
 * either side (sleepable, wdev_lock held by caller).
 * Vendor/event SKBs are NOT duplicated here: wl_cfgvendor_* keeps using
 * bcm419___cfg80211_alloc_event_skb (shim_alloc.c, portid=0). */
struct ieee80211_channel;
struct cfg80211_bss;

/* 4.19-layout sub-structures (byte-identical to the 6.6 ones, asserted
 * in shim_skb.c). Separate names so this header never needs
 * <net/cfg80211.h>, whose 6.6 inline cfg80211_find_ie_match would
 * collide with shim_core.c's 4.19 global of the same name. */
struct ssid419 {
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len;
};
struct fils_resp419 {
	const u8 *kek;
	size_t kek_len;
	bool update_erp_next_seq_num;
	u16 erp_next_seq_num;
	const u8 *pmk;
	size_t pmk_len;
	const u8 *pmkid;
};
struct cfg80211_chandef419 {
	struct ieee80211_channel *chan;
	enum nl80211_chan_width width;
	u32 center_freq1;
	u32 center_freq2;
};
struct cfg80211_connect_resp419 {
	int status;
	const u8 *bssid;
	struct cfg80211_bss *bss;
	const u8 *req_ie;
	size_t req_ie_len;
	const u8 *resp_ie;
	size_t resp_ie_len;
	struct fils_resp419 fils;
	enum nl80211_timeout_reason timeout_reason;
};
struct cfg80211_roam_info419 {
	struct ieee80211_channel *channel;
	struct cfg80211_bss *bss;
	const u8 *bssid;
	const u8 *req_ie;
	size_t req_ie_len;
	const u8 *resp_ie;
	size_t resp_ie_len;
	struct fils_resp419 fils;
};
struct cfg80211_external_auth419 {
	enum nl80211_external_auth_action action;
	u8 bssid[ETH_ALEN] __aligned(2);
	struct ssid419 ssid;
	unsigned int key_mgmt_suite;
	u16 status;
	u8 mld_addr[ETH_ALEN] __aligned(2);
};
void bcm419_cfg80211_ch_switch_notify(struct netdev419_view *old,
				      struct cfg80211_chandef419 *chandef);
void bcm419_cfg80211_connect_done(struct netdev419_view *old,
				  struct cfg80211_connect_resp419 *params,
				  unsigned int gfp419);
void bcm419_cfg80211_roamed(struct netdev419_view *old,
			    struct cfg80211_roam_info419 *info,
			    unsigned int gfp419);
void bcm419_cfg80211_cac_event(struct netdev419_view *old,
			       struct cfg80211_chandef419 *chandef,
			       enum nl80211_radar_event event,
			       unsigned int gfp419);
int bcm419_cfg80211_external_auth_request(struct netdev419_view *old,
					  struct cfg80211_external_auth419 *params,
					  unsigned int gfp419);
#endif
