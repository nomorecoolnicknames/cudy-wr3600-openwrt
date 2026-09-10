// SPDX-License-Identifier: GPL-2.0-only
/* H14: separate legacy/native wiphy + wireless_dev views.
 * Uninitialized alloc/free lifecycle only, plus validated field publish
 * without registration. Not wired to blob imports yet: wiphy_register,
 * band/cipher deep translation, netdev bridging and the ops-thunk
 * attachment (lane D wl_66_ops, cfg80211_compat_attach_blob) are later
 * steps. No pretend registration, no packet callbacks. */
/* H28 (wiphy-reject lane): wired. bcm_shim_wiphy_* wrappers serve the
 * blob's renamed UND (modvermagic --rename-wiphy): shim-alloc returns the
 * legacy view, shim-register runs publish -> real wiphy_register ->
 * sync, free/unregister translate legacy -> native. Deep translation
 * covers bands/channels/rates/caps/ciphers/combinations/mgmt_stypes and
 * per-band HE iftype_data (field-mapped 4.19 -> 6.6, EHT zeroed); the 6 GHz
 * band is published when the blob provides HE for it (skipped loud
 * otherwise). WDS mode is stripped. S1G/LC slots stay NULL (no 4.19
 * source, no such PHY on BCM6764). */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/etherdevice.h>
#include <linux/overflow.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>
#include "shim_wiphy.h"
#include "shim_netdev.h"
#include "shim_wiphy_layout.h"
#include "shim_wiphy_flags.h"

/* Lane-D integration without touching cfg80211_compat.* (file boundary):
 * the blob ops table type stays opaque here — the wrapper only carries
 * the pointer to cfg80211_compat_attach_blob(), never reads it. The
 * native table is borrowed (static, module lifetime). */
struct wl419_ops;
extern void cfg80211_compat_attach_blob(const struct wl419_ops *blob_ops);
extern void cfg80211_compat_detach_blob(void);
extern const struct cfg80211_ops wl_66_ops;
/* Lane-G nvram backend (same module, shim_nvram.c): primary MAC source for
 * publish when the blob leaves perm_addr zero. Contract: NULL on miss,
 * returned pointer valid until the next k_set of the same key (we copy
 * immediately via mac_pton, so no lifetime issue). */
extern char *wlcsm_nvram_k_get(char *name);

/* 4.19 nested geometry used by the deep translators below. Measured with
 * a compiler probe (same technique as triaging/shim/wiphy-h14/probe.py):
 * layout-wiphy.c command lines compiled a nest probe against the BCA
 * 4.19.246 tree and 6.6.93, values extracted from ELF .data. Native-side
 * twins are pinned by static_asserts in shim_wiphy_init(); anything that
 * moves breaks the build instead of miscopying on the router.
 *  band 68 B: {channels@0, bitrates@4, band@8, n_channels@12,
 *    n_bitrates@16, ht_cap@20 (22 B), vht_cap@44 (16 B),
 *    n_iftype_data@60 (u16), iftype_data@64} (6.6: 92 B, s1g+edmg
 *    inserted before n_iftype_data@84/iftype_data@88).
 *  channel 52 B: {band@0, center_freq u16@4, hw_value u16@6, flags@8,
 *    max_antenna_gain@12, max_power@16, max_reg_power@20,
 *    beacon_found@24, orig_flags@28, orig_mag@32, orig_mpwr@36,
 *    dfs_state@40, dfs_state_entered@44, dfs_cac_ms@48} (6.6: 56 B,
 *    center_freq widened to u32@4, freq_offset u16@8 inserted).
 *  rate 12 B both, field-identical. combination 20 B both, field-
 *  identical (limits@0, num_different_channels@4, max_interfaces@8,
 *  n_limits@10, beacon match@11, radar widths/regions/gcd@12..19 —
 *  present in the BCA 4.19 tree too). iface_limit 4 B both
 *  ({max@0, types@2}). txrx_stypes 4 B both. wiphy bands 4 vs 6 slots,
 *  interface types 12 both (WDS=5 both). */
#define WP419_SZ_BAND			68
#define WP419_O_BAND_CHANNELS		0
#define WP419_O_BAND_BITRATES		4
#define WP419_O_BAND_BAND		8
#define WP419_O_BAND_NCHAN		12
#define WP419_O_BAND_NRATES		16
#define WP419_O_BAND_HT			20
#define WP419_SZ_STA_HT			22
#define WP419_O_BAND_VHT		44
#define WP419_SZ_STA_VHT		16
#define WP419_O_BAND_NIFTYPE		60
#define WP419_O_BAND_IFTYPE		64
#define WP419_SZ_CHAN			52
#define WP419_O_CHAN_FREQ		4
#define WP419_O_CHAN_HW			6
#define WP419_O_CHAN_FLAGS		8
#define WP419_O_CHAN_MAG		12
#define WP419_O_CHAN_MPWR		16
#define WP419_O_CHAN_REGPWR		20
#define WP419_O_CHAN_BEACON		24
#define WP419_O_CHAN_OFLAGS		28
#define WP419_O_CHAN_OMAG		32
#define WP419_O_CHAN_OMPWR		36
#define WP419_O_CHAN_DFS		40
#define WP419_O_CHAN_DFSENT		44
#define WP419_O_CHAN_DFSCAC		48
#define WP419_SZ_RATE			12
#define WP419_SZ_COMB			20
/* 4.19 per-interface-type band data (BCA tree with
 * CONFIG_BCM_KF_NL80211_HE_6G_CAP_SUPPORT=y, compiler-measured, see the
 * wiphy-bands REPORT for the full 419-vs-66 probe table):
 *  iftype 56 B: {types_mask u16@0, he_cap@2 {has_he bool@0, he_cap_elem@1
 *    (14 B: mac[5]+phy[9], D2.0), he_mcs@15 (12 B), ppe_thres@27 (25 B)},
 *    he_6ghz_capa@54 (2 B __le16)}.
 * 6.6 entry is 120 B: same mask@0 and he_cap@2, but he_cap_elem is 17 B
 * (mac[6]+phy[11], final spec — growth is append-only, byte meanings
 * identical, verified define-by-define) so mcs shifts to 18 and ppe to 30;
 * then he_6ghz_capa@57, eht_cap@59 (53 B, absent in 4.19) and
 * vendor_elems@112 (absent in 4.19). Translation is therefore field-wise,
 * never whole-struct: elem prefix-copied (14 B) with the 3 new tail bytes
 * zeroed (newer caps the blob firmware lacks -> advertised unsupported,
 * the truthful direction: zeroed bits can only shrink computed PPE/decl
 * lengths, never extend them into garbage), mcs/ppe/he6g 1:1, EHT zeroed
 * (has_eht=false; the blob keeps EHT in phy_ac_ehtcap getters + firmware,
 * not in the 4.19 sband, so there is nothing to copy — `iw list` shows no
 * EHT, the data path is blob-internal and unaffected), vendor NULL/0. */
#define WP419_SZ_IFTYPE		56
#define WP419_O_IFTYPE_MASK		0
#define WP419_O_IFTYPE_HE		2
#define WP419_SZ_HECAP		52
#define WP419_O_HE_HAS		0
#define WP419_O_HE_ELEM		1
#define WP419_SZ_HE_ELEM419		14
#define WP419_SZ_HE_MAC419		5
#define WP419_SZ_HE_PHY419		9
#define WP419_SZ_HE_ELEM66		17
#define WP419_O_HE_MCS		15
#define WP419_SZ_HE_MCS		12
#define WP419_O_HE_PPE		27
#define WP419_SZ_HE_PPE		25
#define WP419_O_IFTYPE_HE6G		54
#define WP419_SZ_HE6G		2
/* types_mask is u16 with non-overlapping bits per entry (enforced at
 * publish, mirroring the 6.6 register gates), so more than
 * NL80211_IFTYPE_MAX entries can never validate. */
#define WP419_MAX_IFTYPE_DATA		12
#define WP419_O_COMB_LIMITS		0
#define WP419_O_COMB_NLIM		10
#define WP419_SZ_LIMIT			4
#define WP419_SZ_TXRX			4
#define WP419_NUM_BANDS			4
#define WP419_NL80211_IFTYPE_MAX	12
/* Sanity caps for blob-owned counts (validate-first, never trust the
 * blob with an unbounded kcalloc): comfortably above the measured blob
 * values (bands 14/32/60 ch, 8/12 rates, 10 ciphers, 1 combination). */
#define WP419_MAX_CHANNELS		128
#define WP419_MAX_BITRATES		32
#define WP419_MAX_CIPHERS		64
#define WP419_MAX_COMBS			8
#define WP419_MAX_COMB_LIMITS		8

struct wiphy419_view {
	u8 bytes[WP419_size_wiphy];
	u8 priv[];
};

struct wdev419_view {
	u8 bytes[WP419_size_wireless_dev];
};

/* Stock cfg80211.h: 20-byte command vs 28-byte native command.
 * wl_cfgvendor_attach publishes two raw commands, three 8-byte events. */
struct vendor419_command {
	struct nl80211_vendor_cmd_info info;
	u32 flags;
	int (*doit)(struct wiphy *, struct wireless_dev *, const void *, int);
	int (*dumpit)(struct wiphy *, struct wireless_dev *, struct sk_buff *,
		      const void *, int, unsigned long *);
};

struct wiphy419_entry {
	struct list_head list;
	struct wiphy *native;
	struct wiphy419_view *old;
	void *allocation;
	int priv_size;
	/* Borrowed ops table handed to wiphy_new_nm (static storage, never
	 * freed: &shim_stripped_ops in production, test tables in
	 * selftests). Kept for introspection (selftest asserts the
	 * stripped table); publish needs no flag-gated ops today. */
	const struct cfg80211_ops *ops_used;
	/* Raw blob ops table this entry was attached with (lane-D global at
	 * attach time). Compared on re-attach: a different pointer means the
	 * wl incarnation changed (rmmod/insmod gives a new .data address),
	 * so stale unregistered entries from the dead incarnation are
	 * dropped by the new_nm guard instead of dangling. */
	const void *blob_ops;
	/* Publish-owned native translation (unpublish frees every slot
	 * and NULLs the matching native field; slots mirror w->bands[]
	 * so a leak would also be a dangling core pointer). */
	struct ieee80211_supported_band *pub_band[NUM_NL80211_BANDS];
	struct ieee80211_channel *pub_chan[NUM_NL80211_BANDS];
	const u8 *old_chan[NUM_NL80211_BANDS];
	struct ieee80211_rate *pub_rates[NUM_NL80211_BANDS];
	struct ieee80211_sband_iftype_data *pub_iftype[NUM_NL80211_BANDS];
	u32 *pub_ciphers;
	struct ieee80211_txrx_stypes *pub_stypes;
	struct ieee80211_iface_combination *pub_combs;
	struct ieee80211_iface_limit **pub_limits;
	int pub_n_comb;
	struct wiphy_vendor_command *pub_vendor;
	struct nl80211_vendor_cmd_info *pub_events;
	struct vendor419_command vendor419[2];
};

struct wdev419_entry {
	struct list_head list;
	struct wireless_dev *native;
	struct wdev419_view *old;
	bool owns_old;
};

static LIST_HEAD(wiphy419_views);
static LIST_HEAD(wdev419_views);
/* Single mutex for both lists: wdev bind resolves a wiphy pair while
 * holding it, so there is no lock ordering to get wrong. */
static DEFINE_MUTEX(wiphy419_mutex);
/* Native ops for blob wiphys: wl_66_ops minus update_connect_params.
 * The blob's 4.19 table leaves that slot NULL (measured), and 6.6
 * wiphy_register refuses -EINVAL a wiphy that carries the op without
 * WIPHY_FLAG_SUPPORTS_FW_ROAM — which the blob never sets. A static
 * thunk (always -EOPNOTSUPP) is NOT equivalent to NULL here, so strip
 * the op instead of fabricating the flag: exact stock semantics (the
 * 4.19 core saw NULL too). Derived from wl_66_ops at init so thunk
 * additions stay in sync automatically; module-lifetime storage, so
 * wiphy_new_nm's borrowed pointer never dangles (no per-wiphy alloc,
 * no free-after-put_device hazard). */
static struct cfg80211_ops shim_stripped_ops;
static bool wiphy_trace;
module_param(wiphy_trace, bool, 0600);
#define WTRACE(fmt, ...) do { if (wiphy_trace) \
	pr_info("bcm_shim: H30_WIPHY " fmt "\n", ##__VA_ARGS__); } while (0)

static bool wiphy_selftest;
module_param(wiphy_selftest, bool, 0400);
MODULE_PARM_DESC(wiphy_selftest, "Test separate legacy/native wiphy allocation without radio");
static bool wdev_selftest;
module_param(wdev_selftest, bool, 0400);
MODULE_PARM_DESC(wdev_selftest, "Test separate legacy/native wireless_dev allocation without radio");

#define W_OFF(field) WP419_off_wiphy_##field
#define W_WIDTH(field) WP419_width_wiphy_##field
#define D_OFF(field) WP419_off_wireless_dev_##field
#define D_WIDTH(field) WP419_width_wireless_dev_##field
/* memcpy handles old fields with weaker alignment than native types. */
#define COPY_W_TO_OLD(old, w, field) do { \
	static_assert(sizeof((w)->field) == W_WIDTH(field)); \
	memcpy((old)->bytes + W_OFF(field), &(w)->field, sizeof((w)->field)); \
} while (0)
#define COPY_W_FROM_OLD(w, old, field) do { \
	static_assert(sizeof((w)->field) == W_WIDTH(field)); \
	memcpy(&(w)->field, (old)->bytes + W_OFF(field), sizeof((w)->field)); \
} while (0)
#define COPY_D_TO_OLD(old, d, field) do { \
	static_assert(sizeof((d)->field) == D_WIDTH(field)); \
	memcpy((old)->bytes + D_OFF(field), &(d)->field, sizeof((d)->field)); \
} while (0)
#define COPY_D_FROM_OLD(d, old, field) do { \
	static_assert(sizeof((d)->field) == D_WIDTH(field)); \
	memcpy(&(d)->field, (old)->bytes + D_OFF(field), sizeof((d)->field)); \
} while (0)

static int wiphy_flags_to_native(u32 old, u32 *native,
				 const struct wiphy419_flag_pair *pairs, size_t n)
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

static u32 wiphy_flags_to_old(u32 native,
			      const struct wiphy419_flag_pair *pairs, size_t n)
{
	u32 old = 0;
	size_t i;

	for (i = 0; i < n; i++)
		if (native & pairs[i].native)
			old |= pairs[i].old;
	return old;
}

static void *old_ptr_at(const u8 *base, unsigned int off)
{
	const void *p;

	memcpy(&p, base + off, sizeof(p));
	return (void *)p;
}

static void set_old_ptr_at(u8 *base, unsigned int off, const void *p)
{
	memcpy(base + off, &p, sizeof(p));
}

static u32 old_u32_at(const u8 *base, unsigned int off)
{
	u32 v;

	memcpy(&v, base + off, sizeof(v));
	return v;
}

/* Copy the scalar init set native -> old. Pointers, embedded struct
 * device and the core-owned wdev_list are never mirrored: their layouts
 * differ (device 288 vs 472) and they belong to the core. ext_features
 * bytes 0..5 are index-identical (probe-verified); native bytes 6..8
 * (indices 42..64, unknown to the blob) are never exposed. */
static void wiphy419_sync_view(struct wiphy419_view *old, struct wiphy *w)
{
	u32 flags;

	COPY_W_TO_OLD(old, w, interface_modes);
	COPY_W_TO_OLD(old, w, max_acl_mac_addrs);
	COPY_W_TO_OLD(old, w, ap_sme_capa);
	COPY_W_TO_OLD(old, w, signal_type);
	COPY_W_TO_OLD(old, w, bss_priv_size);
	COPY_W_TO_OLD(old, w, max_scan_ssids);
	COPY_W_TO_OLD(old, w, max_sched_scan_reqs);
	COPY_W_TO_OLD(old, w, max_sched_scan_ssids);
	COPY_W_TO_OLD(old, w, max_match_sets);
	COPY_W_TO_OLD(old, w, max_scan_ie_len);
	COPY_W_TO_OLD(old, w, max_sched_scan_ie_len);
	COPY_W_TO_OLD(old, w, max_sched_scan_plans);
	COPY_W_TO_OLD(old, w, max_sched_scan_plan_interval);
	COPY_W_TO_OLD(old, w, max_sched_scan_plan_iterations);
	COPY_W_TO_OLD(old, w, n_cipher_suites);
	COPY_W_TO_OLD(old, w, retry_short);
	COPY_W_TO_OLD(old, w, retry_long);
	COPY_W_TO_OLD(old, w, frag_threshold);
	COPY_W_TO_OLD(old, w, rts_threshold);
	COPY_W_TO_OLD(old, w, coverage_class);
	COPY_W_TO_OLD(old, w, fw_version);
	COPY_W_TO_OLD(old, w, hw_version);
	COPY_W_TO_OLD(old, w, max_remain_on_channel_duration);
	COPY_W_TO_OLD(old, w, max_num_pmkids);
	COPY_W_TO_OLD(old, w, available_antennas_tx);
	COPY_W_TO_OLD(old, w, available_antennas_rx);
	COPY_W_TO_OLD(old, w, probe_resp_offload);
	COPY_W_TO_OLD(old, w, extended_capabilities_len);
	COPY_W_TO_OLD(old, w, n_vendor_commands);
	COPY_W_TO_OLD(old, w, n_vendor_events);
	COPY_W_TO_OLD(old, w, max_ap_assoc_sta);
	COPY_W_TO_OLD(old, w, bss_select_support);
	COPY_W_TO_OLD(old, w, nan_supported_bands);
	COPY_W_TO_OLD(old, w, n_iface_combinations);
	COPY_W_TO_OLD(old, w, software_iftypes);
	COPY_W_TO_OLD(old, w, perm_addr);
	COPY_W_TO_OLD(old, w, addr_mask);
	COPY_W_TO_OLD(old, w, registered);
	memcpy(old->bytes + W_OFF(privid), &w->privid, sizeof(w->privid));
	/* to_old drops unknown bits by construction; publish() rejects them
	 * on the way in, and nothing else mutates flags pre-register, so a
	 * round trip is exact. Verified by the selftest. */
	flags = wiphy_flags_to_old(w->flags, wp419_wiphy_flags,
				   ARRAY_SIZE(wp419_wiphy_flags));
	memcpy(old->bytes + W_OFF(flags), &flags, sizeof(flags));
	flags = wiphy_flags_to_old(w->regulatory_flags, wp419_regulatory_flags,
				   ARRAY_SIZE(wp419_regulatory_flags));
	memcpy(old->bytes + W_OFF(regulatory_flags), &flags, sizeof(flags));
	COPY_W_TO_OLD(old, w, features);
	memcpy(old->bytes + W_OFF(ext_features), w->ext_features,
	       WP419_EXT_FEATURE_OLD_BYTES);
}

struct wiphy419_view *shim_wiphy_alloc(int priv_size,
				       const struct cfg80211_ops *native_ops)
{
	struct wiphy419_entry *entry;
	struct wiphy *native;
	void *allocation;
	size_t size;

	if (priv_size < 0 || !native_ops ||
	    check_add_overflow((size_t)priv_size,
		(size_t)WP419_size_wiphy + NETDEV_ALIGN - 1, &size))
		return NULL;
	allocation = kzalloc(size, GFP_KERNEL);
	if (!allocation)
		return NULL;
	/* Native private storage holds only the adapter entry; the blob's
	 * private tail lives in the separate legacy allocation below. */
	native = wiphy_new_nm(native_ops, sizeof(*entry), NULL);
	if (!native) {
		kfree(allocation);
		return NULL;
	}
	entry = wiphy_priv(native);
	entry->native = native;
	entry->allocation = allocation;
	entry->old = PTR_ALIGN(allocation, NETDEV_ALIGN);
	entry->priv_size = priv_size;
	entry->ops_used = native_ops;
	/* wiphy_new_nm kzallocs priv, but pin the publish area explicitly:
	 * unpublish kfree(NULL)s every slot and must see NULLs first. */
	memset(entry->pub_band, 0, sizeof(entry->pub_band));
	memset(entry->pub_chan, 0, sizeof(entry->pub_chan));
	memset(entry->pub_rates, 0, sizeof(entry->pub_rates));
	memset(entry->pub_iftype, 0, sizeof(entry->pub_iftype));
	entry->pub_ciphers = NULL;
	entry->pub_stypes = NULL;
	entry->pub_combs = NULL;
	entry->pub_limits = NULL;
	entry->pub_n_comb = 0;
	wiphy419_sync_view(entry->old, native);
	mutex_lock(&wiphy419_mutex);
	list_add_rcu(&entry->list, &wiphy419_views);
	mutex_unlock(&wiphy419_mutex);
	return entry->old;
}

struct wiphy *shim_wiphy_native(const struct wiphy419_view *old)
{
	struct wiphy419_entry *entry;
	struct wiphy *native = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wiphy419_views, list) {
		if (entry->old == old) {
			native = entry->native;
			break;
		}
	}
	rcu_read_unlock();
	return native;
}

struct wiphy419_view *shim_wiphy_legacy(const struct wiphy *native)
{
	struct wiphy419_entry *entry;
	struct wiphy419_view *old = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wiphy419_views, list) {
		if (entry->native == native) {
			old = entry->old;
			break;
		}
	}
	rcu_read_unlock();
	return old;
}

/* Registry lookup returning the entry (publish/free need more than the
 * native pointer). Same borrowed-pointer discipline as the native/legacy
 * lookups below: RCU protects the walk, the caller must own the object
 * lifetime (the blob's probe path is serial per wiphy). */
static struct wiphy419_entry *wiphy419_entry_of(
	const struct wiphy419_view *old)
{
	struct wiphy419_entry *entry;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wiphy419_views, list) {
		if (entry->old == old) {
			rcu_read_unlock();
			return entry;
		}
	}
	rcu_read_unlock();
	return NULL;
}

/* Drop the publish-owned translation and NULL the matching native
 * fields. Only valid on an UNREGISTERED wiphy (post-register the core
 * owns these pointers); wrapper discipline guarantees it, the WARN
 * catches logic bugs loudly. Idempotent. */
/* No foreign pointer dereference. Channel arrays have different strides;
 * only exact element identities of a published pair are accepted. */
static struct ieee80211_channel *channel_pair(const void *channel, bool to_old)
{
	struct wiphy419_entry *entry;
	struct ieee80211_channel *result = NULL;
	unsigned int b, i;

	if (!channel)
		return NULL;
	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wiphy419_views, list) {
		for (b = 0; b < NUM_NL80211_BANDS; b++) {
			if (!entry->pub_band[b] || !entry->old_chan[b])
				continue;
			for (i = 0; i < entry->pub_band[b]->n_channels; i++) {
				const void *old = entry->old_chan[b] + i * WP419_SZ_CHAN;
				struct ieee80211_channel *native = &entry->pub_chan[b][i];

				if (channel == (to_old ? (const void *)native : old)) {
					result = to_old ? (void *)old : native;
					goto out;
				}
			}
		}
	}
out:
	rcu_read_unlock();
	return result;
}

struct ieee80211_channel *shim_channel_legacy(const struct ieee80211_channel *native)
{
	return channel_pair(native, true);
}

struct ieee80211_channel *shim_channel_native(const struct ieee80211_channel *old)
{
	return channel_pair(old, false);
}

static void wiphy419_unpublish(struct wiphy419_entry *entry)
{
	struct wiphy *w = entry->native;
	int b, i;

	WARN_ON(w->registered);
	/* No callback may run after unregister completes. */
	w->vendor_commands = NULL;
	w->n_vendor_commands = 0;
	w->vendor_events = NULL;
	w->n_vendor_events = 0;
	kfree(entry->pub_vendor);
	kfree(entry->pub_events);
	entry->pub_vendor = NULL;
	entry->pub_events = NULL;
	memset(entry->vendor419, 0, sizeof(entry->vendor419));
	for (b = 0; b < NUM_NL80211_BANDS; b++) {
		if (!entry->pub_band[b])
			continue;
		if (w->bands[b] == entry->pub_band[b])
			w->bands[b] = NULL;
		/* iftype array dies with its band (never installed without
		 * one, never survives it); kzalloc-zeroed tail means no
		 * deep members to free (EHT zero, vendor NULL). */
		kfree(entry->pub_iftype[b]);
		entry->pub_iftype[b] = NULL;
		kfree(entry->pub_chan[b]);
		kfree(entry->pub_rates[b]);
		kfree(entry->pub_band[b]);
		entry->pub_band[b] = NULL;
		entry->pub_chan[b] = NULL;
		entry->old_chan[b] = NULL;
		entry->pub_rates[b] = NULL;
	}
	if (entry->pub_ciphers) {
		if (w->cipher_suites == entry->pub_ciphers)
			w->cipher_suites = NULL;
		w->n_cipher_suites = 0;
		kfree(entry->pub_ciphers);
		entry->pub_ciphers = NULL;
	}
	if (entry->pub_stypes) {
		if (w->mgmt_stypes == entry->pub_stypes)
			w->mgmt_stypes = NULL;
		kfree(entry->pub_stypes);
		entry->pub_stypes = NULL;
	}
	if (entry->pub_combs) {
		if (w->iface_combinations == entry->pub_combs) {
			w->iface_combinations = NULL;
			w->n_iface_combinations = 0;
		}
		if (entry->pub_limits) {
			for (i = 0; i < entry->pub_n_comb; i++)
				kfree(entry->pub_limits[i]);
			kfree(entry->pub_limits);
			entry->pub_limits = NULL;
		}
		kfree(entry->pub_combs);
		entry->pub_combs = NULL;
		entry->pub_n_comb = 0;
	}
}

static void wiphy419_chan_419_to_66(const u8 *src,
				    struct ieee80211_channel *dst)
{
	u16 v16;
	u8 v8;

	/* band is set by the caller (and overwritten by the core at
	 * register); freq zero-extends (all real bands < 65535 MHz). */
	memcpy(&v16, src + WP419_O_CHAN_FREQ, sizeof(v16));
	dst->center_freq = v16;
	dst->freq_offset = 0;
	memcpy(&v16, src + WP419_O_CHAN_HW, sizeof(v16));
	dst->hw_value = v16;
	memcpy(&dst->flags, src + WP419_O_CHAN_FLAGS, sizeof(dst->flags));
	memcpy(&dst->max_antenna_gain, src + WP419_O_CHAN_MAG,
	       sizeof(dst->max_antenna_gain));
	memcpy(&dst->max_power, src + WP419_O_CHAN_MPWR,
	       sizeof(dst->max_power));
	memcpy(&dst->max_reg_power, src + WP419_O_CHAN_REGPWR,
	       sizeof(dst->max_reg_power));
	memcpy(&v8, src + WP419_O_CHAN_BEACON, sizeof(v8));
	dst->beacon_found = v8;
	/* orig_* are re-stamped by the core at register; copy anyway so a
	 * pre-register reader sees blob-consistent values. dfs_state values
	 * are identical in both trees (USABLE/UNAVAILABLE/AVAILABLE). */
	memcpy(&dst->orig_flags, src + WP419_O_CHAN_OFLAGS,
	       sizeof(dst->orig_flags));
	memcpy(&dst->orig_mag, src + WP419_O_CHAN_OMAG,
	       sizeof(dst->orig_mag));
	memcpy(&dst->orig_mpwr, src + WP419_O_CHAN_OMPWR,
	       sizeof(dst->orig_mpwr));
	memcpy(&dst->dfs_state, src + WP419_O_CHAN_DFS,
	       sizeof(dst->dfs_state));
	memcpy(&dst->dfs_state_entered, src + WP419_O_CHAN_DFSENT,
	       sizeof(dst->dfs_state_entered));
	memcpy(&dst->dfs_cac_ms, src + WP419_O_CHAN_DFSCAC,
	       sizeof(dst->dfs_cac_ms));
}

/* Translate one legacy iftype entry array (56 B stride) into native
 * entries (120 B). Field-wise (see the WP419_SZ_IFTYPE comment): the 4.19
 * HE elem is 14 B, the 6.6 one 17 B, so whole-struct copies would
 * misalign mcs/ppe/he6g. Returns 0 with nb->iftype_data installed
 * (n==0 installs nothing and is success: HE-less 2.4/5G bands are legal),
 * -EOPNOTSUPP when an entry fails the same checks the 6.6 register loop
 * applies (nonzero/non-overlapping/in-range mask, has_he). The caller
 * decides whether that fails the whole publish (2.4/5/60G) or skips just
 * the 6 GHz band (graceful degradation: have_band is satisfied by
 * 2.4/5G). EHT stays zero (no 4.19 source), vendor stays NULL/0. */
static int wiphy419_publish_iftype(struct wiphy419_entry *entry,
				   struct ieee80211_supported_band *nb,
				   const u8 *b, int slot)
{
	u16 niftype;
	const u8 *p;
	struct ieee80211_sband_iftype_data *nd = NULL;
	u32 seen = 0;
	int i;

	memcpy(&niftype, b + WP419_O_BAND_NIFTYPE, sizeof(niftype));
	if (!niftype) {
		nb->n_iftype_data = 0;
		nb->iftype_data = NULL;
		return 0;
	}
	if (niftype > WP419_MAX_IFTYPE_DATA)
		return -EOPNOTSUPP;
	memcpy(&p, b + WP419_O_BAND_IFTYPE, sizeof(p));
	if (!p)
		return -EOPNOTSUPP;
	/* kzalloc zeroes the EHT cap (has_eht=false) and vendor_elems
	 * (NULL/0): no 4.19 source exists for either. */
	nd = kcalloc(niftype, sizeof(*nd), GFP_KERNEL);
	if (!nd)
		return -ENOMEM;
	for (i = 0; i < niftype; i++) {
		const u8 *s = p + i * WP419_SZ_IFTYPE;
		struct ieee80211_sband_iftype_data *d = &nd[i];
		u16 types;
		u8 has_he;

		memcpy(&types, s + WP419_O_IFTYPE_MASK, sizeof(types));
		/* Mirror net/wireless/core.c wiphy_register: mask must be
		 * nonzero and unique across entries; additionally refuse
		 * bits beyond NL80211_IFTYPE_MAX (the 6.6 loop does not
		 * range-check, but such bits would index out of the
		 * nl80211 iftype tables on export). */
		if (!types || (seen & types) ||
		    (types & ~((1u << NL80211_IFTYPE_MAX) - 1))) {
			kfree(nd);
			return -EOPNOTSUPP;
		}
		memcpy(&has_he, s + WP419_O_IFTYPE_HE + WP419_O_HE_HAS,
		       sizeof(has_he));
		/* At least one piece of information must be present: the
		 * only one the blob can carry is HE (same gate as 6.6). */
		if (!has_he) {
			kfree(nd);
			return -EOPNOTSUPP;
		}
		seen |= types;
		d->types_mask = types;
		d->he_cap.has_he = true;
		/* Prefix-copy the D2.0 elem (mac[5]+phy[9]) into the
		 * final-spec elem (mac[6]+phy[11]); the 3 tail bytes stay
		 * zeroed (append-only growth, verified define-by-define);
		 * mcs/ppe/he6g are layout-identical payloads. */
		memcpy(d->he_cap.he_cap_elem.mac_cap_info,
		       s + WP419_O_IFTYPE_HE + WP419_O_HE_ELEM,
		       WP419_SZ_HE_MAC419);
		memcpy(d->he_cap.he_cap_elem.phy_cap_info,
		       s + WP419_O_IFTYPE_HE + WP419_O_HE_ELEM +
				WP419_SZ_HE_MAC419,
		       WP419_SZ_HE_PHY419);
		memcpy(&d->he_cap.he_mcs_nss_supp,
		       s + WP419_O_IFTYPE_HE + WP419_O_HE_MCS,
		       WP419_SZ_HE_MCS);
		memcpy(d->he_cap.ppe_thres,
		       s + WP419_O_IFTYPE_HE + WP419_O_HE_PPE,
		       WP419_SZ_HE_PPE);
		memcpy(&d->he_6ghz_capa,
		       s + WP419_O_IFTYPE_HE6G, WP419_SZ_HE6G);
	}
	nb->iftype_data = nd;
	nb->n_iftype_data = niftype;
	entry->pub_iftype[slot] = nd;
	return 0;
}

/* Translate one legacy band (68 B view, walked by memcpy) into a native
 * band. Returns 0 and installs w->bands[slot] on success, 0 with nothing
 * installed for the staged 6 GHz skip (no usable HE entry: 6.6 mandates
 * HE on 6G, and a bare 6G band would -EINVAL the whole wiphy at
 * register), -EOPNOTSUPP for corrupt counts.
 * S1G (slot 4) and LC (slot 5) are never installed: the blob's 4.19 tree
 * has NUM_NL80211_BANDS=4 (no such enum values exist for it), BCM6764 has
 * no S1G/LC PHY (nvram carries only 2.4/5/6G calibration: sb/0 5G+6G
 * incl. 320 MHz EHT keys, sb/1 2.4G), and the 6.6 register loop skips
 * NULL slots. s1g_cap/edmg_cap on installed bands stay zeroed (kzalloc):
 * the blob has none (no 60G EDMG / S1G caps in its bands). */
static int wiphy419_publish_band(struct wiphy419_entry *entry, const u8 *b)
{
	struct wiphy *w = entry->native;
	u32 nchan, nrates, band;
	const void *p;
	struct ieee80211_supported_band *nb;
	struct ieee80211_channel *nc = NULL;
	struct ieee80211_rate *nr = NULL;
	int slot, i, ret;
	bool is_6g;

	memcpy(&nchan, b + WP419_O_BAND_NCHAN, sizeof(nchan));
	memcpy(&nrates, b + WP419_O_BAND_NRATES, sizeof(nrates));
	memcpy(&band, b + WP419_O_BAND_BAND, sizeof(band));
	/* Legacy band enum values are verified identical to 6.6 for
	 * 0..3 (2GHZ/5GHZ/60GHZ/6GHZ); the blob knows no S1GHZ/LC. */
	if (band > NL80211_BAND_6GHZ || nchan == 0 ||
	    nchan > WP419_MAX_CHANNELS || nrates > WP419_MAX_BITRATES ||
	    (nrates == 0 && band != NL80211_BAND_60GHZ))
		return -EOPNOTSUPP;
	slot = (int)band;
	is_6g = (band == NL80211_BAND_6GHZ);
	if (entry->pub_band[slot])
		return -EOPNOTSUPP;
	memcpy(&p, b + WP419_O_BAND_BITRATES, sizeof(p));
	if (nrates && !p)
		return -EOPNOTSUPP;
	memcpy(&p, b + WP419_O_BAND_CHANNELS, sizeof(p));
	if (!p)
		return -EOPNOTSUPP;
	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;
	nc = kcalloc(nchan, sizeof(*nc), GFP_KERNEL);
	if (!nc)
		goto err;
	if (nrates) {
		memcpy(&p, b + WP419_O_BAND_BITRATES, sizeof(p));
		nr = kmemdup(p, nrates * sizeof(*nr), GFP_KERNEL);
		if (!nr)
			goto err;
	}
	memcpy(&p, b + WP419_O_BAND_CHANNELS, sizeof(p));
	for (i = 0; i < (int)nchan; i++) {
		wiphy419_chan_419_to_66((const u8 *)p + i * WP419_SZ_CHAN,
					&nc[i]);
		nc[i].band = slot;
	}
	/* ht/vht caps are layout-identical (22/16 B, asserted at init). */
	memcpy(&nb->ht_cap, b + WP419_O_BAND_HT, WP419_SZ_STA_HT);
	memcpy(&nb->vht_cap, b + WP419_O_BAND_VHT, WP419_SZ_STA_VHT);
	if (is_6g && (nb->ht_cap.ht_supported || nb->vht_cap.vht_supported)) {
		/* 6.6 register -EINVALs HT/VHT on 6G (spec: 6G is HE-only;
		 * the 4.19 tree had no such gate, so strip defensively —
		 * same precedent as the WDS strip, loudly). */
		pr_warn_once("bcm_shim: wiphy publish: stripping HT/VHT on 6 GHz band (HE-only in 6.6)\n");
		nb->ht_cap.ht_supported = false;
		nb->vht_cap.vht_supported = false;
	}
	nb->band = slot;
	nb->n_channels = nchan;
	nb->n_bitrates = nrates;
	nb->channels = nc;
	nb->bitrates = nr;
	/* s1g_cap/edmg_cap stay zeroed (kzalloc): the blob has none.
	 * n_iftype_data/iftype_data come from the translator below. */
	ret = wiphy419_publish_iftype(entry, nb, b, slot);
	if (ret) {
		/* Native iftype (if any) was already dropped inside the
		 * translator; only the band-local parts leak here. */
		kfree(nc);
		kfree(nr);
		kfree(nb);
		if (!is_6g)
			return ret;
		pr_warn_once("bcm_shim: wiphy publish: 6 GHz band skipped (unusable HE iftype entries)\n");
		return 0;
	}
	if (is_6g && !nb->n_iftype_data) {
		/* A bare 6G band would fail the whole register at the 6.6
		 * !have_he gate; skip it loud instead (2.4/5G still
		 * satisfy have_band). */
		pr_warn_once("bcm_shim: wiphy publish: 6 GHz band skipped (no HE iftype entries)\n");
		kfree(nc);
		kfree(nr);
		kfree(nb);
		return 0;
	}
	w->bands[slot] = nb;
	entry->pub_band[slot] = nb;
	entry->pub_chan[slot] = nc;
	memcpy(&entry->old_chan[slot], b + WP419_O_BAND_CHANNELS, sizeof(void *));
	entry->pub_rates[slot] = nr;
	return 0;
err:
	kfree(nc);
	kfree(nb);
	return -ENOMEM;
}

static int wiphy419_publish_ciphers(struct wiphy419_entry *entry,
				    struct wiphy419_view *old)
{
	struct wiphy *w = entry->native;
	u32 n = old_u32_at(old->bytes, W_OFF(n_cipher_suites));
	const void *p;

	memcpy(&p, old->bytes + W_OFF(cipher_suites), sizeof(p));
	if (!n) {
		w->cipher_suites = NULL;
		w->n_cipher_suites = 0;
		return 0;
	}
	if (!p || n > WP419_MAX_CIPHERS)
		return -EOPNOTSUPP;
	/* Cipher selectors are opaque u32 (incl. the 00-90-4C Broadcom
	 * OUI the blob advertises); the core does not validate values. */
	entry->pub_ciphers = kmemdup(p, n * sizeof(u32), GFP_KERNEL);
	if (!entry->pub_ciphers)
		return -ENOMEM;
	w->cipher_suites = entry->pub_ciphers;
	w->n_cipher_suites = n;
	return 0;
}

static int wiphy419_publish_stypes(struct wiphy419_entry *entry,
				   struct wiphy419_view *old)
{
	struct wiphy *w = entry->native;
	const void *p;

	memcpy(&p, old->bytes + W_OFF(mgmt_stypes), sizeof(p));
	if (!p) {
		w->mgmt_stypes = NULL;
		return 0;
	}
	/* One {tx,rx} mask pair per interface type; table shape is
	 * identical (12 x 4 B both, asserted at init). No core-side
	 * validation at register (runtime use only). */
	entry->pub_stypes = kmemdup(p, WP419_NL80211_IFTYPE_MAX *
				       sizeof(*entry->pub_stypes), GFP_KERNEL);
	if (!entry->pub_stypes)
		return -ENOMEM;
	w->mgmt_stypes = entry->pub_stypes;
	return 0;
}

static int wiphy419_publish_combs(struct wiphy419_entry *entry,
				  struct wiphy419_view *old)
{
	struct wiphy *w = entry->native;
	u32 n = old_u32_at(old->bytes, W_OFF(n_iface_combinations));
	const u8 *p;
	int i;

	memcpy(&p, old->bytes + W_OFF(iface_combinations), sizeof(p));
	if (!n) {
		w->iface_combinations = NULL;
		w->n_iface_combinations = 0;
		return 0;
	}
	if (!p || n > WP419_MAX_COMBS)
		return -EOPNOTSUPP;
	entry->pub_combs = kcalloc(n, sizeof(*entry->pub_combs), GFP_KERNEL);
	if (!entry->pub_combs)
		return -ENOMEM;
	entry->pub_limits = kcalloc(n, sizeof(*entry->pub_limits), GFP_KERNEL);
	if (!entry->pub_limits)
		goto err;
	/* Count first: the error path below (via unpublish) frees every
	 * installed limits entry, including a partial set. */
	entry->pub_n_comb = n;
	for (i = 0; i < (int)n; i++) {
		const u8 *c = p + i * WP419_SZ_COMB;
		const void *lp;
		u8 nlim;

		memcpy(&nlim, c + WP419_O_COMB_NLIM, sizeof(nlim));
		memcpy(&lp, c + WP419_O_COMB_LIMITS, sizeof(lp));
		if (!nlim || nlim > WP419_MAX_COMB_LIMITS || !lp)
			goto err;
		/* Combination and limit structs are field-identical
		 * (20/4 B, asserted at init — the BCA 4.19 tree carries
		 * the radar/gcd tail too); the core's verify_combinations
		 * remains the semantic validator. */
		memcpy(&entry->pub_combs[i], c, WP419_SZ_COMB);
		entry->pub_limits[i] = kmemdup(lp, nlim * WP419_SZ_LIMIT,
					       GFP_KERNEL);
		if (!entry->pub_limits[i])
			goto err;
		entry->pub_combs[i].limits = entry->pub_limits[i];
	}
	w->iface_combinations = entry->pub_combs;
	w->n_iface_combinations = n;
	return 0;
err:
	wiphy419_unpublish(entry);
	return -EOPNOTSUPP;
}

/* Fill a zero legacy perm_addr from the lane-G nvram MAC chain.
 * The blob leaves perm_addr zero on the success path (only the detach path
 * poisons it), and a zero perm_addr with NULL addresses passes the 6.6
 * register gates — but `iw list` then shows 00:00:... and any future core
 * check comparing addresses[0] against perm_addr would trip. Non-zero
 * blob values are owned by the blob and never overridden here.
 * Source order is band-aware: a wiphy carrying 5/6 GHz bands belongs to
 * the sb/0 radio (5G+6G calibration incl. 320 MHz keys, first entry of the
 * stock wl_mlo_config "0 1 -1 -1" map), a 2.4 GHz-only wiphy to sb/1;
 * et0macaddr (the bdinfo base both sb MACs derive from) is the last
 * resort. Values come from wlcsm_nvram_k_get (seeded L1 factory image +
 * L3 et0macaddr/wl0_hwaddr/wl1_hwaddr params) and must parse as a valid
 * unicast address, otherwise the zero is kept (register-legal). The
 * chosen MAC is written back to the legacy view so the blob and the
 * post-register sync observe the same address. */
static void wiphy419_fill_perm_addr(struct wiphy419_view *old,
				     struct wiphy *w)
{
	const char *keys[3];
	u8 cur[ETH_ALEN];
	int i;

	memcpy(cur, old->bytes + W_OFF(perm_addr), ETH_ALEN);
	if (!is_zero_ether_addr(cur))
		return;
	if (w->bands[NL80211_BAND_5GHZ] || w->bands[NL80211_BAND_6GHZ]) {
		keys[0] = "sb/0/macaddr";
		keys[1] = "sb/1/macaddr";
	} else {
		keys[0] = "sb/1/macaddr";
		keys[1] = "sb/0/macaddr";
	}
	keys[2] = "et0macaddr";
	for (i = 0; i < 3; i++) {
		/* The wlcsm getter takes char * for historical reasons and
		 * never writes through it; copy to a stack buffer instead
		 * of discarding const. */
		char key[16];
		char *val;
		u8 mac[ETH_ALEN];

		strscpy(key, keys[i], sizeof(key));
		val = wlcsm_nvram_k_get(key);
		if (!val || !*val)
			continue;
		if (!mac_pton(val, mac))
			continue;
		if (!is_valid_ether_addr(mac))
			continue;
		memcpy(w->perm_addr, mac, ETH_ALEN);
		memcpy(old->bytes + W_OFF(perm_addr), mac, ETH_ALEN);
		pr_warn_once("bcm_shim: wiphy publish: perm_addr was zero, using nvram %s\n",
			     keys[i]);
		return;
	}
	pr_warn_once("bcm_shim: wiphy publish: perm_addr zero, no usable nvram MAC (register allows it)\n");
}

static int wiphy419_vendor_call(unsigned int slot, struct wiphy *native,
				struct wireless_dev *wdev,
				const void *data, int len)
{
	struct wiphy419_view *old = shim_wiphy_legacy(native);
	struct wiphy419_entry *entry = old ? wiphy419_entry_of(old) : NULL;
	struct wdev419_view *old_wdev = wdev ? shim_wdev_legacy(wdev) : NULL;

	if (!entry || slot >= native->n_vendor_commands || !entry->vendor419[slot].doit)
		return -ENOENT;
	if (wdev && !old_wdev)
		return -ENOENT;
	return entry->vendor419[slot].doit((struct wiphy *)old,
					(struct wireless_dev *)old_wdev, data, len);
}
#define VENDOR_THUNK(n) \
static int wiphy419_vendor##n(struct wiphy *w, struct wireless_dev *d, \
			     const void *data, int len) \
{ return wiphy419_vendor_call(n, w, d, data, len); }
VENDOR_THUNK(0)
VENDOR_THUNK(1)
#undef VENDOR_THUNK

static int wiphy419_publish_vendor(struct wiphy419_entry *entry)
{
	struct wiphy419_view *old = entry->old;
	struct wiphy *w = entry->native;
	u32 nc = old_u32_at(old->bytes, W_OFF(n_vendor_commands));
	u32 ne = old_u32_at(old->bytes, W_OFF(n_vendor_events));
	const void *commands = old_ptr_at(old->bytes, W_OFF(vendor_commands));
	const void *events = old_ptr_at(old->bytes, W_OFF(vendor_events));
	unsigned int i;

	static_assert(sizeof(struct vendor419_command) == 20);
	static_assert(sizeof(struct wiphy_vendor_command) == 28);
	static_assert(sizeof(struct nl80211_vendor_cmd_info) == 8);
	if (nc > ARRAY_SIZE(entry->vendor419) || ne > 32 ||
	    (!!nc != !!commands) || (!!ne != !!events))
		return -EOPNOTSUPP;
	if (nc) {
		memcpy(entry->vendor419, commands, nc * sizeof(entry->vendor419[0]));
		entry->pub_vendor = kcalloc(nc, sizeof(*entry->pub_vendor), GFP_KERNEL);
		if (!entry->pub_vendor)
			return -ENOMEM;
		for (i = 0; i < nc; i++) {
			const struct vendor419_command *v = &entry->vendor419[i];
			struct wiphy_vendor_command *n = &entry->pub_vendor[i];

			/* Audited two private Broadcom raw-buffer commands only.
			 * Do not assume a policy for an unknown vendor API. */
			if (v->info.vendor_id != 0x1018 || v->info.subcmd != i + 1 ||
			    v->flags != 3 || !v->doit || v->dumpit)
				return -EOPNOTSUPP;
			n->info = v->info;
			n->flags = v->flags;
			n->doit = i ? wiphy419_vendor1 : wiphy419_vendor0;
			n->policy = VENDOR_CMD_RAW_DATA;
		}
	}
	if (ne) {
		entry->pub_events = kmemdup(events, ne * sizeof(*entry->pub_events), GFP_KERNEL);
		if (!entry->pub_events)
			return -ENOMEM;
	}
	w->vendor_commands = entry->pub_vendor;
	w->n_vendor_commands = nc;
	w->vendor_events = entry->pub_events;
	w->n_vendor_events = ne;
	WTRACE("vendor translated commands=%u events=%u", nc, ne);
	return 0;
}

int shim_wiphy_publish(struct wiphy419_view *old)
{
	/* Validate first, commit second: any failure below drops the
	 * partial translation (unpublish) and leaves the native object
	 * clean for a retry or a plain free. */
	struct wiphy419_entry *entry = wiphy419_entry_of(old);
	struct wiphy *w;
	u32 v32;
	u16 v16;
	int ret, i;
	const void *p;

	if (!entry)
		return -ENOENT;
	w = entry->native;
	if (w->registered)
		return -EBUSY;
	/* Re-runnable: rebuild the translation from the current legacy
	 * state (the blob keeps writing between new and register, and
	 * apply_custom_regulatory wants channels even before register). */
	wiphy419_unpublish(entry);
	/* Still-untranslated layout-divergent targets: reject, never
	 * fabricate. Bands/ciphers/combinations/mgmt_stypes have deep
	 * translators below and left this set. */
	#define REFUSE_POINTER(field) do { \
		if (old_ptr_at(old->bytes, W_OFF(field))) { \
			WTRACE("publish unsupported pointer: " #field); \
			return -EOPNOTSUPP; \
		} \
	} while (0)
	REFUSE_POINTER(reg_notifier);
	REFUSE_POINTER(ht_capa_mod_mask);
	REFUSE_POINTER(vht_capa_mod_mask);
	REFUSE_POINTER(extended_capabilities);
	REFUSE_POINTER(extended_capabilities_mask);
	#undef REFUSE_POINTER
	/* addresses/n_addresses: the blob never sets them on the success
	 * path; struct mac_address was not audited, so any non-NULL
	 * pointer is refused rather than guessed. */
	memcpy(&p, old->bytes + W_OFF(addresses), sizeof(p));
	memcpy(&v16, old->bytes + W_OFF(n_addresses), sizeof(v16));
	if (p || v16)
		return -EOPNOTSUPP;
	v32 = old_u32_at(old->bytes, W_OFF(flags));
	ret = wiphy_flags_to_native(v32, &v32, wp419_wiphy_flags,
				    ARRAY_SIZE(wp419_wiphy_flags));
	if (ret)
		return ret;
	w->flags = v32;
	v32 = old_u32_at(old->bytes, W_OFF(regulatory_flags));
	ret = wiphy_flags_to_native(v32, &v32, wp419_regulatory_flags,
				    ARRAY_SIZE(wp419_regulatory_flags));
	if (ret)
		return ret;
	w->regulatory_flags = v32;
	v32 = old_u32_at(old->bytes, W_OFF(features));
	if (v32 & ~WP419_FEATURE_KNOWN_MASK)
		return -EOPNOTSUPP;
	w->features = v32;
	memcpy(w->ext_features, old->bytes + W_OFF(ext_features),
	       WP419_EXT_FEATURE_OLD_BYTES);
	memset(w->ext_features + WP419_EXT_FEATURE_OLD_BYTES, 0,
	       sizeof(w->ext_features) - WP419_EXT_FEATURE_OLD_BYTES);
	COPY_W_FROM_OLD(w, old, interface_modes);
	/* WDS was removed from cfg80211 (6.6 register returns -EINVAL on
	 * the bit); the blob still advertises it (0x6e). Strip, loudly:
	 * the mask only gates nl80211 userspace requests, blob-internal
	 * paths are unaffected. */
	if (w->interface_modes & BIT(NL80211_IFTYPE_WDS)) {
		pr_warn_once("bcm_shim: wiphy publish: stripping WDS mode (unsupported in 6.6)\n");
		w->interface_modes &= ~BIT(NL80211_IFTYPE_WDS);
	}
	COPY_W_FROM_OLD(w, old, max_acl_mac_addrs);
	COPY_W_FROM_OLD(w, old, ap_sme_capa);
	COPY_W_FROM_OLD(w, old, signal_type);
	COPY_W_FROM_OLD(w, old, bss_priv_size);
	COPY_W_FROM_OLD(w, old, max_scan_ssids);
	COPY_W_FROM_OLD(w, old, max_sched_scan_reqs);
	COPY_W_FROM_OLD(w, old, max_sched_scan_ssids);
	COPY_W_FROM_OLD(w, old, max_match_sets);
	COPY_W_FROM_OLD(w, old, max_scan_ie_len);
	COPY_W_FROM_OLD(w, old, max_sched_scan_ie_len);
	COPY_W_FROM_OLD(w, old, max_sched_scan_plans);
	COPY_W_FROM_OLD(w, old, max_sched_scan_plan_interval);
	COPY_W_FROM_OLD(w, old, max_sched_scan_plan_iterations);
	COPY_W_FROM_OLD(w, old, retry_short);
	COPY_W_FROM_OLD(w, old, retry_long);
	COPY_W_FROM_OLD(w, old, frag_threshold);
	COPY_W_FROM_OLD(w, old, rts_threshold);
	COPY_W_FROM_OLD(w, old, coverage_class);
	COPY_W_FROM_OLD(w, old, fw_version);
	COPY_W_FROM_OLD(w, old, hw_version);
	COPY_W_FROM_OLD(w, old, max_remain_on_channel_duration);
	COPY_W_FROM_OLD(w, old, max_num_pmkids);
	COPY_W_FROM_OLD(w, old, available_antennas_tx);
	COPY_W_FROM_OLD(w, old, available_antennas_rx);
	COPY_W_FROM_OLD(w, old, probe_resp_offload);
	COPY_W_FROM_OLD(w, old, extended_capabilities_len);
	COPY_W_FROM_OLD(w, old, max_ap_assoc_sta);
	COPY_W_FROM_OLD(w, old, bss_select_support);
	COPY_W_FROM_OLD(w, old, nan_supported_bands);
	COPY_W_FROM_OLD(w, old, n_iface_combinations);
	COPY_W_FROM_OLD(w, old, software_iftypes);
	COPY_W_FROM_OLD(w, old, perm_addr);
	COPY_W_FROM_OLD(w, old, addr_mask);
	/* privid is an opaque driver cookie, layout-independent. */
	memcpy(&w->privid, old->bytes + W_OFF(privid), sizeof(w->privid));
	/* Deep translation of the pointer tables. Any failure drops the
	 * partial translation (unpublish) so the native object is left
	 * clean for a retry or a plain free. */
	for (i = 0; i < WP419_NUM_BANDS; i++) {
		memcpy(&p, old->bytes + W_OFF(bands) + 4 * i, sizeof(p));
		if (!p)
			continue;
		ret = wiphy419_publish_band(entry, p);
		if (ret)
			goto err;
	}
	ret = wiphy419_publish_ciphers(entry, old);
	if (ret)
		goto err;
	ret = wiphy419_publish_stypes(entry, old);
	if (ret)
		goto err;
	ret = wiphy419_publish_combs(entry, old);
	if (ret)
		goto err;
	ret = wiphy419_publish_vendor(entry);
	if (ret) {
		WTRACE("vendor translation refused rc=%d", ret);
		goto err;
	}
	/* MAC last: band-aware (needs the translated bands above). The blob
	 * leaves perm_addr zero on the success path; fill from nvram. */
	wiphy419_fill_perm_addr(old, w);
	return 0;
err:
	wiphy419_unpublish(entry);
	return ret;
}

void shim_wiphy_sync(struct wiphy419_view *old)
{
	struct wiphy *w = shim_wiphy_native(old);

	if (w)
		wiphy419_sync_view(old, w);
}

int shim_wiphy_free_unregistered(struct wiphy419_view *old)
{
	struct wiphy419_entry *entry, *found = NULL;
	struct wiphy *native;
	void *allocation;

	mutex_lock(&wiphy419_mutex);
	list_for_each_entry(entry, &wiphy419_views, list) {
		if (entry->old != old)
			continue;
		found = entry;
		break;
	}
	if (!found) {
		mutex_unlock(&wiphy419_mutex);
		return -ENOENT;
	}
	/* wiphy_register was never called in this stage; a registered
	 * object has core references (sysfs, rfkill, netns) and must go
	 * through wiphy_unregister first (later step). */
	if (found->native->registered) {
		mutex_unlock(&wiphy419_mutex);
		return -EBUSY;
	}
	list_del_rcu(&found->list);
	native = found->native;
	allocation = found->allocation;
	mutex_unlock(&wiphy419_mutex);
	synchronize_rcu();
	wiphy419_unpublish(found);
	/* Standard in-tree pattern (e.g. virt_wifi register-fail path):
	 * wiphy_free on a never-registered wiphy releases the rdev,
	 * including our entry in its private area. */
	wiphy_free(native);
	kfree(allocation);
	return 0;
}

/* Blob lifecycle wrappers (H28): legacy view in, native action out.
 * The blob owns every byte of the legacy view (including its priv
 * tail); the entry, native object and publish-owned translation are
 * adapter-owned. Every wrapper resolves first and never dereferences
 * a foreign pointer. All exports are plain EXPORT_SYMBOL: wl.ko is
 * Proprietary and cannot resolve _GPL. */

/* Re-attach guard (unload-detach lane): wl_blob_ops points into wl.ko
 * .data, so a wl rmmod/insmod cycle changes the table address while stale
 * registry entries may still record the dead incarnation (only in their
 * blob_ops tag — thunks always read the lane-D global, never per-entry
 * state, so no thunk ever follows a stale pointer once the global is
 * re-attached). On a table change, drop every UNREGISTERED stale entry
 * via the tested free path (adapter-owned, unpublish + wiphy_free +
 * kfree); REGISTERED leftovers are core-owned and cannot be freed here —
 * they are counted loudly and keep dispatching against the new table,
 * which is exact for same-version reloads (identical contents, new
 * address). Entries with a NULL tag (direct-alloc selftest scaffolding,
 * never attached) are always kept. Same-table re-attach (second radio)
 * drops nothing. */
static void wiphy419_drop_stale_incarnation(const void *incoming)
{
	struct wiphy419_entry *entry;
	unsigned int dropped = 0, kept = 0;

	for (;;) {
		struct wiphy419_view *victim = NULL;

		mutex_lock(&wiphy419_mutex);
		list_for_each_entry(entry, &wiphy419_views, list) {
			if (entry->blob_ops && entry->blob_ops != incoming &&
			    !entry->native->registered) {
				victim = entry->old;
				break;
			}
		}
		mutex_unlock(&wiphy419_mutex);
		if (!victim)
			break;
		/* The free path re-locks internally and sleeps
		 * (synchronize_rcu): never hold wiphy419_mutex across it. */
		if (shim_wiphy_free_unregistered(victim))
			break;
		dropped++;
	}
	mutex_lock(&wiphy419_mutex);
	list_for_each_entry(entry, &wiphy419_views, list) {
		if (entry->blob_ops && entry->blob_ops != incoming)
			kept++;
	}
	mutex_unlock(&wiphy419_mutex);
	if (dropped || kept)
		pr_warn("bcm_shim: wiphy_new: blob ops incarnation changed (%u stale dropped, %u registered kept)\n",
			dropped, kept);
}

struct wiphy *bcm_shim_wiphy_new_nm(const struct cfg80211_ops *ops,
				    int sizeof_priv,
				    const char *requested_name)
{
	struct wiphy419_view *old;
	struct wiphy419_entry *entry;

	WTRACE("new enter priv=%d", sizeof_priv);
	if (!ops) {
		pr_warn_once("bcm_shim: wiphy_new: NULL ops, refusing\n");
		return NULL;
	}
	if (requested_name) {
		/* The audited site passes NULL (auto phy name); a named
		 * request is an un-audited variant — fail cleanly on the
		 * blob's beq-fail path instead of handing out a
		 * mis-shaped object (same guard shape as the netdev
		 * alloc wrapper). */
		pr_warn_once("bcm_shim: wiphy_new: named request refused\n");
		return NULL;
	}
	/* Precondition from the wiphy-reject spec (open question 4):
	 * the passed table IS the blob's raw 4.19 table — attach it as
	 * the lane-D blob ops here, and allocate the native object
	 * against the translated table. No separate integrator step.
	 * Re-attach guard first: a wl rmmod/insmod cycle changes the
	 * table address (it lives in wl.ko .data), so entries recorded
	 * with a different table belong to a dead incarnation. */
	wiphy419_drop_stale_incarnation(ops);
	cfg80211_compat_attach_blob((const struct wl419_ops *)ops);
	old = shim_wiphy_alloc(sizeof_priv, &shim_stripped_ops);
	if (!old)
		return NULL;
	entry = wiphy419_entry_of(old);
	if (entry)
		entry->blob_ops = ops;
	WTRACE("new exit old=%p", old);
	return (struct wiphy *)old;
}
EXPORT_SYMBOL(bcm_shim_wiphy_new_nm);

int bcm_shim_wiphy_register(struct wiphy *wiphy)
{
	struct wiphy419_view *old = (struct wiphy419_view *)wiphy;
	struct wiphy *native = old ? shim_wiphy_native(old) : NULL;
	int ret, b;

	if (!wiphy || !native) {
		pr_warn_once("bcm_shim: wiphy_register miss, -ENOENT\n");
		return -ENOENT;
	}
	WTRACE("register publish enter");
	ret = shim_wiphy_publish(old);
	WTRACE("register publish exit rc=%d", ret);
	if (ret)
		return ret;
	/* One info block per register attempt (rare): the HW lane reads the
	 * actually-published shape from dmesg instead of guessing. */
	for (b = 0; b < NUM_NL80211_BANDS; b++) {
		struct ieee80211_supported_band *sb = native->bands[b];

		if (!sb)
			continue;
		pr_info("bcm_shim: wiphy publish: band %d ch=%d rates=%d iftype=%d ht=%d vht=%d perm=%pM\n",
			b, sb->n_channels, sb->n_bitrates,
			sb->n_iftype_data, sb->ht_cap.ht_supported,
			sb->vht_cap.vht_supported, native->perm_addr);
	}
	/* Real registration; locking (rtnl/wiphy mutex) is the core's
	 * job (same process-context probe the blob always used). */
	WTRACE("native register enter");
	ret = wiphy_register(native);
	WTRACE("native register exit rc=%d", ret);
	shim_wiphy_sync(old);
	WTRACE("register sync exit");
	return ret;
}
EXPORT_SYMBOL(bcm_shim_wiphy_register);

void bcm_shim_wiphy_free(struct wiphy *wiphy)
{
	struct wiphy419_view *old = (struct wiphy419_view *)wiphy;
	struct wiphy *native = old ? shim_wiphy_native(old) : NULL;
	bool empty;

	WTRACE("free enter");
	if (!wiphy || !native) {
		pr_warn_once("bcm_shim: wiphy_free miss, skip\n");
		return;
	}
	if (native->registered) {
		/* Blob frees a live wiphy (must not happen on the
		 * audited paths): unregister first so no core reference
		 * is leaked, then fall through to the normal free. */
		pr_warn_once("bcm_shim: wiphy_free of registered wiphy, unregistering first\n");
		wiphy_unregister(native);
		shim_wiphy_sync(old);
	}
	if (shim_wiphy_free_unregistered(old)) {
		pr_warn_once("bcm_shim: wiphy_free: backing free refused\n");
		return;
	}
	/* Last-free detach: wl_blob_ops points into wl.ko .data; with no
	 * wiphy left referencing it, clear the lane-D global so a later wl
	 * unload cannot leave thunks dispatching into freed pages (a later
	 * new_nm re-attaches). Non-last frees keep it: sibling wiphys
	 * still dispatch through it. */
	mutex_lock(&wiphy419_mutex);
	empty = list_empty(&wiphy419_views);
	mutex_unlock(&wiphy419_mutex);
	if (empty)
		cfg80211_compat_detach_blob();
	WTRACE("free exit");
}
EXPORT_SYMBOL(bcm_shim_wiphy_free);

void bcm_shim_wiphy_unregister(struct wiphy *wiphy)
{
	struct wiphy419_view *old = (struct wiphy419_view *)wiphy;
	struct wiphy *native = old ? shim_wiphy_native(old) : NULL;

	if (!wiphy || !native) {
		pr_warn_once("bcm_shim: wiphy_unregister miss, skip\n");
		return;
	}
	if (!native->registered) {
		pr_warn_once("bcm_shim: wiphy_unregister of unregistered wiphy, skip\n");
		return;
	}
	WTRACE("unregister enter");
	wiphy_unregister(native);
	WTRACE("unregister exit");
	/* Translation stays installed: the blob may re-register the same
	 * view (re-attach path), and publish would rebuild it anyway. */
	shim_wiphy_sync(old);
}
EXPORT_SYMBOL(bcm_shim_wiphy_unregister);

extern void wiphy_apply_custom_regulatory_rtnl(struct wiphy *,
			const struct ieee80211_regdomain *);

void bcm_shim_wiphy_apply_custom_regulatory(
	struct wiphy *wiphy, const struct ieee80211_regdomain *regd)
{
	struct wiphy419_view *old = (struct wiphy419_view *)wiphy;
	struct wiphy *native = old ? shim_wiphy_native(old) : NULL;
	int ret;

	if (!wiphy || !native) {
		pr_warn_once("bcm_shim: apply_custom_regulatory miss, skip\n");
		return;
	}
	if (!regd) {
		pr_warn_once("bcm_shim: apply_custom_regulatory NULL regd, skip\n");
		return;
	}
	WTRACE("regdomain enter");
	if (!native->registered) {
		/* Publish first so the core's handle_band_custom walks
		 * real channels, not NULL bands (benign WARN_ON
		 * otherwise). A failed publish still forwards: the
		 * regdomain copy itself is harmless without bands. */
		ret = shim_wiphy_publish(old);
		if (ret)
			pr_warn_once("bcm_shim: apply_custom_regulatory: publish %d, forwarding anyway\n",
				     ret);
	}
	/* regd layout is header-identical in both trees; the 6.6 core
	 * deep-copies it (reg_copy_regd) before taking any lock. */
	WTRACE("native regdomain enter");
	if (shim_netdev_in_rtnl_callback())
		wiphy_apply_custom_regulatory_rtnl(native, regd);
	else
		wiphy_apply_custom_regulatory(native, regd);
	WTRACE("native regdomain exit");
}
EXPORT_SYMBOL(bcm_shim_wiphy_apply_custom_regulatory);

int bcm_shim_regulatory_hint(struct wiphy *wiphy, const char *alpha2)
{
	struct wiphy419_view *old = (struct wiphy419_view *)wiphy;
	struct wiphy *native = old ? shim_wiphy_native(old) : NULL;

	if (!wiphy || !native) {
		pr_warn_once("bcm_shim: regulatory_hint miss, -ENOENT\n");
		return -ENOENT;
	}
	WTRACE("regulatory_hint enter");
	/* alpha2 is copied by the core into its own request. */
	return regulatory_hint(native, alpha2);
}
EXPORT_SYMBOL(bcm_shim_regulatory_hint);

struct wdev419_view *shim_wdev_alloc(void)
{
	struct wdev419_entry *entry;
	struct wireless_dev *native;
	struct wdev419_view *old;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;
	/* No core initialisation exists outside registration (later step);
	 * the object is fully adapter-owned until then. */
	native = kzalloc(sizeof(*native), GFP_KERNEL);
	if (!native) {
		kfree(entry);
		return NULL;
	}
	/* Adapter-owned until registration: the core never links this list
	 * head, but list_empty() on a kzalloc-zeroed {NULL,NULL} head is
	 * false — initialise it so the unregistered-free check can pass. */
	INIT_LIST_HEAD(&native->list);
	old = kzalloc(WP419_size_wireless_dev, GFP_KERNEL);
	if (!old) {
		kfree(native);
		kfree(entry);
		return NULL;
	}
	entry->native = native;
	entry->old = old;
	entry->owns_old = true;
	mutex_lock(&wiphy419_mutex);
	list_add_rcu(&entry->list, &wdev419_views);
	mutex_unlock(&wiphy419_mutex);
	return old;
}

struct wireless_dev *shim_wdev_adopt(struct wdev419_view *old,
				   void *old_netdev, struct net_device *netdev)
{
	struct wdev419_entry *entry;
	struct wireless_dev *native;
	struct wiphy419_view *old_wiphy;
	struct wiphy *wiphy;

	if (!old || !netdev || old_ptr_at(old->bytes, D_OFF(netdev)) != old_netdev)
		return ERR_PTR(-EINVAL);
	old_wiphy = (void *)old_ptr_at(old->bytes, D_OFF(wiphy));
	wiphy = shim_wiphy_native(old_wiphy);
	if (!wiphy)
		return ERR_PTR(-ENOENT);
	native = shim_wdev_native(old);
	if (native)
		return native->netdev == netdev ? native : ERR_PTR(-EBUSY);
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);
	native = kzalloc(sizeof(*native), GFP_KERNEL);
	if (!native) {
		kfree(entry);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&native->list);
	native->wiphy = wiphy;
	native->netdev = netdev;
	COPY_D_FROM_OLD(native, old, iftype);
	COPY_D_FROM_OLD(native, old, address);
	entry->old = old;
	entry->native = native;
	/* Blob owns this memory, often as part of its private allocation. */
	entry->owns_old = false;
	mutex_lock(&wiphy419_mutex);
	list_add_rcu(&entry->list, &wdev419_views);
	mutex_unlock(&wiphy419_mutex);
	WTRACE("wdev adopt iftype=%u", native->iftype);
	return native;
}

struct wireless_dev *shim_wdev_native(const struct wdev419_view *old)
{
	struct wdev419_entry *entry;
	struct wireless_dev *native = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wdev419_views, list) {
		if (entry->old == old) {
			native = entry->native;
			break;
		}
	}
	rcu_read_unlock();
	return native;
}

struct wdev419_view *shim_wdev_legacy(const struct wireless_dev *native)
{
	struct wdev419_entry *entry;
	struct wdev419_view *old = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &wdev419_views, list) {
		if (entry->native == native) {
			old = entry->old;
			break;
		}
	}
	rcu_read_unlock();
	return old;
}

int shim_wdev_bind(struct wdev419_view *old_wdev,
		   struct wiphy419_view *old_wiphy)
{
	struct wdev419_entry *wdev_entry, *wdev_found = NULL;
	struct wiphy419_entry *wiphy_entry, *wiphy_found = NULL;

	mutex_lock(&wiphy419_mutex);
	list_for_each_entry(wdev_entry, &wdev419_views, list) {
		if (wdev_entry->old == old_wdev) {
			wdev_found = wdev_entry;
			break;
		}
	}
	if (!wdev_found) {
		mutex_unlock(&wiphy419_mutex);
		return -ENOENT;
	}
	if (old_wiphy) {
		list_for_each_entry(wiphy_entry, &wiphy419_views, list) {
			if (wiphy_entry->old == old_wiphy) {
				wiphy_found = wiphy_entry;
				break;
			}
		}
		if (!wiphy_found) {
			mutex_unlock(&wiphy419_mutex);
			return -ENOENT;
		}
	}
	/* The two views are never cross-linked: legacy points at legacy,
	 * native at native. Either side may be NULL (unbind). */
	set_old_ptr_at(wdev_found->old->bytes, D_OFF(wiphy), old_wiphy);
	wdev_found->native->wiphy = wiphy_found ? wiphy_found->native : NULL;
	mutex_unlock(&wiphy419_mutex);
	return 0;
}

int shim_wdev_publish(struct wdev419_view *old)
{
	struct wireless_dev *d = shim_wdev_native(old);

	if (!d)
		return -ENOENT;
	/* Only the adapter may link netdevs in this stage; the netdev
	 * bridge (legacy view <-> native netdev) is a later step. */
	if (old_ptr_at(old->bytes, D_OFF(netdev)))
		return -EOPNOTSUPP;
	COPY_D_FROM_OLD(d, old, iftype);
	COPY_D_FROM_OLD(d, old, address);
	return 0;
}

/* cfg80211 holds the interface lifetime across change_virtual_intf. The
 * legacy driver owns the mode transition, including its wdev.iftype write;
 * publish that result before cfg80211 checks the native object's new mode.
 * Do not copy pointers or unrelated mutable state from the old layout. */
int shim_wdev_publish_iftype(struct wireless_dev *native,
			     enum nl80211_iftype expected)
{
	struct wdev419_view *old = shim_wdev_legacy(native);
	enum nl80211_iftype actual;

	if (!old)
		return -ENODEV;
	memcpy(&actual, old->bytes + D_OFF(iftype), sizeof(actual));
	if (actual <= NL80211_IFTYPE_UNSPECIFIED ||
	    actual >= NUM_NL80211_IFTYPES || actual != expected) {
		pr_err("wdev419: mode transition mismatch legacy=%d requested=%d\n",
		       actual, expected);
		return -EPROTO;
	}
	native->iftype = actual;
	return 0;
}

void shim_wdev_sync(struct wdev419_view *old)
{
	struct wireless_dev *d = shim_wdev_native(old);

	if (!d)
		return;
	COPY_D_TO_OLD(old, d, iftype);
	COPY_D_TO_OLD(old, d, address);
	/* Keep the legacy wiphy pointer truthful to the native binding. */
	set_old_ptr_at(old->bytes, D_OFF(wiphy), shim_wiphy_legacy(d->wiphy));
}

int shim_wdev_free(struct wdev419_view *old)
{
	struct wdev419_entry *entry, *found = NULL;
	struct wireless_dev *native;
	struct wdev419_view *victim;

	mutex_lock(&wiphy419_mutex);
	list_for_each_entry(entry, &wdev419_views, list) {
		if (entry->old != old)
			continue;
		found = entry;
		break;
	}
	if (!found) {
		mutex_unlock(&wiphy419_mutex);
		return -ENOENT;
	}
	/* A core-registered wdev (list-linked, netdev-attached) has core
	 * references and must go through unregistration first (later step). */
	if (found->native->registered || found->native->netdev ||
	    !list_empty(&found->native->list)) {
		mutex_unlock(&wiphy419_mutex);
		return -EBUSY;
	}
	list_del_rcu(&found->list);
	native = found->native;
	victim = found->old;
	mutex_unlock(&wiphy419_mutex);
	synchronize_rcu();
	kfree(native);
	if (found->owns_old)
		kfree(victim);
	kfree(found);
	return 0;
}

/* Test fixtures below run only with wiphy_selftest=1 / wdev_selftest=1.
 * Their ops table is all-NULL: wiphy_new_nm stores the pointer without
 * calling anything, so no blob or core callback can fire. */
static const struct cfg80211_ops wiphy419_test_ops;
static const struct cfg80211_ops wiphy419_other_ops;

static int wiphy419_flag_tables_check(void)
{
	u32 native, old;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(wp419_wiphy_flags); i++) {
		if (wiphy_flags_to_native(wp419_wiphy_flags[i].old, &native,
				wp419_wiphy_flags, ARRAY_SIZE(wp419_wiphy_flags)) ||
		    native != wp419_wiphy_flags[i].native ||
		    wiphy_flags_to_old(native, wp419_wiphy_flags,
				ARRAY_SIZE(wp419_wiphy_flags)) != wp419_wiphy_flags[i].old)
			return -EINVAL;
	}
	for (i = 0; i < ARRAY_SIZE(wp419_regulatory_flags); i++) {
		if (wiphy_flags_to_native(wp419_regulatory_flags[i].old, &native,
				wp419_regulatory_flags, ARRAY_SIZE(wp419_regulatory_flags)) ||
		    native != wp419_regulatory_flags[i].native ||
		    wiphy_flags_to_old(native, wp419_regulatory_flags,
				ARRAY_SIZE(wp419_regulatory_flags)) != wp419_regulatory_flags[i].old)
			return -EINVAL;
	}
	/* Trap bits: old-only bits and native-only bits must be rejected. */
	if (!wiphy_flags_to_native(BIT(24), &old, wp419_wiphy_flags,
				   ARRAY_SIZE(wp419_wiphy_flags)))
		return -EINVAL;
	if (!wiphy_flags_to_native(BIT(6), &old, wp419_regulatory_flags,
				   ARRAY_SIZE(wp419_regulatory_flags)))
		return -EINVAL;
	/* The blob's measured init OR-mask must translate 1:1 (success
	 * expected here — unlike the trap probes above, which must fail). */
	if (wiphy_flags_to_native(0x328078, &native, wp419_wiphy_flags,
				   ARRAY_SIZE(wp419_wiphy_flags)) ||
	    native != 0x328078)
		return -EINVAL;
	return 0;
}

static int wiphy419_selftest(void)
{
	/* Blob init-time constants from wiphy-init-writes.txt. */
	static const u8 test_mac[ETH_ALEN] = { 0x02, 0x11, 0x41, 0x90, 0, 1 };
	struct wiphy419_view *a = NULL, *b = NULL;
	struct wiphy *native;
	struct wiphy419_entry *entry;
	/* Zeroed 68 B band: well-formed pointer, corrupt counts (H28: the
	 * deep translator dereferences band pointers, so the trap must
	 * use a readable buffer — never a wild address. Production
	 * safety comes from the blob invariant that bands[] holds only
	 * allocator-owned structs or NULL.) */
	u8 empty_band[WP419_SZ_BAND];
	u32 v32;
	int ret = -EIO;
	int idx_a = -1, idx_b = -1, taken_a = -1, taken_b = -1;

	memset(empty_band, 0, sizeof(empty_band));
	ret = wiphy419_flag_tables_check();
	if (ret)
		return ret;
	/* Restore the failure default: every goto-out below must fail.
	 * (The tables check above legitimately leaves ret == 0.) */
	ret = -EIO;
	a = shim_wiphy_alloc(4, &wiphy419_test_ops);
	b = shim_wiphy_alloc(64, &wiphy419_test_ops);
	if (!a || !b)
		goto out;
	native = shim_wiphy_native(a);
	if (!native || (void *)native == (void *)a ||
	    shim_wiphy_legacy(native) != a ||
	    shim_wiphy_native((void *)1) || shim_wiphy_legacy((void *)1) ||
	    !IS_ALIGNED((unsigned long)a, NETDEV_ALIGN) ||
	    !IS_ALIGNED((unsigned long)a->priv, NETDEV_ALIGN) ||
	    memchr_inv(a->priv, 0, 4) || memchr_inv(b->priv, 0, 64))
		goto out;
	/* Blob private write at +608 and legacy scalar writes must not
	 * touch native storage or the adapter entry. */
	memset(a->priv, 0xa5, 4);
	v32 = 0xa5a5a5a5;
	memcpy(a->bytes + W_OFF(flags), &v32, sizeof(v32));
	memcpy(a->bytes + W_OFF(interface_modes), &v32, 2);
	memset(a->bytes + W_OFF(bands), 0xa5, 16);
	memset(a->bytes + W_OFF(dev), 0xa5, 32);
	entry = wiphy_priv(native);
	/* 6.6 core pre-sets PS_ON_BY_DEFAULT on a fresh wiphy (observed
	 * flags=0x10 on #110; drivers opt out explicitly). The blob's init
	 * OR-mask (0x328078, verified below) already contains that bit, so
	 * publish-by-assign preserves it in the real flow. */
	/* 6.6 never recycles the phy index: wiphy_new_nm() bumps a
	 * function-static atomic counter (net/wireless/core.c) and
	 * wiphy_free() is just put_device() — there is no wiphy_idx_put.
	 * Our free already follows the in-tree pattern (virt_wifi
	 * register-fail path), so unload->reload in one boot continues at
	 * phyN/phyN+1. Require kernel-assigned consecutive phy<N> names
	 * instead of hardcoded phy0/phy1: uniqueness, distinct objects
	 * and consecutive allocation are still verified. */
	sscanf(dev_name(&native->dev), "phy%d%n", &idx_a, &taken_a);
	sscanf(dev_name(&shim_wiphy_native(b)->dev), "phy%d%n",
	       &idx_b, &taken_b);
	if (entry->native != native || entry->old != a ||
	    native->flags != WIPHY_FLAG_PS_ON_BY_DEFAULT ||
	    native->interface_modes != 0 ||
	    native->bands[0] ||
	    taken_a != (int)strlen(dev_name(&native->dev)) ||
	    taken_b != (int)strlen(dev_name(&shim_wiphy_native(b)->dev)) ||
	    idx_a < 0 || idx_b != idx_a + 1)
		goto out;
	memset(a->priv, 0, 4);
	memset(a->bytes + W_OFF(bands), 0, 16);
	memset(a->bytes + W_OFF(dev), 0, 32);
	/* Publish the blob's measured init values, then verify native. */
	v32 = 0x6e;
	memcpy(a->bytes + W_OFF(interface_modes), &v32, 2);
	v32 = 0x328078;
	memcpy(a->bytes + W_OFF(flags), &v32, sizeof(v32));
	v32 = 0x1;
	memcpy(a->bytes + W_OFF(regulatory_flags), &v32, sizeof(v32));
	v32 = NL80211_FEATURE_SK_TX_STATUS | NL80211_FEATURE_AP_SCAN;
	memcpy(a->bytes + W_OFF(features), &v32, sizeof(v32));
	a->bytes[W_OFF(max_scan_ssids)] = 10;
	v32 = 0x800;
	memcpy(a->bytes + W_OFF(max_scan_ie_len), &v32, 2);
	v32 = 0x1388;
	memcpy(a->bytes + W_OFF(max_remain_on_channel_duration), &v32, 2);
	a->bytes[W_OFF(max_num_pmkids)] = 0x10;
	memcpy(a->bytes + W_OFF(perm_addr), test_mac, ETH_ALEN);
	v32 = 0x12345678;
	memcpy(a->bytes + W_OFF(hw_version), &v32, sizeof(v32));
	if (shim_wiphy_publish(a))
		goto out;
	if (native->interface_modes != (0x6e & ~BIT(NL80211_IFTYPE_WDS)) ||
	    native->flags != 0x328078 ||
	    native->regulatory_flags != 0x1 ||
	    native->features != (NL80211_FEATURE_SK_TX_STATUS | NL80211_FEATURE_AP_SCAN) ||
	    native->max_scan_ssids != 10 || native->max_scan_ie_len != 0x800 ||
	    native->max_remain_on_channel_duration != 0x1388 ||
	    native->max_num_pmkids != 0x10 ||
	    memcmp(native->perm_addr, test_mac, ETH_ALEN) ||
	    native->hw_version != 0x12345678 || native->bands[0] ||
	    native->registered)
		goto out;
	/* Trap paths: each must fail without touching native state. */
	v32 = 0x328078 | BIT(24); /* old HAS_STATIC_WEP = native regdom-notify */
	memcpy(a->bytes + W_OFF(flags), &v32, sizeof(v32));
	set_old_ptr_at(a->bytes, W_OFF(bands), empty_band);
	v32 = 0x1 | BIT(6); /* old IGNORE_STALE_KICKOFF, native reuse hole */
	memcpy(a->bytes + W_OFF(regulatory_flags), &v32, sizeof(v32));
	if (!shim_wiphy_publish(a) || native->flags != 0x328078 ||
	    native->regulatory_flags != 0x1 || native->bands[0])
		goto out;
	v32 = 0x328078;
	memcpy(a->bytes + W_OFF(flags), &v32, sizeof(v32));
	set_old_ptr_at(a->bytes, W_OFF(bands), NULL);
	v32 = 0x1;
	memcpy(a->bytes + W_OFF(regulatory_flags), &v32, sizeof(v32));
	if (shim_wiphy_publish(a))
		goto out;
	/* Sync-back: native mutation must appear in the legacy view. */
	native->interface_modes = 0x71;
	native->max_scan_ssids = 7;
	shim_wiphy_sync(a);
	if (old_u32_at(a->bytes, W_OFF(interface_modes)) != 0x71 ||
	    a->bytes[W_OFF(max_scan_ssids)] != 7 ||
	    a->bytes[W_OFF(registered)] != 0)
		goto out;
	pr_info("shim_wiphy: WIPHY419_SELFTEST PASS init-values=published traps=rejected roundtrip=OK\n");
	ret = 0;
out:
	if (b && shim_wiphy_free_unregistered(b))
		ret = -EIO;
	if (a && shim_wiphy_free_unregistered(a))
		ret = -EIO;
	if (!list_empty(&wiphy419_views))
		ret = -EIO;
	if (shim_wiphy_free_unregistered((void *)1) != -ENOENT)
		ret = -EIO;
	return ret;
}

/* H28 lifecycle selftest (mock level + register dry-run, no radio).
 *
 *  - Synthetic 4.19 band/channel/cipher/combination/stype/HE fixtures on
 *    the stack prove the deep translator (slots, field conversion,
 *    deep copies, WDS strip, 6 GHz publish with HT/VHT strip and HE
 *    field mapping, S1G/LC NULL, nvram perm fill) without the blob.
 *  - bcm_shim_wiphy_register on a band-less view must reach the real
 *    core and fail -EINVAL at !have_band — i.e. AFTER the WDS, FW_ROAM,
 *    ifmodes and verify_combinations gates — with zero side effects
 *    (the failure precedes rtnl/device_add/rfkill/regulatory). It does
 *    emit the core's one-line WARN_ON(1); that is expected, not a bug.
 *  - A full register->unregister->free cycle is deliberately NOT run
 *    here: a successful register creates a real phy (sysfs, rfkill,
 *    NEW_WIPHY netlink event). That cycle belongs to the HW lane with
 *    the real blob (H29), not to module-load selftest.
 *  - Miss paths (NULL/foreign pointers) must never fault.
 */
static void wiphy419_put_u16(u8 *b, unsigned int off, u16 v)
{
	memcpy(b + off, &v, sizeof(v));
}

static void wiphy419_put_u32(u8 *b, unsigned int off, u32 v)
{
	memcpy(b + off, &v, sizeof(v));
}

static void wiphy419_put_ptr(u8 *b, unsigned int off, const void *p)
{
	memcpy(b + off, &p, sizeof(p));
}

static void wiphy419_mkchan(u8 *c, u16 freq, u16 hw, u32 flags, int mpwr)
{
	memset(c, 0, WP419_SZ_CHAN);
	wiphy419_put_u16(c, WP419_O_CHAN_FREQ, freq);
	wiphy419_put_u16(c, WP419_O_CHAN_HW, hw);
	wiphy419_put_u32(c, WP419_O_CHAN_FLAGS, flags);
	wiphy419_put_u32(c, WP419_O_CHAN_MPWR, mpwr);
	wiphy419_put_u32(c, WP419_O_CHAN_REGPWR, mpwr);
	wiphy419_put_u32(c, WP419_O_CHAN_OMPWR, mpwr);
}

/* Synthetic 4.19 iftype entry (56 B): types_mask, has_he=1, patterned
 * HE elem/mcs/ppe, he_6ghz_capa. elem[]/mcs[]/ppe[] must each hold at
 * least WP419_SZ_HE_ELEM419 / WP419_SZ_HE_MCS / WP419_SZ_HE_PPE bytes. */
static void wiphy419_mkiftype(u8 *e, u16 types, const u8 *elem,
			      const u8 *mcs, const u8 *ppe, u16 he6g)
{
	memset(e, 0, WP419_SZ_IFTYPE);
	wiphy419_put_u16(e, WP419_O_IFTYPE_MASK, types);
	e[WP419_O_IFTYPE_HE + WP419_O_HE_HAS] = 1;
	memcpy(e + WP419_O_IFTYPE_HE + WP419_O_HE_ELEM, elem,
	       WP419_SZ_HE_ELEM419);
	memcpy(e + WP419_O_IFTYPE_HE + WP419_O_HE_MCS, mcs, WP419_SZ_HE_MCS);
	memcpy(e + WP419_O_IFTYPE_HE + WP419_O_HE_PPE, ppe, WP419_SZ_HE_PPE);
	wiphy419_put_u16(e, WP419_O_IFTYPE_HE6G, he6g);
}

static int wiphy419_lifecycle_selftest(void)
{
	struct wiphy419_view *c = NULL, *d = NULL, *e = NULL;
	struct wiphy419_view *f = NULL, *g = NULL;
	struct wiphy *native;
	struct wiphy419_entry *entry;
	u8 band0[WP419_SZ_BAND], band1[WP419_SZ_BAND], band6[WP419_SZ_BAND];
	u8 ch0[2 * WP419_SZ_CHAN], ch1[WP419_SZ_CHAN], ch6[WP419_SZ_CHAN];
	u8 rt0[2 * WP419_SZ_RATE], rt1[WP419_SZ_RATE], rt6[WP419_SZ_RATE];
	u8 ht[WP419_SZ_STA_HT], vht[WP419_SZ_STA_VHT];
	u8 ift0[WP419_SZ_IFTYPE], ift1[WP419_SZ_IFTYPE], ift6[WP419_SZ_IFTYPE];
	u8 *ift1x = NULL;
	/* One incremental HE pattern triple shared by all bands (per-field
	 * bases differ, so field mixups fail; increment catches shifts;
	 * per-band mask/he6g immediates catch slot routing). */
	u8 elp[WP419_SZ_HE_ELEM419], mcp[WP419_SZ_HE_MCS], ppp[WP419_SZ_HE_PPE];
	/* Blob-value MAC (perm preserved) vs zero (nvram-filled) probes. */
	static const u8 tmac[ETH_ALEN] = { 0x02, 0x90, 0x4c, 0x56, 0x71, 0x48 };
	char nkey[16];
	char *nval;
	u8 nmac[ETH_ALEN];
	bool have_nv;
	u32 ciphers[3] = { 0x000fac01, 0x000fac05, 0x00904c00 };
	u8 comb[WP419_SZ_COMB], lims[2 * WP419_SZ_LIMIT];
	u32 stypes[WP419_NL80211_IFTYPE_MAX];
	/* Empty custom regdomain (n_reg_rules=0): exercises the real
	 * apply_custom_regulatory forward with zero side effects (no
	 * rules to walk; the core deep-copies the header and returns). */
	u8 empty_regd[20];
	u32 v32;
	int i, ret = -EIO;

	memset(band0, 0, sizeof(band0));
	memset(band1, 0, sizeof(band1));
	memset(band6, 0, sizeof(band6));
	memset(rt0, 0x11, sizeof(rt0));
	memset(rt1, 0x22, sizeof(rt1));
	memset(rt6, 0x33, sizeof(rt6));
	memset(ht, 0x5a, sizeof(ht));
	memset(vht, 0xa5, sizeof(vht));
	for (i = 0; i < WP419_SZ_HE_ELEM419; i++)
		elp[i] = 0x40 + i;
	for (i = 0; i < WP419_SZ_HE_MCS; i++)
		mcp[i] = 0x60 + i;
	for (i = 0; i < WP419_SZ_HE_PPE; i++)
		ppp[i] = 0x80 + i;
	/* AP+STATION on 2.4G, AP on 5G, AP on 6G (disjoint, has_he). */
	wiphy419_mkiftype(ift0, BIT(NL80211_IFTYPE_AP) |
				BIT(NL80211_IFTYPE_STATION),
			elp, mcp, ppp, 0x1234);
	wiphy419_mkiftype(ift1, BIT(NL80211_IFTYPE_AP), elp, mcp, ppp, 0x5678);
	wiphy419_mkiftype(ift6, BIT(NL80211_IFTYPE_AP), elp, mcp, ppp, 0x9abc);
	memset(empty_regd, 0, sizeof(empty_regd));
	for (i = 0; i < WP419_NL80211_IFTYPE_MAX; i++)
		stypes[i] = 0x10000 * (u32)(i + 1) + (u32)i;
	/* band0: 2.4 GHz, 2 channels, 2 rates, caps patterns. */
	wiphy419_mkchan(ch0, 2412, 1, 0, 100);
	wiphy419_mkchan(ch0 + WP419_SZ_CHAN, 2437, 6, 0x40, 100);
	wiphy419_put_ptr(band0, WP419_O_BAND_CHANNELS, ch0);
	wiphy419_put_ptr(band0, WP419_O_BAND_BITRATES, rt0);
	wiphy419_put_u32(band0, WP419_O_BAND_BAND, 0);
	wiphy419_put_u32(band0, WP419_O_BAND_NCHAN, 2);
	wiphy419_put_u32(band0, WP419_O_BAND_NRATES, 2);
	memcpy(band0 + WP419_O_BAND_HT, ht, sizeof(ht));
	memcpy(band0 + WP419_O_BAND_VHT, vht, sizeof(vht));
	wiphy419_put_u16(band0, WP419_O_BAND_NIFTYPE, 1);
	wiphy419_put_ptr(band0, WP419_O_BAND_IFTYPE, ift0);
	/* band1: 5 GHz, 1 channel, 1 rate, AP HE entry. */
	wiphy419_mkchan(ch1, 5180, 36, 0x10, 200);
	wiphy419_put_ptr(band1, WP419_O_BAND_CHANNELS, ch1);
	wiphy419_put_ptr(band1, WP419_O_BAND_BITRATES, rt1);
	wiphy419_put_u32(band1, WP419_O_BAND_BAND, 1);
	wiphy419_put_u32(band1, WP419_O_BAND_NCHAN, 1);
	wiphy419_put_u32(band1, WP419_O_BAND_NRATES, 1);
	wiphy419_put_u16(band1, WP419_O_BAND_NIFTYPE, 1);
	wiphy419_put_ptr(band1, WP419_O_BAND_IFTYPE, ift1);
	/* band6: 6 GHz with an AP HE entry; HT/VHT deliberately set (the
	 * 4.19 tree has no 6G HT/VHT gate) — publish must strip them. */
	wiphy419_mkchan(ch6, 5955, 1, 0, 100);
	wiphy419_put_ptr(band6, WP419_O_BAND_CHANNELS, ch6);
	wiphy419_put_ptr(band6, WP419_O_BAND_BITRATES, rt6);
	wiphy419_put_u32(band6, WP419_O_BAND_BAND, NL80211_BAND_6GHZ);
	wiphy419_put_u32(band6, WP419_O_BAND_NCHAN, 1);
	wiphy419_put_u32(band6, WP419_O_BAND_NRATES, 1);
	wiphy419_put_u16(band6, WP419_O_BAND_NIFTYPE, 1);
	wiphy419_put_ptr(band6, WP419_O_BAND_IFTYPE, ift6);
	band6[WP419_O_BAND_HT + 2] = 1; /* ht_supported */
	band6[WP419_O_BAND_VHT + 0] = 1; /* vht_supported */
	/* combination: the blob's real shape (AP x8 + ADHOC|STATION x1). */
	wiphy419_put_u16(lims, 0, 8);
	wiphy419_put_u16(lims, 2, BIT(NL80211_IFTYPE_AP));
	wiphy419_put_u16(lims, 4, 1);
	wiphy419_put_u16(lims, 6, BIT(NL80211_IFTYPE_ADHOC) |
				  BIT(NL80211_IFTYPE_STATION));
	memset(comb, 0, sizeof(comb));
	wiphy419_put_ptr(comb, WP419_O_COMB_LIMITS, lims);
	wiphy419_put_u32(comb, 4, 1);
	wiphy419_put_u16(comb, 8, 8);
	comb[10] = 2;

	c = shim_wiphy_alloc(128, &wiphy419_test_ops);
	if (!c)
		goto out;
	native = shim_wiphy_native(c);
	if (!native)
		goto out;
	/* Legacy init set mirroring the blob (WDS bit included). */
	v32 = 0x6e;
	memcpy(c->bytes + W_OFF(interface_modes), &v32, 2);
	v32 = 0x328078;
	memcpy(c->bytes + W_OFF(flags), &v32, sizeof(v32));
	v32 = 0x1;
	memcpy(c->bytes + W_OFF(regulatory_flags), &v32, sizeof(v32));
	v32 = 32;
	memcpy(c->bytes + W_OFF(features), &v32, sizeof(v32));
	wiphy419_put_ptr(c->bytes, W_OFF(bands), band0);
	wiphy419_put_ptr(c->bytes, W_OFF(bands) + 4, band1);
	wiphy419_put_ptr(c->bytes, W_OFF(bands) + 8, band6);
	v32 = 3;
	memcpy(c->bytes + W_OFF(n_cipher_suites), &v32, sizeof(v32));
	wiphy419_put_ptr(c->bytes, W_OFF(cipher_suites), ciphers);
	wiphy419_put_ptr(c->bytes, W_OFF(mgmt_stypes), stypes);
	v32 = 1;
	memcpy(c->bytes + W_OFF(n_iface_combinations), &v32, sizeof(v32));
	wiphy419_put_ptr(c->bytes, W_OFF(iface_combinations), comb);
	if (shim_wiphy_publish(c))
		goto out;
	/* Slots: 2.4->0, 5->1, 6->3; 60G/S1G/LC empty (no 4.19 source,
	 * no such PHY — the register loop skips NULL slots). */
	if (!native->bands[0] || !native->bands[1] || native->bands[2] ||
	    !native->bands[3] || native->bands[4] || native->bands[5])
		goto out;
	if (native->bands[0]->n_channels != 2 ||
	    native->bands[0]->n_bitrates != 2 ||
	    native->bands[0]->band != 0 ||
	    native->bands[0]->n_iftype_data != 1 ||
	    !native->bands[0]->iftype_data)
		goto out;
	/* HE field mapping on band 0 (AP+STATION mask, patterned caps):
	 * elem prefix-copied with zeroed final-spec tail, mcs/ppe/he6g
	 * 1:1, EHT zeroed, vendor empty. */
	{
		const struct ieee80211_sband_iftype_data *it =
			&native->bands[0]->iftype_data[0];

		if (it->types_mask != (BIT(NL80211_IFTYPE_AP) |
				       BIT(NL80211_IFTYPE_STATION)) ||
		    !it->he_cap.has_he ||
		    memcmp(it->he_cap.he_cap_elem.mac_cap_info, elp, 5) ||
		    it->he_cap.he_cap_elem.mac_cap_info[5] ||
		    memcmp(it->he_cap.he_cap_elem.phy_cap_info, elp + 5, 9) ||
		    it->he_cap.he_cap_elem.phy_cap_info[9] ||
		    it->he_cap.he_cap_elem.phy_cap_info[10] ||
		    memcmp(&it->he_cap.he_mcs_nss_supp, mcp,
			   WP419_SZ_HE_MCS) ||
		    memcmp(it->he_cap.ppe_thres, ppp, WP419_SZ_HE_PPE) ||
		    it->he_6ghz_capa.capa != cpu_to_le16(0x1234) ||
		    it->eht_cap.has_eht || it->vendor_elems.data ||
		    it->vendor_elems.len)
			goto out;
	}
	if (native->bands[1]->n_iftype_data != 1 ||
	    native->bands[1]->iftype_data[0].types_mask !=
			BIT(NL80211_IFTYPE_AP) ||
	    !native->bands[1]->iftype_data[0].he_cap.has_he ||
	    memcmp(native->bands[1]->iftype_data[0].he_cap.ppe_thres, ppp,
		   WP419_SZ_HE_PPE) ||
	    native->bands[3]->n_iftype_data != 1 ||
	    native->bands[3]->iftype_data[0].types_mask !=
			BIT(NL80211_IFTYPE_AP) ||
	    native->bands[3]->iftype_data[0].he_6ghz_capa.capa !=
			cpu_to_le16(0x9abc))
		goto out;
	/* 6G HT/VHT stripped (spec: 6G is HE-only). */
	if (native->bands[3]->ht_cap.ht_supported ||
	    native->bands[3]->vht_cap.vht_supported)
		goto out;
	/* Zero legacy perm_addr is filled from the nvram MAC chain (5G
	 * present -> sb/0 first); the expected value is read back through
	 * the same getter so per-unit overrides stay green. */
	strscpy(nkey, "sb/0/macaddr", sizeof(nkey));
	nval = wlcsm_nvram_k_get(nkey);
	have_nv = nval && *nval && mac_pton(nval, nmac) &&
		  is_valid_ether_addr(nmac);
	if (have_nv) {
		if (memcmp(native->perm_addr, nmac, ETH_ALEN) ||
		    memcmp(c->bytes + W_OFF(perm_addr), nmac, ETH_ALEN))
			goto out;
	} else if (!is_zero_ether_addr(native->perm_addr)) {
		goto out;
	}
	/* Blob-provided MAC is never overridden. */
	memcpy(c->bytes + W_OFF(perm_addr), tmac, ETH_ALEN);
	if (shim_wiphy_publish(c) ||
	    memcmp(native->perm_addr, tmac, ETH_ALEN))
		goto out;
	memset(c->bytes + W_OFF(perm_addr), 0, ETH_ALEN);
	if (shim_wiphy_publish(c))
		goto out;
	if (have_nv) {
		if (memcmp(native->perm_addr, nmac, ETH_ALEN))
			goto out;
	}
	if (native->bands[0]->channels[0].center_freq != 2412 ||
	    native->bands[0]->channels[0].hw_value != 1 ||
	    native->bands[0]->channels[0].flags != 0 ||
	    native->bands[0]->channels[0].max_power != 100 ||
	    native->bands[0]->channels[0].max_reg_power != 100 ||
	    native->bands[0]->channels[0].orig_mpwr != 100 ||
	    native->bands[0]->channels[0].freq_offset != 0 ||
	    native->bands[0]->channels[0].band != 0 ||
	    native->bands[0]->channels[1].center_freq != 2437 ||
	    native->bands[0]->channels[1].hw_value != 6 ||
	    native->bands[0]->channels[1].flags != 0x40)
		goto out;
	if ((void *)shim_channel_legacy(&native->bands[0]->channels[0]) != ch0 ||
	    (void *)shim_channel_legacy(&native->bands[0]->channels[1]) != ch0 + WP419_SZ_CHAN ||
	    shim_channel_native((void *)(ch0 + WP419_SZ_CHAN)) != &native->bands[0]->channels[1] ||
	    shim_channel_native((void *)(ch0 + 1)) || shim_channel_legacy((void *)ch0))
		goto out;
	if (memcmp(native->bands[0]->bitrates, rt0, sizeof(rt0)) ||
	    memcmp(&native->bands[0]->ht_cap, ht, sizeof(ht)) ||
	    memcmp(&native->bands[0]->vht_cap, vht, sizeof(vht)))
		goto out;
	if (native->bands[1]->n_channels != 1 ||
	    native->bands[1]->channels[0].center_freq != 5180 ||
	    native->bands[1]->channels[0].max_power != 200 ||
	    native->bands[1]->band != 1 ||
	    memcmp(native->bands[1]->bitrates, rt1, sizeof(rt1)))
		goto out;
	if (native->n_cipher_suites != 3 ||
	    memcmp((void *)native->cipher_suites, ciphers, sizeof(ciphers)) ||
	    (const void *)native->cipher_suites == (const void *)ciphers)
		goto out;
	if (native->n_iface_combinations != 1 ||
	    native->iface_combinations[0].num_different_channels != 1 ||
	    native->iface_combinations[0].max_interfaces != 8 ||
	    native->iface_combinations[0].n_limits != 2 ||
	    native->iface_combinations[0].limits == (const void *)lims ||
	    memcmp((void *)native->iface_combinations[0].limits, lims,
		   sizeof(lims)) ||
	    memcmp((void *)native->mgmt_stypes, stypes, sizeof(stypes)))
		goto out;
	/* WDS stripped, everything else intact. */
	if (native->interface_modes != (0x6e & ~BIT(NL80211_IFTYPE_WDS)) ||
	    native->flags != 0x328078 || native->regulatory_flags != 0x1 ||
	    native->features != 32)
		goto out;
	/* Re-publish must rebuild cleanly (idempotent). */
	if (shim_wiphy_publish(c) || !native->bands[0] ||
	    native->bands[0]->channels[0].center_freq != 2412 ||
	    !native->bands[1] || !native->bands[3])
		goto out;
	/* Traps: each fails and leaves native translation empty. */
	wiphy419_put_u32(band0, WP419_O_BAND_NCHAN, 0);
	if (!shim_wiphy_publish(c) || native->bands[0] || native->bands[1] ||
	    native->bands[3])
		goto out;
	wiphy419_put_u32(band0, WP419_O_BAND_NCHAN, 2);
	wiphy419_put_ptr(c->bytes, W_OFF(cipher_suites), NULL);
	if (!shim_wiphy_publish(c) || native->bands[0] ||
	    native->cipher_suites || native->n_cipher_suites)
		goto out;
	wiphy419_put_ptr(c->bytes, W_OFF(cipher_suites), ciphers);
	wiphy419_put_u32(band0, WP419_O_BAND_BAND, 7);
	if (!shim_wiphy_publish(c) || native->bands[0])
		goto out;
	wiphy419_put_u32(band0, WP419_O_BAND_BAND, 0);
	if (shim_wiphy_publish(c) || !native->bands[3])
		goto out;
	/* iftype traps: corrupt entries fail kept bands, 6G degrades to a
	 * loud skip (2.4/5G keep satisfying have_band). */
	wiphy419_put_u16(ift0, WP419_O_IFTYPE_MASK, 0);
	if (!shim_wiphy_publish(c) || native->bands[0])
		goto out;
	wiphy419_put_u16(ift0, WP419_O_IFTYPE_MASK,
			 BIT(NL80211_IFTYPE_AP) | BIT(NL80211_IFTYPE_STATION));
	/* Overlapping masks across two entries on band 1 (heap pair: only
	 * needed for this trap). */
	ift1x = kmalloc(2 * WP419_SZ_IFTYPE, GFP_KERNEL);
	if (!ift1x)
		goto out;
	memcpy(ift1x, ift1, WP419_SZ_IFTYPE);
	memcpy(ift1x + WP419_SZ_IFTYPE, ift1, WP419_SZ_IFTYPE);
	wiphy419_put_u16(band1, WP419_O_BAND_NIFTYPE, 2);
	wiphy419_put_ptr(band1, WP419_O_BAND_IFTYPE, ift1x);
	if (!shim_wiphy_publish(c) || native->bands[0] || native->bands[1])
		goto out;
	wiphy419_put_u16(band1, WP419_O_BAND_NIFTYPE, 1);
	wiphy419_put_ptr(band1, WP419_O_BAND_IFTYPE, ift1);
	/* Out-of-range mask bit (>= NL80211_IFTYPE_MAX). */
	wiphy419_put_u16(ift1, WP419_O_IFTYPE_MASK, BIT(12));
	if (!shim_wiphy_publish(c) || native->bands[0] || native->bands[1])
		goto out;
	wiphy419_put_u16(ift1, WP419_O_IFTYPE_MASK, BIT(NL80211_IFTYPE_AP));
	/* 6G without HE: publish succeeds, 6G skipped, 2.4/5G intact. */
	ift6[WP419_O_IFTYPE_HE + WP419_O_HE_HAS] = 0;
	if (shim_wiphy_publish(c) || !native->bands[0] || !native->bands[1] ||
	    native->bands[3])
		goto out;
	ift6[WP419_O_IFTYPE_HE + WP419_O_HE_HAS] = 1;
	/* 6G without any entries: same graceful skip. */
	wiphy419_put_u16(band6, WP419_O_BAND_NIFTYPE, 0);
	if (shim_wiphy_publish(c) || !native->bands[0] || !native->bands[1] ||
	    native->bands[3])
		goto out;
	wiphy419_put_u16(band6, WP419_O_BAND_NIFTYPE, 1);
	if (shim_wiphy_publish(c) || !native->bands[3])
		goto out;
	/* apply_custom forward with an empty regdomain: runs the real
	 * core path (publish-inside + reg_copy + channel walk), then
	 * re-publish restores the DISABLED stamps it leaves. */
	bcm_shim_wiphy_apply_custom_regulatory((struct wiphy *)c,
					       (void *)empty_regd);
	if (shim_wiphy_publish(c) ||
	    native->bands[0]->channels[0].flags != 0)
		goto out;
	/* Register dry-run on a band-less view: the real core must fail
	 * -EINVAL at !have_band (past the WDS/FW_ROAM/ifmodes/combination
	 * gates), with no phy created. The core WARNs once here by
	 * construction — expected, not a failure. */
	d = (struct wiphy419_view *)bcm_shim_wiphy_new_nm(&wiphy419_test_ops,
							    8, NULL);
	if (!d)
		goto out;
	entry = wiphy419_entry_of(d);
	if (!entry || entry->ops_used != &shim_stripped_ops ||
	    shim_stripped_ops.update_connect_params)
		goto out;
	cfg80211_compat_detach_blob();
	v32 = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);
	memcpy(d->bytes + W_OFF(interface_modes), &v32, 2);
	v32 = WIPHY_FLAG_PS_ON_BY_DEFAULT;
	memcpy(d->bytes + W_OFF(flags), &v32, sizeof(v32));
	if (bcm_shim_wiphy_register((struct wiphy *)d) != -EINVAL)
		goto out;
	native = shim_wiphy_native(d);
	if (!native || native->registered ||
	    native->interface_modes !=
			(BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP)))
		goto out;
	bcm_shim_wiphy_free((struct wiphy *)d);
	d = NULL;
	if (shim_wiphy_native((void *)1))
		goto out;
	/* Wrapper alloc guards + miss paths (must never fault). */
	if (bcm_shim_wiphy_new_nm(NULL, 8, NULL) ||
	    bcm_shim_wiphy_new_nm(&wiphy419_test_ops, 8, "phy0"))
		goto out;
	e = (struct wiphy419_view *)bcm_shim_wiphy_new_nm(&wiphy419_test_ops,
							    8, NULL);
	if (!e)
		goto out;
	cfg80211_compat_detach_blob();
	entry = wiphy419_entry_of(e);
	if (!entry || entry->priv_size != 8 ||
	    shim_wiphy_legacy(entry->native) != e)
		goto out;
	bcm_shim_wiphy_free((struct wiphy *)e);
	e = NULL;
	bcm_shim_wiphy_free((struct wiphy *)e);
	bcm_shim_wiphy_free(NULL);
	bcm_shim_wiphy_unregister(NULL);
	bcm_shim_wiphy_unregister((struct wiphy *)c); /* unregistered: skip */
	if (bcm_shim_wiphy_register(NULL) != -ENOENT ||
	    bcm_shim_wiphy_register((struct wiphy *)1) != -ENOENT ||
	    bcm_shim_regulatory_hint(NULL, "US") != -ENOENT ||
	    bcm_shim_regulatory_hint((struct wiphy *)1, "US") != -ENOENT)
		goto out;
	bcm_shim_wiphy_apply_custom_regulatory(NULL, (void *)empty_regd);
	bcm_shim_wiphy_apply_custom_regulatory((struct wiphy *)1,
					       (void *)empty_regd);
	bcm_shim_wiphy_apply_custom_regulatory((struct wiphy *)c, NULL);
	/* Re-attach guard: a different blob table drops stale unregistered
	 * entries (dead incarnation) instead of dangling. c (NULL tag,
	 * direct-alloc scaffolding) is always kept. The guard's one pr_warn
	 * line in dmesg is expected here, not a failure. */
	f = (struct wiphy419_view *)bcm_shim_wiphy_new_nm(&wiphy419_other_ops,
							   8, NULL);
	if (!f)
		goto out;
	cfg80211_compat_detach_blob();
	/* The allocator may immediately reuse f's freed address for g.
	 * A stale pointer lookup cannot distinguish those incarnations.
	 * Check the core's monotonically allocated phy index instead. */
	{
		int previous_idx = -1, next_idx = -1;

		if (sscanf(dev_name(&shim_wiphy_native(f)->dev), "phy%d",
			   &previous_idx) != 1)
			goto out;

		g = (struct wiphy419_view *)bcm_shim_wiphy_new_nm(
					&wiphy419_test_ops, 8, NULL);
		f = NULL; /* new_nm has reclaimed the old incarnation */
		if (!g || sscanf(dev_name(&shim_wiphy_native(g)->dev),
				 "phy%d", &next_idx) != 1 ||
		    next_idx <= previous_idx)
			goto out;
	}
	entry = wiphy419_entry_of(g);
	if (!entry || entry->blob_ops != (const void *)&wiphy419_test_ops ||
	    shim_wiphy_legacy(entry->native) != g)
		goto out;
	bcm_shim_wiphy_free((struct wiphy *)g);
	g = NULL;
	cfg80211_compat_detach_blob();
	pr_info("shim_wiphy: WIPHY419_LIFECYCLE_SELFTEST PASS deep=verified dryrun=-EINVAL miss=no-fault\n");
	ret = 0;
out:
	kfree(ift1x);
	if (g) {
		cfg80211_compat_detach_blob();
		bcm_shim_wiphy_free((struct wiphy *)g);
	}
	if (f && shim_wiphy_native(f)) {
		cfg80211_compat_detach_blob();
		bcm_shim_wiphy_free((struct wiphy *)f);
	}
	if (e) {
		cfg80211_compat_detach_blob();
		bcm_shim_wiphy_free((struct wiphy *)e);
	}
	if (d) {
		cfg80211_compat_detach_blob();
		bcm_shim_wiphy_free((struct wiphy *)d);
	}
	if (c && shim_wiphy_free_unregistered(c))
		ret = -EIO;
	if (shim_wiphy_free_unregistered((void *)1) != -ENOENT)
		ret = -EIO;
	return ret;
}

static struct wiphy419_view *vendor_test_wiphy;
static struct wdev419_view *vendor_test_wdev;
static int vendor_test0(struct wiphy *w, struct wireless_dev *d,
			const void *data, int len)
{
	if (w != (void *)vendor_test_wiphy || d != (void *)vendor_test_wdev ||
	    len != 4 || memcmp(data, "test", 4))
		return -EINVAL;
	return 17;
}
static int vendor_test1(struct wiphy *w, struct wireless_dev *d,
			const void *data, int len)
{
	return vendor_test0(w, d, data, len) == 17 ? 29 : -EINVAL;
}
static int wiphy419_vendor_selftest(void)
{
	struct vendor419_command commands[2] = {
		{ .info = { 0x1018, 1 }, .flags = 3, .doit = vendor_test0 },
		{ .info = { 0x1018, 2 }, .flags = 3, .doit = vendor_test1 },
	};
	const struct nl80211_vendor_cmd_info events[3] = {
		{ 0x1018, 0 }, { 0x1018, 1 }, { 0x1018, 2 },
	};
	struct wiphy419_view *old = shim_wiphy_alloc(8, &wiphy419_test_ops);
	struct wdev419_view *d = shim_wdev_alloc();
	struct wiphy *w = old ? shim_wiphy_native(old) : NULL;
	struct wireless_dev *nd = d ? shim_wdev_native(d) : NULL;
	u32 n;
	int ret = -EINVAL;
#define VCHECK(x) do { if (!(x)) { \
	pr_err("WIPHY419_VENDOR_SELFTEST FAIL line=%d\n", __LINE__); \
	goto done; } } while (0)
	VCHECK(w && nd && !shim_wdev_bind(d, old));
	vendor_test_wiphy = old;
	vendor_test_wdev = d;
	set_old_ptr_at(old->bytes, W_OFF(vendor_commands), commands);
	set_old_ptr_at(old->bytes, W_OFF(vendor_events), events);
	n = 2; memcpy(old->bytes + W_OFF(n_vendor_commands), &n, 4);
	n = 3; memcpy(old->bytes + W_OFF(n_vendor_events), &n, 4);
	VCHECK(!shim_wiphy_publish(old));
	VCHECK(w->n_vendor_commands == 2 && w->n_vendor_events == 3);
	VCHECK(w->vendor_commands[0].policy == VENDOR_CMD_RAW_DATA &&
	       w->vendor_commands[1].policy == VENDOR_CMD_RAW_DATA &&
	       !w->vendor_commands[0].dumpit && !w->vendor_commands[0].maxattr);
	VCHECK(w->vendor_events != events && !memcmp(w->vendor_events, events, sizeof(events)));
	VCHECK(w->vendor_commands[0].doit(w, nd, "test", 4) == 17);
	VCHECK(w->vendor_commands[1].doit(w, nd, "test", 4) == 29);
	VCHECK(w->vendor_commands[0].doit(w, (void *)1, "test", 4) == -ENOENT);
	commands[1].flags = 0x80000000;
	VCHECK(shim_wiphy_publish(old) == -EOPNOTSUPP &&
	       !w->vendor_commands && !w->vendor_events);
	commands[1].flags = 3;
	n = 3; memcpy(old->bytes + W_OFF(n_vendor_commands), &n, 4);
	VCHECK(shim_wiphy_publish(old) == -EOPNOTSUPP);
	n = 2; memcpy(old->bytes + W_OFF(n_vendor_commands), &n, 4);
	VCHECK(!shim_wiphy_publish(old));
	n = 0;
	memcpy(old->bytes + W_OFF(n_vendor_commands), &n, 4);
	memcpy(old->bytes + W_OFF(n_vendor_events), &n, 4);
	set_old_ptr_at(old->bytes, W_OFF(vendor_commands), NULL);
	set_old_ptr_at(old->bytes, W_OFF(vendor_events), NULL);
	VCHECK(!shim_wiphy_publish(old) && !w->vendor_commands && !w->vendor_events);
	ret = 0;
	pr_info("WIPHY419_VENDOR_SELFTEST PASS deep-copy raw-policy callback-view guards cleanup\n");
done:
	vendor_test_wiphy = NULL;
	vendor_test_wdev = NULL;
	if (d)
		shim_wdev_free(d);
	if (old)
		shim_wiphy_free_unregistered(old);
	return ret;
#undef VCHECK
}

static int wdev419_adopt_selftest(void)
{
	struct wiphy419_view *wp = shim_wiphy_alloc(8, &wiphy419_test_ops);
	struct wdev419_view *old = kzalloc(sizeof(*old), GFP_KERNEL);
	struct net_device *dev = alloc_etherdev(0);
	struct wireless_dev *wd = NULL;
	u32 type = NL80211_IFTYPE_AP;
	int ret = -EINVAL;

	if (!wp || !old || !dev)
		goto out;
	set_old_ptr_at(old->bytes, D_OFF(wiphy), wp);
	set_old_ptr_at(old->bytes, D_OFF(netdev), (void *)0x1234);
	memcpy(old->bytes + D_OFF(iftype), &type, sizeof(type));
	wd = shim_wdev_adopt(old, (void *)0x1234, dev);
	if (IS_ERR(wd)) {
		wd = NULL;
		goto out;
	}
	if (wd->netdev != dev || wd->wiphy != shim_wiphy_native(wp) ||
	    wd->iftype != type || shim_wdev_legacy(wd) != old ||
	    shim_wdev_adopt(old, (void *)0x1234, dev) != wd ||
	    PTR_ERR(shim_wdev_adopt(old, (void *)0x4321, dev)) != -EINVAL)
		goto out;
	wd->netdev = NULL;
	if (shim_wdev_free(old))
		goto out;
	wd = NULL;
	/* Borrowed old storage must still belong to its allocator. */
	if (old_ptr_at(old->bytes, D_OFF(wiphy)) != wp ||
	    shim_wdev_native(old))
		goto out;
	ret = 0;
	pr_info("WDEV419_ADOPT_SELFTEST PASS borrowed-view native-links reject-mismatch release\n");
out:
	if (wd) {
		wd->netdev = NULL;
		shim_wdev_free(old);
	}
	kfree(old);
	if (dev)
		free_netdev(dev);
	if (wp)
		shim_wiphy_free_unregistered(wp);
	return ret;
}

static int wdev419_selftest(void)
{
	struct wdev419_view *wa = NULL, *wb = NULL;
	struct wiphy419_view *pa = NULL;
	struct wireless_dev *native;
	u32 v32;
	int ret = -EIO;

	wa = shim_wdev_alloc();
	wb = shim_wdev_alloc();
	pa = shim_wiphy_alloc(8, &wiphy419_test_ops);
	if (!wa || !wb || !pa)
		goto out;
	native = shim_wdev_native(wa);
	if (!native || (void *)native == (void *)wa ||
	    shim_wdev_legacy(native) != wa ||
	    shim_wdev_native((void *)1) || shim_wdev_legacy((void *)1) ||
	    memchr_inv(wa->bytes, 0, WP419_size_wireless_dev))
		goto out;
	/* Bind links both sides without ever cross-linking views. */
	if (shim_wdev_bind(wa, pa))
		goto out;
	if (old_ptr_at(wa->bytes, D_OFF(wiphy)) != pa ||
	    native->wiphy != shim_wiphy_native(pa))
		goto out;
	/* iftype + address round trip through publish/sync. */
	v32 = NL80211_IFTYPE_AP;
	memcpy(wa->bytes + D_OFF(iftype), &v32, sizeof(v32));
	if (shim_wdev_publish(wa) || native->iftype != NL80211_IFTYPE_AP)
		goto out;
	native->iftype = NL80211_IFTYPE_STATION;
	shim_wdev_sync(wa);
	if (old_u32_at(wa->bytes, D_OFF(iftype)) != NL80211_IFTYPE_STATION)
		goto out;
	/* Foreign netdev pointer must be rejected, never installed. */
	set_old_ptr_at(wa->bytes, D_OFF(netdev), (void *)0x1);
	if (!shim_wdev_publish(wa) || native->netdev)
		goto out;
	set_old_ptr_at(wa->bytes, D_OFF(netdev), NULL);
	/* Unbind clears both sides; unknown views are rejected. */
	if (shim_wdev_bind(wa, NULL) || native->wiphy ||
	    old_ptr_at(wa->bytes, D_OFF(wiphy)))
		goto out;
	if (!shim_wdev_bind(wa, (void *)1) ||
	    !shim_wdev_bind((void *)1, pa))
		goto out;
	pr_info("shim_wiphy: WDEV419_SELFTEST PASS bind=paired publish=checked traps=rejected\n");
	ret = 0;
out:
	if (wb && shim_wdev_free(wb))
		ret = -EIO;
	if (wa && shim_wdev_free(wa))
		ret = -EIO;
	if (pa && shim_wiphy_free_unregistered(pa))
		ret = -EIO;
	if (!list_empty(&wdev419_views) || !list_empty(&wiphy419_views))
		ret = -EIO;
	if (shim_wdev_free((void *)1) != -ENOENT)
		ret = -EIO;
	return ret;
}

static bool custom_reg_selftest;
module_param(custom_reg_selftest, bool, 0400);
static int wiphy419_custom_reg_selftest(void)
{
	static const struct cfg80211_ops ops;
	struct ieee80211_regdomain *rd;
	struct wiphy *w;
	struct ieee80211_channel chan = { .band = NL80211_BAND_2GHZ,
		.center_freq = 2412, .max_power = 20 };
	struct ieee80211_supported_band band = { .channels = &chan,
		.n_channels = 1, .band = NL80211_BAND_2GHZ };
	int ret = -EINVAL;
	w = wiphy_new_nm(&ops, 0, NULL);
	if (!w) return -ENOMEM;
	rd = kzalloc(struct_size(rd, reg_rules, 1), GFP_KERNEL);
	if (!rd) { wiphy_free(w); return -ENOMEM; }
	rd->n_reg_rules = 1;
	memcpy(rd->alpha2, "99", 2);
	rd->reg_rules[0].freq_range.start_freq_khz = 2402000;
	rd->reg_rules[0].freq_range.end_freq_khz = 2482000;
	rd->reg_rules[0].freq_range.max_bandwidth_khz = 20000;
	rd->reg_rules[0].power_rule.max_eirp = 2000;
	rd->reg_rules[0].flags = NL80211_RRF_NO_IR;
	w->regulatory_flags = REGULATORY_CUSTOM_REG;
	w->bands[NL80211_BAND_2GHZ] = &band;
	/* Unlocked entry must still take/release its own RTNL. */
	wiphy_apply_custom_regulatory(w, rd);
	if (!(chan.flags & IEEE80211_CHAN_NO_IR) || chan.max_power != 20)
		goto out;
	rd->reg_rules[0].power_rule.max_eirp = 1700;
	rtnl_lock();
	wiphy_apply_custom_regulatory_rtnl(w, rd);
	if (chan.max_power == 17 && (chan.flags & IEEE80211_CHAN_NO_IR) &&
	    rcu_dereference_protected(w->regd, 1)->reg_rules[0].power_rule.max_eirp == 1700)
		ret = 0;
	rtnl_unlock();
out:
	w->bands[NL80211_BAND_2GHZ] = NULL;
	wiphy_free(w);
	kfree(rd);
	pr_info("CUSTOM_REG_RTNL_SELFTEST %s rules-preserved unlocked-and-owned\n", ret ? "FAIL" : "PASS");
	return ret;
}

int shim_wiphy_init(void)
{
	int ret;

	static_assert(sizeof(struct wiphy419_view) == 608);
	static_assert(sizeof(struct wdev419_view) == 224);
	static_assert(WP419_size_wiphy == 608);
	static_assert(WP419_size_wireless_dev == 224);
	static_assert(WP419_size_wiphy % NETDEV_ALIGN == 0);
	static_assert(sizeof(void *) == 4);
	static_assert(sizeof(struct wiphy) == 896);
	static_assert(sizeof(struct wireless_dev) == 896);
	static_assert(offsetof(struct wiphy, perm_addr) == 20);
	static_assert(offsetof(struct wiphy, mgmt_stypes) == 36);
	static_assert(offsetof(struct wiphy, iface_combinations) == 40);
	static_assert(offsetof(struct wiphy, interface_modes) == 52);
	static_assert(offsetof(struct wiphy, flags) == 56);
	static_assert(offsetof(struct wiphy, regulatory_flags) == 60);
	static_assert(offsetof(struct wiphy, features) == 64);
	static_assert(offsetof(struct wiphy, ext_features) == 68);
	static_assert(sizeof(((struct wiphy *)0)->ext_features) == 9);
	static_assert(WP419_width_wiphy_ext_features == 6);
	static_assert(offsetof(struct wiphy, max_scan_ssids) == 92);
	static_assert(offsetof(struct wiphy, max_scan_ie_len) == 96);
	static_assert(offsetof(struct wiphy, n_cipher_suites) == 112);
	static_assert(offsetof(struct wiphy, fw_version) == 149);
	static_assert(offsetof(struct wiphy, hw_version) == 184);
	static_assert(offsetof(struct wiphy, bands) == 236);
	static_assert(offsetof(struct wiphy, privid) == 232);
	static_assert(offsetof(struct wiphy, dev) == 272);
	static_assert(offsetof(struct wiphy, registered) == 744);
	static_assert(offsetof(struct wiphy, vendor_commands) == 776);
	static_assert(offsetof(struct wiphy, n_vendor_commands) == 784);
	static_assert(offsetof(struct wiphy, priv) == 896);
	static_assert(WP419_val_NUM_NL80211_BANDS == 4);
	static_assert(NUM_NL80211_BANDS == 6);
	static_assert(WP419_val_NUM_NL80211_EXT_FEATURES == 42);
	static_assert(NUM_NL80211_EXT_FEATURES == 65);
	static_assert(offsetof(struct wireless_dev, wiphy) == 0);
	static_assert(offsetof(struct wireless_dev, iftype) == 4);
	static_assert(offsetof(struct wireless_dev, list) == 8);
	static_assert(offsetof(struct wireless_dev, netdev) == 16);
	static_assert(offsetof(struct wireless_dev, mtx) == 36);
	static_assert(offsetof(struct wireless_dev, address) == 60);
	/* H28 deep-publish twins (4.19 geometry in the WP419_* defines
	 * above, compiler-measured; native side pinned here). */
	static_assert(sizeof(struct ieee80211_supported_band) == 92);
	static_assert(offsetof(struct ieee80211_supported_band, channels) == 0);
	static_assert(offsetof(struct ieee80211_supported_band, bitrates) == 4);
	static_assert(offsetof(struct ieee80211_supported_band, band) == 8);
	static_assert(offsetof(struct ieee80211_supported_band, n_channels) == 12);
	static_assert(offsetof(struct ieee80211_supported_band, n_bitrates) == 16);
	static_assert(offsetof(struct ieee80211_supported_band, ht_cap) == 20);
	static_assert(offsetof(struct ieee80211_supported_band, vht_cap) == 44);
	static_assert(offsetof(struct ieee80211_supported_band, n_iftype_data) == 84);
	static_assert(offsetof(struct ieee80211_supported_band, iftype_data) == 88);
	static_assert(sizeof(struct ieee80211_sta_ht_cap) == WP419_SZ_STA_HT);
	static_assert(sizeof(struct ieee80211_sta_vht_cap) == WP419_SZ_STA_VHT);
	static_assert(sizeof(struct ieee80211_channel) == 56);
	static_assert(offsetof(struct ieee80211_channel, center_freq) == 4);
	static_assert(offsetof(struct ieee80211_channel, freq_offset) == 8);
	static_assert(offsetof(struct ieee80211_channel, hw_value) == 10);
	static_assert(offsetof(struct ieee80211_channel, flags) == 12);
	static_assert(offsetof(struct ieee80211_channel, max_antenna_gain) == 16);
	static_assert(offsetof(struct ieee80211_channel, max_power) == 20);
	static_assert(offsetof(struct ieee80211_channel, max_reg_power) == 24);
	static_assert(offsetof(struct ieee80211_channel, beacon_found) == 28);
	static_assert(offsetof(struct ieee80211_channel, orig_flags) == 32);
	static_assert(offsetof(struct ieee80211_channel, orig_mag) == 36);
	static_assert(offsetof(struct ieee80211_channel, orig_mpwr) == 40);
	static_assert(offsetof(struct ieee80211_channel, dfs_state) == 44);
	static_assert(offsetof(struct ieee80211_channel, dfs_state_entered) == 48);
	static_assert(offsetof(struct ieee80211_channel, dfs_cac_ms) == 52);
	static_assert(sizeof(struct ieee80211_rate) == WP419_SZ_RATE);
	static_assert(sizeof(struct ieee80211_iface_combination) == WP419_SZ_COMB);
	static_assert(offsetof(struct ieee80211_iface_combination, limits) == 0);
	static_assert(offsetof(struct ieee80211_iface_combination, num_different_channels) == 4);
	static_assert(offsetof(struct ieee80211_iface_combination, max_interfaces) == 8);
	static_assert(offsetof(struct ieee80211_iface_combination, n_limits) == 10);
	static_assert(offsetof(struct ieee80211_iface_combination, beacon_int_infra_match) == 11);
	static_assert(sizeof(struct ieee80211_iface_limit) == WP419_SZ_LIMIT);
	static_assert(offsetof(struct ieee80211_iface_limit, max) == 0);
	static_assert(offsetof(struct ieee80211_iface_limit, types) == 2);
	static_assert(sizeof(struct ieee80211_txrx_stypes) == WP419_SZ_TXRX);
	static_assert(NL80211_IFTYPE_MAX == WP419_NL80211_IFTYPE_MAX);
	static_assert(NUM_NL80211_BANDS == 6);
	static_assert(NL80211_BAND_6GHZ == 3);
	static_assert(NL80211_IFTYPE_WDS == 5);
	static_assert(offsetof(struct wiphy, cipher_suites) == 116);
	static_assert(offsetof(struct wiphy, n_cipher_suites) == 112);
	static_assert(offsetof(struct wiphy, mgmt_stypes) == 36);
	static_assert(offsetof(struct wiphy, iface_combinations) == 40);
	static_assert(offsetof(struct wiphy, n_iface_combinations) == 44);
	static_assert(offsetof(struct wiphy, n_addresses) == 50);
	/* H-bands iftype twins (419 geometry in the WP419_SZ_IFTYPE block
	 * above, both sides compiler-measured; the 4.19 HE elem is 14 B,
	 * the 6.6 one 17 B — translation is field-wise, never
	 * whole-struct). The elem prefix assumption (mac[6]@0, phy[11]@6)
	 * is pinned too: the 14 B D2.0 prefix keeps byte meanings. */
	static_assert(sizeof(struct ieee80211_sband_iftype_data) == 120);
	static_assert(offsetof(struct ieee80211_sband_iftype_data, types_mask) == 0);
	static_assert(offsetof(struct ieee80211_sband_iftype_data, he_cap) == 2);
	static_assert(offsetof(struct ieee80211_sband_iftype_data, he_6ghz_capa) == 57);
	static_assert(offsetof(struct ieee80211_sband_iftype_data, eht_cap) == 59);
	static_assert(offsetof(struct ieee80211_sband_iftype_data, vendor_elems) == 112);
	static_assert(sizeof(struct ieee80211_sta_he_cap) == 55);
	static_assert(offsetof(struct ieee80211_sta_he_cap, has_he) == 0);
	static_assert(offsetof(struct ieee80211_sta_he_cap, he_cap_elem) == 1);
	static_assert(offsetof(struct ieee80211_sta_he_cap, he_mcs_nss_supp) == 18);
	static_assert(offsetof(struct ieee80211_sta_he_cap, ppe_thres) == 30);
	static_assert(sizeof(struct ieee80211_he_cap_elem) == WP419_SZ_HE_ELEM66);
	static_assert(offsetof(struct ieee80211_he_cap_elem, mac_cap_info) == 0);
	static_assert(offsetof(struct ieee80211_he_cap_elem, phy_cap_info) == 6);
	static_assert(sizeof(((struct ieee80211_he_cap_elem *)0)->mac_cap_info) == 6);
	static_assert(sizeof(((struct ieee80211_he_cap_elem *)0)->phy_cap_info) == 11);
	static_assert(sizeof(struct ieee80211_he_mcs_nss_supp) == WP419_SZ_HE_MCS);
	static_assert(sizeof(struct ieee80211_he_6ghz_capa) == WP419_SZ_HE6G);
	static_assert(sizeof(((struct ieee80211_sta_he_cap *)0)->ppe_thres) == WP419_SZ_HE_PPE);
	static_assert(sizeof(struct ieee80211_sta_s1g_cap) == 16);
	static_assert(sizeof(struct ieee80211_edmg) == 8);
	static_assert(WP419_SZ_IFTYPE == 56);
	static_assert(WP419_MAX_IFTYPE_DATA <= NL80211_IFTYPE_MAX);
	static_assert(NL80211_BAND_2GHZ == 0);
	static_assert(NL80211_BAND_5GHZ == 1);
	static_assert(NL80211_BAND_60GHZ == 2);
	static_assert(NL80211_BAND_S1GHZ == 4);
	static_assert(NL80211_BAND_LC == 5);
	/* Derived translated ops: wl_66_ops minus update_connect_params
	 * (register gate vs the blob's NULL slot, see the definition).
	 * Installed here so wrapper-alloc selftests below already use it. */
	shim_stripped_ops = wl_66_ops;
	shim_stripped_ops.update_connect_params = NULL;
	ret = custom_reg_selftest ? wiphy419_custom_reg_selftest() : 0;
	if (ret) return ret;
	ret = wiphy_selftest ? wiphy419_selftest() : 0;
	if (!ret && wiphy_selftest)
		ret = wiphy419_lifecycle_selftest();
	if (!ret && wiphy_selftest)
		ret = wiphy419_vendor_selftest();
	if (!ret && wdev_selftest)
		ret = wdev419_selftest();
	if (!ret && wdev_selftest)
		ret = wdev419_adopt_selftest();
	return ret;
}

void shim_wiphy_exit(void)
{
	/* Defensive drain for the init-failure path (both selftests free
	 * everything they allocate and assert empty registries, so this is
	 * a no-op on success). Idempotent: a second call finds empty lists.
	 * Only unregistered objects are adapter-owned and freed via the
	 * tested free calls (they sleep on synchronize_rcu — hence the lock
	 * is dropped around the calls); anything the core owns is reported
	 * and retained. Single-threaded here (init failure or module exit),
	 * so peek-and-free needs no extra serialization beyond the mutex. */
	for (;;) {
		struct wiphy419_entry *entry;
		struct wdev419_entry *wdev;
		struct wiphy419_view *victim = NULL;
		struct wdev419_view *wdev_victim = NULL;

		mutex_lock(&wiphy419_mutex);
		list_for_each_entry(entry, &wiphy419_views, list) {
			if (!entry->native->registered) {
				victim = entry->old;
				break;
			}
		}
		list_for_each_entry(wdev, &wdev419_views, list) {
			if (!wdev->native->registered && !wdev->native->netdev &&
			    list_empty(&wdev->native->list)) {
				wdev_victim = wdev->old;
				break;
			}
		}
		if (!victim && !wdev_victim &&
		    (!list_empty(&wiphy419_views) || !list_empty(&wdev419_views)))
			pr_warn("bcm_shim: wiphy_exit: registered objects retained\n");
		mutex_unlock(&wiphy419_mutex);
		if (!victim && !wdev_victim)
			break;
		if (wdev_victim)
			shim_wdev_free(wdev_victim);
		if (victim)
			shim_wiphy_free_unregistered(victim);
	}
}
