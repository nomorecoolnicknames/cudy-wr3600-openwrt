/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cfg80211_compat.c - cfg80211_ops 4.19 -> 6.6 translation for stock wl.ko
 *
 * Lane D of SHIM_WORKPLAN.md . The stock wl.ko blob was built
 * against a Broadcom BCA 4.19 tree: its cfg80211_ops table has 106 entries
 * and every op from add_key on is shifted by +2..+4 versus kernel 6.6
 * (124 entries with TESTMODE, 122 without). Registering the blob table
 * directly would misdispatch (e.g. 6.6 scan idx40 = 4.19 deauth).
 *
 * This module builds a native 6.6 struct cfg80211_ops (wl_66_ops) where
 * every entry is a thunk: it fetches the blob implementation from the
 * attached 4.19-layout table (struct wl419_ops), converts arguments from
 * 6.6 layouts to 4.19 layouts where needed, and calls through.
 *
 * Blob table acquisition (lane E/H): the raw table lives in wl.ko
 * .data+0x3298 (see triaging/cfg80211_ops_map.txt); pass its address to
 * cfg80211_compat_attach_blob() after insmod of wl.ko and before the
 * blob's wiphy registers. Every thunk null-checks the blob pointer, so
 * an unattached table degrades to -EOPNOTSUPP, never to a crash.
 *
 * All symbols exported for the blob are plain EXPORT_SYMBOL (never _GPL):
 * wl.ko is Proprietary and cannot resolve _GPL exports.
 *
 * Merge D (2026-09-07): this file replaces shim_cfg80211.c in bcm_shim.ko
 * (plus its 5 inline-forwarders, transplanted to the file end). It is no
 * longer a standalone module: init is cfg80211_compat_subinit(), called
 * from shim_core_init(); MODULE boilerplate lives in shim_core.c.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
/* The 6.6 headers define static inlines with the same names as the
 * 4.19-compat globals forwarded at the end of this file. Rename the
 * inlines at include time (transplanted from shim_cfg80211.c at merge
 * D); the rest of this TU never uses those 5 identifiers, so the
 * rename is side-effect free. Guarded by IS_ENABLED so the dormant
 * branch (CONFIG_CFG80211=n, current tree) still compiles. */
#if IS_ENABLED(CONFIG_CFG80211)
#define cfg80211_rx_mgmt		cfg80211_rx_mgmt_inl
#define cfg80211_mgmt_tx_status		cfg80211_mgmt_tx_status_inl
#define ieee80211_channel_to_frequency	ieee80211_channel_to_frequency_inl
#define ieee80211_frequency_to_channel	ieee80211_frequency_to_channel_inl
#define ieee80211_get_channel		ieee80211_get_channel_inl
#endif
#include <net/cfg80211.h>

#include "cfg80211_compat.h"
#include "shim_wiphy.h"
#include "shim_netdev.h"
#include "shim_gfp.h"
#if IS_ENABLED(CONFIG_CFG80211)
#undef cfg80211_rx_mgmt
#undef cfg80211_mgmt_tx_status
#undef ieee80211_channel_to_frequency
#undef ieee80211_frequency_to_channel
#undef ieee80211_get_channel
#endif

/* ------------------------------------------------------------------ */
/* Blob attachment                                                     */
/* ------------------------------------------------------------------ */

static const struct wl419_ops *wl_blob_ops;

void cfg80211_compat_attach_blob(const struct wl419_ops *blob_ops)
{
	WRITE_ONCE(wl_blob_ops, blob_ops);
	pr_info("cfg80211_compat: blob ops attached at %ps\n", blob_ops);
}
EXPORT_SYMBOL(cfg80211_compat_attach_blob);

void cfg80211_compat_detach_blob(void)
{
	WRITE_ONCE(wl_blob_ops, NULL);
	pr_info("cfg80211_compat: blob ops detached\n");
}
EXPORT_SYMBOL(cfg80211_compat_detach_blob);

static bool cfg_call_trace;
module_param(cfg_call_trace, bool, 0600);
/* Debug only: identify the exact legacy callback, preserving its signature. */
#define CFG_CALL(member, ...) ({ \
	typeof(b->member(__VA_ARGS__)) _result; \
	if (cfg_call_trace) dev_info(wiphy_dev(wiphy), "H30_CFG " #member " enter\n"); \
	_result = b->member(__VA_ARGS__); \
	if (cfg_call_trace) dev_info(wiphy_dev(wiphy), "H30_CFG " #member " exit %ld\n", (long)_result); \
	_result; \
})

static inline const struct wl419_ops *wl_blob_get(void)
{
	return READ_ONCE(wl_blob_ops);
}

static int wl_op_missing_int(const char *op)
{
	pr_warn_once("cfg80211_compat: blob op %s missing, -EOPNOTSUPP\n", op);
	return -EOPNOTSUPP;
}

static void wl_op_missing_void(const char *op)
{
	pr_warn_once("cfg80211_compat: blob op %s missing, ignored\n", op);
}

/* ------------------------------------------------------------------ */
/* mgmt-path telemetry (ASSOC_TRIAGE lane). Every forwarder/thunk leg  */
/* below bumps a counter on entry and on silent-drop legs. Drops use   */
/* pr_warn_once (never silent: the assoc-timeout symptom was ZERO      */
/* dmesg), entries use pr_info_ratelimited gated by wl_mgmt_trace so   */
/* the HW lane can watch live firmware<->hostapd traffic. Counters     */
/* are dmesg-only (no sysfs: keep the blob-facing surface minimal).    */
/* ------------------------------------------------------------------ */

static bool wl_mgmt_trace;
module_param_named(mgmt_trace, wl_mgmt_trace, bool, 0600);
MODULE_PARM_DESC(mgmt_trace, "ratelimited pr_info on every mgmt RX/TX leg");

static atomic_long_t wl_mgmt_rx_calls = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_mgmt_rx_drop_nowdev = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_mgmt_txst_calls = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_mgmt_txst_drop_nowdev = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_mgmt_tx_calls = ATOMIC_LONG_INIT(0);

/* filled-bit allowlist for wl_shim_station_info_19_to_66(): the 4.19 BCA
 * enum nl80211_sta_info ends at DATA_ACK_SIGNAL_AVG (kept as a compat alias
 * in 6.6); everything above it is post-4.19 (RX_MPDUS .. CONNECTED_TO_AS).
 * Bit 0 (__INVALID) is never a valid filled bit. */
#define WL_SINFO419_FILLED_MASK \
	GENMASK_ULL(NL80211_STA_INFO_DATA_ACK_SIGNAL_AVG, \
		    __NL80211_STA_INFO_INVALID + 1)

/* Ownership telemetry for the event-emit chain. ie allocs/frees are always
 * paired inside the shim (own_ies/disown_ies); pertid dups transfer to the
 * 6.6 core on emit (core kfree) and pair with pertid_released only on drop
 * paths and in the selftest. */
static atomic_long_t wl_sinfo_ie_allocs = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_sinfo_ie_frees = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_sinfo_pertid_dup_ok = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_sinfo_pertid_dup_fail = ATOMIC_LONG_INIT(0);
static atomic_long_t wl_sinfo_pertid_released = ATOMIC_LONG_INIT(0);

/* ------------------------------------------------------------------ */
/* Converters 6.6 -> 4.19 (sync direction: core -> blob)               */
/* ------------------------------------------------------------------ */

void wl_shim_key_66_to_19(const struct key_params *src,
			   struct wl419_key_params *dst)
{
	dst->key = src->key;
	dst->seq = src->seq;
	dst->key_len = src->key_len;
	dst->seq_len = src->seq_len;
	dst->cipher = src->cipher;
	/* DROPPED: vlan_id (per-vlan GTK, blob is pre-vlan API),
	 * mode (EXT_KEY_ID, unknown to 4.19 firmware path). */
}
EXPORT_SYMBOL(wl_shim_key_66_to_19);

void wl_shim_beacon_66_to_19(const struct cfg80211_beacon_data *src,
			     struct wl419_beacon_data *dst)
{
	dst->head = src->head;
	dst->tail = src->tail;
	dst->beacon_ies = src->beacon_ies;
	dst->proberesp_ies = src->proberesp_ies;
	dst->assocresp_ies = src->assocresp_ies;
	dst->probe_resp = src->probe_resp;
	dst->head_len = src->head_len;
	dst->tail_len = src->tail_len;
	dst->beacon_ies_len = src->beacon_ies_len;
	dst->proberesp_ies_len = src->proberesp_ies_len;
	dst->assocresp_ies_len = src->assocresp_ies_len;
	dst->probe_resp_len = src->probe_resp_len;
	/* DROPPED: link_id (MLO, single-link blob), lci, civicloc,
	 * mbssid_ies, rnr_ies, ftm_responder, he_bss_color. If the AP
	 * needs MBSSID/RNR the blob must be driven via ioctl/iovar
	 * (lane G / WL_IOCTL_ANALYSIS.md), not via this path. */
}
EXPORT_SYMBOL(wl_shim_beacon_66_to_19);

void wl_shim_chandef_66_to_19(const struct cfg80211_chan_def *src,
			      struct wl419_chan_def *dst)
{
	dst->chan = shim_channel_legacy(src->chan);
	dst->width = src->width;
	dst->center_freq1 = src->center_freq1;
	dst->center_freq2 = src->center_freq2;
	/* DROPPED: edmg (60 GHz, N/A on BCM6764), freq1_offset. */
}
EXPORT_SYMBOL(wl_shim_chandef_66_to_19);

void wl_shim_bss_66_to_19(const struct bss_parameters *src,
			   struct wl419_bss_params *dst)
{
	dst->use_cts_prot = src->use_cts_prot;
	dst->use_short_preamble = src->use_short_preamble;
	dst->use_short_slot_time = src->use_short_slot_time;
	dst->basic_rates = src->basic_rates;
	dst->basic_rates_len = src->basic_rates_len;
	dst->ap_isolate = src->ap_isolate;
	dst->ht_opmode = src->ht_opmode;
	dst->p2p_ctwindow = src->p2p_ctwindow;
	dst->p2p_opp_ps = src->p2p_opp_ps;
	/* DROPPED: link_id (first field of the 6.6 struct). */
}
EXPORT_SYMBOL(wl_shim_bss_66_to_19);

/* bitrate mask entry: 6.6 widened the per-band control block with
 * he_mcs/he_gi/he_ltf, so per-band stride differs -> deep copy.
 */
static void wl_shim_mask_66_to_19(const struct cfg80211_bitrate_mask *src,
				  struct wl419_bitrate_mask *dst)
{
	int b;

	for (b = 0; b < WL419_NUM_BANDS; b++) {
		dst->control[b].legacy = src->control[b].legacy;
		memcpy(dst->control[b].ht_mcs, src->control[b].ht_mcs,
		       IEEE80211_HT_MCS_MASK_LEN);
		memcpy(dst->control[b].vht_mcs, src->control[b].vht_mcs,
		       sizeof(dst->control[b].vht_mcs));
		dst->control[b].gi = src->control[b].gi;
		/* DROPPED: he_mcs, he_gi, he_ltf (no HE rate control
		 * in the 4.19 firmware API). */
	}
}

/* Deep-convert crypto settings. 6.6 removed static WEP keys from this
 * struct (they live in ibss_params / connect key fields now), so the
 * 4.19 wep_keys pointer is always NULL here; the blob's WEP path on
 * managed mode uses sme->key/key_idx, copied by the caller.
 */
static void wl_shim_crypto_66_to_19(const struct cfg80211_crypto_settings *src,
				    struct wl419_crypto_settings *dst)
{
	int n;

	dst->wpa_versions = src->wpa_versions;
	dst->cipher_group = src->cipher_group;
	n = min_t(int, src->n_ciphers_pairwise, NL80211_MAX_NR_CIPHER_SUITES);
	dst->n_ciphers_pairwise = n;
	memcpy(dst->ciphers_pairwise, src->ciphers_pairwise,
	       n * sizeof(u32));
	/* 4.19 akm array holds 2 entries, 6.6 holds
	 * CFG80211_MAX_NUM_AKM_SUITES (10). Clamp. */
	n = min_t(int, src->n_akm_suites, NL80211_MAX_NR_AKM_SUITES);
	dst->n_akm_suites = n;
	memcpy(dst->akm_suites, src->akm_suites, n * sizeof(u32));
	dst->control_port = src->control_port;
	dst->control_port_ethertype = src->control_port_ethertype;
	dst->control_port_no_encrypt = src->control_port_no_encrypt;
	dst->control_port_over_nl80211 = src->control_port_over_nl80211;
	dst->psk = src->psk; /* Borrowed for the synchronous blob call. */
	/* DROPPED: control_port_no_preauth, sae_pwd/sae_pwd_len/
	 * sae_pwe (SAE extensions unknown to 4.19). */
	dst->wep_keys = NULL;
	dst->wep_tx_key = 0;
}

static void wl_shim_ap_66_to_19(const struct cfg80211_ap_settings *src,
				struct wl419_ap_settings *dst)
{
	wl_shim_chandef_66_to_19(&src->chandef, &dst->chandef);
	wl_shim_beacon_66_to_19(&src->beacon, &dst->beacon);
	dst->beacon_interval = src->beacon_interval;
	dst->dtim_period = src->dtim_period;
	dst->ssid = src->ssid;
	dst->ssid_len = src->ssid_len;
	dst->hidden_ssid = src->hidden_ssid;
	wl_shim_crypto_66_to_19(&src->crypto, &dst->crypto);
	dst->privacy = src->privacy;
	dst->auth_type = src->auth_type;
	dst->smps_mode = src->smps_mode;
	dst->inactivity_timeout = src->inactivity_timeout;
	dst->p2p_ctwindow = src->p2p_ctwindow;
	dst->p2p_opp_ps = src->p2p_opp_ps;
	dst->acl = src->acl; /* layout-identical (only __counted_by added) */
	dst->pbss = src->pbss;
	wl_shim_mask_66_to_19(&src->beacon_rate, &dst->beacon_rate);
	dst->ht_cap = src->ht_cap;
	dst->vht_cap = src->vht_cap;
	dst->ht_required = src->ht_required;
	dst->vht_required = src->vht_required;
	/* DROPPED: he_cap/he_oper/eht_cap/eht_oper/he_required/
	 * sae_h2e_required/twt_responder/flags/he_obss_pd/fils_discovery/
	 * unsol_bcast_probe_resp/mbssid_config/punct_bitmap. HE/EHT bring-up
	 * goes through the blob's internal tables (WIFI7_MLO_EHT_ANALYSIS.md),
	 * not through AP-start IEs on this path. */
}

void wl_shim_station_params_66_to_19(const struct station_parameters *src,
				     struct wl419_station_params *dst)
{
	/* 6.6 moved radio caps into link_sta_params; 4.19 keeps them at
	 * top level. Non-MLO callers leave link_sta_params empty, so the
	 * 4.19 fields become NULL/0 and the blob uses its defaults. */
	dst->supported_rates = src->link_sta_params.supported_rates;
	dst->supported_rates_len = src->link_sta_params.supported_rates_len;
	dst->vlan = src->vlan;
	dst->sta_flags_mask = src->sta_flags_mask;
	dst->sta_flags_set = src->sta_flags_set;
	dst->sta_modify_mask = src->sta_modify_mask;
	dst->listen_interval = src->listen_interval;
	dst->aid = src->aid;
	dst->peer_aid = src->peer_aid;
	dst->plink_action = src->plink_action;
	dst->plink_state = src->plink_state;
	dst->ht_capa = src->link_sta_params.ht_capa;
	dst->vht_capa = src->link_sta_params.vht_capa;
	dst->uapsd_queues = src->uapsd_queues;
	dst->max_sp = src->max_sp;
	dst->local_pm = src->local_pm;
	dst->capability = src->capability;
	dst->ext_capab = src->ext_capab;
	dst->ext_capab_len = src->ext_capab_len;
	dst->supported_channels = src->supported_channels;
	dst->supported_channels_len = src->supported_channels_len;
	dst->supported_oper_classes = src->supported_oper_classes;
	dst->supported_oper_classes_len = src->supported_oper_classes_len;
	dst->opmode_notif = src->link_sta_params.opmode_notif;
	dst->opmode_notif_used = src->link_sta_params.opmode_notif_used;
	dst->support_p2p_ps = src->support_p2p_ps;
	dst->he_capa = src->link_sta_params.he_capa;
	dst->he_capa_len = src->link_sta_params.he_capa_len;
	/* DROPPED: vlan_id, airtime_weight, txpwr/txpwr_set, he_6ghz_capa,
	 * eht_capa (EHT caps live in blob-internal tables). */
}
EXPORT_SYMBOL(wl_shim_station_params_66_to_19);

/* Async scan: build a 4.19-layout request the blob can parse. The 6.6
 * struct inserted scan_6ghz/scan_6ghz_params before channels[], so the
 * flex array moved: a pointer cast would feed garbage channels.
 * Buffers (ssids/ie/channels[]) are owned by the core and stay alive
 * until scan_done; only the header + pointer array are copied.
 */
static struct wl419_scan_request *
wl_shim_scan_66_to_19(const struct cfg80211_scan_request *src)
{
	struct wl419_scan_request *dst;
	size_t hdr = sizeof(*dst) + src->n_channels * sizeof(dst->channels[0]);

	dst = kmalloc(hdr, GFP_KERNEL);
	if (!dst)
		return NULL;
	dst->ssids = src->ssids; /* struct cfg80211_ssid identical */
	dst->n_ssids = src->n_ssids;
	dst->n_channels = src->n_channels;
	dst->scan_width = src->scan_width;
	dst->ie = src->ie;
	dst->ie_len = src->ie_len;
	dst->duration = src->duration;
	dst->duration_mandatory = src->duration_mandatory;
	dst->flags = src->flags;
	memcpy(dst->rates, src->rates, sizeof(dst->rates));
	dst->wdev = (void *)shim_wdev_legacy(src->wdev);
	memcpy(dst->mac_addr, src->mac_addr, ETH_ALEN);
	memcpy(dst->mac_addr_mask, src->mac_addr_mask, ETH_ALEN);
	memcpy(dst->bssid, src->bssid, ETH_ALEN);
	dst->wiphy = (void *)shim_wiphy_legacy(src->wiphy);
	dst->scan_start = src->scan_start;
	dst->info = src->info;
	dst->notified = src->notified;
	dst->no_cck = src->no_cck;
	{
		unsigned int i;

		if (!dst->wdev || !dst->wiphy)
			goto invalid;
		for (i = 0; i < src->n_channels; i++) {
			dst->channels[i] = shim_channel_legacy(src->channels[i]);
			if (!dst->channels[i])
				goto invalid;
		}
	}
	/* DROPPED: scan_6ghz, scan_6ghz_params, n_6ghz_params (no 6 GHz
	 * collocated-scan support in the 4.19 firmware API). */
	return dst;
invalid:
	kfree(dst);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Converters 4.19 -> 6.6 (fill direction: blob -> core)               */
/* ------------------------------------------------------------------ */

void wl_shim_rate_19_to_66(const struct wl419_rate_info *src,
			    struct rate_info *dst)
{
	memset(dst, 0, sizeof(*dst));
	/* 4.19 flags/mcs are u8, 6.6 flags u16: low flag bits match
	 * (MCS/VHT/GI/HE), EHT/S1G bits cannot occur from this blob. */
	dst->flags = src->flags;
	dst->mcs = src->mcs;
	dst->legacy = src->legacy;
	dst->nss = src->nss;
	dst->bw = src->bw;
	dst->he_gi = src->he_gi;
	dst->he_dcm = src->he_dcm;
	dst->he_ru_alloc = src->he_ru_alloc;
}
EXPORT_SYMBOL(wl_shim_rate_19_to_66);

void wl_shim_station_info_19_to_66(const struct wl419_station_info *src,
				   struct station_info *dst)
{
	u64 stripped;

	/* filled uses BIT_ULL(NL80211_STA_INFO_*) in both trees. The 4.19
	 * BCA enum ends at DATA_ACK_SIGNAL_AVG; 6.6 appended RX_MPDUS ..
	 * CONNECTED_TO_AS. The blob cannot legitimately set those bits, so
	 * mask them: the matching 6.6-only fields below stay zero and the
	 * core will not emit bogus zero-valued attrs (incl. MLO) from
	 * garbage. Shared-bit numbering is stable, verified 4.19-vs-6.6
	 * header-to-header (see cfg80211_compat.h wl419_station_info). */
	memset(dst, 0, sizeof(*dst));
	stripped = src->filled & ~WL_SINFO419_FILLED_MASK;
	if (stripped)
		pr_warn_once("cfg80211_compat: station_info filled has post-4.19 bits 0x%llx, cleared\n",
			     (unsigned long long)stripped);
	dst->filled = src->filled & WL_SINFO419_FILLED_MASK;
	dst->connected_time = src->connected_time;
	dst->inactive_time = src->inactive_time;
	dst->rx_bytes = src->rx_bytes;
	dst->tx_bytes = src->tx_bytes;
	dst->llid = src->llid;
	dst->plid = src->plid;
	dst->plink_state = src->plink_state;
	dst->signal = src->signal;
	dst->signal_avg = src->signal_avg;
	dst->chains = src->chains;
	memcpy(dst->chain_signal, src->chain_signal, IEEE80211_MAX_CHAINS);
	memcpy(dst->chain_signal_avg, src->chain_signal_avg,
	       IEEE80211_MAX_CHAINS);
	wl_shim_rate_19_to_66(&src->txrate, &dst->txrate);
	wl_shim_rate_19_to_66(&src->rxrate, &dst->rxrate);
	dst->rx_packets = src->rx_packets;
	dst->tx_packets = src->tx_packets;
	dst->tx_retries = src->tx_retries;
	dst->tx_failed = src->tx_failed;
	dst->rx_dropped_misc = src->rx_dropped_misc;
	dst->bss_param = src->bss_param; /* layout-identical */
	dst->sta_flags = src->sta_flags; /* layout-identical (uapi) */
	dst->generation = src->generation;
	/* assoc_req_ies stays BORROWED from the blob here: the 6.6 core
	 * copies the bytes synchronously into its nlmsg (nl80211_send_station
	 * -> nla_put) and never retains the pointer, so no free is needed on
	 * the emit path. Use wl_shim_sinfo_own_ies() when the emitter wants
	 * the bytes to survive past the blob's event-buffer lifetime.
	 * Length is validated: a NULL pointer with nonzero length, or a
	 * length past IEEE80211_MAX_DATA_LEN (the core's NL80211_ATTR_IE
	 * policy cap), would make nla_put read out of bounds. */
	if (!src->assoc_req_ies && src->assoc_req_ies_len) {
		pr_warn_once("cfg80211_compat: station_info NULL assoc IEs with len %zu, dropped\n",
			     src->assoc_req_ies_len);
		dst->assoc_req_ies = NULL;
		dst->assoc_req_ies_len = 0;
	} else if (src->assoc_req_ies_len > IEEE80211_MAX_DATA_LEN) {
		pr_warn_once("cfg80211_compat: station_info assoc IE len %zu exceeds %d, clamped\n",
			     src->assoc_req_ies_len, IEEE80211_MAX_DATA_LEN);
		dst->assoc_req_ies = src->assoc_req_ies;
		dst->assoc_req_ies_len = IEEE80211_MAX_DATA_LEN;
	} else {
		dst->assoc_req_ies = src->assoc_req_ies;
		dst->assoc_req_ies_len = src->assoc_req_ies_len;
	}
	dst->beacon_loss_count = src->beacon_loss_count;
	dst->t_offset = src->t_offset;
	dst->local_pm = src->local_pm;
	dst->peer_pm = src->peer_pm;
	dst->nonpeer_pm = src->nonpeer_pm;
	dst->expected_throughput = src->expected_throughput;
	dst->rx_beacon = src->rx_beacon;
	dst->rx_duration = src->rx_duration;
	dst->rx_beacon_signal_avg = src->rx_beacon_signal_avg;
	/* pertid is DEEP-COPIED: the 6.6 core frees sinfo->pertid via
	 * cfg80211_sinfo_release_content() on every emit path (new_sta,
	 * del_sta_sinfo, get/dump_station replies). Passing the blob's
	 * pointer through would make the core kfree blob-owned memory.
	 * Ownership of the copy transfers to the core on emit; on drop paths
	 * the caller must run wl_shim_sinfo_release_pertid(). The array is
	 * IEEE80211_NUM_TIDS+1 entries, cfg80211_tid_stats is
	 * layout-identical in both trees (field-by-field incl. txq_stats).
	 * GFP_ATOMIC: the event chain (wl_event worklet) has no sleepable
	 * guarantee, and ~1.5 KB never justifies risking a sleep here. */
	if (src->pertid) {
		struct cfg80211_tid_stats *copy;

		copy = kmemdup(src->pertid,
			       (IEEE80211_NUM_TIDS + 1) * sizeof(*copy),
			       GFP_ATOMIC);
		if (!copy) {
			pr_warn_once("cfg80211_compat: station_info pertid copy OOM, stats dropped\n");
			atomic_long_inc(&wl_sinfo_pertid_dup_fail);
			dst->pertid = NULL;
		} else {
			atomic_long_inc(&wl_sinfo_pertid_dup_ok);
			dst->pertid = copy;
		}
	} else {
		dst->pertid = NULL;
	}
	dst->ack_signal = src->ack_signal;
	dst->avg_ack_signal = src->avg_ack_signal;
	/* 6.6-only tail (assoc_at, tx_duration, airtime_*, mlo_*, assoc_resp)
	 * stays zero from the memset above with the filled bits cleared. */
}
EXPORT_SYMBOL(wl_shim_station_info_19_to_66);

/* ------------------------------------------------------------------ */
/* Event-emit ownership helpers (see cfg80211_compat.h for the pattern) */
/* ------------------------------------------------------------------ */

int wl_shim_sinfo_own_ies(struct station_info *dst, gfp_t gfp,
			  struct wl_sinfo_owned *tok)
{
	u8 *copy;

	if (!dst || !tok)
		return -EINVAL;
	tok->borrowed_ies = dst->assoc_req_ies;
	tok->owned_ies = NULL;
	if (!dst->assoc_req_ies || !dst->assoc_req_ies_len)
		return 0;
	copy = kmemdup(dst->assoc_req_ies, dst->assoc_req_ies_len, gfp);
	if (!copy) {
		pr_warn_once("cfg80211_compat: station_info IE own OOM len %zu, emitting borrowed\n",
			     dst->assoc_req_ies_len);
		return -ENOMEM;
	}
	atomic_long_inc(&wl_sinfo_ie_allocs);
	dst->assoc_req_ies = copy;
	tok->owned_ies = copy;
	return 0;
}
EXPORT_SYMBOL(wl_shim_sinfo_own_ies);

void wl_shim_sinfo_disown_ies(struct station_info *dst,
			      struct wl_sinfo_owned *tok)
{
	if (!dst || !tok || !tok->owned_ies)
		return;
	kfree(tok->owned_ies);
	atomic_long_inc(&wl_sinfo_ie_frees);
	dst->assoc_req_ies = tok->borrowed_ies;
	tok->owned_ies = NULL;
}
EXPORT_SYMBOL(wl_shim_sinfo_disown_ies);

void wl_shim_sinfo_release_pertid(struct station_info *dst)
{
	if (!dst || !dst->pertid)
		return;
	kfree(dst->pertid);
	dst->pertid = NULL;
	atomic_long_inc(&wl_sinfo_pertid_released);
}
EXPORT_SYMBOL(wl_shim_sinfo_release_pertid);

struct net_device *wl_shim_sta_emit_dev(struct net_device *dev,
					const char *who)
{
	struct wireless_dev *wdev;
	struct wiphy *wiphy;

	if (!who)
		who = "sta_emit";
	if (!dev) {
		pr_warn_once("cfg80211_compat: %s: NULL netdev, event dropped\n",
			     who);
		return NULL;
	}
	wdev = dev->ieee80211_ptr;
	if (!wdev) {
		pr_warn_once("cfg80211_compat: %s: netdev without wdev, event dropped\n",
			     who);
		return NULL;
	}
	wiphy = wdev->wiphy;
	if (!wiphy) {
		pr_warn_once("cfg80211_compat: %s: wdev without wiphy, event dropped\n",
			     who);
		return NULL;
	}
	/* The wiphy must be one of ours: a foreign wiphy means the legacy
	 * view resolved to a native object outside the shim registry (same
	 * native/legacy confusion class as the H30 P0 crash). */
	if (!shim_wiphy_legacy(wiphy)) {
		pr_warn_once("cfg80211_compat: %s: foreign wiphy, event dropped\n",
			     who);
		return NULL;
	}
	return dev;
}
EXPORT_SYMBOL(wl_shim_sta_emit_dev);

/* ------------------------------------------------------------------ */
/* Scan translation registry (async path, shared with lane C)          */
/* ------------------------------------------------------------------ */

#define WL_SCAN_SLOTS	16 /* core serialises scans per wiphy; plenty */

struct wl_scan_slot {
	bool used;
	const struct cfg80211_scan_request *orig;
	struct wl419_scan_request *copy;
};

static struct wl_scan_slot wl_scan_slots[WL_SCAN_SLOTS];
static DEFINE_SPINLOCK(wl_scan_lock);

int cfg80211_compat_scan_register(struct cfg80211_scan_request *orig66,
				  struct wl419_scan_request *copy419)
{
	int i, ret = -EBUSY;
	unsigned long flags;

	spin_lock_irqsave(&wl_scan_lock, flags);
	for (i = 0; i < WL_SCAN_SLOTS; i++) {
		if (!wl_scan_slots[i].used) {
			wl_scan_slots[i].used = true;
			wl_scan_slots[i].orig = orig66;
			wl_scan_slots[i].copy = copy419;
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_scan_lock, flags);
	return ret;
}
EXPORT_SYMBOL(cfg80211_compat_scan_register);

struct cfg80211_scan_request *
cfg80211_compat_scan_lookup(const struct wl419_scan_request *copy419)
{
	int i;
	struct cfg80211_scan_request *ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&wl_scan_lock, flags);
	for (i = 0; i < WL_SCAN_SLOTS; i++) {
		if (wl_scan_slots[i].used && wl_scan_slots[i].copy == copy419) {
			ret = (struct cfg80211_scan_request *)wl_scan_slots[i].orig;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_scan_lock, flags);
	return ret;
}
EXPORT_SYMBOL(cfg80211_compat_scan_lookup);

void cfg80211_compat_scan_done(const struct wl419_scan_request *copy419)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&wl_scan_lock, flags);
	for (i = 0; i < WL_SCAN_SLOTS; i++) {
		if (wl_scan_slots[i].used && wl_scan_slots[i].copy == copy419) {
			wl_scan_slots[i].used = false;
			wl_scan_slots[i].orig = NULL;
			wl_scan_slots[i].copy = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&wl_scan_lock, flags);
	kfree(copy419);
}
EXPORT_SYMBOL(cfg80211_compat_scan_done);

/* ------------------------------------------------------------------ */
/* mgmt_frame_register adapter (stateful)                              */
/*                                                                     */
/* 4.19: mgmt_frame_register(wiphy, wdev, frame_type, reg) — exact      */
/* u16 frame type per call.                                            */
/* 6.6:  update_mgmt_frame_registrations(wiphy, wdev, upd) — class      */
/* bitmaps where bit = (frame_type >> 4) (see                        */
/* cfg80211_mgmt_registrations_update(), net/wireless/mlme.c).         */
/*                                                                     */
/* The adapter keeps the last mask per wdev and replays only the       */
/* changed class bits into the blob as (bit << 4, on/off).             */
/* APPROXIMATION: 16 frame types share one class bit; the blob gets    */
/* the class base type, so firmware-side filtering is coarser than     */
/* the core asked for. Management RX path stays functional, only       */
/* over-registered.                                                    */
/* ------------------------------------------------------------------ */

#define WL_MGMT_SLOTS	8

struct wl_mgmt_slot {
	bool used;
	struct wireless_dev *wdev;
	u32 mask;
};

static struct wl_mgmt_slot wl_mgmt_slots[WL_MGMT_SLOTS];
static DEFINE_SPINLOCK(wl_mgmt_lock);

static void wl66_update_mgmt_frame_regs(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					struct mgmt_frame_regs *upd)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();
	u32 new_mask, old_mask = 0, changed;
	struct wl_mgmt_slot *slot = NULL;
	unsigned long flags;
	int i, free_idx = -1;

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->mgmt_frame_register) {
		wl_op_missing_void("update_mgmt_frame_registrations");
		return;
	}
	new_mask = upd->interface_stypes | upd->global_stypes;

	spin_lock_irqsave(&wl_mgmt_lock, flags);
	for (i = 0; i < WL_MGMT_SLOTS; i++) {
		if (wl_mgmt_slots[i].used && wl_mgmt_slots[i].wdev == wdev) {
			slot = &wl_mgmt_slots[i];
			break;
		}
		if (!wl_mgmt_slots[i].used && free_idx < 0)
			free_idx = i;
	}
	if (!slot && free_idx >= 0) {
		slot = &wl_mgmt_slots[free_idx];
		slot->used = true;
		slot->wdev = wdev;
		slot->mask = 0;
	}
	if (slot) {
		old_mask = slot->mask;
		slot->mask = new_mask;
	}
	spin_unlock_irqrestore(&wl_mgmt_lock, flags);

	if (!slot) {
		pr_warn_once("cfg80211_compat: mgmt slot table full\n");
		return;
	}
	changed = old_mask ^ new_mask;
	while (changed) {
		int bit = __ffs(changed);

		changed &= ~BIT(bit);
		b->mgmt_frame_register(old_wiphy, old_wdev, (u16)(bit << 4),
				       !!(new_mask & BIT(bit)));
	}
}

/* ------------------------------------------------------------------ */
/* DIFF thunks (11): 6.6 signature in, link_id dropped, structs        */
/* converted, 4.19 blob called.                                        */
/* ------------------------------------------------------------------ */

static int wl66_add_key(struct wiphy *wiphy, struct net_device *netdev,
			int link_id, u8 key_index, bool pairwise,
			const u8 *mac_addr, struct key_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_key_params p419;

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	(void)link_id; /* single-link blob: MLO link id ignored */
	if (!b || !b->add_key)
		return wl_op_missing_int("add_key");
	wl_shim_key_66_to_19(params, &p419);
	return CFG_CALL(add_key, old_wiphy, old_netdev, key_index, pairwise, mac_addr, &p419);
}

struct wl66_key_cb_ctx {
	void (*cb)(void *cookie, struct key_params *);
	void *cookie;
};

static void wl66_get_key_cb(void *cookie, struct wl419_key_params *p419)
{
	struct wl66_key_cb_ctx *ctx = cookie;
	struct key_params p66;

	p66.key = p419->key;
	p66.seq = p419->seq;
	p66.key_len = p419->key_len;
	p66.seq_len = p419->seq_len;
	p66.vlan_id = 0;
	p66.cipher = p419->cipher;
	p66.mode = NL80211_KEY_RX_TX; /* 4.19 knows no key modes */
	ctx->cb(ctx->cookie, &p66);
}

static int wl66_get_key(struct wiphy *wiphy, struct net_device *netdev,
			int link_id, u8 key_index, bool pairwise,
			const u8 *mac_addr, void *cookie,
			void (*callback)(void *cookie, struct key_params *))
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl66_key_cb_ctx ctx = { .cb = callback, .cookie = cookie };

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->get_key)
		return wl_op_missing_int("get_key");
	/* Callback signatures differ (key_params layout), so interpose. */
	return CFG_CALL(get_key, old_wiphy, old_netdev, key_index, pairwise, mac_addr,
			  &ctx, wl66_get_key_cb);
}

static int wl66_del_key(struct wiphy *wiphy, struct net_device *netdev,
			int link_id, u8 key_index, bool pairwise,
			const u8 *mac_addr)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->del_key)
		return wl_op_missing_int("del_key");
	return CFG_CALL(del_key, old_wiphy, old_netdev, key_index, pairwise, mac_addr);
}

static int wl66_set_default_key(struct wiphy *wiphy,
				struct net_device *netdev, int link_id,
				u8 key_index, bool unicast, bool multicast)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->set_default_key)
		return wl_op_missing_int("set_default_key");
	return CFG_CALL(set_default_key, old_wiphy, old_netdev, key_index, unicast,
				  multicast);
}

static int wl66_set_default_mgmt_key(struct wiphy *wiphy,
				     struct net_device *netdev, int link_id,
				     u8 key_index)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->set_default_mgmt_key)
		return wl_op_missing_int("set_default_mgmt_key");
	return CFG_CALL(set_default_mgmt_key, old_wiphy, old_netdev, key_index);
}

static int wl66_stop_ap(struct wiphy *wiphy, struct net_device *dev,
			unsigned int link_id)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->stop_ap)
		return wl_op_missing_int("stop_ap");
	return CFG_CALL(stop_ap, old_wiphy, old_dev);
}

static int wl66_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
			  const u8 *peer, int link_id,
			  u8 action_code, u8 dialog_token, u16 status_code,
			  u32 peer_capability, bool initiator,
			  const u8 *buf, size_t len)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->tdls_mgmt)
		return wl_op_missing_int("tdls_mgmt");
	return CFG_CALL(tdls_mgmt, old_wiphy, old_dev, peer, action_code, dialog_token,
			    status_code, peer_capability, initiator, buf, len);
}

static int wl66_get_channel(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    unsigned int link_id,
			    struct cfg80211_chan_def *chandef)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_chan_def c419;
	int ret;

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	(void)link_id;
	if (!b || !b->get_channel)
		return wl_op_missing_int("get_channel");
	ret = b->get_channel(old_wiphy, old_wdev, &c419);
	if (ret)
		return ret;
	chandef->chan = shim_channel_native(c419.chan);
	if (!chandef->chan)
		return -ENODEV;
	chandef->width = c419.width;
	chandef->center_freq1 = c419.center_freq1;
	chandef->center_freq2 = c419.center_freq2;
	/* Blob predates EDMG chandef: clear what it cannot fill. */
	memset(&chandef->edmg, 0, sizeof(chandef->edmg));
	chandef->freq1_offset = 0;
	return 0;
}

static int wl66_set_ap_chanwidth(struct wiphy *wiphy, struct net_device *dev,
				 unsigned int link_id,
				 struct cfg80211_chan_def *chandef)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_chan_def c419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->set_ap_chanwidth)
		return wl_op_missing_int("set_ap_chanwidth");
	wl_shim_chandef_66_to_19(chandef, &c419);
	if (!c419.chan)
		return -ENODEV;
	return CFG_CALL(set_ap_chanwidth, old_wiphy, old_dev, &c419);
}

static int wl66_tx_control_port(struct wiphy *wiphy,
				struct net_device *dev,
				const u8 *buf, size_t len,
				const u8 *dest, const __be16 proto,
				const bool noencrypt, int link_id,
				u64 *cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	(void)link_id; /* MLO link id ignored */
	if (cookie)
		*cookie = 0; /* 4.19 has no cookie: nothing to match on */
	if (!b || !b->tx_control_port)
		return wl_op_missing_int("tx_control_port");
	return CFG_CALL(tx_control_port, old_wiphy, old_dev, buf, len, dest, proto,
				  noencrypt);
}

/* ------------------------------------------------------------------ */
/* SAME-but-extended thunks (11): signatures match, nested structs     */
/* grew. Converters strip what the blob cannot parse.                  */
/* ------------------------------------------------------------------ */

static int wl66_start_ap(struct wiphy *wiphy, struct net_device *dev,
			 struct cfg80211_ap_settings *settings)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_ap_settings s419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->start_ap)
		return wl_op_missing_int("start_ap");
	wl_shim_ap_66_to_19(settings, &s419);
	if (!s419.chandef.chan)
		return -ENODEV;
	return CFG_CALL(start_ap, old_wiphy, old_dev, &s419);
}

static int wl66_change_beacon(struct wiphy *wiphy, struct net_device *dev,
			      struct cfg80211_beacon_data *info)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_beacon_data b419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->change_beacon)
		return wl_op_missing_int("change_beacon");
	wl_shim_beacon_66_to_19(info, &b419);
	return CFG_CALL(change_beacon, old_wiphy, old_dev, &b419);
}

static int wl66_change_bss(struct wiphy *wiphy, struct net_device *dev,
			   struct bss_parameters *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_bss_params p419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->change_bss)
		return wl_op_missing_int("change_bss");
	wl_shim_bss_66_to_19(params, &p419);
	return CFG_CALL(change_bss, old_wiphy, old_dev, &p419);
}

static int wl66_add_station(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *mac, struct station_parameters *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_station_params p419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->add_station)
		return wl_op_missing_int("add_station");
	wl_shim_station_params_66_to_19(params, &p419);
	return CFG_CALL(add_station, old_wiphy, old_dev, mac, &p419);
}

static int wl66_change_station(struct wiphy *wiphy, struct net_device *dev,
			       const u8 *mac,
			       struct station_parameters *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_station_params p419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->change_station)
		return wl_op_missing_int("change_station");
	wl_shim_station_params_66_to_19(params, &p419);
	return CFG_CALL(change_station, old_wiphy, old_dev, mac, &p419);
}

static int wl66_get_station(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *mac, struct station_info *sinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_station_info s419;
	int ret;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->get_station)
		return wl_op_missing_int("get_station");
	memset(&s419, 0, sizeof(s419));
	ret = b->get_station(old_wiphy, old_dev, mac, &s419);
	if (ret)
		return ret;
	wl_shim_station_info_19_to_66(&s419, sinfo);
	return 0;
}

static int wl66_dump_station(struct wiphy *wiphy, struct net_device *dev,
			     int idx, u8 *mac, struct station_info *sinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_station_info s419;
	int ret;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->dump_station)
		return wl_op_missing_int("dump_station");
	memset(&s419, 0, sizeof(s419));
	ret = b->dump_station(old_wiphy, old_dev, idx, mac, &s419);
	if (ret)
		return ret;
	wl_shim_station_info_19_to_66(&s419, sinfo);
	return 0;
}

static int wl66_scan(struct wiphy *wiphy,
		     struct cfg80211_scan_request *request)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_scan_request *r419;
	int ret;

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->scan)
		return wl_op_missing_int("scan");
	r419 = wl_shim_scan_66_to_19(request);
	if (!r419)
		return -ENOMEM;
	if (cfg80211_compat_scan_register(request, r419)) {
		kfree(r419);
		return -EBUSY;
	}
	ret = b->scan(old_wiphy, r419);
	if (ret) {
		cfg80211_compat_scan_done(r419);
		return ret;
	}
	/* Success: r419 stays alive until the blob completes the scan;
	 * lane C's scan_done wrapper maps it back with
	 * cfg80211_compat_scan_lookup() and releases it with
	 * cfg80211_compat_scan_done(). */
	return 0;
}

/* connect / update_connect_params: crypto_settings grew 60 -> 100 B
 * (measured), so everything after crypto shifted. Explicit field copy;
 * only the [channel..crypto) prefix is provably identical (assert below
 * pins offsetof(crypto)). WEP travels in key/key_len/key_idx, same in
 * both trees. DROPPED: trailing edmg. */
static void wl_shim_connect_66_to_19(const struct cfg80211_connect_params *src,
				     struct wl419_connect_params *dst)
{
	dst->channel = shim_channel_legacy(src->channel);
	dst->channel_hint = shim_channel_legacy(src->channel_hint);
	dst->bssid = src->bssid;
	dst->bssid_hint = src->bssid_hint;
	dst->ssid = src->ssid;
	dst->ssid_len = src->ssid_len;
	dst->auth_type = src->auth_type;
	dst->ie = src->ie;
	dst->ie_len = src->ie_len;
	dst->privacy = src->privacy;
	dst->mfp = src->mfp;
	wl_shim_crypto_66_to_19(&src->crypto, &dst->crypto);
	dst->key = src->key;
	dst->key_len = src->key_len;
	dst->key_idx = src->key_idx;
	dst->flags = src->flags;
	dst->bg_scan_period = src->bg_scan_period;
	dst->ht_capa = src->ht_capa;
	dst->ht_capa_mask = src->ht_capa_mask;
	dst->vht_capa = src->vht_capa;
	dst->vht_capa_mask = src->vht_capa_mask;
	dst->pbss = src->pbss;
	dst->bss_select = src->bss_select; /* 12 B, identical layout */
	dst->prev_bssid = src->prev_bssid;
	dst->fils_erp_username = src->fils_erp_username;
	dst->fils_erp_username_len = src->fils_erp_username_len;
	dst->fils_erp_realm = src->fils_erp_realm;
	dst->fils_erp_realm_len = src->fils_erp_realm_len;
	dst->fils_erp_next_seq_num = src->fils_erp_next_seq_num;
	dst->fils_erp_rrk = src->fils_erp_rrk;
	dst->fils_erp_rrk_len = src->fils_erp_rrk_len;
	dst->want_1x = src->want_1x;
}

static int wl_shim_connect_call(struct wiphy *wiphy, struct net_device *dev,
				struct cfg80211_connect_params *sme,
				u32 changed, bool is_update)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_connect_params *c419;
	int ret;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || (!is_update && !b->connect) || (is_update && !b->update_connect_params))
		return wl_op_missing_int(is_update ? "update_connect_params" :
						     "connect");
	c419 = kmalloc(sizeof(*c419), GFP_KERNEL);
	if (!c419)
		return -ENOMEM;
	wl_shim_connect_66_to_19(sme, c419);
	if (is_update)
		ret = b->update_connect_params(old_wiphy, old_dev, c419, changed);
	else
		ret = b->connect(old_wiphy, old_dev, c419);
	kfree(c419);
	return ret;
}

static int wl66_connect(struct wiphy *wiphy, struct net_device *dev,
			struct cfg80211_connect_params *sme)
{
	return wl_shim_connect_call(wiphy, dev, sme, 0, false);
}

static int wl66_update_connect_params(struct wiphy *wiphy,
				      struct net_device *dev,
				      struct cfg80211_connect_params *sme,
				      u32 changed)
{
	return wl_shim_connect_call(wiphy, dev, sme, changed, true);
}

/* set_pmksa / del_pmksa: 6.6 appended pmk_lifetime/pmk_reauth_threshold
 * (proven by _Static_assert below) -> direct prefix pass, sync call. */
static int wl66_set_pmksa(struct wiphy *wiphy, struct net_device *netdev,
			  struct cfg80211_pmksa *pmksa)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	if (!b || !b->set_pmksa)
		return wl_op_missing_int("set_pmksa");
	return CFG_CALL(set_pmksa, old_wiphy, old_netdev, (struct wl419_pmksa *)pmksa);
}

static int wl66_del_pmksa(struct wiphy *wiphy, struct net_device *netdev,
			  struct cfg80211_pmksa *pmksa)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	if (!b || !b->del_pmksa)
		return wl_op_missing_int("del_pmksa");
	return CFG_CALL(del_pmksa, old_wiphy, old_netdev, (struct wl419_pmksa *)pmksa);
}

/* set_rekey_data: 6.6 appended akm/kek_len/kck_len (assert below) -> pass. */
static int wl66_set_rekey_data(struct wiphy *wiphy, struct net_device *dev,
			       struct cfg80211_gtk_rekey_data *data)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_rekey_data)
		return wl_op_missing_int("set_rekey_data");
	return CFG_CALL(set_rekey_data, old_wiphy, old_dev,
				 (struct wl419_gtk_rekey_data *)data);
}

/* set_bitrate_mask: 6.6 added link_id AND widened the per-band block
 * (he_mcs/he_gi/he_ltf) -> drop link_id, deep-copy the mask. */
static int wl66_set_bitrate_mask(struct wiphy *wiphy, struct net_device *dev,
				 unsigned int link_id, const u8 *peer,
				 const struct cfg80211_bitrate_mask *mask)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	struct wl419_bitrate_mask m419;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	(void)link_id;
	if (!b || !b->set_bitrate_mask)
		return wl_op_missing_int("set_bitrate_mask");
	wl_shim_mask_66_to_19(mask, &m419);
	return CFG_CALL(set_bitrate_mask, old_wiphy, old_dev, peer, &m419);
}

/* mgmt_tx: 6.6 appended link_id at the tail (verified by reading both
 * definitions: 9 shared fields first, pinned by _Static_assert below) ->
 * direct pass. */
static int wl66_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
			struct cfg80211_mgmt_tx_params *params, u64 *cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (wl_mgmt_trace)
		pr_info_ratelimited("cfg80211_compat: mgmt TX len=%zu chan=%d cookie_slot=%p\n",
				    params ? params->len : 0,
				    params && params->chan ? params->chan->center_freq : -1,
				    cookie);
	atomic_long_inc(&wl_mgmt_tx_calls);

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!params || !params->buf || !params->len) {
		pr_warn_once("cfg80211_compat: mgmt_tx with empty frame, rejected\n");
		return -EINVAL;
	}
	if (!b || !b->mgmt_tx)
		return wl_op_missing_int("mgmt_tx");
	{
		/* 6.6 only appends link_id; the 4.19 prefix is field-identical. */
		struct cfg80211_mgmt_tx_params p419 = *params;

		p419.chan = shim_channel_legacy(params->chan);
		if (params->chan && !p419.chan)
			return -ENODEV;
		return CFG_CALL(mgmt_tx, old_wiphy, old_wdev, &p419, cookie);
	}
}

/* ------------------------------------------------------------------ */
/* Pass-through thunks: signature AND all reachable structs identical  */
/* in both trees (verified field-by-field while writing).              */
/* ------------------------------------------------------------------ */

static int wl66_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->suspend)
		return wl_op_missing_int("suspend");
	return CFG_CALL(suspend, old_wiphy, wow);
}

static int wl66_resume(struct wiphy *wiphy)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->resume)
		return wl_op_missing_int("resume");
	return CFG_CALL(resume, old_wiphy);
}

static void wl66_set_wakeup(struct wiphy *wiphy, bool enabled)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return;

	if (!b || !b->set_wakeup)
		return wl_op_missing_void("set_wakeup");
	b->set_wakeup(old_wiphy, enabled);
}

static struct wireless_dev * wl66_add_virtual_intf(struct wiphy *wiphy,
						  const char *name,
						  unsigned char name_assign_type,
						  enum nl80211_iftype type,
						  struct vif_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return ERR_PTR(-ENODEV);

	if (!b || !b->add_virtual_intf) {
		wl_op_missing_void("add_virtual_intf");
		return ERR_PTR(-EOPNOTSUPP);
	}
	{
		struct wireless_dev *old, *native;

		old = b->add_virtual_intf(old_wiphy, name, name_assign_type, type, params);
		if (IS_ERR_OR_NULL(old))
			return old ? old : ERR_PTR(-ENODEV);
		native = shim_wdev_native((void *)old);
		if (!native && b->del_virtual_intf)
			b->del_virtual_intf(old_wiphy, old);
		return native ? native : ERR_PTR(-ENODEV);
	}
}

static int wl66_del_virtual_intf(struct wiphy *wiphy,
				 struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->del_virtual_intf)
		return wl_op_missing_int("del_virtual_intf");
	return CFG_CALL(del_virtual_intf, old_wiphy, old_wdev);
}

static int wl66_change_virtual_intf(struct wiphy *wiphy,
				    struct net_device *dev,
				    enum nl80211_iftype type,
				    struct vif_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();
	int ret;

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->change_virtual_intf)
		return wl_op_missing_int("change_virtual_intf");
	ret = CFG_CALL(change_virtual_intf, old_wiphy, old_dev, type, params);
	if (ret)
		return ret;
	return shim_wdev_publish_iftype(dev->ieee80211_ptr, type);
}

static int wl66_del_station(struct wiphy *wiphy, struct net_device *dev,
			    struct station_del_parameters *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->del_station)
		return wl_op_missing_int("del_station");
	return CFG_CALL(del_station, old_wiphy, old_dev, params);
}

static int wl66_add_mpath(struct wiphy *wiphy, struct net_device *dev,
			  const u8 *dst, const u8 *next_hop)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->add_mpath)
		return wl_op_missing_int("add_mpath");
	return CFG_CALL(add_mpath, old_wiphy, old_dev, dst, next_hop);
}

static int wl66_del_mpath(struct wiphy *wiphy, struct net_device *dev,
			  const u8 *dst)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->del_mpath)
		return wl_op_missing_int("del_mpath");
	return CFG_CALL(del_mpath, old_wiphy, old_dev, dst);
}

static int wl66_change_mpath(struct wiphy *wiphy, struct net_device *dev,
			     const u8 *dst, const u8 *next_hop)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->change_mpath)
		return wl_op_missing_int("change_mpath");
	return CFG_CALL(change_mpath, old_wiphy, old_dev, dst, next_hop);
}

static int wl66_get_mpath(struct wiphy *wiphy, struct net_device *dev,
			  u8 *dst, u8 *next_hop, struct mpath_info *pinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->get_mpath)
		return wl_op_missing_int("get_mpath");
	return CFG_CALL(get_mpath, old_wiphy, old_dev, dst, next_hop, pinfo);
}

static int wl66_dump_mpath(struct wiphy *wiphy, struct net_device *dev,
			   int idx, u8 *dst, u8 *next_hop,
			   struct mpath_info *pinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->dump_mpath)
		return wl_op_missing_int("dump_mpath");
	return CFG_CALL(dump_mpath, old_wiphy, old_dev, idx, dst, next_hop, pinfo);
}

static int wl66_get_mpp(struct wiphy *wiphy, struct net_device *dev,
			u8 *dst, u8 *mpp, struct mpath_info *pinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->get_mpp)
		return wl_op_missing_int("get_mpp");
	return CFG_CALL(get_mpp, old_wiphy, old_dev, dst, mpp, pinfo);
}

static int wl66_dump_mpp(struct wiphy *wiphy, struct net_device *dev,
			 int idx, u8 *dst, u8 *mpp, struct mpath_info *pinfo)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->dump_mpp)
		return wl_op_missing_int("dump_mpp");
	return CFG_CALL(dump_mpp, old_wiphy, old_dev, idx, dst, mpp, pinfo);
}

static int wl66_get_mesh_config(struct wiphy *wiphy, struct net_device *dev,
				struct mesh_config *conf)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->get_mesh_config)
		return wl_op_missing_int("get_mesh_config");
	return CFG_CALL(get_mesh_config, old_wiphy, old_dev, conf);
}

static int wl66_update_mesh_config(struct wiphy *wiphy, struct net_device *dev,
				   u32 mask, const struct mesh_config *nconf)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->update_mesh_config)
		return wl_op_missing_int("update_mesh_config");
	return CFG_CALL(update_mesh_config, old_wiphy, old_dev, mask, nconf);
}

static int wl66_join_mesh(struct wiphy *wiphy, struct net_device *dev,
			  const struct mesh_config *conf,
			  const struct mesh_setup *setup)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->join_mesh)
		return wl_op_missing_int("join_mesh");
	return CFG_CALL(join_mesh, old_wiphy, old_dev, conf, setup);
}

static int wl66_leave_mesh(struct wiphy *wiphy, struct net_device *dev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->leave_mesh)
		return wl_op_missing_int("leave_mesh");
	return CFG_CALL(leave_mesh, old_wiphy, old_dev);
}

static int wl66_join_ocb(struct wiphy *wiphy, struct net_device *dev,
			 struct ocb_setup *setup)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->join_ocb)
		return wl_op_missing_int("join_ocb");
	return CFG_CALL(join_ocb, old_wiphy, old_dev, setup);
}

static int wl66_leave_ocb(struct wiphy *wiphy, struct net_device *dev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->leave_ocb)
		return wl_op_missing_int("leave_ocb");
	return CFG_CALL(leave_ocb, old_wiphy, old_dev);
}

static int wl66_set_txq_params(struct wiphy *wiphy, struct net_device *dev,
			       struct ieee80211_txq_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_txq_params)
		return wl_op_missing_int("set_txq_params");
	return CFG_CALL(set_txq_params, old_wiphy, old_dev, params);
}

static int wl66_libertas_set_mesh_channel(struct wiphy *wiphy,
					  struct net_device *dev,
					  struct ieee80211_channel *chan)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->libertas_set_mesh_channel)
		return wl_op_missing_int("libertas_set_mesh_channel");
	return CFG_CALL(libertas_set_mesh_channel, old_wiphy, old_dev, shim_channel_legacy(chan));
}

/* chandef pass-through: blob reads chan/width/freq1/freq2 only. */
static int wl66_set_monitor_channel(struct wiphy *wiphy,
				    struct cfg80211_chan_def *chandef)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->set_monitor_channel)
		return wl_op_missing_int("set_monitor_channel");
	return CFG_CALL(set_monitor_channel, old_wiphy, chandef);
}

static void wl66_abort_scan(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->abort_scan)
		return wl_op_missing_void("abort_scan");
	b->abort_scan(old_wiphy, old_wdev);
}

static int wl66_auth(struct wiphy *wiphy, struct net_device *dev,
		     struct cfg80211_auth_request *req)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->auth)
		return wl_op_missing_int("auth");
	return CFG_CALL(auth, old_wiphy, old_dev, req);
}

static int wl66_assoc(struct wiphy *wiphy, struct net_device *dev,
		      struct cfg80211_assoc_request *req)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->assoc)
		return wl_op_missing_int("assoc");
	return CFG_CALL(assoc, old_wiphy, old_dev, req);
}

static int wl66_deauth(struct wiphy *wiphy, struct net_device *dev,
		       struct cfg80211_deauth_request *req)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->deauth)
		return wl_op_missing_int("deauth");
	return CFG_CALL(deauth, old_wiphy, old_dev, req);
}

static int wl66_disassoc(struct wiphy *wiphy, struct net_device *dev,
			 struct cfg80211_disassoc_request *req)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->disassoc)
		return wl_op_missing_int("disassoc");
	return CFG_CALL(disassoc, old_wiphy, old_dev, req);
}

static int wl66_disconnect(struct wiphy *wiphy, struct net_device *dev,
			   u16 reason_code)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->disconnect)
		return wl_op_missing_int("disconnect");
	return CFG_CALL(disconnect, old_wiphy, old_dev, reason_code);
}

static int wl66_join_ibss(struct wiphy *wiphy, struct net_device *dev,
			  struct cfg80211_ibss_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->join_ibss)
		return wl_op_missing_int("join_ibss");
	return CFG_CALL(join_ibss, old_wiphy, old_dev, params);
}

static int wl66_leave_ibss(struct wiphy *wiphy, struct net_device *dev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->leave_ibss)
		return wl_op_missing_int("leave_ibss");
	return CFG_CALL(leave_ibss, old_wiphy, old_dev);
}

static int wl66_set_mcast_rate(struct wiphy *wiphy, struct net_device *dev,
			       int rate[NUM_NL80211_BANDS])
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_mcast_rate)
		return wl_op_missing_int("set_mcast_rate");
	return CFG_CALL(set_mcast_rate, old_wiphy, old_dev, rate);
}

static int wl66_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->set_wiphy_params)
		return wl_op_missing_int("set_wiphy_params");
	return CFG_CALL(set_wiphy_params, old_wiphy, changed);
}

static int wl66_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
			     enum nl80211_tx_power_setting type, int mbm)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->set_tx_power)
		return wl_op_missing_int("set_tx_power");
	return CFG_CALL(set_tx_power, old_wiphy, old_wdev, type, mbm);
}

static int wl66_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
			     int *dbm)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->get_tx_power)
		return wl_op_missing_int("get_tx_power");
	return CFG_CALL(get_tx_power, old_wiphy, old_wdev, dbm);
}

static void wl66_rfkill_poll(struct wiphy *wiphy)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return;

	if (!b || !b->rfkill_poll)
		return wl_op_missing_void("rfkill_poll");
	b->rfkill_poll(old_wiphy);
}

#ifdef CONFIG_NL80211_TESTMODE
static int wl66_testmode_cmd(struct wiphy *wiphy, struct wireless_dev *wdev,
			     void *data, int len)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->testmode_cmd)
		return wl_op_missing_int("testmode_cmd");
	return CFG_CALL(testmode_cmd, old_wiphy, old_wdev, data, len);
}

static int wl66_testmode_dump(struct wiphy *wiphy, struct sk_buff *skb,
			      struct netlink_callback *cb, void *data, int len)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->testmode_dump)
		return wl_op_missing_int("testmode_dump");
	return CFG_CALL(testmode_dump, old_wiphy, skb, cb, data, len);
}
#endif

static int wl66_dump_survey(struct wiphy *wiphy, struct net_device *netdev,
			    int idx, struct survey_info *info)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	if (!b || !b->dump_survey)
		return wl_op_missing_int("dump_survey");
	return CFG_CALL(dump_survey, old_wiphy, old_netdev, idx, info);
}

static int wl66_flush_pmksa(struct wiphy *wiphy, struct net_device *netdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_netdev = (void *)shim_netdev_legacy(netdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_netdev)
		return -ENODEV;

	if (!b || !b->flush_pmksa)
		return wl_op_missing_int("flush_pmksa");
	return CFG_CALL(flush_pmksa, old_wiphy, old_netdev);
}

static int wl66_remain_on_channel(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  struct ieee80211_channel *chan,
				  unsigned int duration, u64 *cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->remain_on_channel)
		return wl_op_missing_int("remain_on_channel");
	return CFG_CALL(remain_on_channel, old_wiphy, old_wdev, shim_channel_legacy(chan), duration, cookie);
}

static int wl66_cancel_remain_on_channel(struct wiphy *wiphy,
					 struct wireless_dev *wdev, u64 cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->cancel_remain_on_channel)
		return wl_op_missing_int("cancel_remain_on_channel");
	return CFG_CALL(cancel_remain_on_channel, old_wiphy, old_wdev, cookie);
}

static int wl66_mgmt_tx_cancel_wait(struct wiphy *wiphy,
				    struct wireless_dev *wdev, u64 cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->mgmt_tx_cancel_wait)
		return wl_op_missing_int("mgmt_tx_cancel_wait");
	return CFG_CALL(mgmt_tx_cancel_wait, old_wiphy, old_wdev, cookie);
}

static int wl66_set_power_mgmt(struct wiphy *wiphy, struct net_device *dev,
			       bool enabled, int timeout)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_power_mgmt)
		return wl_op_missing_int("set_power_mgmt");
	return CFG_CALL(set_power_mgmt, old_wiphy, old_dev, enabled, timeout);
}

static int wl66_set_cqm_rssi_config(struct wiphy *wiphy,
				    struct net_device *dev,
				    s32 rssi_thold, u32 rssi_hyst)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_cqm_rssi_config)
		return wl_op_missing_int("set_cqm_rssi_config");
	return CFG_CALL(set_cqm_rssi_config, old_wiphy, old_dev, rssi_thold, rssi_hyst);
}

static int wl66_set_cqm_rssi_range_config(struct wiphy *wiphy,
					  struct net_device *dev,
					  s32 rssi_low, s32 rssi_high)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_cqm_rssi_range_config)
		return wl_op_missing_int("set_cqm_rssi_range_config");
	return CFG_CALL(set_cqm_rssi_range_config, old_wiphy, old_dev, rssi_low, rssi_high);
}

static int wl66_set_cqm_txe_config(struct wiphy *wiphy, struct net_device *dev,
				   u32 rate, u32 pkts, u32 intvl)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_cqm_txe_config)
		return wl_op_missing_int("set_cqm_txe_config");
	return CFG_CALL(set_cqm_txe_config, old_wiphy, old_dev, rate, pkts, intvl);
}

static int wl66_set_antenna(struct wiphy *wiphy, u32 tx_ant, u32 rx_ant)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->set_antenna)
		return wl_op_missing_int("set_antenna");
	return CFG_CALL(set_antenna, old_wiphy, tx_ant, rx_ant);
}

static int wl66_get_antenna(struct wiphy *wiphy, u32 *tx_ant, u32 *rx_ant)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->get_antenna)
		return wl_op_missing_int("get_antenna");
	return CFG_CALL(get_antenna, old_wiphy, tx_ant, rx_ant);
}

/* sched_scan_request may have grown scan_6ghz legs in 6.6; the blob has
 * no sched_scan ops (absent from cfg80211_ops_map.txt), so these thunks
 * only null-check today. If a blob revision implements them, a deep
 * converter becomes mandatory here. */
static int wl66_sched_scan_start(struct wiphy *wiphy, struct net_device *dev,
				 struct cfg80211_sched_scan_request *request)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->sched_scan_start)
		return wl_op_missing_int("sched_scan_start");
	return CFG_CALL(sched_scan_start, old_wiphy, old_dev, request);
}

static int wl66_sched_scan_stop(struct wiphy *wiphy, struct net_device *dev,
				u64 reqid)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->sched_scan_stop)
		return wl_op_missing_int("sched_scan_stop");
	return CFG_CALL(sched_scan_stop, old_wiphy, old_dev, reqid);
}

static int wl66_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
			  const u8 *peer, enum nl80211_tdls_operation oper)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->tdls_oper)
		return wl_op_missing_int("tdls_oper");
	return CFG_CALL(tdls_oper, old_wiphy, old_dev, peer, oper);
}

static int wl66_probe_client(struct wiphy *wiphy, struct net_device *dev,
			     const u8 *peer, u64 *cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->probe_client)
		return wl_op_missing_int("probe_client");
	return CFG_CALL(probe_client, old_wiphy, old_dev, peer, cookie);
}

static int wl66_set_noack_map(struct wiphy *wiphy, struct net_device *dev,
			      u16 noack_map)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_noack_map)
		return wl_op_missing_int("set_noack_map");
	return CFG_CALL(set_noack_map, old_wiphy, old_dev, noack_map);
}

static int wl66_start_p2p_device(struct wiphy *wiphy,
				 struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->start_p2p_device)
		return wl_op_missing_int("start_p2p_device");
	return CFG_CALL(start_p2p_device, old_wiphy, old_wdev);
}

static void wl66_stop_p2p_device(struct wiphy *wiphy,
				 struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->stop_p2p_device)
		return wl_op_missing_void("stop_p2p_device");
	b->stop_p2p_device(old_wiphy, old_wdev);
}

static int wl66_set_mac_acl(struct wiphy *wiphy, struct net_device *dev,
			    const struct cfg80211_acl_data *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_mac_acl)
		return wl_op_missing_int("set_mac_acl");
	return CFG_CALL(set_mac_acl, old_wiphy, old_dev, params);
}

static int wl66_start_radar_detection(struct wiphy *wiphy,
				      struct net_device *dev,
				      struct cfg80211_chan_def *chandef,
				      u32 cac_time_ms)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->start_radar_detection)
		return wl_op_missing_int("start_radar_detection");
	return CFG_CALL(start_radar_detection, old_wiphy, old_dev, chandef, cac_time_ms);
}

static void wl66_end_cac(struct wiphy *wiphy, struct net_device *dev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return;

	if (!b || !b->end_cac)
		return wl_op_missing_void("end_cac");
	b->end_cac(old_wiphy, old_dev);
}

static int wl66_update_ft_ies(struct wiphy *wiphy, struct net_device *dev,
			      struct cfg80211_update_ft_ies_params *ftie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->update_ft_ies)
		return wl_op_missing_int("update_ft_ies");
	return CFG_CALL(update_ft_ies, old_wiphy, old_dev, ftie);
}

static int wl66_crit_proto_start(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 enum nl80211_crit_proto_id protocol,
				 u16 duration)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->crit_proto_start)
		return wl_op_missing_int("crit_proto_start");
	return CFG_CALL(crit_proto_start, old_wiphy, old_wdev, protocol, duration);
}

static void wl66_crit_proto_stop(struct wiphy *wiphy,
				 struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->crit_proto_stop)
		return wl_op_missing_void("crit_proto_stop");
	b->crit_proto_stop(old_wiphy, old_wdev);
}

static int wl66_set_coalesce(struct wiphy *wiphy,
			     struct cfg80211_coalesce *coalesce)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy)
		return -ENODEV;

	if (!b || !b->set_coalesce)
		return wl_op_missing_int("set_coalesce");
	return CFG_CALL(set_coalesce, old_wiphy, coalesce);
}

/* RISK (documented): cfg80211_csa_settings embeds beacon_data, which grew
 * link_id + new IEs in 6.6. The blob has no channel_switch op
 * (absent from cfg80211_ops_map.txt), so this only null-checks today.
 * A blob revision with channel_switch needs a csa converter. */
static int wl66_channel_switch(struct wiphy *wiphy, struct net_device *dev,
			       struct cfg80211_csa_settings *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->channel_switch)
		return wl_op_missing_int("channel_switch");
	return CFG_CALL(channel_switch, old_wiphy, old_dev, params);
}

static int wl66_set_qos_map(struct wiphy *wiphy, struct net_device *dev,
			    struct cfg80211_qos_map *qos_map)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_qos_map)
		return wl_op_missing_int("set_qos_map");
	return CFG_CALL(set_qos_map, old_wiphy, old_dev, qos_map);
}

static int wl66_add_tx_ts(struct wiphy *wiphy, struct net_device *dev,
			  u8 tsid, const u8 *peer, u8 user_prio,
			  u16 admitted_time)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->add_tx_ts)
		return wl_op_missing_int("add_tx_ts");
	return CFG_CALL(add_tx_ts, old_wiphy, old_dev, tsid, peer, user_prio, admitted_time);
}

static int wl66_del_tx_ts(struct wiphy *wiphy, struct net_device *dev,
			  u8 tsid, const u8 *peer)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->del_tx_ts)
		return wl_op_missing_int("del_tx_ts");
	return CFG_CALL(del_tx_ts, old_wiphy, old_dev, tsid, peer);
}

static int wl66_tdls_channel_switch(struct wiphy *wiphy,
				    struct net_device *dev,
				    const u8 *addr, u8 oper_class,
				    struct cfg80211_chan_def *chandef)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->tdls_channel_switch)
		return wl_op_missing_int("tdls_channel_switch");
	return CFG_CALL(tdls_channel_switch, old_wiphy, old_dev, addr, oper_class, chandef);
}

static void wl66_tdls_cancel_channel_switch(struct wiphy *wiphy,
					    struct net_device *dev,
					    const u8 *addr)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return;

	if (!b || !b->tdls_cancel_channel_switch)
		return wl_op_missing_void("tdls_cancel_channel_switch");
	b->tdls_cancel_channel_switch(old_wiphy, old_dev, addr);
}

static int wl66_start_nan(struct wiphy *wiphy, struct wireless_dev *wdev,
			  struct cfg80211_nan_conf *conf)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->start_nan)
		return wl_op_missing_int("start_nan");
	return CFG_CALL(start_nan, old_wiphy, old_wdev, conf);
}

static void wl66_stop_nan(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->stop_nan)
		return wl_op_missing_void("stop_nan");
	b->stop_nan(old_wiphy, old_wdev);
}

static int wl66_add_nan_func(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct cfg80211_nan_func *nan_func)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->add_nan_func)
		return wl_op_missing_int("add_nan_func");
	return CFG_CALL(add_nan_func, old_wiphy, old_wdev, nan_func);
}

static void wl66_del_nan_func(struct wiphy *wiphy, struct wireless_dev *wdev,
			      u64 cookie)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return;

	if (!b || !b->del_nan_func)
		return wl_op_missing_void("del_nan_func");
	b->del_nan_func(old_wiphy, old_wdev, cookie);
}

static int wl66_nan_change_conf(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				struct cfg80211_nan_conf *conf, u32 changes)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->nan_change_conf)
		return wl_op_missing_int("nan_change_conf");
	return CFG_CALL(nan_change_conf, old_wiphy, old_wdev, conf, changes);
}

static int wl66_set_multicast_to_unicast(struct wiphy *wiphy,
					 struct net_device *dev,
					 const bool enabled)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_multicast_to_unicast)
		return wl_op_missing_int("set_multicast_to_unicast");
	return CFG_CALL(set_multicast_to_unicast, old_wiphy, old_dev, enabled);
}

static int wl66_get_txq_stats(struct wiphy *wiphy, struct wireless_dev *wdev,
			      struct cfg80211_txq_stats *txqstats)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct wireless_dev *old_wdev = (void *)shim_wdev_legacy(wdev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || (wdev && !old_wdev))
		return -ENODEV;

	if (!b || !b->get_txq_stats)
		return wl_op_missing_int("get_txq_stats");
	return CFG_CALL(get_txq_stats, old_wiphy, old_wdev, txqstats);
}

static int wl66_set_pmk(struct wiphy *wiphy, struct net_device *dev,
			const struct cfg80211_pmk_conf *conf)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->set_pmk)
		return wl_op_missing_int("set_pmk");
	return CFG_CALL(set_pmk, old_wiphy, old_dev, conf);
}

static int wl66_del_pmk(struct wiphy *wiphy, struct net_device *dev,
			const u8 *aa)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->del_pmk)
		return wl_op_missing_int("del_pmk");
	return CFG_CALL(del_pmk, old_wiphy, old_dev, aa);
}

/* CAVEAT: 6.6 external_auth_params appended pmkid before mld_addr while
 * the BCA 4.19 tree places mld_addr right after status (under
 * CONFIG_BCM_KF_NL80211_EXTAUTH_MLD_ADDR). Prefix fields
 * (action/bssid/ssid/key_mgmt_suite/status) match; mld_addr is only
 * valid for MLO SAE, which this non-MLO path does not use. */
static int wl66_external_auth(struct wiphy *wiphy, struct net_device *dev,
			      struct cfg80211_external_auth_params *params)
{
	struct wiphy *old_wiphy = (void *)shim_wiphy_legacy(wiphy);
	struct net_device *old_dev = (void *)shim_netdev_legacy(dev);
	const struct wl419_ops *b = wl_blob_get();

	if (!old_wiphy || !old_dev)
		return -ENODEV;

	if (!b || !b->external_auth)
		return wl_op_missing_int("external_auth");
	return CFG_CALL(external_auth, old_wiphy, old_dev, params);
}

/* ------------------------------------------------------------------ */
/* Full 6.6 ops table. Order MUST match struct cfg80211_ops. MLO and   */
/* post-4.19 ops stay NULL until firmware MLO is validated (M5+).      */
/* WIPHY_FLAG_SUPPORTS_MLO must NOT be set while these are NULL.       */
/* ------------------------------------------------------------------ */

const struct cfg80211_ops wl_66_ops = {
	.suspend = wl66_suspend,
	.resume = wl66_resume,
	.set_wakeup = wl66_set_wakeup,
	.add_virtual_intf = wl66_add_virtual_intf,
	.del_virtual_intf = wl66_del_virtual_intf,
	.change_virtual_intf = wl66_change_virtual_intf,
	.add_intf_link = NULL,		/* MLO */
	.del_intf_link = NULL,		/* MLO */
	.add_key = wl66_add_key,
	.get_key = wl66_get_key,
	.del_key = wl66_del_key,
	.set_default_key = wl66_set_default_key,
	.set_default_mgmt_key = wl66_set_default_mgmt_key,
	.set_default_beacon_key = NULL,	/* MLO variant, no 4.19 equivalent */
	.start_ap = wl66_start_ap,
	.change_beacon = wl66_change_beacon,
	.stop_ap = wl66_stop_ap,
	.add_station = wl66_add_station,
	.del_station = wl66_del_station,
	.change_station = wl66_change_station,
	.get_station = wl66_get_station,
	.dump_station = wl66_dump_station,
	.add_mpath = wl66_add_mpath,
	.del_mpath = wl66_del_mpath,
	.change_mpath = wl66_change_mpath,
	.get_mpath = wl66_get_mpath,
	.dump_mpath = wl66_dump_mpath,
	.get_mpp = wl66_get_mpp,
	.dump_mpp = wl66_dump_mpp,
	.get_mesh_config = wl66_get_mesh_config,
	.update_mesh_config = wl66_update_mesh_config,
	.join_mesh = wl66_join_mesh,
	.leave_mesh = wl66_leave_mesh,
	.join_ocb = wl66_join_ocb,
	.leave_ocb = wl66_leave_ocb,
	.change_bss = wl66_change_bss,
	.inform_bss = NULL,		/* kernel-internal, drivers never set */
	.set_txq_params = wl66_set_txq_params,
	.libertas_set_mesh_channel = wl66_libertas_set_mesh_channel,
	.set_monitor_channel = wl66_set_monitor_channel,
	.scan = wl66_scan,
	.abort_scan = wl66_abort_scan,
	.auth = wl66_auth,
	.assoc = wl66_assoc,
	.deauth = wl66_deauth,
	.disassoc = wl66_disassoc,
	.connect = wl66_connect,
	.update_connect_params = wl66_update_connect_params,
	.disconnect = wl66_disconnect,
	.join_ibss = wl66_join_ibss,
	.leave_ibss = wl66_leave_ibss,
	.set_mcast_rate = wl66_set_mcast_rate,
	.set_wiphy_params = wl66_set_wiphy_params,
	.set_tx_power = wl66_set_tx_power,
	.get_tx_power = wl66_get_tx_power,
	.rfkill_poll = wl66_rfkill_poll,
#ifdef CONFIG_NL80211_TESTMODE
	.testmode_cmd = wl66_testmode_cmd,
	.testmode_dump = wl66_testmode_dump,
#endif
	.set_bitrate_mask = wl66_set_bitrate_mask,
	.dump_survey = wl66_dump_survey,
	.set_pmksa = wl66_set_pmksa,
	.del_pmksa = wl66_del_pmksa,
	.flush_pmksa = wl66_flush_pmksa,
	.remain_on_channel = wl66_remain_on_channel,
	.cancel_remain_on_channel = wl66_cancel_remain_on_channel,
	.mgmt_tx = wl66_mgmt_tx,
	.mgmt_tx_cancel_wait = wl66_mgmt_tx_cancel_wait,
	.set_power_mgmt = wl66_set_power_mgmt,
	.set_cqm_rssi_config = wl66_set_cqm_rssi_config,
	.set_cqm_rssi_range_config = wl66_set_cqm_rssi_range_config,
	.set_cqm_txe_config = wl66_set_cqm_txe_config,
	.update_mgmt_frame_registrations = wl66_update_mgmt_frame_regs,
	.set_antenna = wl66_set_antenna,
	.get_antenna = wl66_get_antenna,
	.sched_scan_start = wl66_sched_scan_start,
	.sched_scan_stop = wl66_sched_scan_stop,
	.set_rekey_data = wl66_set_rekey_data,
	.tdls_mgmt = wl66_tdls_mgmt,
	.tdls_oper = wl66_tdls_oper,
	.probe_client = wl66_probe_client,
	.set_noack_map = wl66_set_noack_map,
	.get_channel = wl66_get_channel,
	.start_p2p_device = wl66_start_p2p_device,
	.stop_p2p_device = wl66_stop_p2p_device,
	.set_mac_acl = wl66_set_mac_acl,
	.start_radar_detection = wl66_start_radar_detection,
	.end_cac = wl66_end_cac,
	.update_ft_ies = wl66_update_ft_ies,
	.crit_proto_start = wl66_crit_proto_start,
	.crit_proto_stop = wl66_crit_proto_stop,
	.set_coalesce = wl66_set_coalesce,
	.channel_switch = wl66_channel_switch,
	.set_qos_map = wl66_set_qos_map,
	.set_ap_chanwidth = wl66_set_ap_chanwidth,
	.add_tx_ts = wl66_add_tx_ts,
	.del_tx_ts = wl66_del_tx_ts,
	.tdls_channel_switch = wl66_tdls_channel_switch,
	.tdls_cancel_channel_switch = wl66_tdls_cancel_channel_switch,
	.start_nan = wl66_start_nan,
	.stop_nan = wl66_stop_nan,
	.add_nan_func = wl66_add_nan_func,
	.del_nan_func = wl66_del_nan_func,
	.nan_change_conf = wl66_nan_change_conf,
	.set_multicast_to_unicast = wl66_set_multicast_to_unicast,
	.get_txq_stats = wl66_get_txq_stats,
	.set_pmk = wl66_set_pmk,
	.del_pmk = wl66_del_pmk,
	.external_auth = wl66_external_auth,
	.tx_control_port = wl66_tx_control_port,
	.get_ftm_responder_stats = NULL,
	.start_pmsr = NULL,
	.abort_pmsr = NULL,
	.update_owe_info = NULL,
	.probe_mesh_link = NULL,
	.set_tid_config = NULL,
	.reset_tid_config = NULL,
	.set_sar_specs = NULL,
	.color_change = NULL,
	.set_fils_aad = NULL,
	.set_radar_background = NULL,
	.add_link_station = NULL,	/* MLO */
	.mod_link_station = NULL,	/* MLO */
	.del_link_station = NULL,	/* MLO */
	.set_hw_timestamp = NULL,
};
EXPORT_SYMBOL(wl_66_ops);

/* ------------------------------------------------------------------ */
/* Compile-time geometry checks. If Broadcom or upstream move a field, */
/* the build breaks here instead of misdispatching on the router.      */
/* ------------------------------------------------------------------ */

/* 6.6 table indices (TM-aware via enum). */
_Static_assert(offsetof(struct cfg80211_ops, add_key) == WL66_ADD_KEY * 4,
	       "6.6 add_key moved");
_Static_assert(offsetof(struct cfg80211_ops, stop_ap) == WL66_STOP_AP * 4,
	       "6.6 stop_ap moved");
_Static_assert(offsetof(struct cfg80211_ops, change_bss) == WL66_CHANGE_BSS * 4,
	       "6.6 change_bss moved");
_Static_assert(offsetof(struct cfg80211_ops, scan) == WL66_SCAN * 4,
	       "6.6 scan moved");
_Static_assert(offsetof(struct cfg80211_ops, connect) == WL66_CONNECT * 4,
	       "6.6 connect moved");
_Static_assert(offsetof(struct cfg80211_ops, disconnect) == WL66_DISCONNECT * 4,
	       "6.6 disconnect moved");
_Static_assert(offsetof(struct cfg80211_ops, set_pmksa) == WL66_SET_PMKSA * 4,
	       "6.6 set_pmksa moved");
_Static_assert(offsetof(struct cfg80211_ops, update_mgmt_frame_registrations) ==
	       WL66_UPDATE_MGMT_FRAME_REGS * 4,
	       "6.6 update_mgmt_frame_registrations moved");
_Static_assert(offsetof(struct cfg80211_ops, set_rekey_data) ==
	       WL66_SET_REKEY_DATA * 4, "6.6 set_rekey_data moved");
_Static_assert(offsetof(struct cfg80211_ops, tdls_mgmt) == WL66_TDLS_MGMT * 4,
	       "6.6 tdls_mgmt moved");
_Static_assert(offsetof(struct cfg80211_ops, get_channel) ==
	       WL66_GET_CHANNEL * 4, "6.6 get_channel moved");
_Static_assert(offsetof(struct cfg80211_ops, set_ap_chanwidth) ==
	       WL66_SET_AP_CHANWIDTH * 4, "6.6 set_ap_chanwidth moved");
_Static_assert(offsetof(struct cfg80211_ops, tx_control_port) ==
	       WL66_TX_CONTROL_PORT * 4, "6.6 tx_control_port moved");

#include "shim_cfg_layout_assert.h"

/* 4.19 mirror geometry: our wl419_ops must reproduce the blob layout. */
_Static_assert(offsetof(struct wl419_ops, add_key) == WL419_ADD_KEY * 4,
	       "wl419 mirror: add_key drifted");
_Static_assert(offsetof(struct wl419_ops, stop_ap) == WL419_STOP_AP * 4,
	       "wl419 mirror: stop_ap drifted");
_Static_assert(offsetof(struct wl419_ops, change_bss) == WL419_CHANGE_BSS * 4,
	       "wl419 mirror: change_bss drifted");
_Static_assert(offsetof(struct wl419_ops, scan) == WL419_SCAN * 4,
	       "wl419 mirror: scan drifted");
_Static_assert(offsetof(struct wl419_ops, connect) == WL419_CONNECT * 4,
	       "wl419 mirror: connect drifted");
_Static_assert(offsetof(struct wl419_ops, set_pmksa) == WL419_SET_PMKSA * 4,
	       "wl419 mirror: set_pmksa drifted");
_Static_assert(offsetof(struct wl419_ops, mgmt_frame_register) ==
	       WL419_MGMT_FRAME_REGISTER * 4,
	       "wl419 mirror: mgmt_frame_register drifted");
_Static_assert(offsetof(struct wl419_ops, tdls_mgmt) == WL419_TDLS_MGMT * 4,
	       "wl419 mirror: tdls_mgmt drifted");
_Static_assert(offsetof(struct wl419_ops, get_channel) ==
	       WL419_GET_CHANNEL * 4, "wl419 mirror: get_channel drifted");
_Static_assert(offsetof(struct wl419_ops, set_ap_chanwidth) ==
	       WL419_SET_AP_CHANWIDTH * 4,
	       "wl419 mirror: set_ap_chanwidth drifted");
_Static_assert(offsetof(struct wl419_ops, tx_control_port) ==
	       WL419_TX_CONTROL_PORT * 4,
	       "wl419 mirror: tx_control_port drifted");
_Static_assert(sizeof(struct wl419_ops) == WL419_OPS_COUNT * 4,
	       "wl419 mirror: table size drifted");

/* Struct growth points: where 6.6 inserted/appended fields. */
_Static_assert(offsetof(struct cfg80211_beacon_data, link_id) == 0,
	       "beacon_data: link_id not first");
_Static_assert(offsetof(struct bss_parameters, link_id) == 0,
	       "bss_parameters: link_id not first");
_Static_assert(offsetof(struct station_info, assoc_at) ==
	       offsetof(struct station_info, inactive_time) + 4,
	       "station_info: assoc_at not after inactive_time");
/* Event-chain mask geometry: the 4.19 BCA enum ends at DATA_ACK_SIGNAL_AVG
 * (value 35, still < 64 so a u64 mask holds it); 6.6 appended 8 more attrs
 * after it. If either side moves, the filled sanitiser must be revisited. */
_Static_assert(NL80211_STA_INFO_DATA_ACK_SIGNAL_AVG == 35,
	       "station_info: 4.19 max STA_INFO bit moved");
_Static_assert(NL80211_STA_INFO_MAX > NL80211_STA_INFO_DATA_ACK_SIGNAL_AVG,
	       "station_info: no post-4.19 STA_INFO bits to strip?");
_Static_assert(offsetof(struct key_params, vlan_id) ==
	       offsetof(struct wl419_key_params, cipher),
	       "key_params: vlan_id not at 4.19 cipher offset");
_Static_assert(offsetof(struct cfg80211_pmksa, pmk_lifetime) ==
	       sizeof(struct wl419_pmksa),
	       "pmksa: 6.6 fields not pure tail append");
_Static_assert(offsetof(struct cfg80211_gtk_rekey_data, akm) ==
	       sizeof(struct wl419_gtk_rekey_data),
	       "gtk_rekey: 6.6 fields not pure tail append");
/* Only the [channel..crypto) prefix of connect_params is shared: crypto
 * sits at the same offset (measured 44 in both trees) but grew 60->100 B,
 * shifting everything after it. Field copies above must stay in sync. */
_Static_assert(offsetof(struct cfg80211_connect_params, crypto) ==
	       offsetof(struct wl419_connect_params, crypto),
	       "connect_params: crypto moved, prefix copy broken");
_Static_assert(offsetof(struct cfg80211_chan_def, edmg) ==
	       sizeof(struct wl419_chan_def),
	       "chan_def: edmg not pure tail append");
/* wl66_mgmt_tx passes a 6.6 struct cfg80211_mgmt_tx_params (stack copy with
 * translated chan) to the 4.19 blob op: valid only while link_id is a pure
 * tail append after csa_offsets, i.e. the 9-field 4.19 prefix is intact. */
_Static_assert(offsetof(struct cfg80211_mgmt_tx_params, link_id) ==
	       offsetof(struct cfg80211_mgmt_tx_params, csa_offsets) +
	       sizeof(((struct cfg80211_mgmt_tx_params *)0)->csa_offsets),
	       "mgmt_tx_params: link_id not pure tail append");

/* ------------------------------------------------------------------ */
/* 4.19-inline forwarders (transplanted from shim_cfg80211.c at merge */
/* D so the 5 wl.ko UND that are static inlines in 6.6 keep a home).  */
/* 4.19 prototypes (linux-4.19.246) vs 6.6 inlines (6.6.93) are      */
/* IDENTICAL — verified header-to-header by lane C — so each global  */
/* forwards to its renamed inline: body is upstream's by             */
/* construction, no copy drift. Guard: IS_ENABLED (not plain         */
/* #ifdef CONFIG_CFG80211 — an out-of-tree module built against a    */
/* CONFIG_CFG80211=m kernel sees CONFIG_CFG80211_MODULE, and plain   */
/* #ifdef would stay dormant forever; lane-C skeleton had that bug). */
/* While dormant, wl.ko UND on these 5 stay unresolved — they        */
/* activate with the lane-B rebuild.                                 */
/* ------------------------------------------------------------------ */

#if IS_ENABLED(CONFIG_CFG80211)

/* Blob -> core notifiers. The wdev the blob passes is its own 4.19-layout
 * allocation (adopted at netdev-register time into the shim registry);
 * an unmapped pointer means adoption never happened for that object, so
 * the frame is undeliverable — count it and warn, never drop silently
 * (silent RX drops were the ASSOC_TRIAGE signature). The 6.6 inlines
 * convert MHz->kHz (RX) and wrap status (TX-status) for _ext; freq/sig
 * units are dBm on both sides (BCA 4.19 tree already documents sig_dbm).
 */
bool cfg80211_rx_mgmt(struct wireless_dev *wdev, int freq, int sig_mbm,
		      const u8 *buf, size_t len, u32 flags)
{
	struct wireless_dev *native = shim_wdev_native((void *)wdev);

	atomic_long_inc(&wl_mgmt_rx_calls);
	if (wl_mgmt_trace)
		pr_info_ratelimited("cfg80211_compat: mgmt RX freq=%d sig=%d len=%zu flags=0x%x\n",
				    freq, sig_mbm, len, flags);
	if (!native) {
		atomic_long_inc(&wl_mgmt_rx_drop_nowdev);
		pr_warn_once("cfg80211_compat: mgmt RX from unmapped wdev %p, frame dropped\n",
			     wdev);
		return false;
	}
	return cfg80211_rx_mgmt_inl(native, freq, sig_mbm, buf, len, flags);
}
EXPORT_SYMBOL(cfg80211_rx_mgmt);

void cfg80211_mgmt_tx_status(struct wireless_dev *wdev, u64 cookie,
			     const u8 *buf, size_t len, bool ack,
			     gfp_t gfp)
{
	struct wireless_dev *native = shim_wdev_native((void *)wdev);

	atomic_long_inc(&wl_mgmt_txst_calls);
	if (wl_mgmt_trace)
		pr_info_ratelimited("cfg80211_compat: mgmt TX-status cookie=0x%llx len=%zu ack=%d\n",
				    (unsigned long long)cookie, len, ack);
	if (!native) {
		atomic_long_inc(&wl_mgmt_txst_drop_nowdev);
		pr_warn_once("cfg80211_compat: mgmt TX-status from unmapped wdev %p, status dropped\n",
			     wdev);
		return;
	}
	cfg80211_mgmt_tx_status_inl(native, cookie, buf, len, ack, shim_gfp419(gfp));
}
EXPORT_SYMBOL(cfg80211_mgmt_tx_status);

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	return ieee80211_channel_to_frequency_inl(chan, band);
}
EXPORT_SYMBOL(ieee80211_channel_to_frequency);

int ieee80211_frequency_to_channel(int freq)
{
	return ieee80211_frequency_to_channel_inl(freq);
}
EXPORT_SYMBOL(ieee80211_frequency_to_channel);

struct ieee80211_channel *ieee80211_get_channel(struct wiphy *wiphy,
						int freq)
{
	struct wiphy *native = shim_wiphy_native((void *)wiphy);

	if (!native) {
		pr_warn_once("cfg80211_compat: ieee80211_get_channel on unmapped wiphy %p\n",
			     wiphy);
		return NULL;
	}
	return shim_channel_legacy(ieee80211_get_channel_inl(native, freq));
}
EXPORT_SYMBOL(ieee80211_get_channel);

#endif /* IS_ENABLED(CONFIG_CFG80211) */

/* ------------------------------------------------------------------ */

/* Opt-in boundary test: three callback shapes, unknown-object rejection,
 * and reverse translation of add_virtual_intf's returned wdev. No radio. */
static bool cfg_object_selftest;
module_param(cfg_object_selftest, bool, 0400);
static void *cfg_test_w, *cfg_test_d, *cfg_test_v;
static unsigned int cfg_test_calls;
static int cfg_test_change_ret = 17;
static enum nl80211_iftype cfg_test_old_type;
static int cfg_test_change(struct wiphy *w, struct net_device *d,
			   enum nl80211_iftype type, struct vif_params *params)
{
	if ((void *)w != cfg_test_w || (void *)d != cfg_test_d)
		return -EFAULT;
	cfg_test_calls++;
	/* Literal vendor DWARF offset, independent of the publisher accessor. */
	memcpy((u8 *)cfg_test_v + 4, &cfg_test_old_type, sizeof(cfg_test_old_type));
	return cfg_test_change_ret;
}
static int cfg_test_power(struct wiphy *w, struct wireless_dev *v, int *dbm)
{
	if ((void *)w != cfg_test_w || (void *)v != cfg_test_v)
		return -EFAULT;
	cfg_test_calls++;
	*dbm = 19;
	return 0;
}
static struct wireless_dev *cfg_test_add(struct wiphy *w, const char *name,
			unsigned char assign, enum nl80211_iftype type,
			struct vif_params *params)
{
	if ((void *)w != cfg_test_w)
		return ERR_PTR(-EFAULT);
	cfg_test_calls++;
	return cfg_test_v;
}
static int cfg_test_pm(struct wiphy *w, struct net_device *d, bool enabled, int timeout)
{
	if ((void *)w != cfg_test_w || (void *)d != cfg_test_d || !enabled || timeout != -1)
		return -EFAULT;
	cfg_test_calls++;
	return 23;
}
static int cfg_test_wrong_slot(struct wiphy *w, struct net_device *d, bool enabled, int timeout)
{
	return -EBADMSG;
}
static int cfg_objects_test(void)
{
	static const void * const raw_mock[106] = {
		[62] = cfg_test_wrong_slot, [64] = cfg_test_pm,
	};
	static const struct wl419_ops mock = {
		.change_virtual_intf = cfg_test_change,
		.get_tx_power = cfg_test_power,
		.add_virtual_intf = cfg_test_add,
	};
	struct wiphy419_view *w = shim_wiphy_alloc(4, &wl_66_ops);
	struct netdev419_view *d = shim_netdev_alloc_ether(4, "cft%d", NET_NAME_UNKNOWN, 1, 1);
	struct wdev419_view *v = shim_wdev_alloc();
	struct wiphy *nw;
	struct net_device *nd = NULL;
	struct wireless_dev *nv = NULL;
	int dbm = 0, ret = -EIO;

	if (!w || !d || !v)
		goto out;
	if (shim_wdev_bind(v, w))
		goto out;
	nw = shim_wiphy_native(w);
	nd = shim_netdev_native(d);
	nv = shim_wdev_native(v);
	cfg_test_w = w; cfg_test_d = d; cfg_test_v = v; cfg_test_calls = 0;
	cfg80211_compat_attach_blob(&mock);
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_AP, NULL) != 17 ||
	    wl66_get_tx_power(nw, nv, &dbm) || dbm != 19 ||
	    wl66_add_virtual_intf(nw, "cft", 0, NL80211_IFTYPE_AP, NULL) != nv ||
	    cfg_test_calls != 3)
		goto out;
	if (wl66_change_virtual_intf((void *)w, nd, NL80211_IFTYPE_AP, NULL) != -ENODEV ||
	    wl66_change_virtual_intf(nw, (void *)d, NL80211_IFTYPE_AP, NULL) != -ENODEV ||
	    wl66_get_tx_power(nw, (void *)v, &dbm) != -ENODEV || cfg_test_calls != 3)
		goto out;
	cfg80211_compat_attach_blob((const void *)raw_mock);
	if (wl66_set_power_mgmt(nw, nd, true, -1) != 23 || cfg_test_calls != 4)
		goto out;
	pr_info("CFG419_RAW_OPS_SELFTEST PASS slot64-testmode-present\n");
	cfg80211_compat_attach_blob(&mock);
	nd->ieee80211_ptr = nv;
	nv->netdev = nd;
	nv->iftype = NL80211_IFTYPE_STATION;
	cfg_test_old_type = NL80211_IFTYPE_AP;
	cfg_test_change_ret = 0;
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_AP, NULL) ||
	    nv->iftype != NL80211_IFTYPE_AP)
		goto out;
	cfg_test_old_type = NL80211_IFTYPE_STATION;
	cfg_test_change_ret = -EBUSY;
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_STATION, NULL) != -EBUSY ||
	    nv->iftype != NL80211_IFTYPE_AP)
		goto out;
	cfg_test_change_ret = 0;
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_STATION, NULL) ||
	    nv->iftype != NL80211_IFTYPE_STATION)
		goto out;
	/* A success return without the driver's matching state write is rejected. */
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_AP, NULL) != -EPROTO ||
	    nv->iftype != NL80211_IFTYPE_STATION)
		goto out;
	cfg_test_old_type = NUM_NL80211_IFTYPES;
	if (wl66_change_virtual_intf(nw, nd, NL80211_IFTYPE_AP, NULL) != -EPROTO ||
	    nv->iftype != NL80211_IFTYPE_STATION)
		goto out;
	pr_info("CFG419_IFTYPE_SELFTEST PASS STA-AP-STA failure-preserved mismatch-rejected\n");
	ret = 0;
out:
	cfg80211_compat_detach_blob();
	if (nd) nd->ieee80211_ptr = NULL;
	if (nv) nv->netdev = NULL;
	cfg_test_change_ret = 17;
	if (v) shim_wdev_free(v);
	if (d) shim_netdev_free_unregistered(d);
	if (w) shim_wiphy_free_unregistered(w);
	cfg_test_w = cfg_test_d = cfg_test_v = NULL;
	pr_info("CFG419_OBJECT_SELFTEST %s callback-views return-view foreign-rejected\n", ret ? "FAIL" : "PASS");
	return ret;
}

/* ------------------------------------------------------------------ */
/* Event-chain selftest (gated, no blob, no hardware).                  */
/* Synthetic wl_event -> wl_cfg80211_event -> cfg80211_new_sta payloads: */
/* new (IEs + pertid + garbage filled bits), update (re-convert changed */
/* lengths), del (empty/NULL legs), length validation, IE own/disown,   */
/* pertid dup/release, emit-dev guards. Counters must return to their   */
/* baseline: every owned buffer is accounted. HW lane runs it with      */
/* cfg_events_selftest=1 next to cfg_object_selftest=1.                 */
/* ------------------------------------------------------------------ */

static bool cfg_events_selftest;
module_param(cfg_events_selftest, bool, 0400);
MODULE_PARM_DESC(cfg_events_selftest, "Test cfg80211 event station_info translation");

#define CEVCHECK(expr) do { if (!(expr)) { ret = -EINVAL; \
	pr_err("cfg80211_compat: CFG419_EVENTS_SELFTEST failed line=%d\n", __LINE__); \
	goto cevout; } } while (0)

static int cfg_events_test(void)
{
	static u8 fake_ies[160];
	static struct cfg80211_tid_stats fake_pertid[IEEE80211_NUM_TIDS + 1];
	/* Translation structs live on the heap: two station_info plus the
	 * 419 mirror and a wireless_dev exceed the 1024 B stack frame. */
	struct cev_ctx {
		struct wl419_station_info src419;
		struct station_info native;
		struct station_info empty;
		struct wireless_dev foreign_wdev;
	} *ctx;
	struct wl_sinfo_owned tok = { NULL, NULL };
	struct net_device *d = NULL;
#if IS_ENABLED(CONFIG_CFG80211)
	struct wiphy419_view *w = NULL;
	struct wdev419_view *v = NULL;
	struct wireless_dev *nv;
	struct wiphy *foreign = NULL;
#endif
	long ia, ieff, pok, pfail, prel;
	int i, ret = -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	CEVCHECK(ctx);
	for (i = 0; i < (int)sizeof(fake_ies); i++)
		fake_ies[i] = (u8)(0xA0 + i);
	memset(fake_pertid, 0, sizeof(fake_pertid));
	fake_pertid[3].filled = 0x5;
	fake_pertid[3].rx_msdu = 0x1122334455667788ULL;
	fake_pertid[3].tx_msdu = 0x99AABBCCDDEEFF00ULL;
	fake_pertid[IEEE80211_NUM_TIDS].filled = 0x1;
	fake_pertid[IEEE80211_NUM_TIDS].tx_msdu_failed = 7;

	ia = atomic_long_read(&wl_sinfo_ie_allocs);
	ieff = atomic_long_read(&wl_sinfo_ie_frees);
	pok = atomic_long_read(&wl_sinfo_pertid_dup_ok);
	pfail = atomic_long_read(&wl_sinfo_pertid_dup_fail);
	prel = atomic_long_read(&wl_sinfo_pertid_released);

	/* CASE new: full new_sta-shaped payload. */
	memset(&ctx->src419, 0, sizeof(ctx->src419));
	ctx->src419.filled = WL_SINFO419_FILLED_MASK |
			BIT_ULL(60) | BIT_ULL(NL80211_STA_INFO_TX_DURATION);
	ctx->src419.signal = -42;
	ctx->src419.signal_avg = -45;
	ctx->src419.chains = 0x3;
	ctx->src419.generation = 11;
	ctx->src419.assoc_req_ies = fake_ies;
	ctx->src419.assoc_req_ies_len = sizeof(fake_ies);
	ctx->src419.pertid = fake_pertid;
	wl_shim_station_info_19_to_66(&ctx->src419, &ctx->native);
	CEVCHECK(ctx->native.filled == (ctx->src419.filled & WL_SINFO419_FILLED_MASK));
	CEVCHECK(!(ctx->native.filled & BIT_ULL(60)));
	CEVCHECK(!(ctx->native.filled & BIT_ULL(NL80211_STA_INFO_TX_DURATION)));
	CEVCHECK(ctx->native.signal == -42 && ctx->native.generation == 11);
	CEVCHECK(ctx->native.assoc_req_ies == fake_ies &&
		 ctx->native.assoc_req_ies_len == sizeof(fake_ies));
	CEVCHECK(!ctx->native.assoc_at && !ctx->native.tx_duration &&
		 !ctx->native.mlo_params_valid && !ctx->native.assoc_resp_ies &&
		 !ctx->native.assoc_resp_ies_len);
	CEVCHECK(ctx->native.pertid && ctx->native.pertid != fake_pertid);
	CEVCHECK(!memcmp(ctx->native.pertid, fake_pertid, sizeof(fake_pertid)));
	CEVCHECK(!wl_shim_sinfo_own_ies(&ctx->native, GFP_KERNEL, &tok));
	CEVCHECK(tok.owned_ies && ctx->native.assoc_req_ies == tok.owned_ies &&
		 ctx->native.assoc_req_ies != fake_ies);
	CEVCHECK(!memcmp((const void *)ctx->native.assoc_req_ies, fake_ies,
			 sizeof(fake_ies)));
	wl_shim_sinfo_disown_ies(&ctx->native, &tok);
	CEVCHECK(ctx->native.assoc_req_ies == fake_ies && !tok.owned_ies);
	wl_shim_sinfo_release_pertid(&ctx->native);
	CEVCHECK(!ctx->native.pertid);

	/* CASE update: same station, changed (shorter) IEs. */
	ctx->src419.assoc_req_ies_len = 8;
	wl_shim_station_info_19_to_66(&ctx->src419, &ctx->native);
	CEVCHECK(ctx->native.assoc_req_ies == fake_ies &&
		 ctx->native.assoc_req_ies_len == 8);
	CEVCHECK(!wl_shim_sinfo_own_ies(&ctx->native, GFP_KERNEL, &tok));
	CEVCHECK(tok.owned_ies && ctx->native.assoc_req_ies_len == 8);
	CEVCHECK(!memcmp((const void *)ctx->native.assoc_req_ies, fake_ies, 8));
	wl_shim_sinfo_disown_ies(&ctx->native, &tok);
	wl_shim_sinfo_release_pertid(&ctx->native);
	CEVCHECK(!ctx->native.pertid && !tok.owned_ies);

	/* CASE del: empty/NULL legs never allocate, never crash. */
	CEVCHECK(!wl_shim_sinfo_own_ies(&ctx->empty, GFP_KERNEL, &tok) &&
		 !tok.owned_ies);
	wl_shim_sinfo_disown_ies(&ctx->empty, &tok);
	wl_shim_sinfo_release_pertid(&ctx->empty);
	wl_shim_sinfo_disown_ies(NULL, &tok);
	wl_shim_sinfo_release_pertid(NULL);
	CEVCHECK(wl_shim_sinfo_own_ies(NULL, GFP_KERNEL, &tok) == -EINVAL);
	CEVCHECK(wl_shim_sinfo_own_ies(&ctx->empty, GFP_KERNEL, NULL) == -EINVAL);

	/* CASE lengths: NULL pointer with length drops; oversize clamps. */
	memset(&ctx->src419, 0, sizeof(ctx->src419));
	ctx->src419.assoc_req_ies = NULL;
	ctx->src419.assoc_req_ies_len = 64;
	wl_shim_station_info_19_to_66(&ctx->src419, &ctx->native);
	CEVCHECK(!ctx->native.assoc_req_ies && !ctx->native.assoc_req_ies_len);
	ctx->src419.assoc_req_ies = fake_ies;
	ctx->src419.assoc_req_ies_len = IEEE80211_MAX_DATA_LEN + 100;
	wl_shim_station_info_19_to_66(&ctx->src419, &ctx->native);
	CEVCHECK(ctx->native.assoc_req_ies == fake_ies &&
		 ctx->native.assoc_req_ies_len == IEEE80211_MAX_DATA_LEN);
	CEVCHECK(!wl_shim_sinfo_own_ies(&ctx->native, GFP_KERNEL, &tok));
	CEVCHECK(tok.owned_ies &&
		 ctx->native.assoc_req_ies_len == IEEE80211_MAX_DATA_LEN);
	wl_shim_sinfo_disown_ies(&ctx->native, &tok);
	CEVCHECK(ctx->native.assoc_req_ies == fake_ies && !tok.owned_ies);

	/* CASE guards: emit-dev legs. */
	CEVCHECK(!wl_shim_sta_emit_dev(NULL, "selftest"));
	CEVCHECK(!wl_shim_sta_emit_dev(NULL, NULL));
	d = alloc_etherdev(0);
	CEVCHECK(d);
	/* Fresh etherdev has no wdev: must be refused, not dereferenced. */
	CEVCHECK(!d->ieee80211_ptr);
	CEVCHECK(!wl_shim_sta_emit_dev(d, "selftest"));
#if IS_ENABLED(CONFIG_CFG80211)
	/* Positive leg: genuine shim wiphy binding passes. */
	w = shim_wiphy_alloc(4, &wl_66_ops);
	CEVCHECK(w);
	v = shim_wdev_alloc();
	CEVCHECK(v);
	CEVCHECK(!shim_wdev_bind(v, w));
	nv = shim_wdev_native(v);
	CEVCHECK(nv);
	d->ieee80211_ptr = nv;
	CEVCHECK(wl_shim_sta_emit_dev(d, "selftest") == d);
	d->ieee80211_ptr = NULL;
	/* Foreign (non-shim) wiphy is refused. */
	foreign = wiphy_new(&wl_66_ops, 0);
	CEVCHECK(foreign);
	memset(&ctx->foreign_wdev, 0, sizeof(ctx->foreign_wdev));
	ctx->foreign_wdev.wiphy = foreign;
	d->ieee80211_ptr = &ctx->foreign_wdev;
	CEVCHECK(!wl_shim_sta_emit_dev(d, "selftest"));
	d->ieee80211_ptr = NULL;
#endif
	/* Counters return to baseline: no owned byte leaked. */
	CEVCHECK(atomic_long_read(&wl_sinfo_ie_allocs) - ia ==
		 atomic_long_read(&wl_sinfo_ie_frees) - ieff);
	CEVCHECK(atomic_long_read(&wl_sinfo_pertid_dup_ok) - pok ==
		 atomic_long_read(&wl_sinfo_pertid_released) - prel);
	CEVCHECK(atomic_long_read(&wl_sinfo_pertid_dup_fail) == pfail);
	pr_info("CFG419_EVENTS_SELFTEST PASS new-update-del ie-owned pertid-dup guards-balanced\n");
	ret = 0;
cevout:
	if (ctx) {
		if (tok.owned_ies)
			wl_shim_sinfo_disown_ies(&ctx->native, &tok);
		if (ctx->native.pertid)
			wl_shim_sinfo_release_pertid(&ctx->native);
		kfree(ctx);
	}
	if (d) {
		d->ieee80211_ptr = NULL;
		free_netdev(d);
	}
#if IS_ENABLED(CONFIG_CFG80211)
	if (foreign)
		wiphy_free(foreign);
	if (v)
		shim_wdev_free(v);
	if (w)
		shim_wiphy_free_unregistered(w);
#endif
	pr_info("CFG419_EVENTS_SELFTEST %s synthetic-events guards-checked\n",
		ret ? "FAIL" : "PASS");
	return ret;
}

#undef CEVCHECK

/* ------------------------------------------------------------------ */
/* mgmt RX->TX roundtrip selftest (gated, no blob, no air). Synthetic   */
/* assoc-shaped legs through the three mgmt thunks:                     */
/*  1. RX/status guard legs: notifiers with an unmapped wdev must drop  */
/*     WITHOUT entering the core (no live wiphy exists here) and bump   */
/*     the drop counters.                                               */
/*  2. TX thunk leg: wl66_mgmt_tx via wl_66_ops against a mock blob op  */
/*     (NULL-chan passthrough, buf/len/cookie passthrough, empty-frame  */
/*     -EINVAL, missing-op -EOPNOTSUPP, unknown-chan -ENODEV).           */
/*  3. REG adapter leg: update_mgmt_frame_registrations replays          */
/*     class-bit diffs as (frame_type, on/off) into the mock blob op.   */
/* HW lane runs it with mgmt_selftest=1 next to the other gates.        */
/* ------------------------------------------------------------------ */

static bool mgmt_selftest;
module_param_named(mgmt_selftest, mgmt_selftest, bool, 0400);
MODULE_PARM_DESC(mgmt_selftest, "Test mgmt RX/TX thunk roundtrip (synthetic)");

#define MCHK(expr) do { if (!(expr)) { \
	pr_err("cfg80211_compat: MGMT_SELFTEST failed line=%d\n", __LINE__); \
	goto mout; } } while (0)

static unsigned int mgmt_test_tx_calls;
static const u8 *mgmt_test_tx_buf;
static size_t mgmt_test_tx_len;
static struct ieee80211_channel *mgmt_test_tx_chan;
static int mgmt_test_tx_ret = -EIO;

static int mgmt_test_mgmt_tx(struct wiphy *w, struct wireless_dev *v,
			     struct cfg80211_mgmt_tx_params *p, u64 *cookie)
{
	if (!w || !v || !p || !cookie)
		return -EFAULT;
	mgmt_test_tx_calls++;
	mgmt_test_tx_buf = p->buf;
	mgmt_test_tx_len = p->len;
	mgmt_test_tx_chan = p->chan;
	*cookie = 0xA55A5AA55A5AA5A5ULL;
	return mgmt_test_tx_ret;
}

#define MGMT_TEST_REG_MAX 8
static unsigned int mgmt_test_reg_calls;
static u16 mgmt_test_reg_type[MGMT_TEST_REG_MAX];
static bool mgmt_test_reg_on[MGMT_TEST_REG_MAX];

static void mgmt_test_frame_register(struct wiphy *w, struct wireless_dev *v,
				     u16 frame_type, bool reg)
{
	if (!w || mgmt_test_reg_calls >= MGMT_TEST_REG_MAX)
		return;
	(void)v;
	mgmt_test_reg_type[mgmt_test_reg_calls] = frame_type;
	mgmt_test_reg_on[mgmt_test_reg_calls] = reg;
	mgmt_test_reg_calls++;
}

static const struct wl419_ops mgmt_test_blob = {
	.mgmt_tx = mgmt_test_mgmt_tx,
	.mgmt_frame_register = mgmt_test_frame_register,
};

static const struct wl419_ops mgmt_test_blob_no_tx = {
	.mgmt_tx = NULL,
	.mgmt_frame_register = mgmt_test_frame_register,
};

static int mgmt_roundtrip_test(void)
{
	static u8 fake_mgmt[64];
	struct wiphy419_view *w = NULL;
	struct wdev419_view *v = NULL;
	struct wiphy *nw;
	struct wireless_dev *nv;
	struct cfg80211_mgmt_tx_params txp;
	struct ieee80211_channel fake_chan;
	struct mgmt_frame_regs regs;
	u64 cookie = 0;
	int i, ret = -EINVAL;
	long rx0, rxd0, txs0, txsd0, tx0;
#if IS_ENABLED(CONFIG_CFG80211)
	long rx1, rxd1, txs1, txsd1;
#endif

	for (i = 0; i < (int)sizeof(fake_mgmt); i++)
		fake_mgmt[i] = (u8)(0x40 + i);
	rx0 = atomic_long_read(&wl_mgmt_rx_calls);
	rxd0 = atomic_long_read(&wl_mgmt_rx_drop_nowdev);
	txs0 = atomic_long_read(&wl_mgmt_txst_calls);
	txsd0 = atomic_long_read(&wl_mgmt_txst_drop_nowdev);
	tx0 = atomic_long_read(&wl_mgmt_tx_calls);

#if IS_ENABLED(CONFIG_CFG80211)
	/* LEG 1: RX/status guard legs — unmapped wdev, core never entered. */
	if (cfg80211_rx_mgmt((void *)0x1234, 5180, -50,
			     fake_mgmt, sizeof(fake_mgmt), 0))
		goto mout;
	if (cfg80211_rx_mgmt(NULL, 2412, 0, fake_mgmt, sizeof(fake_mgmt), 0))
		goto mout;
	cfg80211_mgmt_tx_status((void *)0x1234, 0xA55A5AA55A5AA5A5ULL,
				fake_mgmt, sizeof(fake_mgmt), true, GFP_KERNEL);
	rx1 = atomic_long_read(&wl_mgmt_rx_calls);
	rxd1 = atomic_long_read(&wl_mgmt_rx_drop_nowdev);
	txs1 = atomic_long_read(&wl_mgmt_txst_calls);
	txsd1 = atomic_long_read(&wl_mgmt_txst_drop_nowdev);
	MCHK(rx1 - rx0 == 2 && rxd1 - rxd0 == 2);
	MCHK(txs1 - txs0 == 1 && txsd1 - txsd0 == 1);
#endif

	/* LEG 2: TX thunk leg against the mock blob op. */
	w = shim_wiphy_alloc(4, &wl_66_ops);
	MCHK(w);
	v = shim_wdev_alloc();
	MCHK(v);
	MCHK(!shim_wdev_bind(v, w));
	nw = shim_wiphy_native(w);
	nv = shim_wdev_native(v);
	MCHK(nw && nv);

	mgmt_test_tx_calls = 0;
	mgmt_test_tx_ret = 0;
	cfg80211_compat_attach_blob(&mgmt_test_blob);
	memset(&txp, 0, sizeof(txp));
	txp.buf = fake_mgmt;
	txp.len = sizeof(fake_mgmt);
	txp.chan = NULL; /* AP-mode assoc response: current channel */
	MCHK(wl_66_ops.mgmt_tx(nw, nv, &txp, &cookie) == 0);
	MCHK(mgmt_test_tx_calls == 1);
	MCHK(mgmt_test_tx_buf == fake_mgmt && mgmt_test_tx_len == sizeof(fake_mgmt));
	MCHK(mgmt_test_tx_chan == NULL);
	MCHK(cookie == 0xA55A5AA55A5AA5A5ULL);

	/* Empty frame rejected before the blob is entered. */
	txp.buf = NULL;
	txp.len = 0;
	cookie = 0;
	MCHK(wl_66_ops.mgmt_tx(nw, nv, &txp, &cookie) == -EINVAL);
	MCHK(mgmt_test_tx_calls == 1);

	/* Missing blob op degrades to -EOPNOTSUPP. */
	cfg80211_compat_attach_blob(&mgmt_test_blob_no_tx);
	txp.buf = fake_mgmt;
	txp.len = sizeof(fake_mgmt);
	MCHK(wl_66_ops.mgmt_tx(nw, nv, &txp, &cookie) == -EOPNOTSUPP);
	MCHK(mgmt_test_tx_calls == 1);

	/* Unknown channel (not a published band member) -> -ENODEV. */
	cfg80211_compat_attach_blob(&mgmt_test_blob);
	memset(&fake_chan, 0, sizeof(fake_chan));
	txp.chan = &fake_chan;
	MCHK(wl_66_ops.mgmt_tx(nw, nv, &txp, &cookie) == -ENODEV);
	MCHK(mgmt_test_tx_calls == 1);
	MCHK(atomic_long_read(&wl_mgmt_tx_calls) - tx0 == 4);

	/* LEG 3: REG adapter leg — class-bit diffs replayed as pairs. */
	mgmt_test_reg_calls = 0;
	memset(&regs, 0, sizeof(regs));
	regs.interface_stypes = BIT(4) | BIT(11); /* assoc-req class, auth class */
	wl_66_ops.update_mgmt_frame_registrations(nw, nv, &regs);
	MCHK(mgmt_test_reg_calls == 2);
	MCHK(mgmt_test_reg_type[0] == (4 << 4) && mgmt_test_reg_on[0]);
	MCHK(mgmt_test_reg_type[1] == (11 << 4) && mgmt_test_reg_on[1]);
	regs.interface_stypes = BIT(11); /* assoc class withdrawn */
	wl_66_ops.update_mgmt_frame_registrations(nw, nv, &regs);
	MCHK(mgmt_test_reg_calls == 3);
	MCHK(mgmt_test_reg_type[2] == (4 << 4) && !mgmt_test_reg_on[2]);
	memset(&regs, 0, sizeof(regs)); /* leave the slot table clean */
	wl_66_ops.update_mgmt_frame_registrations(nw, nv, &regs);
	MCHK(mgmt_test_reg_calls == 4);

	pr_info("CFG419_MGMT_SELFTEST PASS rx-guard tx-mock reg-replay\n");
	ret = 0;
mout:
	cfg80211_compat_detach_blob();
	if (v)
		shim_wdev_free(v);
	if (w)
		shim_wiphy_free_unregistered(w);
	pr_info("CFG419_MGMT_SELFTEST %s synthetic roundtrip, no blob, no air\n",
		ret ? "FAIL" : "PASS");
	return ret;
}

#undef MCHK

int cfg80211_compat_subinit(void)
{
	if (cfg_object_selftest) {
		int ret = cfg_objects_test();
		if (ret)
			return ret;
	}
	if (cfg_events_selftest)
		return cfg_events_test();
	if (mgmt_selftest)
		return mgmt_roundtrip_test();
#if IS_ENABLED(CONFIG_CFG80211)
	pr_info("cfg80211_compat: 4.19->6.6 ops shim up, inline fwds active, blob %sattached\n",
		wl_blob_get() ? "" : "not ");
#else
	pr_info("cfg80211_compat: ops table up, inline fwds dormant (CONFIG_CFG80211 off)\n");
#endif
	return 0;
}
