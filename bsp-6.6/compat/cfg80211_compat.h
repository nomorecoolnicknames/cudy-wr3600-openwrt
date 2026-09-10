/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cfg80211_compat.h - 4.19 ABI mirrors for stock wl.ko on kernel 6.6.93
 *
 * Sub-agent A (lane D of SHIM_WORKPLAN.md): cfg80211_ops translation
 * 4.19-layout -> 6.6-layout for the proprietary stock wl.ko blob
 * (radio/wl.ko, 4.19.294, fullmac, BCM6764).
 *
 * 4.19 reference: gpl/openwrt/21.02/build_dir/target-.../linux-4.19.246/
 *   include/net/cfg80211.h (Broadcom BCA tree, NOT vanilla 4.19)
 * 6.6 reference: kernel-6.6/src/linux-6.6.93/include/net/cfg80211.h
 *
 * Rule: every "wl419_" type below reproduces the 4.19 BCA layout
 * field-by-field. The blob reads/writes these layouts, so the mirrors
 * must match the 4.19 header, not the 6.6 one. Offsets of the critical
 * members are enforced with _Static_assert in cfg80211_compat.c.
 */
#ifndef _CFG80211_COMPAT_H_
#define _CFG80211_COMPAT_H_

#include <linux/types.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>

/* ------------------------------------------------------------------ */
/* 4.19 table geometry (verified against 4.19.246 header, struct       */
/* cfg80211_ops @ line 3159). 106 function pointers, indices 0..105.  */
/* ------------------------------------------------------------------ */
/* Blob configuration is fixed, independent of the host kernel config.
 * Compiler oracle + ELF ops relocs: testmode slots53/54 exist even when
 * NULL, set_power_mgmt is slot64, total106. Host #110 has TESTMODE off. */
#define WL419_OPS_COUNT 106
#define WL419_TM_COUNT 2
#define WL419_NUM_BANDS 4
#ifdef CONFIG_NL80211_TESTMODE
#define WL66_TM_COUNT 2
#else
#define WL66_TM_COUNT 0
#endif

/* 4.19 indices of ops we translate (callback excluded).
 * Bases are without-TESTMODE values; +TM where needed.
 */
enum wl419_op_idx {
	WL419_SUSPEND		= 0,
	WL419_RESUME		= 1,
	WL419_SET_WAKEUP	= 2,
	WL419_ADD_VIRTUAL_INTF	= 3,
	WL419_DEL_VIRTUAL_INTF	= 4,
	WL419_CHANGE_VIRTUAL_INTF = 5,
	WL419_ADD_KEY		= 6,
	WL419_GET_KEY		= 7,
	WL419_DEL_KEY		= 8,
	WL419_SET_DEFAULT_KEY	= 9,
	WL419_SET_DEFAULT_MGMT_KEY = 10,
	WL419_START_AP		= 11,
	WL419_CHANGE_BEACON	= 12,
	WL419_STOP_AP		= 13,
	WL419_ADD_STATION	= 14,
	WL419_DEL_STATION	= 15,
	WL419_CHANGE_STATION	= 16,
	WL419_GET_STATION	= 17,
	WL419_DUMP_STATION	= 18,
	/* 19..31: mpath/mpp/mesh/ocb */
	WL419_CHANGE_BSS	= 32,
	/* 33..35: set_txq/libertas/set_monitor */
	WL419_SCAN		= 36,
	WL419_ABORT_SCAN	= 37,
	/* 38..41: auth/assoc/deauth/disassoc */
	WL419_CONNECT		= 42,
	WL419_UPDATE_CONNECT_PARAMS = 43,
	WL419_DISCONNECT	= 44,
	WL419_JOIN_IBSS		= 45,
	WL419_LEAVE_IBSS	= 46,
	/* 47..50: mcast_rate/wiphy_params/tx_power */
	WL419_SET_WDS_PEER	= 51,	/* removed in 6.6, always NULL */
	WL419_RFKILL_POLL	= 52,
	/* 53,54: testmode (ifdef) */
	WL419_SET_BITRATE_MASK	= 53 + WL419_TM_COUNT,
	WL419_DUMP_SURVEY	= 54 + WL419_TM_COUNT,
	WL419_SET_PMKSA		= 55 + WL419_TM_COUNT,
	WL419_DEL_PMKSA		= 56 + WL419_TM_COUNT,
	WL419_FLUSH_PMKSA	= 57 + WL419_TM_COUNT,
	WL419_REMAIN_ON_CHANNEL	= 58 + WL419_TM_COUNT,
	WL419_CANCEL_REMAIN_ON_CHANNEL = 59 + WL419_TM_COUNT,
	WL419_MGMT_TX		= 60 + WL419_TM_COUNT,
	WL419_MGMT_TX_CANCEL_WAIT = 61 + WL419_TM_COUNT,
	WL419_SET_POWER_MGMT	= 62 + WL419_TM_COUNT,
	/* cqm */
	WL419_MGMT_FRAME_REGISTER = 66 + WL419_TM_COUNT,
	WL419_SET_ANTENNA	= 67 + WL419_TM_COUNT,
	WL419_GET_ANTENNA	= 68 + WL419_TM_COUNT,
	WL419_SCHED_SCAN_START	= 69 + WL419_TM_COUNT,
	WL419_SCHED_SCAN_STOP	= 70 + WL419_TM_COUNT,
	WL419_SET_REKEY_DATA	= 71 + WL419_TM_COUNT,
	WL419_TDLS_MGMT		= 72 + WL419_TM_COUNT,
	WL419_TDLS_OPER		= 73 + WL419_TM_COUNT,
	WL419_PROBE_CLIENT	= 74 + WL419_TM_COUNT,
	WL419_SET_NOACK_MAP	= 75 + WL419_TM_COUNT,
	WL419_GET_CHANNEL	= 76 + WL419_TM_COUNT,
	/* 79..89: p2p/mac_acl/radar/ft/crit/coalesce/csa/qos */
	WL419_SET_AP_CHANWIDTH	= 88 + WL419_TM_COUNT,
	/* 91..103: tx_ts/nan/mcast_ucast/txq/pmk */
	WL419_EXTERNAL_AUTH	= 102 + WL419_TM_COUNT,
	WL419_TX_CONTROL_PORT	= 103 + WL419_TM_COUNT,
};

/* 6.6 indices (struct cfg80211_ops @ 6.6 header line 4405, 124 pointers
 * with TESTMODE, 122 without). Bases are without-TESTMODE values.
 */
enum wl66_op_idx {
	WL66_ADD_KEY		= 8,
	WL66_GET_KEY		= 9,
	WL66_DEL_KEY		= 10,
	WL66_SET_DEFAULT_KEY	= 11,
	WL66_SET_DEFAULT_MGMT_KEY = 12,
	WL66_START_AP		= 14,
	WL66_CHANGE_BEACON	= 15,
	WL66_STOP_AP		= 16,
	WL66_CHANGE_BSS		= 35,
	WL66_SCAN		= 40,
	WL66_CONNECT		= 46,
	WL66_DISCONNECT		= 48,
	WL66_SET_PMKSA		= 58 + WL66_TM_COUNT,
	WL66_DEL_PMKSA		= 59 + WL66_TM_COUNT,
	WL66_UPDATE_MGMT_FRAME_REGS = 69 + WL66_TM_COUNT,
	WL66_SET_REKEY_DATA	= 74 + WL66_TM_COUNT,
	WL66_TDLS_MGMT		= 75 + WL66_TM_COUNT,
	WL66_GET_CHANNEL	= 79 + WL66_TM_COUNT,
	WL66_SET_AP_CHANWIDTH	= 91 + WL66_TM_COUNT,
	WL66_TX_CONTROL_PORT	= 106 + WL66_TM_COUNT,
};

/* ------------------------------------------------------------------ */
/* 4.19-layout mirrors of structures the blob touches.                 */
/* Source: 4.19.246 BCA cfg80211.h (line numbers in comments).         */
/* ------------------------------------------------------------------ */

/* 4.19 line 499: no vlan_id, no mode */
struct wl419_key_params {
	const u8 *key;
	const u8 *seq;
	int key_len;
	int seq_len;
	u32 cipher;
};

/* 4.19 line 789: no link_id, no lci/civicloc/mbssid/rnr/ftm/color */
struct wl419_beacon_data {
	const u8 *head, *tail;
	const u8 *beacon_ies;
	const u8 *proberesp_ies;
	const u8 *assocresp_ies;
	const u8 *probe_resp;
	size_t head_len, tail_len;
	size_t beacon_ies_len;
	size_t proberesp_ies_len;
	size_t assocresp_ies_len;
	size_t probe_resp_len;
};

/* 4.19 cfg80211_chan_def: no edmg, no freq1_offset */
struct wl419_chan_def {
	struct ieee80211_channel *chan;
	enum nl80211_chan_width width;
	u32 center_freq1;
	u32 center_freq2;
};

/* 4.19 line 826 bitrate mask entry: no he_mcs/he_gi/he_ltf */
struct wl419_bitrate_mask {
	struct {
		u32 legacy;
		u8 ht_mcs[IEEE80211_HT_MCS_MASK_LEN];
		u16 vht_mcs[NL80211_VHT_NSS_MAX];
		enum nl80211_txrate_gi gi;
	} control[WL419_NUM_BANDS];
};

/* 4.19 crypto settings: akm array is NL80211_MAX_NR_AKM_SUITES (2),
 * no control_port_no_preauth; BCA has psk; wep_keys points at 4.19 key_params.
 */
struct wl419_crypto_settings {
	u32 wpa_versions;
	u32 cipher_group;
	int n_ciphers_pairwise;
	u32 ciphers_pairwise[NL80211_MAX_NR_CIPHER_SUITES];
	int n_akm_suites;
	u32 akm_suites[NL80211_MAX_NR_AKM_SUITES];
	bool control_port;
	__be16 control_port_ethertype;
	bool control_port_no_encrypt;
	bool control_port_over_nl80211;
	struct wl419_key_params *wep_keys;
	int wep_tx_key;
	const u8 *psk;
};

/* 4.19 line 865 */
struct wl419_ap_settings {
	struct wl419_chan_def chandef;
	struct wl419_beacon_data beacon;
	int beacon_interval, dtim_period;
	const u8 *ssid;
	size_t ssid_len;
	enum nl80211_hidden_ssid hidden_ssid;
	struct wl419_crypto_settings crypto;
	bool privacy;
	enum nl80211_auth_type auth_type;
	enum nl80211_smps_mode smps_mode;
	int inactivity_timeout;
	u8 p2p_ctwindow;
	bool p2p_opp_ps;
	const struct cfg80211_acl_data *acl;
	bool pbss;
	struct wl419_bitrate_mask beacon_rate;
	const struct ieee80211_ht_cap *ht_cap;
	const struct ieee80211_vht_cap *vht_cap;
	bool ht_required, vht_required;
};

/* 4.19 line 1472: no link_id */
struct wl419_bss_params {
	int use_cts_prot;
	int use_short_preamble;
	int use_short_slot_time;
	const u8 *basic_rates;
	u8 basic_rates_len;
	int ap_isolate;
	int ht_opmode;
	s8 p2p_ctwindow, p2p_opp_ps;
};

/* 4.19 line 1002: has top-level supported_rates, no vlan_id/airtime/link */
struct wl419_station_params {
	const u8 *supported_rates;
	struct net_device *vlan;
	u32 sta_flags_mask, sta_flags_set;
	u32 sta_modify_mask;
	int listen_interval;
	u16 aid;
	u16 peer_aid;
	u8 supported_rates_len;
	u8 plink_action;
	u8 plink_state;
	const struct ieee80211_ht_cap *ht_capa;
	const struct ieee80211_vht_cap *vht_capa;
	u8 uapsd_queues;
	u8 max_sp;
	enum nl80211_mesh_power_mode local_pm;
	u16 capability;
	const u8 *ext_capab;
	u8 ext_capab_len;
	const u8 *supported_channels;
	u8 supported_channels_len;
	const u8 *supported_oper_classes;
	u8 supported_oper_classes_len;
	u8 opmode_notif;
	bool opmode_notif_used;
	int support_p2p_ps;
	const struct ieee80211_he_cap_elem *he_capa;
	u8 he_capa_len;
};

/* 4.19 line 1152 rate_info: flags/mcs are u8, no eht fields */
struct wl419_rate_info {
	u8 flags;
	u8 mcs;
	u16 legacy;
	u8 nss;
	u8 bw;
	u8 he_gi;
	u8 he_dcm;
	u8 he_ru_alloc;
};

/* 4.19 line 1304: no assoc_at; tx_duration/connected_to_gate/airtime/mlo
 * fields absent; rx_beacon/rx_duration/rx_beacon_signal_avg present.
 * sta_bss_parameters, nl80211_sta_flag_update, cfg80211_tid_stats are
 * layout-identical in 6.6 (verified field-by-field), reused natively.
 */
struct wl419_station_info {
	u64 filled;
	u32 connected_time;
	u32 inactive_time;
	u64 rx_bytes;
	u64 tx_bytes;
	u16 llid;
	u16 plid;
	u8 plink_state;
	s8 signal;
	s8 signal_avg;
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	s8 chain_signal_avg[IEEE80211_MAX_CHAINS];
	struct wl419_rate_info txrate;
	struct wl419_rate_info rxrate;
	u32 rx_packets;
	u32 tx_packets;
	u32 tx_retries;
	u32 tx_failed;
	u32 rx_dropped_misc;
	struct sta_bss_parameters bss_param;
	struct nl80211_sta_flag_update sta_flags;
	int generation;
	const u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	u32 beacon_loss_count;
	s64 t_offset;
	enum nl80211_mesh_power_mode local_pm;
	enum nl80211_mesh_power_mode peer_pm;
	enum nl80211_mesh_power_mode nonpeer_pm;
	u32 expected_throughput;
	u64 rx_beacon;
	u64 rx_duration;
	u8 rx_beacon_signal_avg;
	struct cfg80211_tid_stats *pertid;
	s8 ack_signal;
	s8 avg_ack_signal;
};

/* 4.19 line 1738 scan request: no scan_6ghz/scan_6ghz_params, channels[0] */
struct wl419_scan_request {
	struct cfg80211_ssid *ssids;
	int n_ssids;
	u32 n_channels;
	enum nl80211_bss_scan_width scan_width;
	const u8 *ie;
	size_t ie_len;
	u16 duration;
	bool duration_mandatory;
	u32 flags;
	u32 rates[WL419_NUM_BANDS];
	struct wireless_dev *wdev;
	u8 mac_addr[ETH_ALEN] __aligned(2);
	u8 mac_addr_mask[ETH_ALEN] __aligned(2);
	u8 bssid[ETH_ALEN] __aligned(2);
	struct wiphy *wiphy;
	unsigned long scan_start;
	struct cfg80211_scan_info info;
	bool notified;
	bool no_cck;
	struct ieee80211_channel *channels[0];
};

/* 4.19 line 2299 connect params: identical to 6.6 except trailing edmg */
struct wl419_connect_params {
	struct ieee80211_channel *channel;
	struct ieee80211_channel *channel_hint;
	const u8 *bssid;
	const u8 *bssid_hint;
	const u8 *ssid;
	size_t ssid_len;
	enum nl80211_auth_type auth_type;
	const u8 *ie;
	size_t ie_len;
	bool privacy;
	enum nl80211_mfp mfp;
	struct wl419_crypto_settings crypto;
	const u8 *key;
	u8 key_len, key_idx;
	u32 flags;
	int bg_scan_period;
	struct ieee80211_ht_cap ht_capa;
	struct ieee80211_ht_cap ht_capa_mask;
	struct ieee80211_vht_cap vht_capa;
	struct ieee80211_vht_cap vht_capa_mask;
	bool pbss;
	struct cfg80211_bss_selection bss_select;
	const u8 *prev_bssid;
	const u8 *fils_erp_username;
	size_t fils_erp_username_len;
	const u8 *fils_erp_realm;
	size_t fils_erp_realm_len;
	u16 fils_erp_next_seq_num;
	const u8 *fils_erp_rrk;
	size_t fils_erp_rrk_len;
	bool want_1x;
};

/* 4.19 line 2393 pmksa: identical to 6.6 except trailing lifetime fields */
struct wl419_pmksa {
	const u8 *bssid;
	const u8 *pmkid;
	const u8 *pmk;
	size_t pmk_len;
	const u8 *ssid;
	size_t ssid_len;
	const u8 *cache_id;
};

/* 4.19 line 2579 gtk rekey: identical to 6.6 except trailing akm/lengths */
struct wl419_gtk_rekey_data {
	const u8 *kek, *kck, *replay_ctr;
};

/* ------------------------------------------------------------------ */
/* Blob ops table: exact 4.19 layout (106 pointers). Lane E/H obtains  */
/* the raw table address from wl.ko (.data+0x3298 per cfg80211_ops_map */
/* or /proc/kallsyms) and passes it to cfg80211_compat_attach_blob().  */
/* Entries the blob leaves NULL stay NULL; every thunk null-checks.    */
/* ------------------------------------------------------------------ */
typedef void (*wl419_get_key_cb_t)(void *cookie, struct wl419_key_params *);

struct wl419_ops {
	int (*suspend)(struct wiphy *wiphy, struct cfg80211_wowlan *wow);
	int (*resume)(struct wiphy *wiphy);
	void (*set_wakeup)(struct wiphy *wiphy, bool enabled);
	struct wireless_dev *(*add_virtual_intf)(struct wiphy *wiphy,
						 const char *name,
						 unsigned char name_assign_type,
						 enum nl80211_iftype type,
						 struct vif_params *params);
	int (*del_virtual_intf)(struct wiphy *wiphy, struct wireless_dev *wdev);
	int (*change_virtual_intf)(struct wiphy *wiphy, struct net_device *dev,
				   enum nl80211_iftype type,
				   struct vif_params *params);
	int (*add_key)(struct wiphy *wiphy, struct net_device *netdev,
		       u8 key_index, bool pairwise, const u8 *mac_addr,
		       struct wl419_key_params *params);
	int (*get_key)(struct wiphy *wiphy, struct net_device *netdev,
		       u8 key_index, bool pairwise, const u8 *mac_addr,
		       void *cookie, wl419_get_key_cb_t callback);
	int (*del_key)(struct wiphy *wiphy, struct net_device *netdev,
		       u8 key_index, bool pairwise, const u8 *mac_addr);
	int (*set_default_key)(struct wiphy *wiphy, struct net_device *netdev,
			       u8 key_index, bool unicast, bool multicast);
	int (*set_default_mgmt_key)(struct wiphy *wiphy,
				    struct net_device *netdev, u8 key_index);
	int (*start_ap)(struct wiphy *wiphy, struct net_device *dev,
			struct wl419_ap_settings *settings);
	int (*change_beacon)(struct wiphy *wiphy, struct net_device *dev,
			     struct wl419_beacon_data *info);
	int (*stop_ap)(struct wiphy *wiphy, struct net_device *dev);
	int (*add_station)(struct wiphy *wiphy, struct net_device *dev,
			   const u8 *mac, struct wl419_station_params *params);
	int (*del_station)(struct wiphy *wiphy, struct net_device *dev,
			   struct station_del_parameters *params);
	int (*change_station)(struct wiphy *wiphy, struct net_device *dev,
			      const u8 *mac,
			      struct wl419_station_params *params);
	int (*get_station)(struct wiphy *wiphy, struct net_device *dev,
			   const u8 *mac, struct wl419_station_info *sinfo);
	int (*dump_station)(struct wiphy *wiphy, struct net_device *dev,
			    int idx, u8 *mac, struct wl419_station_info *sinfo);
	int (*add_mpath)(struct wiphy *wiphy, struct net_device *dev,
			 const u8 *dst, const u8 *next_hop);
	int (*del_mpath)(struct wiphy *wiphy, struct net_device *dev,
			 const u8 *dst);
	int (*change_mpath)(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *dst, const u8 *next_hop);
	int (*get_mpath)(struct wiphy *wiphy, struct net_device *dev,
			 u8 *dst, u8 *next_hop, struct mpath_info *pinfo);
	int (*dump_mpath)(struct wiphy *wiphy, struct net_device *dev,
			  int idx, u8 *dst, u8 *next_hop,
			  struct mpath_info *pinfo);
	int (*get_mpp)(struct wiphy *wiphy, struct net_device *dev,
		       u8 *dst, u8 *mpp, struct mpath_info *pinfo);
	int (*dump_mpp)(struct wiphy *wiphy, struct net_device *dev,
			int idx, u8 *dst, u8 *mpp, struct mpath_info *pinfo);
	int (*get_mesh_config)(struct wiphy *wiphy, struct net_device *dev,
			       struct mesh_config *conf);
	int (*update_mesh_config)(struct wiphy *wiphy, struct net_device *dev,
				  u32 mask, const struct mesh_config *nconf);
	int (*join_mesh)(struct wiphy *wiphy, struct net_device *dev,
			 const struct mesh_config *conf,
			 const struct mesh_setup *setup);
	int (*leave_mesh)(struct wiphy *wiphy, struct net_device *dev);
	int (*join_ocb)(struct wiphy *wiphy, struct net_device *dev,
			struct ocb_setup *setup);
	int (*leave_ocb)(struct wiphy *wiphy, struct net_device *dev);
	int (*change_bss)(struct wiphy *wiphy, struct net_device *dev,
			  struct wl419_bss_params *params);
	int (*set_txq_params)(struct wiphy *wiphy, struct net_device *dev,
			      struct ieee80211_txq_params *params);
	int (*libertas_set_mesh_channel)(struct wiphy *wiphy,
					 struct net_device *dev,
					 struct ieee80211_channel *chan);
	int (*set_monitor_channel)(struct wiphy *wiphy,
				   struct cfg80211_chan_def *chandef);
	int (*scan)(struct wiphy *wiphy, struct wl419_scan_request *request);
	void (*abort_scan)(struct wiphy *wiphy, struct wireless_dev *wdev);
	int (*auth)(struct wiphy *wiphy, struct net_device *dev,
		    struct cfg80211_auth_request *req);
	int (*assoc)(struct wiphy *wiphy, struct net_device *dev,
		     struct cfg80211_assoc_request *req);
	int (*deauth)(struct wiphy *wiphy, struct net_device *dev,
		      struct cfg80211_deauth_request *req);
	int (*disassoc)(struct wiphy *wiphy, struct net_device *dev,
			struct cfg80211_disassoc_request *req);
	int (*connect)(struct wiphy *wiphy, struct net_device *dev,
		       struct wl419_connect_params *sme);
	int (*update_connect_params)(struct wiphy *wiphy,
				     struct net_device *dev,
				     struct wl419_connect_params *sme,
				     u32 changed);
	int (*disconnect)(struct wiphy *wiphy, struct net_device *dev,
			  u16 reason_code);
	int (*join_ibss)(struct wiphy *wiphy, struct net_device *dev,
			 struct cfg80211_ibss_params *params);
	int (*leave_ibss)(struct wiphy *wiphy, struct net_device *dev);
	int (*set_mcast_rate)(struct wiphy *wiphy, struct net_device *dev,
			      int rate[WL419_NUM_BANDS]);
	int (*set_wiphy_params)(struct wiphy *wiphy, u32 changed);
	int (*set_tx_power)(struct wiphy *wiphy, struct wireless_dev *wdev,
			    enum nl80211_tx_power_setting type, int mbm);
	int (*get_tx_power)(struct wiphy *wiphy, struct wireless_dev *wdev,
			    int *dbm);
	int (*set_wds_peer)(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *addr);
	void (*rfkill_poll)(struct wiphy *wiphy);
	int (*testmode_cmd)(struct wiphy *wiphy, struct wireless_dev *wdev,
			    void *data, int len);
	int (*testmode_dump)(struct wiphy *wiphy, struct sk_buff *skb,
			     struct netlink_callback *cb, void *data, int len);
	int (*set_bitrate_mask)(struct wiphy *wiphy, struct net_device *dev,
				const u8 *peer,
				const struct wl419_bitrate_mask *mask);
	int (*dump_survey)(struct wiphy *wiphy, struct net_device *netdev,
			   int idx, struct survey_info *info);
	int (*set_pmksa)(struct wiphy *wiphy, struct net_device *netdev,
			 struct wl419_pmksa *pmksa);
	int (*del_pmksa)(struct wiphy *wiphy, struct net_device *netdev,
			 struct wl419_pmksa *pmksa);
	int (*flush_pmksa)(struct wiphy *wiphy, struct net_device *netdev);
	int (*remain_on_channel)(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 struct ieee80211_channel *chan,
				 unsigned int duration, u64 *cookie);
	int (*cancel_remain_on_channel)(struct wiphy *wiphy,
					struct wireless_dev *wdev, u64 cookie);
	int (*mgmt_tx)(struct wiphy *wiphy, struct wireless_dev *wdev,
		       struct cfg80211_mgmt_tx_params *params, u64 *cookie);
	int (*mgmt_tx_cancel_wait)(struct wiphy *wiphy,
				   struct wireless_dev *wdev, u64 cookie);
	int (*set_power_mgmt)(struct wiphy *wiphy, struct net_device *dev,
			      bool enabled, int timeout);
	int (*set_cqm_rssi_config)(struct wiphy *wiphy, struct net_device *dev,
				   s32 rssi_thold, u32 rssi_hyst);
	int (*set_cqm_rssi_range_config)(struct wiphy *wiphy,
					 struct net_device *dev,
					 s32 rssi_low, s32 rssi_high);
	int (*set_cqm_txe_config)(struct wiphy *wiphy, struct net_device *dev,
				  u32 rate, u32 pkts, u32 intvl);
	void (*mgmt_frame_register)(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    u16 frame_type, bool reg);
	int (*set_antenna)(struct wiphy *wiphy, u32 tx_ant, u32 rx_ant);
	int (*get_antenna)(struct wiphy *wiphy, u32 *tx_ant, u32 *rx_ant);
	int (*sched_scan_start)(struct wiphy *wiphy, struct net_device *dev,
				struct cfg80211_sched_scan_request *request);
	int (*sched_scan_stop)(struct wiphy *wiphy, struct net_device *dev,
			       u64 reqid);
	int (*set_rekey_data)(struct wiphy *wiphy, struct net_device *dev,
			      struct wl419_gtk_rekey_data *data);
	int (*tdls_mgmt)(struct wiphy *wiphy, struct net_device *dev,
			 const u8 *peer, u8 action_code, u8 dialog_token,
			 u16 status_code, u32 peer_capability, bool initiator,
			 const u8 *buf, size_t len);
	int (*tdls_oper)(struct wiphy *wiphy, struct net_device *dev,
			 const u8 *peer, enum nl80211_tdls_operation oper);
	int (*probe_client)(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *peer, u64 *cookie);
	int (*set_noack_map)(struct wiphy *wiphy, struct net_device *dev,
			     u16 noack_map);
	int (*get_channel)(struct wiphy *wiphy, struct wireless_dev *wdev,
			   struct wl419_chan_def *chandef);
	int (*start_p2p_device)(struct wiphy *wiphy, struct wireless_dev *wdev);
	void (*stop_p2p_device)(struct wiphy *wiphy, struct wireless_dev *wdev);
	int (*set_mac_acl)(struct wiphy *wiphy, struct net_device *dev,
			   const struct cfg80211_acl_data *params);
	int (*start_radar_detection)(struct wiphy *wiphy,
				     struct net_device *dev,
				     struct cfg80211_chan_def *chandef,
				     u32 cac_time_ms);
	void (*end_cac)(struct wiphy *wiphy, struct net_device *dev);
	int (*update_ft_ies)(struct wiphy *wiphy, struct net_device *dev,
			     struct cfg80211_update_ft_ies_params *ftie);
	int (*crit_proto_start)(struct wiphy *wiphy, struct wireless_dev *wdev,
				enum nl80211_crit_proto_id protocol,
				u16 duration);
	void (*crit_proto_stop)(struct wiphy *wiphy, struct wireless_dev *wdev);
	int (*set_coalesce)(struct wiphy *wiphy,
			    struct cfg80211_coalesce *coalesce);
	int (*channel_switch)(struct wiphy *wiphy, struct net_device *dev,
			      struct cfg80211_csa_settings *params);
	int (*set_qos_map)(struct wiphy *wiphy, struct net_device *dev,
			   struct cfg80211_qos_map *qos_map);
	int (*set_ap_chanwidth)(struct wiphy *wiphy, struct net_device *dev,
				struct wl419_chan_def *chandef);
	int (*add_tx_ts)(struct wiphy *wiphy, struct net_device *dev,
			 u8 tsid, const u8 *peer, u8 user_prio,
			 u16 admitted_time);
	int (*del_tx_ts)(struct wiphy *wiphy, struct net_device *dev,
			 u8 tsid, const u8 *peer);
	int (*tdls_channel_switch)(struct wiphy *wiphy, struct net_device *dev,
				   const u8 *addr, u8 oper_class,
				   struct cfg80211_chan_def *chandef);
	void (*tdls_cancel_channel_switch)(struct wiphy *wiphy,
					   struct net_device *dev,
					   const u8 *addr);
	int (*start_nan)(struct wiphy *wiphy, struct wireless_dev *wdev,
			 struct cfg80211_nan_conf *conf);
	void (*stop_nan)(struct wiphy *wiphy, struct wireless_dev *wdev);
	int (*add_nan_func)(struct wiphy *wiphy, struct wireless_dev *wdev,
			    struct cfg80211_nan_func *nan_func);
	void (*del_nan_func)(struct wiphy *wiphy, struct wireless_dev *wdev,
			     u64 cookie);
	int (*nan_change_conf)(struct wiphy *wiphy, struct wireless_dev *wdev,
			       struct cfg80211_nan_conf *conf, u32 changes);
	int (*set_multicast_to_unicast)(struct wiphy *wiphy,
					struct net_device *dev,
					const bool enabled);
	int (*get_txq_stats)(struct wiphy *wiphy, struct wireless_dev *wdev,
			     struct cfg80211_txq_stats *txqstats);
	int (*set_pmk)(struct wiphy *wiphy, struct net_device *dev,
		       const struct cfg80211_pmk_conf *conf);
	int (*del_pmk)(struct wiphy *wiphy, struct net_device *dev,
		       const u8 *aa);
	int (*external_auth)(struct wiphy *wiphy, struct net_device *dev,
			     struct cfg80211_external_auth_params *params);
	int (*tx_control_port)(struct wiphy *wiphy, struct net_device *dev,
			       const u8 *buf, size_t len,
			       const u8 *dest, const __be16 proto,
			       const bool noencrypt);
};

/* ------------------------------------------------------------------ */
/* Public API of this module (plain EXPORT_SYMBOL, never _GPL: the     */
/* proprietary blob must resolve them).                                */
/* ------------------------------------------------------------------ */

/* 6.6-layout ops table for wiphy_new(): every entry is our thunk. */
extern const struct cfg80211_ops wl_66_ops;

/*
 * Attach/detach the blob's raw 4.19 ops table.
 * Must be called before wl.ko registers its wiphy (attach) and is
 * meaningful only while wl.ko is loaded. Lane E/H integration point:
 * address = wl.ko .data section base + 0x3298 (see cfg80211_ops_map.txt).
 */
void cfg80211_compat_attach_blob(const struct wl419_ops *blob_ops);
void cfg80211_compat_detach_blob(void);

/*
 * Scan translation registry (async path). wl66_scan() allocates a
 * 4.19-layout copy and registers (orig66 -> copy419). Lane C's
 * cfg80211_scan_done wrapper must call cfg80211_compat_scan_lookup()
 * to map the blob's pointer back, then cfg80211_compat_scan_done()
 * to release the copy after reporting the *original* request.
 */
int cfg80211_compat_scan_register(struct cfg80211_scan_request *orig66,
				  struct wl419_scan_request *copy419);
struct cfg80211_scan_request *
cfg80211_compat_scan_lookup(const struct wl419_scan_request *copy419);
void cfg80211_compat_scan_done(const struct wl419_scan_request *copy419);

/* Structure converters (also used by unit checks / lane C). */
void wl_shim_key_66_to_19(const struct key_params *src,
			   struct wl419_key_params *dst);
void wl_shim_beacon_66_to_19(const struct cfg80211_beacon_data *src,
			     struct wl419_beacon_data *dst);
void wl_shim_chandef_66_to_19(const struct cfg80211_chan_def *src,
			      struct wl419_chan_def *dst);
void wl_shim_bss_66_to_19(const struct bss_parameters *src,
			   struct wl419_bss_params *dst);
void wl_shim_station_params_66_to_19(const struct station_parameters *src,
				     struct wl419_station_params *dst);
void wl_shim_station_info_19_to_66(const struct wl419_station_info *src,
				   struct station_info *dst);
void wl_shim_rate_19_to_66(const struct wl419_rate_info *src,
			    struct rate_info *dst);

/*
 * Event-emit ownership helpers (cfg80211_new_sta / del_sta_sinfo chain).
 *
 * wl_shim_station_info_19_to_66() above leaves assoc_req_ies BORROWED from
 * the blob (the 6.6 core copies the bytes synchronously into its nlmsg and
 * never retains the pointer) and hands pertid to the core (the core frees
 * it via cfg80211_sinfo_release_content()). The helpers below close the
 * remaining lifetime gaps; the emit pattern for the --cfgevents wrappers
 * (shim_cfg_events.c, owned by another lane) is:
 *
 *	struct station_info native;
 *	struct wl_sinfo_owned tok;
 *
 *	wl_shim_station_info_19_to_66(info419, &native);
 *	if (wl_shim_sinfo_own_ies(&native, gfp, &tok))
 *		return; // -ENOMEM, nothing owned, nothing to release
 *	dev = wl_shim_sta_emit_dev(shim_netdev_native(old), "new_sta");
 *	if (dev)
 *		cfg80211_new_sta(dev, mac, &native, gfp);
 *	// core consumed (and freed) native.pertid; IEs stay ours:
 *	wl_shim_sinfo_disown_ies(&native, &tok);
 *
 * If the emit is skipped (unknown dev, OOM before emit), the caller must
 * ALSO call wl_shim_sinfo_release_pertid(&native): on the emit path the
 * core owns pertid, on the drop path the shim does.
 */
struct wl_sinfo_owned {
	const u8 *borrowed_ies;
	u8 *owned_ies;
};

/* Duplicate dst->assoc_req_ies (validated/clamped by the converter) into a
 * shim-owned buffer and repoint dst at it. gfp is the emitter's context
 * (usually the blob's translated GFP). Returns 0 with tok armed, or
 * -ENOMEM leaving dst BORROWED (tok.owned NULL, still synchronously
 * emittable) — never a half-owned state. NULL-safe, no-op when empty. */
int wl_shim_sinfo_own_ies(struct station_info *dst, gfp_t gfp,
			  struct wl_sinfo_owned *tok);
/* Undo own_ies: free the owned copy (if any) and restore the borrowed
 * pointer. NULL-safe, idempotent for a consumed tok. */
void wl_shim_sinfo_disown_ies(struct station_info *dst,
			      struct wl_sinfo_owned *tok);
/* Free a converter-duplicated pertid on NON-emit paths (drop/error legs,
 * selftest). Must NOT be called after the struct was handed to the core:
 * the core already freed it. NULL-safe. */
void wl_shim_sinfo_release_pertid(struct station_info *dst);

/*
 * Emit-step object check for the wl_event -> wl_cfg80211_event ->
 * cfg80211_new_sta chain: the native netdev must carry a native wdev bound
 * to a shim-registered wiphy, otherwise cfg80211_new_sta() would follow
 * dev->ieee80211_ptr->wiphy into NULL/foreign memory (same Oops class as
 * the H30 P0 dev_get_by_name crash). Returns dev or NULL with a
 * pr_warn_once identifying the failed step. Borrowed pointer, no ref taken.
 */
struct net_device *wl_shim_sta_emit_dev(struct net_device *dev,
					const char *who);

#endif /* _CFG80211_COMPAT_H_ */
