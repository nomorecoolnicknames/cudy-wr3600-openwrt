// SPDX-License-Identifier: GPL-2.0-only
/* 4.19 -> 6.6 event boundaries. Scalar prototypes below match both local
 * include/net/cfg80211.h headers. Device/channel identity does not: resolve
 * every borrowed object before entering cfg80211. Station info is copied
 * synchronously; cfg80211_new/del_sta do not retain the supplied structure. */
#include <linux/module.h>
#include <net/cfg80211.h>
#include "cfg80211_compat.h"
#include "shim_netdev.h"
#include "shim_wiphy.h"
#include "shim_gfp.h"

void bcm419_cfg80211_new_sta(struct netdev419_view *old, const u8 *mac,
		struct wl419_station_info *info, unsigned int gfp)
{
	struct net_device *raw = shim_netdev_native(old);
	struct net_device *dev;
	struct station_info native;
	struct wl_sinfo_owned tok;
	gfp_t ngfp = shim_gfp419(gfp);

	if (!raw || !info || !mac)
		return;
	wl_shim_station_info_19_to_66(info, &native);
	if (wl_shim_sinfo_own_ies(&native, ngfp, &tok)) {
		/* IE copy OOM: event dropped, converter pertid still ours. */
		wl_shim_sinfo_release_pertid(&native);
		return;
	}
	dev = wl_shim_sta_emit_dev(raw, "new_sta");
	if (!dev) {
		/* Gate refused: IEs stay ours, converter pertid still ours. */
		wl_shim_sinfo_disown_ies(&native, &tok);
		wl_shim_sinfo_release_pertid(&native);
		return;
	}
	cfg80211_new_sta(dev, mac, &native, ngfp);
	/* Core consumed (and freed) native.pertid; IEs stay ours. */
	wl_shim_sinfo_disown_ies(&native, &tok);
}
EXPORT_SYMBOL(bcm419_cfg80211_new_sta);

void bcm419_cfg80211_del_sta_sinfo(struct netdev419_view *old, const u8 *mac,
		struct wl419_station_info *info, unsigned int gfp)
{
	struct net_device *raw = shim_netdev_native(old);
	struct net_device *dev;
	struct station_info native;
	struct wl_sinfo_owned tok;
	gfp_t ngfp = shim_gfp419(gfp);

	if (!raw || !mac)
		return;
	dev = wl_shim_sta_emit_dev(raw, "del_sta");
	if (!dev)
		return;
	if (!info) {
		/* NULL sinfo leg still derefs dev->ieee80211_ptr->wiphy
		 * inside cfg80211_del_sta_sinfo (nl80211.c), hence gated. */
		cfg80211_del_sta_sinfo(dev, mac, NULL, ngfp);
		return;
	}
	wl_shim_station_info_19_to_66(info, &native);
	if (wl_shim_sinfo_own_ies(&native, ngfp, &tok)) {
		/* IE copy OOM: event dropped, converter pertid still ours. */
		wl_shim_sinfo_release_pertid(&native);
		return;
	}
	cfg80211_del_sta_sinfo(dev, mac, &native, ngfp);
	/* Core consumed (and freed) native.pertid; IEs stay ours. */
	wl_shim_sinfo_disown_ies(&native, &tok);
}
EXPORT_SYMBOL(bcm419_cfg80211_del_sta_sinfo);

void bcm419_cfg80211_disconnected(struct netdev419_view *old, u16 reason,
		const u8 *ie, size_t len, bool local, unsigned int gfp)
{
	struct net_device *dev = shim_netdev_native(old);

	if (dev)
		cfg80211_disconnected(dev, reason, ie, len, local, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_disconnected);

void bcm419_cfg80211_ready_on_channel(struct wdev419_view *old, u64 cookie,
		struct ieee80211_channel *channel, unsigned int duration,
		unsigned int gfp)
{
	struct wireless_dev *wdev = shim_wdev_native(old);
	struct ieee80211_channel *native = shim_channel_native(channel);

	if (wdev && native)
		cfg80211_ready_on_channel(wdev, cookie, native, duration, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_ready_on_channel);

void bcm419_cfg80211_remain_on_channel_expired(struct wdev419_view *old,
		u64 cookie, struct ieee80211_channel *channel, unsigned int gfp)
{
	struct wireless_dev *wdev = shim_wdev_native(old);
	struct ieee80211_channel *native = shim_channel_native(channel);

	if (wdev && native)
		cfg80211_remain_on_channel_expired(wdev, cookie, native, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_remain_on_channel_expired);

void bcm419_cfg80211_ibss_joined(struct netdev419_view *old, const u8 *bssid,
		struct ieee80211_channel *channel, unsigned int gfp)
{
	struct net_device *dev = shim_netdev_native(old);
	struct ieee80211_channel *native = shim_channel_native(channel);

	if (dev && native)
		cfg80211_ibss_joined(dev, bssid, native, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_ibss_joined);

void bcm419_cfg80211_cqm_rssi_notify(struct netdev419_view *old,
		enum nl80211_cqm_rssi_threshold_event event, s32 level, unsigned int gfp)
{
	struct net_device *dev = shim_netdev_native(old);

	if (dev)
		cfg80211_cqm_rssi_notify(dev, event, level, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_cqm_rssi_notify);

void bcm419_cfg80211_michael_mic_failure(struct netdev419_view *old,
		const u8 *addr, enum nl80211_key_type type, int id,
		const u8 *tsc, unsigned int gfp)
{
	struct net_device *dev = shim_netdev_native(old);

	if (dev)
		cfg80211_michael_mic_failure(dev, addr, type, id, tsc, shim_gfp419(gfp));
}
EXPORT_SYMBOL(bcm419_cfg80211_michael_mic_failure);
