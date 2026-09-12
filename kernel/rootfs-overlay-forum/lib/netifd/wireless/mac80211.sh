#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Cudy WR3600 (BCM6764): netifd wireless driver for the stock Broadcom wl.ko
# blob running behind bcm_shim. The radios are plain cfg80211 devices (wl0 =
# phy0 = 5 GHz, wl1 = phy1 = 2.4 GHz), NOT mac80211, so OpenWrt's stock
# mac80211.sh (wifi-scripts) does not fit: no interface creation through
# nl80211, no `iw phy` capability parsing, no ACS, one AP per radio.
#
# This file REPLACES /lib/netifd/wireless/mac80211.sh from wifi-scripts and
# keeps the driver name "mac80211" on purpose: LuCI's wireless page only shows
# the WPA2/WPA3 encryption list for that type (view/network/wireless.js gates
# it on hwtype == 'mac80211').
#
# What it does per radio: builds /var/run/hostapd-<phy>.conf with the standard
# helpers from hostapd.sh (ssid/key/encryption/... from /etc/config/wireless),
# asks the blob for the channel width through its own ioctl interface
# (/usr/sbin/wl66-chan, see there), starts one hostapd per radio and puts the
# interface into the LAN bridge (br-lan is created by /etc/init.d/wifi66, it
# is not a netifd interface yet).
#
# HARD RULE (bench 2026-09-09 and 2026-09-12): a hostapd whose AP is really up
# must never be stopped while the system keeps running - the blob's stop_ap
# hangs the whole SoC (no log, watchdog only). Only a reboot may end it (the
# kernel arms the watchdog in its reboot notifier). Therefore hostapd is NOT
# handed to netifd as a managed process (netifd would kill it on teardown),
# teardown leaves it alone, and a changed configuration is applied by
# rebooting. "wifi reload" with an unchanged config just re-adopts the
# running hostapd.
. /lib/netifd/netifd-wireless.sh
. /lib/netifd/hostapd.sh

init_wireless_driver "$@"

drv_mac80211_init_device_config() {
	hostapd_common_add_device_config
	config_add_string path phy 'macaddr:macaddr'
	config_add_int beacon_int txpower
}

drv_mac80211_init_iface_config() {
	hostapd_common_add_bss_config
	config_add_string 'macaddr:macaddr' ifname
	config_add_int dtim_period max_listen_int
}

drv_mac80211_init_vlan_config() {
	:
}

drv_mac80211_init_station_config() {
	:
}

# netdev of a wiphy: /sys/class/net/<if>/phy80211 -> .../ieee80211/<phy>
wl66_phy_ifname() {
	local d
	for d in /sys/class/net/*/phy80211; do
		[ -e "$d" ] || continue
		[ "$(basename "$(readlink -f "$d")")" = "$1" ] || continue
		basename "$(dirname "$d")"
		return 0
	done
	return 1
}

wl66_log() {
	logger -t wl66 "$*"
	echo "wl66: $*" > /dev/kmsg 2>/dev/null
}

wl66_setup_ap() {
	local name="$1"

	if [ -n "$ap_ifname" ]; then
		wl66_log "$phy: only one AP per radio is supported, skipping $name"
		wireless_setup_vif_failed ONE_AP_PER_RADIO
		return 1
	fi
	json_select config
	json_get_vars ifname dtim_period max_listen_int
	[ -n "$ifname" ] || ifname="$(wl66_phy_ifname "$phy")"
	[ -n "$ifname" ] || {
		json_select ..
		wireless_setup_vif_failed NO_IFNAME
		return 1
	}
	hostapd_cfg=
	append hostapd_cfg "interface=$ifname" "$N"
	hostapd_set_bss_options hostapd_cfg "$phy" "$name" || {
		json_select ..
		wireless_setup_vif_failed HOSTAPD_CONFIG
		return 1
	}
	json_select ..
	cat >> "$hostapd_conf_file" <<EOF
$hostapd_cfg
${dtim_period:+dtim_period=$dtim_period}
${max_listen_int:+max_listen_interval=$max_listen_int}
EOF
	# the blob has no cfg80211 set_qos_map: hostapd aborts the whole BSS
	# setup on it ("Failed to initialize QoS Map", bench 2026-09-12)
	sed -i '/^qos_map_set=/d' "$hostapd_conf_file"
	ap_ifname="$ifname"
	wireless_add_vif "$name" "$ifname"
}

drv_mac80211_setup() {
	json_select config
	json_get_vars phy htmode txpower
	json_select ..

	[ -n "$phy" ] && [ -d "/sys/class/ieee80211/$phy" ] || {
		wl66_log "radio $phy: no such wiphy"
		wireless_set_retry 0
		return 1
	}
	# $channel $band $hwmode $auto_channel come from _wdev_prepare_channel.
	# The blob path has no ACS: "auto" falls back to a fixed default.
	[ "$auto_channel" -gt 0 ] && {
		[ "$band" = 5g ] && channel=36 || channel=1
		auto_channel=0
		wl66_log "radio $phy: no ACS, using channel $channel"
	}

	hostapd_conf_file="/var/run/hostapd-$phy.conf"
	json_select config
	hostapd_prepare_device_config "$hostapd_conf_file" nl80211
	json_select ..
	# hostapd only authenticates here: the blob builds its own HT/VHT/HE
	# elements and takes the width from bw_cap/chanspec (wl66-chan), so the
	# hostapd side stays at the legacy 20 MHz definition that is known to
	# work with the shim (cfg80211 would reject wider chandefs anyway: the
	# blob's wiphy advertises no HT/VHT capabilities).
	# the marker line makes width changes visible to the "unchanged?" check
	# below (the width is applied by wl66-chan, not by hostapd)
	cat >> "$hostapd_conf_file" <<EOF
channel=$channel
ieee80211n=0
# wl66: band=$band htmode=$htmode channel=$channel txpower=$txpower
EOF

	wireless_set_data phy="$phy"
	ap_ifname=
	for_each_interface "ap" wl66_setup_ap
	[ -n "$ap_ifname" ] || {
		wireless_setup_failed NO_AP
		return 1
	}

	# A hostapd from before this setup (boot, or "wifi reload")? Re-adopt it
	# if the configuration did not change; otherwise the change needs a
	# reboot (see the header). The pidfile survives teardown on purpose.
	local pidf="/var/run/wifi-$phy.pid" prev="/var/run/hostapd-$phy.conf.running" opid i=0
	opid="$(cat "$pidf" 2>/dev/null)"
	if [ -n "$opid" ] && [ -d "/proc/$opid" ]; then
		if [ -f "$prev" ] && cmp -s "$prev" "$hostapd_conf_file"; then
			wl66_log "radio $phy: configuration unchanged, keeping hostapd $opid"
			ip link set "$ap_ifname" master br-lan 2>/dev/null
			wireless_set_up
			return 0
		fi
		wl66_log "radio $phy: wireless configuration changed - the blob cannot restart an AP in place, rebooting in 5 s to apply it"
		cp "$hostapd_conf_file" "$prev.pending" 2>/dev/null
		[ -e /tmp/.wl66-reboot ] || {
			touch /tmp/.wl66-reboot
			( sleep 5; reboot ) >/dev/null 2>&1 </dev/null &
		}
		wireless_set_up
		return 0
	fi

	# No hostapd yet (fresh boot). Do NOT set the link down here and do not
	# enslave the interface before hostapd: with either the blob's start_ap
	# failed ("ADD/SET beacon failed", bench 2026-09-12).
	[ -x /usr/sbin/wl66-chan ] && \
		/usr/sbin/wl66-chan "$ap_ifname" "$band" "$channel" "$htmode" pre

	rm -f "$pidf"
	/usr/sbin/hostapd -s -P "$pidf" -B "$hostapd_conf_file" || {
		wl66_log "radio $phy: hostapd failed to start ($hostapd_conf_file)"
		wireless_setup_failed HOSTAPD_START_FAILED
		return 1
	}
	while [ ! -s "$pidf" ] && [ $i -lt 5 ]; do sleep 1; i=$((i + 1)); done
	[ -s "$pidf" ] || {
		wireless_setup_failed HOSTAPD_START_FAILED
		return 1
	}
	cp "$hostapd_conf_file" "$prev"
	# not registered with netifd on purpose (see the header)

	# LAN bridge (see the header) and the operating channel width
	ip link set "$ap_ifname" master br-lan 2>/dev/null
	[ -x /usr/sbin/wl66-chan ] && \
		/usr/sbin/wl66-chan "$ap_ifname" "$band" "$channel" "$htmode" post
	[ -n "$txpower" ] && iw dev "$ap_ifname" set txpower fixed "$((txpower * 100))" 2>/dev/null

	wl66_log "radio $phy up: $ap_ifname channel $channel $htmode"
	wireless_set_up
}

drv_mac80211_teardown() {
	# Nothing is torn down (see the header): hostapd keeps running, the
	# interface stays up and bridged. Setup decides between re-adopting it
	# and rebooting.
	json_select data
	json_get_vars phy
	json_select ..
	wl66_log "radio $phy: teardown requested, AP left running (changes apply on reboot)"
}

drv_mac80211_cleanup() {
	:
}

add_driver mac80211
