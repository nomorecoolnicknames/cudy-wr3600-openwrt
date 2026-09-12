#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Cudy WR3600 (BCM6764) platform hooks for sysupgrade / LuCI "Flash firmware".
#
# The image is a tar with the two volumes and their checksums; the upgrade
# writes the slot the router is NOT running from, verifies it, commits it and
# reboots (update-from-release.sh). The running system is never touched, so
# pulling the plug during an upgrade leaves a bootable router.
#
# "Keep settings" is implicit here: configuration lives in the persistent
# overlay volume, which the upgrade leaves alone. sysupgrade -n (no backup
# archive, UPGRADE_BACKUP empty) wipes it, which is what a factory reset
# should do.

CUDY_VOL_NAME=cudy66_data

# sysupgrade's stage2 pivots into a ramfs and copies ONLY what is listed here
# (plus busybox and a fixed applet list, see /lib/upgrade/stage2). Without
# these the updater, ubiwrite and the slot metadata blobs are simply absent
# in stage2 - found while reviewing the first draft of this file.
RAMFS_COPY_BIN="/usr/bin/ubiwrite /usr/bin/ubimkvol sha256sum head"
RAMFS_COPY_DATA="/usr/bin/update-from-release.sh /usr/share/cudy/meta-committed1.bin /usr/share/cudy/meta-committed2.bin "

cudy_vol_dev() {
	local v
	for v in /sys/class/ubi/ubi*_*; do
		[ -f "$v/name" ] || continue
		[ "$(cat "$v/name" 2>/dev/null)" = "$CUDY_VOL_NAME" ] || continue
		echo "/dev/$(basename "$v")"
		return 0
	done
	return 1
}

# sysupgrade's stage2 starts with kill_remaining (SIGTERM to everything).
# A hostapd whose AP is up then runs the blob's stop_ap, which hangs the SoC
# (bench 2026-09-09/12). Two guards, both from stage1 where the running system
# is still whole: (1) a watchdog deadline a few minutes ahead, so a hang
# resets the router into the slot it runs from instead of needing a power
# cycle; (2) hostapd is ended with SIGKILL first - the process dies without
# running its deinit path, the AP keeps beaconing without an authenticator
# until the reboot. Skipped for "sysupgrade --test" (TEST=1 in that shell).
cudy_prepare_for_stage2() {
	local now
	# only from the real sysupgrade run: COMMAND is set by /sbin/sysupgrade,
	# TEST=1 there means --test; LuCI's validate_firmware_image has neither
	[ -n "$COMMAND" ] && [ "${TEST:-0}" != 1 ] || return 0
	now=$(cut -d. -f1 /proc/uptime)
	echo $((now + 420)) > /proc/bcm96764_wdt_kick_secs 2>/dev/null
	logger -t sysupgrade "cudy: watchdog deadline armed (+420 s), ending hostapd with SIGKILL before stage2"
	killall -9 hostapd 2>/dev/null
	return 0
}

platform_check_image() {
	local file="$1"

	[ "$#" -gt 1 ] && return 1
	[ -f "$file" ] || { echo "no such file: $file"; return 1; }

	tar -tf "$file" 2>/dev/null | grep -qx 'bootfs-release.itb' || {
		echo "this does not look like a Cudy WR3600 image"; return 1; }
	tar -tf "$file" 2>/dev/null | grep -qx 'rootfs-forum.sq' || {
		echo "the image has no rootfs-forum.sq"; return 1; }
	cudy_prepare_for_stage2
	return 0
}

platform_do_upgrade() {
	local file="$1" dir=/tmp/cudy-sysupgrade dev

	rm -rf "$dir"
	mkdir -p "$dir" || return 1
	tar -xf "$file" -C "$dir" || { echo "cannot unpack $file"; return 1; }
	( cd "$dir" && sha256sum -c SHA256SUMS ) || {
		echo "image checksum mismatch - refusing to flash"; return 1; }

	# "Keep settings" reaches stage2 only as UPGRADE_BACKUP (the backup
	# archive procd was given); with sysupgrade -n it is empty and
	# SAVE_CONFIG is not exported at all (checked in 24.10.2 stage2/do_stage2).
	if [ -z "$UPGRADE_BACKUP" ]; then
		dev="$(cudy_vol_dev)" && {
			echo "wiping saved settings ($dev)"
			# stage2 has lazily unmounted /overlay; the volume stays busy
			# until the last reference to the old root is gone, which can
			# take a moment (the same window in which OpenWrt's NAND path
			# runs ubirmvol). Insist for a while, then say so and go on -
			# the settings are then simply kept, and "firstboot -y" clears
			# them from the running system.
			umount /overlay 2>/dev/null
			i=0
			until /usr/bin/ubiwrite --wipe "$dev"; do
				i=$((i + 1))
				[ "$i" -lt 15 ] || {
					echo "WARNING: could not wipe $dev, settings are kept"
					break
				}
				sleep 1
			done
		}
	fi

	# Writes the other slot, verifies it and commits it. FORCE=1 because an
	# explicit sysupgrade is meant to overwrite whatever is in that slot (the
	# updater otherwise refuses to clobber a foreign rootfs, which is what
	# protects the factory firmware in the manual path - so the FIRST
	# sysupgrade replaces the factory firmware in the other slot; the docs say
	# so). UPD66_DETACHED=1: no background copy here - do_stage2 reboots the
	# moment this function returns, so the write must happen inline. REBOOT=no:
	# do_stage2 does the reboot itself.
	UPD66_DETACHED=1 FORCE=1 REBOOT=no sh /usr/bin/update-from-release.sh \
		"$dir/bootfs-release.itb" "$dir/rootfs-forum.sq"
}

platform_copy_config() {
	# the persistent overlay already carries /etc across the upgrade
	return 0
}
