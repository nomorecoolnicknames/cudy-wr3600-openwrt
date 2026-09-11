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
# overlay volume, which the upgrade leaves alone. sysupgrade -n (SAVE_CONFIG=0)
# wipes it, which is what a factory reset should do.

CUDY_VOL_NAME=cudy66_data

# sysupgrade's stage2 pivots into a ramfs and copies ONLY what is listed here
# (plus busybox and a fixed applet list, see /lib/upgrade/stage2). Without
# these the updater, ubiwrite and the slot metadata blobs are simply absent
# in stage2 - found while reviewing the first draft of this file.
RAMFS_COPY_BIN="/usr/bin/ubiwrite sha256sum head"
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

platform_check_image() {
	local file="$1"

	[ "$#" -gt 1 ] && return 1
	[ -f "$file" ] || { echo "no such file: $file"; return 1; }

	tar -tf "$file" 2>/dev/null | grep -qx 'bootfs-release.itb' || {
		echo "this does not look like a Cudy WR3600 image"; return 1; }
	tar -tf "$file" 2>/dev/null | grep -qx 'rootfs-forum.sq' || {
		echo "the image has no rootfs-forum.sq"; return 1; }
	return 0
}

platform_do_upgrade() {
	local file="$1" dir=/tmp/cudy-sysupgrade dev

	rm -rf "$dir"
	mkdir -p "$dir" || return 1
	tar -xf "$file" -C "$dir" || { echo "cannot unpack $file"; return 1; }
	( cd "$dir" && sha256sum -c SHA256SUMS ) || {
		echo "image checksum mismatch - refusing to flash"; return 1; }

	if [ "${SAVE_CONFIG:-1}" = "0" ]; then
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
