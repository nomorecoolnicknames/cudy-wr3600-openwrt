#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# update-from-release.sh — update a Cudy WR3600 that ALREADY runs this
# firmware (Linux 6.6 / OpenWrt 24.10) to a newer bootfs/rootfs, in place.
#
#   scp -O bootfs-release.itb rootfs-forum.sq ubiwrite update-from-release.sh root@192.168.10.1:/tmp/
#   ssh root@192.168.10.1 'sh /tmp/update-from-release.sh /tmp/bootfs-release.itb /tmp/rootfs-forum.sq'
#
# How it works: the running rootfs is a read-only squashfs served straight
# from the UBI volume, so the volume cannot be rewritten underneath it. The
# script therefore copies busybox, its libc loader and ubiwrite into a tmpfs,
# bind-mounts that copy of /lib over the real one, stops the services,
# re-execs itself from RAM (the same idea as OpenWrt's sysupgrade stage2) and
# only then replaces the volumes of the slot it was booted from. It ends with
# a hard reboot; the board resets through the watchdog.
#
# ubiwrite = tools/ubiwrite.c from the source package (static ARM build). If
# it is not in the image, copy the binary to /tmp/ubiwrite first.
# Nothing else is touched (loader, u-boot, bdinfo, the other slot).
set -e

BOOTFS=${1:?usage: update-from-release.sh <bootfs.itb> <rootfs.sq>}
ROOTFS=${2:?usage: update-from-release.sh <bootfs.itb> <rootfs.sq>}
RAM=/tmp/upd66
DRYRUN=${DRYRUN:-0}          # DRYRUN=1: go through the whole RAM stage, write nothing, reboot
LEB=126976

say() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# stage 2: runs from RAM only (re-exec'd below with PATH=$RAM)
# ---------------------------------------------------------------------------
if [ "$UPD66_STAGE2" = 1 ]; then
	BVOL=$3; RVOL=$4; BSHA=$5; RSHA=$6
	cd "$RAM"
	if [ "$DRYRUN" = 1 ]; then
		say "stage2: DRYRUN — RAM stage works (sh/head/sha256sum/ubiwrite from $RAM), not writing, rebooting"
		./ubiwrite 2>&1 | head -1 || true
		sync; reboot -f; sleep 120; exit 0
	fi
	say "stage2: writing $BVOL"
	./ubiwrite "$BVOL" "$BOOTFS"
	say "stage2: writing $RVOL"
	./ubiwrite "$RVOL" "$ROOTFS"
	sync
	bsize=$(wc -c < "$BOOTFS"); rsize=$(wc -c < "$ROOTFS")
	b=$(head -c "$bsize" "$BVOL" | sha256sum | cut -c1-64)
	r=$(head -c "$rsize" "$RVOL" | sha256sum | cut -c1-64)
	if [ "$b" = "$BSHA" ] && [ "$r" = "$RSHA" ]; then
		say "stage2: verified, rebooting"
	else
		say "stage2: READBACK MISMATCH (bootfs $([ "$b" = "$BSHA" ] && echo ok || echo BAD), rootfs $([ "$r" = "$RSHA" ] && echo ok || echo BAD))"
		say "stage2: rebooting anyway; if this slot no longer boots, the watchdog fuse returns the board to the other slot"
	fi
	sync
	echo 10 > /proc/bcm96764_wdt_kick_secs 2>/dev/null || true
	reboot -f
	sleep 120
	exit 0
fi

# ---------------------------------------------------------------------------
# stage 1: checks, copy to RAM, re-exec
# ---------------------------------------------------------------------------
[ -f /etc/cudy-release ] || die "this is not the 6.6/OpenWrt release; use install-on-router.sh on the stock firmware"
[ -f "$BOOTFS" ] || die "no such file: $BOOTFS"
[ -f "$ROOTFS" ] || die "no such file: $ROOTFS"

if command -v ubiwrite >/dev/null 2>&1; then
	UBIWRITE=$(command -v ubiwrite)
elif [ -x /tmp/ubiwrite ]; then
	UBIWRITE=/tmp/ubiwrite
else
	die "ubiwrite not found: copy the static binary to /tmp/ubiwrite"
fi

# Which slot are we running from? NOT from the kernel command line: U-Boot's
# root=/dev/ubiblock0_N in /chosen/bootargs does not always match the image
# it loaded (seen on the bench: bootargs said slot 2 while bootfs1 was booted
# and the preinit fell back to rootfs1). The squashfs that is actually
# mounted is the truth; OpenWrt keeps it at /rom under the overlay.
ROOTDEV=$(awk '$2=="/rom" || $2=="/" {print $1}' /proc/mounts | grep -oE 'ubiblock0_[46]' | head -1)
case "$ROOTDEV" in
ubiblock0_4) SLOT=1; BVOL=/dev/ubi0_3; RVOL=/dev/ubi0_4 ;;
ubiblock0_6) SLOT=2; BVOL=/dev/ubi0_5; RVOL=/dev/ubi0_6 ;;
*) die "cannot tell which slot the running rootfs comes from (/proc/mounts has no ubiblock0_4/6)" ;;
esac
# Never overwrite a slot that does not carry this firmware (the factory slot
# is the rollback): the running rootfs has the marker, so the slot it lives
# in is ours by definition — that is the only slot we touch.

bsize=$(wc -c < "$BOOTFS")
[ "$bsize" -le $((27 * LEB)) ] || die "bootfs is $bsize bytes; over 27 LEB it does not boot"
bsha=$(sha256sum "$BOOTFS" | cut -c1-64)
rsha=$(sha256sum "$ROOTFS" | cut -c1-64)
say "booted from slot $SLOT ($BVOL, $RVOL)"
say "new bootfs $(echo "$bsha" | cut -c1-16), rootfs $(echo "$rsha" | cut -c1-16)"

# --- everything stage 2 needs goes to RAM -------------------------------------
rm -rf "$RAM"; mkdir -p "$RAM/lib"
cp /bin/busybox "$RAM/busybox"
cp "$UBIWRITE" "$RAM/ubiwrite"
cp "$0" "$RAM/update.sh"
cp "$BOOTFS" "$RAM/bootfs.itb"
cp "$ROOTFS" "$RAM/rootfs.sq"
# busybox in the image is dynamically linked (musl loader + libgcc_s), and the
# kernel resolves the loader by the absolute path embedded in the binary, so
# a copy of /lib (it is small) is bind-mounted over the real one. Seen on the
# bench when only ld-musl was copied: "Error loading shared library
# libgcc_s.so.1", and the box had to wait for the watchdog fuse.
cp -a /lib/*.so* "$RAM/lib/" 2>/dev/null || true
[ -e "$RAM/lib/libgcc_s.so.1" ] || die "no libgcc_s.so.1 under /lib — refusing to continue"
ls "$RAM"/lib/ld-musl-*.so.1 >/dev/null 2>&1 || die "no musl loader under /lib — refusing to continue"
for a in sh head cut sha256sum sync echo wc reboot sleep cat tr sed; do ln -sf busybox "$RAM/$a"; done
chmod +x "$RAM/ubiwrite" "$RAM/busybox"
sync

say "stopping services (Wi-Fi drops now; the update takes about a minute, then the board reboots)"
for s in podkop uhttpd rpcd dnsmasq cron log; do /etc/init.d/$s stop >/dev/null 2>&1 || true; done
killall -q hostapd sing-box dnsmasq 2>/dev/null || true
echo 900 > /proc/bcm96764_wdt_kick_secs 2>/dev/null || true
mount -o bind "$RAM/lib" /lib || die "cannot bind-mount the RAM copy of /lib"

# From here on nothing under / (squashfs) may be touched: exec the RAM copy.
cd "$RAM"
export PATH=$RAM
UPD66_STAGE2=1 DRYRUN=$DRYRUN exec "$RAM/sh" "$RAM/update.sh" "$RAM/bootfs.itb" "$RAM/rootfs.sq" "$BVOL" "$RVOL" "$bsha" "$rsha"
