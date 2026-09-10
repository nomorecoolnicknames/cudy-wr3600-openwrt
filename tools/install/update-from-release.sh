#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# update-from-release.sh - update a Cudy WR3600 that ALREADY runs this
# firmware (Linux 6.6 / OpenWrt 24.10) to a newer bootfs/rootfs.
#
#   scp -O bootfs-release.itb rootfs-forum.sq root@192.168.10.1:/tmp/
#   ssh root@192.168.10.1 'sh /usr/bin/update-from-release.sh \
#       /tmp/bootfs-release.itb /tmp/rootfs-forum.sq'
#
# How it works (A/B): the running rootfs is served by a ubiblock device on its
# own UBI volume, and a volume that is in use CANNOT be rewritten - the first
# version of this script tried exactly that and died with
# "UBI_IOCVOLUP: Device or resource busy" (verified on hardware). So the new
# images go into the OTHER slot, which is idle, are verified by reading them
# back, the bootloader metadata is pointed at that slot and the board reboots.
# The slot we were running from stays untouched and becomes the fallback.
#
# The factory firmware normally sits in the other slot. Overwriting it erases
# the "return to stock" rollback, so the script refuses unless FORCE=1 is given
# (and then says so loudly).
#
# Variables: DRYRUN=1 (plan only), FORCE=1 (allow replacing a foreign rootfs),
#            REBOOT=no (do not reboot at the end), UBIWRITE=<path>,
#            META_DIR=<dir with meta-committed{1,2}.bin>
set -e

BOOTFS=${1:?usage: update-from-release.sh <bootfs.itb> <rootfs.sq>}
ROOTFS=${2:?usage: update-from-release.sh <bootfs.itb> <rootfs.sq>}
DRYRUN=${DRYRUN:-0}
FORCE=${FORCE:-0}
REBOOT=${REBOOT:-yes}
UBIWRITE=${UBIWRITE:-/usr/bin/ubiwrite}
META_DIR=${META_DIR:-/usr/share/cudy}
LEB=126976

say() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[ -f "$BOOTFS" ] || die "no such file: $BOOTFS"
[ -f "$ROOTFS" ] || die "no such file: $ROOTFS"

# ---------------------------------------------------------------------------
# Which slot are we running from? The mounted squashfs is the only reliable
# answer - U-Boot's bootargs named the committed slot even when the preinit
# had fallen back to the other one (verified on hardware).
# ---------------------------------------------------------------------------
ROOTDEV=$(awk '$2 == "/rom" { print $1 }' /proc/mounts)
case "$ROOTDEV" in
*ubiblock0_4*) RUN=1 ;;
*ubiblock0_6*) RUN=2 ;;
*) die "cannot tell which slot is running (no /rom ubiblock in /proc/mounts)" ;;
esac

if [ "$RUN" = 1 ]; then
	TGT=2; BVOL=/dev/ubi0_5; RVOL=/dev/ubi0_6
else
	TGT=1; BVOL=/dev/ubi0_3; RVOL=/dev/ubi0_4
fi
say "running slot $RUN ($ROOTDEV); updating slot $TGT ($BVOL, $RVOL)"

# ---------------------------------------------------------------------------
# What is in the target slot now?
# ---------------------------------------------------------------------------
FOREIGN=0
mkdir -p /tmp/upd66-mnt
if [ -b "$RVOL" ] && mount -t squashfs -o ro "$RVOL" /tmp/upd66-mnt 2>/dev/null; then
	[ -f /tmp/upd66-mnt/etc/cudy-release ] || FOREIGN=1
	umount /tmp/upd66-mnt 2>/dev/null || true
fi
if [ "$FOREIGN" = 1 ]; then
	if [ "$FORCE" != 1 ]; then
		die "slot $TGT holds a foreign rootfs (the factory firmware?).
     Updating would erase the rollback to stock. Re-run with FORCE=1 if that is
     what you want - the slot you are running now then becomes the fallback."
	fi
	say "WARNING: slot $TGT holds a foreign rootfs - replacing it, the rollback to stock is lost"
fi

# ---------------------------------------------------------------------------
# Sizes and hashes
# ---------------------------------------------------------------------------
bsize=$(wc -c < "$BOOTFS"); rsize=$(wc -c < "$ROOTFS")
bmax=$((27 * LEB))
[ "$bsize" -le "$bmax" ] || die "bootfs is $bsize bytes, the slot holds at most $bmax"
bsha=$(sha256sum "$BOOTFS" | cut -c1-64)
rsha=$(sha256sum "$ROOTFS" | cut -c1-64)
say "bootfs $bsha ($bsize B), rootfs $rsha ($rsize B)"

if [ "$DRYRUN" = 1 ]; then
	say "DRYRUN: would write $BVOL and $RVOL, commit slot $TGT and reboot"
	exit 0
fi

# Detach: the write takes a couple of minutes and this board's dropbear drops
# long sessions (verified on hardware - the first two runs lost their SSH
# connection mid-update, and one of them stopped before the commit). Run the
# real work in its own session so closing the terminal cannot abort an update
# that is halfway through, and keep a log.
if [ "$UPD66_DETACHED" != 1 ]; then
	UPD66_DETACHED=1
	export UPD66_DETACHED
	LOG=${LOG:-/tmp/update-from-release.log}
	setsid sh "$0" "$@" > "$LOG" 2>&1 &
	say "update started in the background (log: $LOG)"
	say "the board commits slot $TGT and reboots when it finishes"
	exit 0
fi

[ -x "$UBIWRITE" ] || die "no ubiwrite at $UBIWRITE (copy it to /tmp and set UBIWRITE=)"
[ -f "$META_DIR/meta-committed$TGT.bin" ] || \
	die "no bootloader metadata blob at $META_DIR/meta-committed$TGT.bin"

# ---------------------------------------------------------------------------
# Write, verify, commit
# ---------------------------------------------------------------------------
say "writing $BVOL"
"$UBIWRITE" "$BVOL" "$BOOTFS" || die "bootfs write failed"

say "writing $RVOL (takes about a minute)"
"$UBIWRITE" "$RVOL" "$ROOTFS" || die "rootfs write failed"
sync

# Reading a 24 MB volume back with `head -c` hangs on this SoC (verified: the
# process ends up in D state), so the bootfs is hashed with a bounded dd and
# the rootfs is verified by mounting the freshly written squashfs - which is
# both faster and a stronger check, because it walks the whole metadata tree.
b=$(dd if="$BVOL" bs=65536 count=$(( (bsize + 65535) / 65536 )) 2>/dev/null \
	| head -c "$bsize" | sha256sum | cut -c1-64)
[ "$b" = "$bsha" ] || die "bootfs readback mismatch ($b)"
say "bootfs readback verified"

if [ "$TGT" = 2 ]; then UBIBLK=/dev/ubiblock0_6; else UBIBLK=/dev/ubiblock0_4; fi
i=0; while [ ! -b "$UBIBLK" ] && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
[ -b "$UBIBLK" ] || die "no $UBIBLK (the kernel command line should expose both slots)"
mkdir -p /tmp/upd66-mnt
mount -t squashfs -o ro "$UBIBLK" /tmp/upd66-mnt 2>/dev/null || \
	die "the rootfs just written to slot $TGT does not mount"
v=$(sed -n 's/^version=//p' /tmp/upd66-mnt/etc/cudy-release 2>/dev/null)
umount /tmp/upd66-mnt 2>/dev/null || true
[ -n "$v" ] || die "the rootfs in slot $TGT has no /etc/cudy-release"
say "rootfs mounts, reports version $v"

say "committing slot $TGT"
"$UBIWRITE" /dev/ubi0_1 "$META_DIR/meta-committed$TGT.bin" || die "metadata write failed"
"$UBIWRITE" /dev/ubi0_2 "$META_DIR/meta-committed$TGT.bin" || die "metadata write failed"
sync
say "slot $TGT is now the committed boot slot; the slot we ran from stays as the fallback"

if [ "$REBOOT" != no ]; then
	say "rebooting"
	echo 10 > /proc/bcm96764_wdt_kick_secs 2>/dev/null || true
	reboot -f
	sleep 120
fi
