#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# install-on-router.sh — write the 6.6/OpenWrt firmware into a slot of a
# Cudy WR3600 (BCM6764). Runs ON THE ROUTER, on the STOCK firmware, over an
# SSH session you already have (root, port 2222 after the bootstrap).
#
#   scp -O -P 2222 -i KEY bootfs-release.itb rootfs-forum.sq install-on-router.sh root@192.168.10.1:/tmp/
#   ssh -p 2222 -i KEY root@192.168.10.1 'sh /tmp/install-on-router.sh /tmp/bootfs-release.itb /tmp/rootfs-forum.sq'
#
# Options (environment variables):
#   SLOT=1|2        slot to write (default 1; 2 = the factory slot, only if you know why)
#   COMMIT=yes|no   yes (default): make the slot permanent; no: boot it once for a trial
#   REBOOT=yes|no   reboot at the end (default yes)
#
# Never touches loader, u-boot, bdinfo or the other slot.
set -e

BOOTFS=${1:?usage: install-on-router.sh <bootfs.itb> <rootfs.sq>}
ROOTFS=${2:?usage: install-on-router.sh <bootfs.itb> <rootfs.sq>}
SLOT=${SLOT:-1}
COMMIT=${COMMIT:-yes}
REBOOT=${REBOOT:-yes}
LEB=126976
BOOTFS_MAX=$((27 * LEB))

say() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

case "$SLOT" in
1) BVOL=/dev/ubi0_3; RVOL=/dev/ubi0_4 ;;
2) BVOL=/dev/ubi0_5; RVOL=/dev/ubi0_6 ;;
*) die "SLOT must be 1 or 2" ;;
esac

# --- sanity -----------------------------------------------------------------
[ -f "$BOOTFS" ] || die "no such file: $BOOTFS"
[ -f "$ROOTFS" ] || die "no such file: $ROOTFS"
command -v ubiupdatevol >/dev/null || die "ubiupdatevol not found: run this on the STOCK firmware"
command -v bcm_bootstate >/dev/null || die "bcm_bootstate not found: run this on the STOCK firmware"
model=$(tr -d '\000' < /proc/device-tree/model 2>/dev/null || true)
case "$model" in
*6764*) ;;
*) die "unexpected board '$model' (need BCM96764 / Cudy WR3600)" ;;
esac
[ -e "$BVOL" ] && [ -e "$RVOL" ] || die "UBI volumes $BVOL/$RVOL not present"
for v in 3 4 5 6; do
	n=$(cat /sys/class/ubi/ubi0_$v/name 2>/dev/null || true)
	case "$v:$n" in 3:bootfs1|4:rootfs1|5:bootfs2|6:rootfs2) ;; *) die "unexpected UBI layout: ubi0_$v is '$n'" ;; esac
done

bsize=$(wc -c < "$BOOTFS")
rsize=$(wc -c < "$ROOTFS")
[ "$bsize" -le "$BOOTFS_MAX" ] || die "bootfs is $bsize bytes; over 27 LEB ($BOOTFS_MAX) it does not boot"
rmax=$(cat /sys/class/ubi/ubi0_$((SLOT * 2 + 2))/reserved_ebs 2>/dev/null || echo 0)
[ "$rmax" = 0 ] || [ "$rsize" -le $((rmax * LEB)) ] || die "rootfs ($rsize) larger than the volume ($((rmax * LEB)))"

bsha=$(sha256sum "$BOOTFS" | cut -c1-64)
rsha=$(sha256sum "$ROOTFS" | cut -c1-64)
say "board: $model"
say "bootfs $bsize bytes sha256 $(echo "$bsha" | cut -c1-16)  -> $BVOL"
say "rootfs $rsize bytes sha256 $(echo "$rsha" | cut -c1-16)  -> $RVOL"
say "bootstate before: $(bcm_bootstate 2>&1 | grep -m1 committed)"

# --- write --------------------------------------------------------------------
say "writing bootfs"
ubiupdatevol "$BVOL" "$BOOTFS"
say "writing rootfs (takes a minute)"
ubiupdatevol "$RVOL" "$ROOTFS"
sync

say "verifying readback"
[ "$(head -c "$bsize" "$BVOL" | sha256sum | cut -c1-64)" = "$bsha" ] || die "bootfs readback mismatch — boot slot NOT changed"
[ "$(head -c "$rsize" "$RVOL" | sha256sum | cut -c1-64)" = "$rsha" ] || die "rootfs readback mismatch — boot slot NOT changed"

# --- select the slot --------------------------------------------------------------
if [ "$COMMIT" = yes ]; then
	bcm_bootstate "+$SLOT"
	say "slot $SLOT committed"
else
	bcm_bootstate "+$SLOT" >/dev/null 2>&1 || true
	echo 1 > /proc/bootstate/reset_reason     # ACTIVATE: boot the other slot once
	say "slot $SLOT will boot ONCE; the next reboot returns to the committed slot"
fi
say "bootstate after: $(bcm_bootstate 2>&1 | grep -m1 committed)"

if [ "$REBOOT" = yes ]; then
	say "rebooting; the new firmware appears in ~2 minutes as Wi-Fi 'CudyWR3600' / 12345678, 192.168.10.1"
	sync
	(sleep 1; reboot) >/dev/null 2>&1 &
else
	say "not rebooting (REBOOT=no)"
fi
