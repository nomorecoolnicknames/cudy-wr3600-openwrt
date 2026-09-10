#!/bin/bash
# ---------------------------------------------------------------------------
# Public source package for the Cudy WR3600 (BCM6764) 6.6 port.
#
#   release/cudy-wr3600-6.6-src-<VER>.tar.gz
#   release/cudy-wr3600-6.6-src-<VER>.tar.gz.sha256
#
# Contains only our own GPL-2.0 sources plus the build inputs we authored
# (device tree, FIT description, initramfs, rootfs overlay, build scripts).
# It deliberately excludes:
#   - the proprietary Broadcom wl.ko / hnd.ko / wlshared.ko blobs
#   - the vendor GPL drop and the OpenWrt build tree
#   - bring-up notes, logs, packet captures and analysis (triaging/, obs/)
#   - anything personal (keys, addresses, VPN subscriptions)
# ---------------------------------------------------------------------------
set -euo pipefail

R=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VER=${VER:-$(date +%Y-%m-%d)}
NAME=cudy-wr3600-6.6-src-$VER
OUT=${OUT:-$R/release/$NAME.tar.gz}
W=$R/.work/srcpkg/$NAME

say() { printf -- '--- %s\n' "$*"; }
rm -rf "$W"
mkdir -p "$W"/{kernel,port66,bsp-6.6,tools,docs}

say "kernel side"
cp "$R/kernel-6.6/build.sh" "$R/kernel-6.6/initramfs.list" "$W/kernel/"
cp -a "$R/kernel-6.6/initramfs-release" "$W/kernel/"
cp -a "$R/kernel-6.6/rootfs-overlay-forum" "$W/kernel/"
mkdir -p "$W/kernel/port"
rsync -a --exclude '*.itb' --exclude '*.bak*' --exclude '.omc' \
	--exclude '*.orig' --exclude '*.rej' --exclude '*.log' \
	"$R/kernel-6.6/port/" "$W/kernel/port/"

say "out-of-tree modules"
for d in enet66 enet66b leds66 reboot66 shim66 vpcie66; do
	mkdir -p "$W/port66/$d"
	rsync -a \
		--exclude '*.ko' --exclude '*.o' --exclude '*.mod' \
		--exclude '*.mod.c' --exclude '.*.cmd' --exclude '*.d' \
		--exclude 'modules.order' --exclude 'Module.symvers' \
		--exclude '__pycache__' --exclude '.omc' --exclude '.git*' \
		--exclude '*.bak*' --exclude '*.orig' --exclude '*.rej' \
		--exclude '*.log' \
		"$R/port66/$d/" "$W/port66/$d/"
done
mkdir -p "$W/bsp-6.6/compat"
rsync -a \
	--exclude '*.ko' --exclude '*.o' --exclude '*.mod' \
	--exclude '*.mod.c' --exclude '.*.cmd' --exclude '*.d' \
	--exclude 'modules.order' --exclude 'Module.symvers' \
	--exclude '.omc' --exclude '.git*' --exclude '*.bak*' \
	--exclude '*.orig' --exclude '*.rej' --exclude '*.log' \
	"$R/bsp-6.6/compat/" "$W/bsp-6.6/compat/"

say "build scripts"
cp "$R/tools/build_release.sh" "$R/tools/clean_release_rootfs.sh" \
   "$R/tools/make_source_tarball.sh" "$R/tools/insmodf.c" \
   "$R/tools/ubiwrite.c" "$W/tools/"

say "documentation"
cp "$R/docs/SOURCE_README.md" "$W/README.md"
cp "$R/FORUM_BUILD_GUIDE.md" "$W/docs/" 2>/dev/null || true
[ -f "$R/release/RELEASE_NOTES.md" ] && cp "$R/release/RELEASE_NOTES.md" "$W/docs/"
[ -f "$R/release/ROOTFS_PACKAGES.md" ] && cp "$R/release/ROOTFS_PACKAGES.md" "$W/docs/"

say "verification"
rc=0
# real secrets (VPN subscription identifiers) must not appear anywhere
personal='24955a25-14ad-49dd-87f0-3ae61a3449a1|4cd28b92-c1ed-4923-b151-e79e241e0492'
bad=$(grep -rIl -E "$personal" "$W" 2>/dev/null \
	| grep -v 'tools/clean_release_rootfs.sh$' \
	| grep -v 'tools/make_source_tarball.sh$' | head || true)
[ -z "$bad" ] || { echo "personal data in package:"; echo "$bad"; rc=1; }
# bring-up addresses must not leak into shipped code; docs may still describe
# the reference TFTP setup (they are not installed on the device)
bad=$(grep -rIl -E '192\.168\.1\.(88|119|120)|gunwest' \
	"$W/kernel/rootfs-overlay-forum" "$W/kernel/initramfs-release" \
	"$W/port66" "$W/bsp-6.6" 2>/dev/null | grep -v '\.md$' | head || true)
[ -z "$bad" ] || { echo "test addresses in shipped code:"; echo "$bad"; rc=1; }
for f in $(find "$W" -name '*.ko' -o -name '*.o' -o -name '*.mod.c'); do
	echo "build artifact in package: $f"; rc=1
done
[ "$rc" = 0 ] || { echo "FATAL: source package verification failed"; exit 1; }

say "tarball"
mkdir -p "$(dirname "$OUT")"
tar -C "$(dirname "$W")" -czf "$OUT" "$NAME"
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
echo "$OUT: $(stat -c%s "$OUT") bytes"
cat "$(dirname "$OUT")/$(basename "$OUT").sha256"
echo "SOURCE_PACKAGE_DONE"
