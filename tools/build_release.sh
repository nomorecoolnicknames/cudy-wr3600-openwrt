#!/bin/bash
# ---------------------------------------------------------------------------
# Cudy WR3600 (BCM6764) release build.
#
#   release/bootfs-release.itb   Linux 6.6.93 + initramfs (quiet boot, WDT fuse)
#   release/rootfs-forum.sq      OpenWrt 24.10.2 + 6.6.93 modules + wl.ko shim
#   release/bundle-forum.itb     loader/u-boot/bootfs/rootfs recovery bundle
#   release/SHA256SUMS
#
# Everything is idempotent and self-contained: nothing outside .work/release and
# release/ is written, and the tested build trees (build-h30coh) are only read.
#
# Prerequisites (not part of this repository):
#   - kernel source tree + a configured/built kernel build dir (see README)
#   - the ARM glibc cross toolchain from the vendor GPL drop
#   - an OpenWrt 24.10.2 armsr/armv7 rootfs staging tree (STAGE_BASE)
#   - the stock (patched) wl.ko / hnd.ko / wlshared.ko blobs (BLOBS)
#   - stock loader.bin / u-boot.bin for the recovery bundle (STOCK)
# ---------------------------------------------------------------------------
set -euo pipefail

R=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# ---- inputs (override on the command line) --------------------------------
SRC=${SRC:-$R/kernel-6.6/src/linux-6.6.93-h30coh}
KB=${KB:-$R/kernel-6.6/build-h30coh}          # tested kernel build (read-only)
KBR=${KBR:-$R/kernel-6.6/build-release}       # release kernel build (copy)
TC=${TC:-$R/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi-}
MK=${MK:-$R/gpl/openwrt/21.02/build_dir/host/u-boot-2021.01/tools/mkimage}
LZ=${LZ:-$R/gpl/openwrt/21.02/staging_dir/host/bin/lzma}
STAGE_BASE=${STAGE_BASE:-/mnt/ramdisk/owrt24/sq2}          # tested rootfs staging
BASE_ROOTFS=${BASE_ROOTFS:-/mnt/ramdisk/owrt24/rootfs.sq}  # pristine OpenWrt base
BLOBS=${BLOBS:-$R/triaging/shim/h30/stage-hw32}            # patched stock blobs
STOCK=${STOCK:-$R/stock/fit}                               # loader.bin/u-boot.bin
BUSYBOX=${BUSYBOX:-$R/kernel-6.6/build-bb/busybox}         # static busybox (initramfs)

# ---- outputs --------------------------------------------------------------
REL=${REL:-$R/release}
W=${W:-$R/.work/release}
# VER is the version string that lands in /etc/cudy-release and in the source
# package name; RELEASE_DATE drives every embedded timestamp and must stay a
# plain date so the build is reproducible. A version like "2026-09-10.3" is
# therefore fine as long as RELEASE_DATE (or VER itself, when it is a date) is
# given too.
VER=${VER:-$(date +%Y-%m-%d)}
RELEASE_DATE=${RELEASE_DATE:-$(date -d "${VER%%.*}" +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)}

# bootfs1 is a 28-LEB static UBI volume (LEB 126976); a FIT that fills it
# completely does not boot, so stay at 27 LEB.
BOOTFS_MAX=$((27 * 126976))

# Reproducible build: pin every timestamp that ends up inside an artifact.
#   SOURCE_DATE_EPOCH   -> mkimage (FIT) and mksquashfs (superblock)
#   KBUILD_BUILD_*      -> the kernel's init/version-timestamp.o
# The default is the release date (not the commit time) so that the artifacts
# do not change when the commit that records their checksums is made.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date -u -d "$RELEASE_DATE 00:00:00" +%s)}
export KBUILD_BUILD_TIMESTAMP=${KBUILD_BUILD_TIMESTAMP:-$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S')}
export KBUILD_BUILD_USER=${KBUILD_BUILD_USER:-release}
export KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST:-cudy-wr3600}
BUILT_UTC=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')

JOBS=$(nproc)
say()  { printf '\n=== %s ===\n' "$*"; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
need() { [ -e "$1" ] || die "missing: $1"; }

# ---------------------------------------------------------------------------
say "0/8 prerequisites"
for p in "$SRC/Makefile" "$KB/.config" "$STAGE_BASE/etc" "$BASE_ROOTFS" \
         "$BLOBS/wl-h7.ko" "$BLOBS/hnd-h7.ko" "$BLOBS/wlshared-h7.ko" \
         "$STOCK/loader.bin" "$STOCK/uboot.bin" "${TC}gcc" "$MK" "$LZ" \
         "$BUSYBOX"; do
	need "$p"
done
mkdir -p "$REL" "$W"
echo "repo      : $R"
echo "version   : $VER"
echo "kernel src: $SRC"
echo "kernel bld: $KB -> $KBR"

# ---------------------------------------------------------------------------
say "1/8 release kernel build tree"
# A copy keeps the tested build dir untouched; only INITRAMFS_SOURCE changes.
rsync -a --delete "$KB/" "$KBR/"
make -C "$SRC" O="$KBR" ARCH=arm CROSS_COMPILE="$TC" -s prepare >/dev/null

# ---------------------------------------------------------------------------
say "2/8 out-of-tree modules"
mod() { # $1 = dir under repo, $2 = KBUILD_EXTRA_SYMBOLS
	printf -- '--- %s\n' "$1"
	make -C "$SRC" O="$KBR" M="$R/$1" ARCH=arm CROSS_COMPILE="$TC" \
	     KBUILD_EXTRA_SYMBOLS="${2:-}" modules >/dev/null
}
mod port66/enet66 ""
mod port66/enet66b "$R/port66/enet66/Module.symvers"
mod port66/vpcie66 "$R/port66/enet66/Module.symvers"
mod port66/leds66 ""
mod bsp-6.6/compat ""
mod port66/shim66 "$R/bsp-6.6/compat/Module.symvers $R/port66/enet66/Module.symvers"
mod port66/reboot66 ""
for m in port66/enet66/enet6764.ko port66/enet66b/serdes6764.ko \
         port66/enet66b/extsw6764.ko port66/leds66/leds-bca-cled.ko \
         port66/vpcie66/vpcie66.ko bsp-6.6/compat/bcm_shim.ko \
         port66/shim66/h30_bpm_live.ko port66/shim66/h30_ubus_all.ko \
         port66/shim66/h30_ubus_probe.ko port66/shim66/h30_rx_snapshot.ko \
         port66/shim66/h30_irqgate.ko port66/reboot66/reboot6764.ko; do
	need "$R/$m"
done

# ---------------------------------------------------------------------------
say "3/8 initramfs"
rm -rf "$W/initramfs"
# The mount points MUST exist as directory entries: the preinit mounts proc,
# sysfs and devtmpfs on them, and without /dev (devtmpfs) there is no
# /dev/ubiblock0_4, so the rootfs can never be mounted.
mkdir -p "$W/initramfs"/{bin,dev,proc,sys,etc,sbin,tmp}
cp "$R/kernel-6.6/initramfs-release/init" "$W/initramfs/init"
chmod 0755 "$W/initramfs/init"
cp "$R/kernel-6.6/initramfs-release/modules.order" "$W/initramfs/modules.order"
# static busybox: the only userspace in the initramfs (init runs
# "busybox --install -s /bin", the symlinks below are for convenience)
cp "$BUSYBOX" "$W/initramfs/bin/busybox"
chmod 0755 "$W/initramfs/bin/busybox"
for a in sh init echo uname cat dmesg mount ls ps free insmod; do
	ln -sf busybox "$W/initramfs/bin/$a"
done
while read -r m; do
	[ -n "$m" ] || continue
	case "$m" in
	enet6764.ko)     src=$R/port66/enet66/enet6764.ko ;;
	serdes6764.ko)   src=$R/port66/enet66b/serdes6764.ko ;;
	extsw6764.ko)    src=$R/port66/enet66b/extsw6764.ko ;;
	leds-bca-cled.ko) src=$R/port66/leds66/leds-bca-cled.ko ;;
	*) die "unknown initramfs module: $m" ;;
	esac
	need "$src"
	cp "$src" "$W/initramfs/$m"
done < "$W/initramfs/modules.order"
# normalize timestamps: the cpio kbuild embeds preserves mtimes
# (CONFIG_INITRAMFS_PRESERVE_MTIME), including those of the directories
find "$W/initramfs" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
ls -la "$W/initramfs" "$W/initramfs/bin"

# ---------------------------------------------------------------------------
say "4/8 kernel Image"
# Kernel command line: expose the ubiblock device of BOTH slots so the preinit
# can pick the release rootfs by its marker (slot 1 first, then slot 2).
CMDLINE="console=ttyAMA0,115200 earlycon coherent_pool=4M mtdparts=spi1.0:2097152(loader),262144@2097152(bdinfo),130809856@2359296(image) ubi.mtd=image ubi.block=0,4 ubi.block=0,6 panic=5"
"$SRC/scripts/config" --file "$KBR/.config" \
	--set-str INITRAMFS_SOURCE "$W/initramfs $R/kernel-6.6/initramfs.list" \
	--set-str CMDLINE "$CMDLINE"
make -C "$SRC" O="$KBR" ARCH=arm CROSS_COMPILE="$TC" -j"$JOBS" Image
need "$KBR/arch/arm/boot/Image"

# ---------------------------------------------------------------------------
say "5/8 bootfs FIT"
FIT=$W/fit
rm -rf "$FIT"; mkdir -p "$FIT"
cp "$KBR/arch/arm/boot/Image" "$FIT/Image"
# the initramfs is embedded in the Image (xz-compressed); verify the exact cpio
# kbuild produced before compression
need "$KBR/usr/initramfs_data.cpio"
cpio -it --quiet < "$KBR/usr/initramfs_data.cpio" > "$W/initramfs.list" 2>/dev/null || true
for e in init modules.order bin/busybox enet6764.ko serdes6764.ko \
         extsw6764.ko leds-bca-cled.ko \
         dev dev/console dev/null proc sys; do
	grep -qx "$e" "$W/initramfs.list" || die "initramfs is missing $e"
done
isz=$(stat -c%s "$KBR/arch/arm/boot/Image")
echo "initramfs entries: $(wc -l < "$W/initramfs.list"), kernel Image: $isz bytes"
[ "$isz" -gt 9000000 ] || die "kernel Image looks too small ($isz bytes): initramfs not embedded?"
( cd "$FIT" && "$LZ" e Image Image.lzma -d23 >/dev/null )
cp "$R/kernel-6.6/port/fdt_96764SV1-66.dtb" "$FIT/fdt.dtb"
cp "$R/kernel-6.6/port/bootfs66.its" "$FIT/bootfs66.its"
( cd "$FIT" && "$MK" -f bootfs66.its bootfs-release.itb >/dev/null )
cp "$FIT/bootfs-release.itb" "$REL/bootfs-release.itb"
bsz=$(stat -c%s "$REL/bootfs-release.itb")
echo "bootfs-release.itb: $bsz bytes ($(( (bsz + 126975) / 126976 )) LEB)"
[ "$bsz" -le "$BOOTFS_MAX" ] || die "bootfs exceeds 27 LEB ($BOOTFS_MAX bytes)"

# ---------------------------------------------------------------------------
say "6/8 rootfs"
rm -rf "$W/rootfs"
mkdir -p "$W/rootfs"
rsync -a --exclude 'etc/uci-defaults/' "$STAGE_BASE/" "$W/rootfs/"
"$R/tools/clean_release_rootfs.sh" "$W/rootfs" "$BASE_ROOTFS"

KM=$W/rootfs/lib/modules/6.6.93
mkdir -p "$KM" "$W/rootfs/lib/modules/blobs" "$W/rootfs/usr/bin"
cp "$KBR"/net/wireless/cfg80211.ko \
   "$KBR"/net/netfilter/*.ko "$KBR"/net/ipv4/netfilter/*.ko \
   "$KBR"/net/ipv6/netfilter/*.ko "$KBR"/net/llc/llc.ko \
   "$KBR"/net/802/stp.ko "$KBR"/net/802/p8022.ko "$KBR"/net/802/psnap.ko \
   "$KBR"/net/bridge/bridge.ko "$KBR"/drivers/net/tun.ko \
   "$KBR"/net/sched/sch_cake.ko "$KBR"/net/sched/sch_fq_codel.ko \
   "$KBR"/net/sched/sch_htb.ko "$KBR"/net/ipv4/tcp_bbr.ko \
   "$KBR"/net/ipv6/ipv6.ko \
   "$KM/"
cp "$R/port66/enet66/enet6764.ko" "$R/port66/enet66b/serdes6764.ko" \
   "$R/port66/enet66b/extsw6764.ko" "$R/port66/leds66/leds-bca-cled.ko" \
   "$R/port66/vpcie66/vpcie66.ko" "$R/bsp-6.6/compat/bcm_shim.ko" \
   "$R/port66/shim66/h30_bpm_live.ko" "$R/port66/shim66/h30_ubus_all.ko" \
   "$R/port66/shim66/h30_ubus_probe.ko" "$R/port66/shim66/h30_rx_snapshot.ko" \
   "$R/port66/shim66/h30_irqgate.ko" "$R/port66/reboot66/reboot6764.ko" \
   "$KM/"
cp "$BLOBS/wl-h7.ko"        "$W/rootfs/lib/modules/blobs/wl.ko"
cp "$BLOBS/hnd-h7.ko"       "$W/rootfs/lib/modules/blobs/hnd.ko"
cp "$BLOBS/wlshared-h7.ko"  "$W/rootfs/lib/modules/blobs/wlshared.ko"
# insmodf: static ARM build from source (busybox insmod cannot force-load the
# unversioned vendor blobs into a modversions kernel)
"${TC}gcc" -static -Os -s -o "$W/insmodf" "$R/tools/insmodf.c"
file "$W/insmodf" | grep -q 'ARM' || die "insmodf is not an ARM binary"
cp "$W/insmodf" "$W/rootfs/usr/bin/insmodf"
chmod 0755 "$W/rootfs/usr/bin/insmodf"
# ubiwrite: the image ships no ubi-utils; tools/install/update-from-release.sh
# needs a volume writer to update a slot from the running system
"${TC}gcc" -static -Os -s -o "$W/ubiwrite" "$R/tools/ubiwrite.c"
file "$W/ubiwrite" | grep -q 'ARM' || die "ubiwrite is not an ARM binary"
cp "$W/ubiwrite" "$W/rootfs/usr/bin/ubiwrite"
chmod 0755 "$W/rootfs/usr/bin/ubiwrite"
cp "$W/ubiwrite" "$REL/ubiwrite"
# Bootloader slot metadata blobs (COMMITTED=1|2 + CRC32, exactly what
# bcm_bootstate writes) and the in-place updater. The updater writes the OTHER
# slot and needs the blob for it, so both live in the image; they are also
# shipped next to the images for the manual path.
mkdir -p "$W/rootfs/usr/share/cudy"
python3 - "$W/rootfs/usr/share/cudy" "$REL" <<'PYEOF'
import struct, sys, zlib
out_dir, rel_dir = sys.argv[1], sys.argv[2]
for committed in (1, 2):
    blob = bytearray(1280)
    data = ("COMMITTED=%d\0VALID=1,2\0SEQ=1,2\0\0" % committed).encode()
    payload = data + b"\0" * (252 - len(data))
    struct.pack_into('<III', blob, 0, 256, 256, zlib.crc32(payload) & 0xffffffff)
    blob[12:12 + 252] = payload
    for d in (out_dir, rel_dir):
        with open("%s/meta-committed%d.bin" % (d, committed), "wb") as f:
            f.write(bytes(blob))
PYEOF
for b in "$W/rootfs/usr/share/cudy"/meta-committed*.bin; do
	need "$b"
done
cp "$R/tools/install/update-from-release.sh" "$W/rootfs/usr/bin/update-from-release.sh"
chmod 0755 "$W/rootfs/usr/bin/update-from-release.sh"
cp -a "$R/kernel-6.6/rootfs-overlay-forum/." "$W/rootfs/"
# No git revision here on purpose: it would make the artifacts depend on the
# commit that records them. The source package name identifies the sources.
cat > "$W/rootfs/etc/cudy-release" <<EOF
version=$VER
source=cudy-wr3600-6.6-src-$VER
kernel=6.6.93
openwrt=24.10.2
target=armsr/armv7
wired=eth0 (all switch ports, WAN role)
wifi=stock wl.ko (Broadcom 4.19 blob) via bcm_shim
built=$BUILT_UTC
EOF
# sanity: every module wifi66 loads must exist
miss=0
for m in $(sed -n 's#.*/lib/modules/6\.6\.93/\([a-z0-9_-]*\)\.ko.*#\1#p' \
		"$W/rootfs/etc/init.d/wifi66" | sort -u); do
	[ -f "$KM/$m.ko" ] || { echo "MISSING module: $m"; miss=1; }
done
[ "$miss" = 0 ] || die "rootfs is missing modules that wifi66 loads"

# and every dependency of every module we ship must be in the image too
# (busybox insmod does not resolve dependencies)
for f in "$KM"/*.ko; do
	for dep in $(modinfo -F depends "$f" 2>/dev/null | tr ',' ' '); do
		[ -f "$KM/$dep.ko" ] || { echo "MISSING dependency: $(basename "$f") needs $dep"; miss=1; }
	done
done
[ "$miss" = 0 ] || die "rootfs is missing kernel module dependencies"

# provenance: every module in the rootfs must come from this build. An OpenWrt
# kmod carries the same vermagic (6.6.93 modversions) but different symbol
# CRCs, so it would fail to load at run time.
{ find "$KBR" -name '*.ko' -not -path "$KBR/scripts/*"
  find "$R/port66" "$R/bsp-6.6" -name '*.ko'; } \
	| xargs -r sha256sum | awk '{print $1}' | sort -u > "$W/our-modules.sha"
bad=0
( cd "$KM" && sha256sum *.ko ) | while read -r h b; do
	grep -qx "$h" "$W/our-modules.sha" || echo "NOT FROM THIS BUILD: $b"
done > "$W/foreign-modules.txt" || true
[ ! -s "$W/foreign-modules.txt" ] || {
	cat "$W/foreign-modules.txt"; die "rootfs contains foreign kernel modules"; }

# normalize every timestamp so mksquashfs output does not depend on build time
find "$W/rootfs" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

# mksquashfs honours SOURCE_DATE_EPOCH on its own (it rejects -mkfs-time then)
mksquashfs "$W/rootfs" "$REL/rootfs-forum.sq" -noappend -comp xz -b 262144 \
	-no-xattrs >/dev/null
echo "rootfs-forum.sq: $(stat -c%s "$REL/rootfs-forum.sq") bytes"

# ---------------------------------------------------------------------------
say "7/8 recovery bundle"
cp "$STOCK/loader.bin" "$STOCK/uboot.bin" "$FIT/"
cp "$REL/bootfs-release.itb" "$REL/rootfs-forum.sq" "$FIT/"
cat > "$FIT/bundle-forum.its" <<'EOF'
/dts-v1/;
/ {
	description = "R77";
	#address-cells = <1>;
	images {
		loader {
			description = "loader";
			data = /incbin/("loader.bin");
			type = "firmware";
			compression = "none";
			hash-1 { algo = "sha256"; };
		};
		u-boot {
			description = "uboot";
			data = /incbin/("uboot.bin");
			type = "firmware";
			compression = "none";
			hash-1 { algo = "sha256"; };
		};
		bootfs {
			description = "bootfs";
			data = /incbin/("bootfs-release.itb");
			type = "multi";
			compression = "none";
			hash-1 { algo = "sha256"; };
		};
		nand_squashfs {
			description = "rootfs";
			data = /incbin/("rootfs-forum.sq");
			type = "filesystem";
			compression = "none";
			hash-1 { algo = "sha256"; };
		};
	};
	configurations {
		default = "conf_6764_a0+_nand_squashfs";
		conf_6764_a0+_nand_squashfs {
			description = "Brcm Image Bundle";
			loader = "loader";
			uboot = "u-boot";
			bootfs = "bootfs";
			rootfs = "nand_squashfs";
			compatible = "flash=nand;chip=6764;rev=a0+;ip=ipv6,ipv4;ddr=ddr3,ddr4;fstype=squashfs";
		};
	};
};
EOF
( cd "$FIT" && "$MK" -f bundle-forum.its bundle-forum.itb >/dev/null )
cp "$FIT/bundle-forum.itb" "$REL/bundle-forum.itb"

# ---------------------------------------------------------------------------
say "8/8 checksums"
( cd "$REL" && sha256sum bootfs-release.itb rootfs-forum.sq bundle-forum.itb \
	> SHA256SUMS )
cat "$REL/SHA256SUMS"
ls -la "$REL"
echo
echo "RELEASE_BUILD_DONE"
