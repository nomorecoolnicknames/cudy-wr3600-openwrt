#!/bin/bash
# Build minimal Linux 6.6 (OpenWrt 24.10 kernel family) for BCM6764/BCM96764.
# Output: TFTP-bootable FIT images. NOTHING is flashed, GPL tree untouched.
# Usage: ./build.sh 2>&1 | tee out/build.log
set -euo pipefail

# Everything is derived from this script's location; REPO_ROOT overrides it.
K66="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$K66/.." && pwd)}"
SRC=$K66/src/linux-6.6.93
BB=$K66/src/busybox-1.36.1
BUILD=$K66/build
OUT=$K66/out
INITRAMFS=$K66/initramfs
# glibc cross-toolchain from the GPL build (READ-ONLY use, never modified)
TC=$REPO_ROOT/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi-
STOCK_DTB=$REPO_ROOT/stock/fit/fdt_96764SV1.dtb
JOBS=$(nproc)

export ARCH=arm
export CROSS_COMPILE=$TC

mkdir -p "$BUILD" "$OUT" "$INITRAMFS"

echo "=== 0. toolchain ==="
${TC}gcc --version | head -1

echo "=== 1. integrate port shim (reversible patch + file copies) ==="
cd "$SRC"
if ! patch -p1 --dry-run -R < "$K66/port/bcm96764.patch" >/dev/null 2>&1; then
  patch -p1 < "$K66/port/bcm96764.patch"
  echo "patch applied"
else
  echo "patch already applied"
fi
cp "$K66/port/bcm96764.c" arch/arm/mach-bcm/bcm96764.c
cp "$K66/port/bcm96764sv1-min.dts" arch/arm/boot/dts/broadcom/bcm96764sv1-min.dts
cp "$K66/port/bcm96764_min_defconfig" arch/arm/configs/bcm96764_min_defconfig

echo "=== 2. busybox static (initramfs userspace) ==="
mkdir -p "$K66/build-bb"
cd "$BB"
make O="$K66/build-bb" ARCH=arm CROSS_COMPILE="$TC" defconfig >/dev/null
"$SRC/scripts/config" --file "$K66/build-bb/.config" -e STATIC
make O="$K66/build-bb" ARCH=arm CROSS_COMPILE="$TC" -j"$JOBS" >/dev/null
BB_BIN="$K66/build-bb/busybox"
file "$BB_BIN"

echo "=== 3. initramfs staging ==="
rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,etc,proc,sys,dev}
cp "$BB_BIN" "$INITRAMFS/bin/busybox"
cd "$INITRAMFS"
for a in sh init echo uname cat dmesg mount ls ps free; do ln -sf busybox "bin/$a"; done
cat > init <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null
echo ""
echo "=== BCM96764 / Linux 6.6 minimal bring-up (Cudy WR3600, TFTP test) ==="
uname -a
grep -m1 "model\|Hardware" /proc/cpuinfo /proc/device-tree/model 2>/dev/null
echo "--- cpuinfo ---"
grep -m4 "model name\|CPU implementer\|CPU part" /proc/cpuinfo
echo "--- mem ---"
free | head -2
echo "--- cmdline ---"
cat /proc/cmdline
echo "dropping to shell on console"
exec setsid sh -c 'exec sh </dev/console >/dev/console 2>&1'
EOF
chmod +x init

echo "=== 4. kernel defconfig (initramfs path injected) ==="
cd "$SRC"
make O="$BUILD" bcm96764_min_defconfig
"$SRC/scripts/config" --file "$BUILD/.config" --set-str INITRAMFS_SOURCE "$INITRAMFS"
make O="$BUILD" olddefconfig

echo "=== 5. kernel build: Image + dtbs ==="
make O="$BUILD" -j"$JOBS" Image dtbs

echo "=== 6. package: lzma + FIT (stock layout: load/entry 0x108000) ==="
MIN_DTB="$BUILD/arch/arm/boot/dts/broadcom/bcm96764sv1-min.dtb"
ls -la "$BUILD/arch/arm/boot/Image" "$MIN_DTB"
lzma -k -f -9 "$BUILD/arch/arm/boot/Image"
mv "$BUILD/arch/arm/boot/Image.lzma" "$OUT/Image-6.6.93-bcm96764.lzma"
cp "$MIN_DTB" "$OUT/bcm96764sv1-min.dtb"

mk_fit() { # $1=its $2=itb $3=kernel.lzma $4=dtb
  cat > "$1" <<EOF
/dts-v1/;
/ {
	description = "BCM96764 Linux 6.6 minimal TFTP test (kernel lzma + fdt)";
	#address-cells = <1>;
	images {
		kernel {
			description = "Linux 6.6.93 minimal";
			data = /incbin/("$3");
			type = "kernel"; os = "linux"; arch = "arm";
			compression = "lzma";
			load = <0x108000>; entry = <0x108000>;
			hash-1 { algo = "sha256"; };
		};
		fdt_min {
			description = "dtb";
			data = /incbin/("$4");
			type = "flat_dt"; arch = "arm"; compression = "none";
			hash-1 { algo = "sha256"; };
		};
	};
	configurations {
		default = "conf_96764_66";
		conf_96764_66 {
			description = "BCM96764 Linux 6.6 minimal";
			kernel = "kernel"; fdt = "fdt_min";
		};
	};
};
EOF
  mkimage -f "$1" -r "$2"
}

mk_fit "$OUT/fit-min.its"   "$OUT/brcm_fit_66_min.itb"   "$OUT/Image-6.6.93-bcm96764.lzma" "$OUT/bcm96764sv1-min.dtb"
mk_fit "$OUT/fit-stock.its" "$OUT/brcm_fit_66_stockdtb.itb" "$OUT/Image-6.6.93-bcm96764.lzma" "$STOCK_DTB"

cp "$BUILD/arch/arm/boot/Image" "$OUT/Image-6.6.93-bcm96764"
cp "$BUILD/.config" "$OUT/config-6.6.93-bcm96764-min"
(cd "$OUT" && sha256sum Image-6.6.93-bcm96764 Image-6.6.93-bcm96764.lzma bcm96764sv1-min.dtb brcm_fit_66_min.itb brcm_fit_66_stockdtb.itb config-6.6.93-bcm96764-min > SHA256SUMS)

echo "=== 7. sizes ==="
ls -la "$OUT"
echo BUILD_DONE
