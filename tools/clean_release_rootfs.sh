#!/bin/bash
# ---------------------------------------------------------------------------
# Make an OpenWrt staging tree fit for public release.
#
#   clean_release_rootfs.sh <staging-tree> <pristine-openwrt-rootfs.sq>
#
# The staging tree used during bring-up accumulated test scaffolding and
# personal data. This script removes all of it and repairs the damage done to
# /etc/uci-defaults (the bring-up tree has those scripts replaced by
# character devices, so they never ran). It is idempotent and fails loudly if
# anything personal survives.
# ---------------------------------------------------------------------------
set -euo pipefail

S=${1:?usage: clean_release_rootfs.sh <staging-tree> <pristine-rootfs.sq>}
BASE=${2:?usage: clean_release_rootfs.sh <staging-tree> <pristine-rootfs.sq>}

say() { printf -- '--- %s\n' "$*"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

[ -d "$S/etc" ] || die "not an OpenWrt tree: $S"
[ -f "$BASE" ]  || die "missing pristine rootfs: $BASE"

# --- 1. /etc/uci-defaults: restore the upstream scripts --------------------
# The bring-up tree has them as character devices (0,0): OpenWrt could never
# run them. Take the real files from the pristine OpenWrt 24.10.2 image.
say "restoring /etc/uci-defaults from $(basename "$BASE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
unsquashfs -ignore-errors -no-exit-code -q -d "$TMP" "$BASE" etc/uci-defaults >/dev/null
[ -d "$TMP/etc/uci-defaults" ] || die "no /etc/uci-defaults in $BASE"
rm -rf "$S/etc/uci-defaults"
mkdir -p "$S/etc/uci-defaults"
cp -a "$TMP/etc/uci-defaults/." "$S/etc/uci-defaults/"

# --- 2. test scaffolding ---------------------------------------------------
say "removing bring-up scaffolding"
rm -f "$S/etc/init.d/aa-netconsole" "$S/etc/rc.d/S09aa-netconsole"
rm -f "$S/etc/init.d/zz-diag"       "$S/etc/rc.d/S99zz-diag"

# --- 3. personal data ------------------------------------------------------
# podkop gate/subscription cache (real VLESS endpoint + UUID) and the
# sing-box config generated from it. The firmware ships an empty podkop
# account; the user enters their own access key in LuCI.
say "removing personal VPN data"
rm -f "$S/etc/podkop/sota_gate.json"
rm -f "$S/etc/sing-box/config.json"
if [ -f "$S/etc/config/podkop" ]; then
	sed -i "s#^\t*option access_key .*#\toption access_key ''#" \
		"$S/etc/config/podkop"
	sed -i "s#^\t*option gate_id .*#\toption gate_id ''#" \
		"$S/etc/config/podkop"
fi

# --- 4. generated keys/certs ----------------------------------------------
# Baked-in dropbear host keys would be identical on every device; let dropbear
# generate them on first boot. Same for the LuCI self-signed certificate.
say "removing baked host keys and certificates"
rm -f "$S/etc/dropbear/dropbear_rsa_host_key" \
      "$S/etc/dropbear/dropbear_ed25519_host_key"
rm -f "$S/etc/uhttpd.crt" "$S/etc/uhttpd.key"
rm -rf "$S/etc/ssl/private"
rm -f "$S/etc/urandom.seed"

# --- 5. /etc/config/system: no debug netconsole, neutral hostname ----------
say "cleaning /etc/config/system"
if [ -f "$S/etc/config/system" ]; then
	sed -i -E '/^[[:space:]]*option[[:space:]]+log_(ip|port|proto|size)[[:space:]]/d' \
		"$S/etc/config/system"
	sed -i "s#^\([[:space:]]*option[[:space:]]*hostname[[:space:]]*\).*#\1'CudyWR3600'#" \
		"$S/etc/config/system"
fi

# --- 6. verification -------------------------------------------------------
say "verification"
rc=0

devs=$(find "$S" -type c -o -type b | head -20)
if [ -n "$devs" ]; then
	echo "device nodes left:"; echo "$devs"; rc=1
fi

if [ "$(find "$S/etc/uci-defaults" -type f | wc -l)" -lt 10 ]; then
	echo "uci-defaults looks incomplete"; rc=1
fi

# Values that must never ship: the maintainer's own VPN subscription IDs and
# the bench addresses. Keep them out of the sources - read them from the
# environment (BENCH_SECRETS) or from a gitignored tools/bench_secrets.local
# file, both of which are checked below.
_bench_local="$(dirname "$0")/bench_secrets.local"
[ -f "$_bench_local" ] && . "$_bench_local"
personal="${BENCH_SECRETS:-}"
# bench networks plus any UUID-shaped string (a subscription id) are enough to
# fail the release; the exact ids come from BENCH_SECRETS when available.
pattern="192\.168\.1\.(88|119|120)|192\.168\.10\.(55|99)|gunwest"
[ -n "$personal" ] && pattern="$pattern|$personal"
if grep -rIl -E "$pattern" "$S" >/dev/null 2>&1; then
	echo "personal/test data left:"
	grep -rIl -E "$personal|192\.168\.1\.88|192\.168\.1\.119|192\.168\.1\.120|192\.168\.10\.55|gunwest" "$S" | head -20
	rc=1
fi

if [ -n "$(ls -A "$S/etc/dropbear" 2>/dev/null)" ]; then
	echo "dropbear dir not empty: $(ls -A "$S/etc/dropbear")"; rc=1
fi

[ "$rc" = 0 ] || die "release rootfs still contains junk"
say "rootfs clean"

# Root password: the published image ships a *known* password on purpose.
# Users flash and update the box themselves, often with no LAN cable (over
# Wi-Fi only), so the credentials have to be predictable and documented. The
# WAN input filter in wifi66 is what keeps the internet side out; change this
# (and the AP passphrase 12345678) if your LAN is not trusted.
# sha512-crypt, fixed salt -> the build stays reproducible.
ROOT_HASH='$6$cudy$PMzBoiSY.3eDAynpvEePbKrXSX/B0daJ7jsUzDxPcTeKPr6UzwcGgGDikcg0K270iNaE4qkqtEpHN4nGcnXwv1'
if [ -f "$S/etc/shadow" ]; then
	sed -i "s|^root:[^:]*:|root:$ROOT_HASH:|" "$S/etc/shadow"
	grep -q '^root:\$6\$cudy\$' "$S/etc/shadow" ||
		die "failed to set the root password"
else
	die "no /etc/shadow in the rootfs"
fi
