#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# load_wifi.sh — ordered load of the BCM 4.19 wifi stack on Linux 6.6.
#
# Runs ON THE ROUTER (OpenWrt 6.6.93, root). Copies of the stock blobs with
# patched vermagic plus our modules must be in $MODDIR (default: current
# directory). Lane H owns this file.
#
# Load order (bottom-up; FACT, dependency+provider analysis 2026-09-07,
# see triaging/shim/SHIM_C_SUMMARY.md):
#   0. enet6764.ko      (Ethernet, already loaded normally — checked only)
#   1. cfg80211.ko      IN-TREE 6.6 (from /lib/modules, modprobe) — NOT the
#                       stock 4.19 blob (REJECTED: 148 UND incl. 27 missing
#                       on 6.6, BCA genl backports clash with nl80211).
#   2. bcm_shim.ko      our compat (vermagic native, plain insmod). Exports
#                       85 non-GPL symbols for the blobs below.
#   3. bcm_knvram.ko    stock, patched vermagic, insmod -f (3 gaps: 2 from
#                       shim + fortify_panic from kernel-after-CONFIG).
#   4. bcmlibs.ko       stock, patched, insmod -f (3 gaps, all from shim).
#   5. wlshared.ko      stock, patched, insmod -f (8 gaps: 4 shim +
#                       NETFILTER + SWITCHDEV from kernel-after-CONFIG).
#   6. hnd.ko           stock, patched, insmod -f (26 gaps: 18 shim +
#                       FORTIFY + PCI from kernel-after-CONFIG).
#   7. bcmmcast.ko      stock, patched, insmod -f (36 gaps: 34 shim +
#                       NETFILTER from kernel-after-CONFIG).
#   8. emf.ko           stock, patched, insmod -f (needs hnd+bcmmcast).
#   9. igs.ko           stock, patched, insmod -f (needs emf+hnd+bcmmcast).
#  10. wl.ko            stock, patched, insmod -f (M3: si_doattach probe).
#
# NOT loaded (deliberate):
#   bcm_pcie_hcd.ko  — stock needs bcm_enet (our enet6764 owns ethernet)
#                      + 46 gaps; lane A (vpcie66) owns BAR/IRQ instead.
#                      wl's 2 symbols from it (bcm_pcie_config/map_bar_addr)
#                      are a lane-A+E item (M3 blocker, stubbed later).
#   dhd.ko           — dongle-mode sibling, not needed for AP bring-up.
#   stock cfg80211.ko— see (1).
#   bcm_enet.ko and friends (archer/pktflow/...) — ethernet lives in
#                      enet6764; the Runner datapath is out of scope.
#
# Safety (SHIM_WORKPLAN rules):
#  - every stage writes a bootmark marker (0xC0..0xCC) BEFORE the insmod,
#    so a bus hang still leaves the last reached stage in
#    reset_reason[31:24] (read back via bootmark.ko after power-cycle).
#  - dmesg is snapshotted before/after each insmod; new "Unknown symbol",
#    "taint", "Oops", "external abort" lines abort the sequence.
#  - the WDT fuse must be armed BEFORE running this (on OpenWrt):
#      echo 3600 > /proc/bcm96764_wdt_kick_secs
#    NOTE: it does NOT save from a hard UBUS hang (run #92) — that needs
#    a physical power-cycle by the operator.
#
# Usage on the router:
#   cd /lib/modules/6.6.93-wifi && ./load_wifi.sh [--dry-run] [--upto hnd]
set -u

MODDIR="${MODDIR:-$(dirname "$0")}"
DRY=0
UPTO="wl"
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1; shift ;;
        --upto) UPTO="${2:-wl}"; shift 2 ;;
        --upto=*) UPTO="${1#--upto=}"; shift ;;
        *) shift ;;
    esac
done

INSMODF="${INSMODF:-$MODDIR/insmodf}"

log() { echo "[load_wifi] $*"; logger -t load_wifi "$*" 2>/dev/null; }
die() { log "FATAL: $*"; exit 1; }

# bootmark helper: bootmark.ko exposes /proc/bootmark `reason=0x..`
mark() {
    # $1 = hex byte
    if [ -e /proc/bootmark ]; then
        echo "mark=$1" > /proc/bootmark 2>/dev/null && return 0
    fi
    if insmod /etc/bootmark.ko "mark=$1" 2>/dev/null; then
        rmmod bootmark 2>/dev/null
        return 0
    fi
    log "note: bootmark unavailable, continuing without marker $1"
    return 0
}

dmesg_new() {
    # $1 = baseline file; prints lines added since, returns count on stdout
    dmesg | tail -n +1 > "$2"
    grep -vxFf "$1" "$2" || true
}

check_fatal() {
    # $1 = new-lines file; abort on Unknown symbol / Oops / abort
    if grep -qE "Unknown symbol|Unknown symbol|module has no symbols|disagrees about version|Oops|external abort|Unable to handle" "$1"; then
        log "--- fatal kernel output ---"
        cat "$1"
        return 1
    fi
    return 0
}

need_file() {
    [ -f "$MODDIR/$1" ] || die "missing $MODDIR/$1"
}

do_insmod() {
    # $1 = marker, $2 = file, $3 = force(0/1), rest = params
    _mk="$1"; _ko="$2"; _force="$3"; shift 3
    need_file "$_ko"
    if lsmod | grep -q "^$(modname "$_ko") "; then
        log "skip: $(modname "$_ko") already loaded"
        return 0
    fi
    mark "$_mk"
    dmesg -c > /dev/null 2>&1
    if [ "$DRY" = 1 ]; then
        log "dry-run: insmod$([ "$_force" = 1 ] && echo " -f") $MODDIR/$_ko $*"
        return 0
    fi
    if [ "$_force" = 1 ]; then
        # busybox insmod (all the OpenWrt image has) does NOT support -f - it
        # takes "-f" as the module name and fails with "Failed to find -f".
        # Force loading goes through our finit_module helper instead
        # (tools/insmodf.c, MODULE_INIT_IGNORE_MODVERSIONS; the kernel honours
        # it because lane B set CONFIG_MODULE_FORCE_LOAD=y).
        # shellcheck disable=SC2086
        "$INSMODF" "$MODDIR/$_ko" $* 2>/tmp/insmod_err.txt
    else
        # shellcheck disable=SC2086
        insmod "$MODDIR/$_ko" $* 2>/tmp/insmod_err.txt
    fi
    _rc=$?
    _new="$(dmesg)"
    echo "$_new" | grep -qE "bcm_shim|hnd:|wl0|wl1|si_doattach" && echo "$_new" | tail -5
    if [ $_rc -ne 0 ]; then
        log "insmod $_ko failed rc=$_rc:"
        cat /tmp/insmod_err.txt
        log "dmesg tail:"; echo "$_new" | tail -8
        return 1
    fi
    if echo "$_new" | grep -qE "Unknown symbol|Oops|external abort|Unable to handle"; then
        log "insmod $_ko returned 0 BUT kernel reports trouble:"
        echo "$_new" | grep -E "Unknown symbol|Oops|external abort|Unable to handle" | head -10
        return 1
    fi
    log "ok: $_ko"
    return 0
}

# internal module name (from .modinfo `name=`, not the file name):
# bcm_shim.ko->bcm_shim, wl66.ko->wl, hnd66.ko->hnd, ...
modname() {
    case "$1" in
        wl66.ko) echo wl ;; hnd66.ko) echo hnd ;;
        wlshared66.ko) echo wlshared ;; emf66.ko) echo emf ;;
        igs66.ko) echo igs ;; bcmmcast66.ko) echo bcmmcast ;;
        bcmlibs66.ko) echo bcmlibs ;; bcm_knvram66.ko) echo bcm_knvram ;;
        bcm_shim.ko) echo bcm_shim ;; *) echo "${1%.ko}" ;;
    esac
}

log "MODDIR=$MODDIR UPTO=$UPTO dry=$DRY"
log "WDT fuse: $(cat /proc/bcm96764_wdt_kick_secs 2>/dev/null || echo MISSING)"

# stage 0: sanity — ethernet alive, kernel version as expected
uname -r | grep -q "^6\.6\.93" || die "unexpected kernel: $(uname -r)"
lsmod | grep -q "^enet6764" || log "WARN: enet6764 not loaded (ethernet usually built-in here?)"

# stage 1: in-tree cfg80211 (MUST come from /lib/modules, not $MODDIR)
mark 0xC0
if ! lsmod | grep -q "^cfg80211"; then
    if [ "$DRY" = 1 ]; then log "dry-run: modprobe cfg80211"; else
        modprobe cfg80211 || die "modprobe cfg80211 failed"
    fi
fi
[ "$UPTO" = "cfg80211" ] && { log "reached --upto $UPTO"; exit 0; }

# stage 2: our shim (native vermagic — no force)
do_insmod 0xC6 bcm_shim.ko 0 "mark=0xC6" || die "bcm_shim failed"
[ "$UPTO" = "shim" ] && { log "reached --upto $UPTO"; exit 0; }

# stages 3..10: stock blobs, patched vermagic, forced (no CRCs in blobs)
do_insmod 0xC7 bcm_knvram66.ko 1 || die "bcm_knvram failed"
[ "$UPTO" = "knvram" ] && exit 0
do_insmod 0xC7 bcmlibs66.ko 1 || die "bcmlibs failed"
[ "$UPTO" = "bcmlibs" ] && exit 0
do_insmod 0xC8 wlshared66.ko 1 || die "wlshared failed (M2 gate)"
[ "$UPTO" = "wlshared" ] && exit 0
do_insmod 0xC7 hnd66.ko 1 || die "hnd failed (M2 gate)"
[ "$UPTO" = "hnd" ] && exit 0
log "M2 gate: hnd+wlshared loaded:"
lsmod | grep -E "^(hnd|wlshared|bcm_shim|cfg80211|bcm_knvram|bcmlibs)"
do_insmod 0xC9 bcmmcast66.ko 1 || die "bcmmcast failed"
[ "$UPTO" = "bcmmcast" ] && exit 0
do_insmod 0xCA emf66.ko 1 || die "emf failed"
[ "$UPTO" = "emf" ] && exit 0
do_insmod 0xCB igs66.ko 1 || die "igs failed"
[ "$UPTO" = "igs" ] && exit 0
do_insmod 0xCC wl66.ko 1 || die "wl failed (M3 gate)"
log "M3 gate: wl loaded:"
lsmod | grep -E "^(wl|hnd|emf|igs)"
log "wiphy check:"; ls /sys/class/ieee80211/ 2>/dev/null || log "(no wiphy yet — expected before M4)"
mark 0xCC
log "load_wifi.sh DONE"
