#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# unload_wifi.sh — reverse-order unload of the wifi stack.
#
# Runs ON THE ROUTER. Strict reverse of load_wifi.sh. Stops at the first
# failure and reports (a module stuck after a failed module_init can NOT
# be removed even with CONFIG_MODULE_UNLOAD=y — FACT, run #93 tail:
# rmmod -> 255 — then the only way forward is `reboot`, which returns to
# the same 6.6 slot; see SHIM_C_SUMMARY.md test plan).
#
# Usage: ./unload_wifi.sh
set -u

log() { echo "[unload_wifi] $*"; logger -t unload_wifi "$*" 2>/dev/null; }

ORDER="wl igs emf bcmmcast hnd wlshared bcmlibs bcm_knvram bcm_shim cfg80211"
FILEMAP="wl:wl66 hnd:hnd66 wlshared:wlshared66 emf:emf66 igs:igs66 bcmmcast:bcmmcast66 bcmlibs:bcmlibs66 bcm_knvram:bcm_knvram66 bcm_shim:bcm_shim cfg80211:cfg80211"

modfile() {
    echo "$FILEMAP" | tr ' ' '\n' | awk -F: -v m="$1" '$1==m{print $2}'
}

fail=0
for m in $ORDER; do
    if lsmod | grep -q "^${m} "; then
        if rmmod "$m" 2>/tmp/rmmod_err.txt; then
            log "ok: rmmod $m"
        else
            log "FAIL: rmmod $m rc=$? $(cat /tmp/rmmod_err.txt)"
            log "dmesg tail:"; dmesg | tail -5
            fail=1
            break
        fi
    else
        log "skip: $m (not loaded)"
    fi
done

if [ "$fail" = 1 ]; then
    log "UNLOAD INCOMPLETE — still loaded:"; lsmod | grep -E "^(wl|hnd|emf|igs|bcmmcast|wlshared|bcmlibs|bcm_knvram|bcm_shim|cfg80211)"
    log "if a module died in module_init, reboot is required (rmmod -> 255 is expected)"
    exit 1
fi
log "unload_wifi.sh DONE — wifi stack fully unloaded"
