#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Host-side check of wl66ctl's chanspec encoder against the values recovered
# from the stock CLI (triaging/wifi-width/WL_IOCTL_SPEC.md §4). No ioctls.
set -e
d=$(dirname "$0")
t=$(mktemp)
gcc -O2 -Wall -o "$t" "$d/wl66ctl.c"
rc=0
for c in "1:0x1001" "6/40u:0x1904" "6/40l:0x1808" "6u:0x1904" "36/80:0xe02a" \
	 "100/80:0xe06a" "36/160:0xe832" "5g149/80:0xe09b" "6g1/320-1:0x7000" \
	 "6g37/320-2:0x7041" "36:0xd024" "149/80:0xe09b" "40/80:0xe12a"; do
	s=${c%%:*}; want=${c##*:}
	got=$("$t" spec "$s" | cut -d' ' -f1)
	[ "$got" = "$want" ] && echo "ok   $s = $got" || { echo "FAIL $s = $got (want $want)"; rc=1; }
done
rm -f "$t"
exit $rc
