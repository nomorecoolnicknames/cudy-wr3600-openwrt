# SPDX-License-Identifier: GPL-2.0-only
#
# 6.6 helper modules that the stock wl.ko blob needs at run time
# (see kernel-6.6/rootfs-overlay-release/etc/init.d/wifi66).
#
# Out-of-tree build (release):
#   make -C <kernel-src> O=<kernel-build> M=port66/shim66 \
#        ARCH=arm CROSS_COMPILE=<toolchain-> modules
#
# h30_*_probe/observe/lookup modules are diagnostics only; the release loads
# h30_bpm_live, h30_ubus_all, h30_ubus_probe and h30_irqgate.

obj-m += h30_bpm_live.o
obj-m += h30_xpm_observe.o
obj-m += h30_ubus_probe.o
obj-m += h30_ubus_all.o
obj-m += h30_rx_snapshot.o
obj-m += h30_lookup_probe.o
obj-m += h30_irqgate.o

ccflags-y += -I$(src)/../../bsp-6.6/compat
