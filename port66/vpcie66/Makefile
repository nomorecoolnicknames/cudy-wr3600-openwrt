# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build for the vpcie66 modules (M4: on-chip WLAN cores).
#
#   make            build wlprobe66.ko
#   make clean
#
# Depends on port66/enet66 (pmc6764_wlan_power_up) and on the kernel symbol
# bcm96764_mark, so enet66 has to be built first and its Module.symvers passed
# in, exactly like enet66b does:
#
#   make KBUILD_EXTRA_SYMBOLS=$(REPO)/port66/enet66/Module.symvers

REPO    ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
KDIR    ?= $(REPO)/kernel-6.6/src/linux-6.6.93
KOUT    ?= $(REPO)/kernel-6.6/build
CROSS   ?= $(REPO)/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi-
ARCH    ?= arm
M       := $(CURDIR)

# vpcie66 uses pmc6764_wlan_power_up() + bcm96764_mark() from enet66,
# exactly like wlprobe66 does; pass its symvers so modpost can check.
# Override on the command line if enet66 was built elsewhere.
ENET_SYMVERS ?= $(REPO)/port66/enet66/Module.symvers

KBUILD_ARGS = -C $(KDIR) O=$(KOUT) M=$(M) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS)

KBUILD_EXTRA_SYMBOLS ?= $(ENET_SYMVERS)

KBUILD_ARGS += KBUILD_EXTRA_SYMBOLS="$(KBUILD_EXTRA_SYMBOLS)"

.PHONY: all modules clean

all modules:
	$(MAKE) $(KBUILD_ARGS) modules

clean:
	$(MAKE) $(KBUILD_ARGS) clean
