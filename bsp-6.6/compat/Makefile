# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree build for the 6.6 wifi-shim modules (bcm_shim.ko + legacy
# bcm_compat.ko). kbuild file is Kbuild (owned by integrator, lane H).
#
# Default (cross, 6.6.93 target):
#   make            build bcm_shim.ko bcm_compat.ko
#   make clean
#
#   make -C /home/n8n/cudy_be3600/kernel-6.6/src/linux-6.6.93 \
#        O=/home/n8n/cudy_be3600/kernel-6.6/build \
#        M=/home/n8n/cudy_be3600/bsp-6.6/compat \
#        ARCH=arm \
#        CROSS_COMPILE=/home/n8n/cudy_be3600/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi- \
#        modules
#
# Native/smoke build against another tree:
#   make KDIR=/path/to/src KOUT=/path/to/build CROSS= ARCH=

KDIR    ?= /home/n8n/cudy_be3600/kernel-6.6/src/linux-6.6.93
KOUT    ?= /home/n8n/cudy_be3600/kernel-6.6/build
CROSS   ?= /home/n8n/cudy_be3600/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi-
ARCH    ?= arm
M       := $(CURDIR)

KBUILD_ARGS = -C $(KDIR) O=$(KOUT) M=$(M) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS)

ifneq ($(KBUILD_EXTRA_SYMBOLS),)
KBUILD_ARGS += KBUILD_EXTRA_SYMBOLS="$(KBUILD_EXTRA_SYMBOLS)"
endif

.PHONY: all modules clean

all modules:
	$(MAKE) $(KBUILD_ARGS) modules

clean:
	$(MAKE) $(KBUILD_ARGS) clean
