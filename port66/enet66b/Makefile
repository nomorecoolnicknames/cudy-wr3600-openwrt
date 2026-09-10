# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build for the enet66b modules.
#
#   make            build serdes6764.ko, extsw6764.ko, enet66b_mdio.ko
#   make clean
#   make ENET66B_STANDALONE_MDIO=0 \
#        KBUILD_EXTRA_SYMBOLS=$(REPO)/port66/enet66/Module.symvers
#                   build without the local SF2 MDIO master and resolve
#                   sf2_mdio_read()/sf2_mdio_write() against the SoC-side
#                   driver in port66/enet66 instead.  Without the extra
#                   symbols file modpost fails on those two symbols, which is
#                   the intended signal that the SoC driver is not exporting
#                   them yet.
#
# The kernel tree must already be configured and built: Module.symvers has to
# contain bcm96764_mark.

REPO    ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
KDIR    ?= $(REPO)/kernel-6.6/src/linux-6.6.93
KOUT    ?= $(REPO)/kernel-6.6/build
CROSS   ?= $(REPO)/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi-
ARCH    ?= arm
M       := $(CURDIR)

ENET66B_STANDALONE_MDIO ?= 1

KBUILD_ARGS = -C $(KDIR) O=$(KOUT) M=$(M) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) \
	      ENET66B_STANDALONE_MDIO=$(ENET66B_STANDALONE_MDIO)

ifneq ($(KBUILD_EXTRA_SYMBOLS),)
KBUILD_ARGS += KBUILD_EXTRA_SYMBOLS="$(KBUILD_EXTRA_SYMBOLS)"
endif

.PHONY: all modules clean ucode

all modules:
	$(MAKE) $(KBUILD_ARGS) modules

clean:
	$(MAKE) $(KBUILD_ARGS) clean

# regenerate merlin16_shortfin_ucode.h from the vendor U-Boot GPL header
ucode:
	./gen_ucode.sh
