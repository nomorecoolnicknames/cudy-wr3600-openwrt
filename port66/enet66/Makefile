# SPDX-License-Identifier: GPL-2.0
#
# One module, three compilation units. See NOTES.md.
#
# Out-of-tree build:
#   make -C /home/n8n/cudy_be3600/kernel-6.6/src/linux-6.6.93 \
#        O=/home/n8n/cudy_be3600/kernel-6.6/build \
#        M=/home/n8n/cudy_be3600/port66/enet66 \
#        ARCH=arm \
#        CROSS_COMPILE=/home/n8n/cudy_be3600/gpl/openwrt/21.02/build_dir/toolchains/crosstools-arm_softfp-gcc-10.3-linux-4.19-glibc-2.32-binutils-2.36.1/bin/arm-buildroot-linux-gnueabi- \
#        modules

obj-m += enet6764.o

enet6764-y := pmc6764.o sf2_6764.o sysport6764.o

ccflags-y += -Wall
