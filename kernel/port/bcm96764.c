// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal machine shim for Broadcom BCM6764 / BCM96764 (Cudy WR3600 V1).
 *
 * Why this file exists:
 *  - linux-6.6 (same LTS family as OpenWrt 24.10's kernel) already has
 *    ARCH_BCMBCA with GIC / arch-timer / PSCI / PL011 support, i.e. every
 *    driver needed for "decompress -> serial console -> initramfs shell".
 *  - But it has NO DT_MACHINE_START matching "brcm,bcm96764" (and no
 *    bcm96764 .dts at all), so a 6.6 kernel refuses to boot with either the
 *    stock DTB or a ported minimal DTB ("No machine record").
 *  - SMP is via PSCI (stock DTB: psci-0.2/smc + enable-method=psci), so no
 *    platsmp/PMB code is needed for the minimal bring-up.
 *
 * This mirrors what a downstream OpenWrt 24.10 brcmbca target port would
 * carry for this SoC. Upstream-only drivers only; no BCA BSP code.
 */

#include <asm/mach/arch.h>

static const char *const bcm96764_dt_compat[] __initconst = {
	"brcm,bcm96764",
	NULL,
};

DT_MACHINE_START(BCM96764, "Broadcom BCM96764 (minimal bring-up)")
	.l2c_aux_val	= 0,
	.l2c_aux_mask	= ~0,
	.dt_compat	= bcm96764_dt_compat,
MACHINE_END
