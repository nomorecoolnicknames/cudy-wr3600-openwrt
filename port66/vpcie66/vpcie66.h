/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vpcie66 - virtual PCI host for the BCM6764 on-chip WLAN cores (Linux 6.6).
 *
 * The two radio blocks are plain AXI backplane cores, not real PCIe
 * endpoints, but the stock fullmac blob (radio/wl.ko, built for 4.19)
 * only attaches through struct pci_dev (__pci_register_driver,
 * pci_enable_device, pci_find_capability, pci_alloc_irq_vectors_affinity).
 * This module re-hosts the vendor emulation
 * (GPL: bcmdrivers/opensource/bus/pci/host/impl1/pcie-vcore.c +
 * pcie-vdev.h, hereafter "VENDOR") on the upstream 6.6 PCI core so that
 * wl.ko finds the devices it expects:
 *
 *   0000:01:00.0  vendor:device 0x14e4:0x603b  BAR0 0x90000000/128M
 *   0001:01:01.0  vendor:device 0x14e4:0x6038  BAR0 0x98000000/128M
 *
 * Contract source: SHIM_WORKPLAN.md lane A + WIFI_CORE_MAP.md; DT nodes
 * vpcie@0/vpcie@1 in fdt_96764SV1-66.dtb (brcm,coreid/devid,
 * linux,pci-domain, 10 interrupts, reg windows).
 *
 * Only PCI config space is emulated. No radio register is touched here;
 * the only hardware access is the optional BPCM power-up through
 * pmc6764_wlan_power_up() (PMC procmon keyhole, proven safe on 6.6 by
 * wlprobe66, runs #93+), mirroring VENDOR bcmvpcie_hc_pwrup_dev().
 */
#ifndef _VPCIE66_H
#define _VPCIE66_H

#include <linux/types.h>

/* One platform device (one vpcie@N DT node) = one domain = one vdev. */
#define VPCIE66_MAX_DEVS		1	/* like VENDOR MAX_NUM_VDEV */

/* PCI config space template: 256 bytes = 64 u32 words. */
#define VPCIE66_CFG_SIZE		0x100
#define VPCIE66_CFG_WORDS		(VPCIE66_CFG_SIZE / 4)

/* Capability offsets (VENDOR pcie_cfg_space_regs + SHIM_WORKPLAN lane A). */
#define VPCIE66_CAP_PM			0x48
#define VPCIE66_CAP_MSI			0x58
#define VPCIE66_CAP_VNDR		0x68
#define VPCIE66_CAP_MSIX		0xa0
#define VPCIE66_CAP_PCIE		0xac

/*
 * Vendor-specific capability @0x68 layout (VENDOR struct pcie_vdev_cap_vndr):
 *   +0x00: cap_id(0x09) next_ptr(0xa0) length version(0x01)
 *   +0x04: 10 x u16 wifi_irq, then reserved.
 */
#define VPCIE66_VNDR_LEN_BASE		1	/* + sizeof(u16) per IRQ */

/* IRQ indices inside the vendor capability (VENDOR PCIE_VDEV_IRQ_IDX_*). */
enum vpcie66_irq_idx {
	VPCIE66_IRQ_CCM = 0,
	VPCIE66_IRQ_D11MAC = 1,		/* <- dev->irq (stock: IRQ 36/46) */
	VPCIE66_IRQ_M2MDMA = 2,
	VPCIE66_IRQ_WDRST = 3,
	VPCIE66_IRQ_M2MDMA1 = 4,
	VPCIE66_IRQ_MLC = 5,
	VPCIE66_IRQ_PHY = 6,
	VPCIE66_IRQ_THERM_HIGH = 7,
	VPCIE66_IRQ_THERM_LOW = 8,
	VPCIE66_IRQ_THERM_SHUTDOWN = 9,
	VPCIE66_IRQ_MAX = 10,
};

/*
 * Stage markers for bcm96764_mark(), reset_reason[31:24].
 * 0xB0..0xBF is taken by wlprobe66, 0x60..0x6F/0xE0..0xEF by enet6764;
 * 0xA0..0xAF was free at the time of writing (checked 2026-09-07).
 */
#define VPCIE66_MK_ENTER	0xA0
#define VPCIE66_MK_DT_OK	0xA1
#define VPCIE66_MK_PMC_PRE	0xA2
#define VPCIE66_MK_PMC_OK	0xA3
#define VPCIE66_MK_BRIDGE	0xA4
#define VPCIE66_MK_SCAN_OK	0xA5
#define VPCIE66_MK_VERIFY_OK	0xA6
#define VPCIE66_MK_DONE		0xA7
#define VPCIE66_MK_WARN_PMC	0xAE
#define VPCIE66_MK_ERR		0xAF

/* Expected window size; a different DT value is honoured but warned about. */
#define VPCIE66_WIN_SIZE	0x08000000u	/* 128 MiB */

#endif /* _VPCIE66_H */
