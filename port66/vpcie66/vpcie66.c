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
 * Upstream API used (6.6.93, drivers/pci/probe.c): one struct
 * pci_host_bridge per radio block, created with pci_alloc_host_bridge()
 * (NOT the devm variant: devm_of_pci_bridge_init() would parse a bus-range
 * of [00-ff] from our DT node and pci_scan_root_bus_bridge() would then
 * move the root bus to 0, while the contract demands bus 1), filled in
 * (busnr=1, domain_nr=linux,pci-domain, ops, map_irq, swizzle_irq,
 * MEM window + explicit busn [1,1] resources) and enumerated with
 * pci_host_probe() = scan + BAR assignment + pci_bus_add_devices().
 * dev->irq comes from map_irq() (D11MAC virq) via pci_assign_irq().
 *
 * Only PCI config space is emulated. No radio register is touched here;
 * the only hardware access is the optional BPCM power-up through
 * pmc6764_wlan_power_up() (PMC procmon keyhole, proven safe on 6.6 by
 * wlprobe66, runs #93+), mirroring VENDOR bcmvpcie_hc_pwrup_dev().
 *
 * Contract source: SHIM_WORKPLAN.md lane A + WIFI_CORE_MAP.md; DT nodes
 * vpcie@0/vpcie@1 in fdt_96764SV1-66.dtb (brcm,coreid/devid,
 * linux,pci-domain, 10 interrupts, reg windows).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/pci_regs.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../enet66/enet6764.h"
#include "vpcie66.h"

#define DRV_NAME	"vpcie66"

static bool powerup = true;
module_param(powerup, bool, 0444);
MODULE_PARM_DESC(powerup,
	"call pmc6764_wlan_power_up(coreid) in probe (PMC only, no radio regs)");

/*
 * Per-radio-block state. Lives in the host bridge private area, so it is
 * valid from the first config-space access (during pci_host_probe) until
 * after pci_remove_root_bus().
 */
struct vpcie66_vdev {
	struct pci_host_bridge *bridge;
	u32 coreid;		/* brcm,coreid = PCI slot */
	u32 devid;		/* brcm,devid, e.g. 0x603b */
	u32 domain;		/* linux,pci-domain */
	u32 bus;		/* always 1, like VENDOR defdev_cfg */
	u32 slot;		/* == coreid */
	u8 rev;			/* PCI revision id (DT brcm,revid or coreid) */
	struct resource busn;	/* bus-number window [1,1], pins root busnr */
	struct resource memwin;	/* radio window, also the bridge MEM window */
	int irq[VPCIE66_IRQ_MAX];
	int nirq;
	u32 bar_size[6];
	u32 cfg[VPCIE66_CFG_WORDS];
};

/*
 * Config-space template, words 0x00..0xFC. Byte-for-byte the VENDOR
 * PCIE_VDEV_FILL_CFG_REG() table (pcie-vdev.h), with the four per-device
 * fields patched by vpcie66_build_cfg(): device_vendor_id [0x00],
 * rev_id_class_code [0x08], bar_1 [0x10], subsystem [0x2c] and the
 * vendor capability @0x68 (IRQs, patched separately).
 */
static const u32 vpcie66_cfg_tpl[VPCIE66_CFG_WORDS] = {
	0x00000000, 0x00100000, 0x00000000, 0x00000000, /* 00 */
	0x00000000, 0x00000000, 0x00000004, 0x00000000, /* 10 */
	0x0000000c, 0x00000000, 0x00000000, 0x00000000, /* 20 */
	0x00000000, 0x00000048, 0x00000000, 0x00000000, /* 30 */
	0x00000000, 0x00000000, 0x06035801, 0x00004108, /* 40 */
	0x00000000, 0x00000000, 0x008b6805, 0x00000000, /* 50 */
	0x00000000, 0x00000000, 0x0000a009, 0x00000000, /* 60 */
	0x28100000, 0x00000000, 0x00000000, 0x00000000, /* 70 */
	0x28000000, 0x00000000, 0x00000080, 0x00000000, /* 80 */
	0x00000000, 0x00000100, 0x00000000, 0x00000000, /* 90 */
	0x003fac11, 0x00008000, 0x00008800, 0x00020010, /* a0 */
	0x00008f82, 0x00102c10, 0x0046dc22, 0x10220000, /* b0 */
	0x00000000, 0x00000000, 0x00000000, 0x00000000, /* c0 */
	0x0008081f, 0x00000000, 0x00000006, 0x00000002, /* d0 */
	0x00000000, 0x00000000, 0x00000000, 0x00000000, /* e0 */
	0x00000000, 0x00000000, 0x00000000, 0x00000000, /* f0 */
};

/* Fill the per-device config space. IRQs must already be collected. */
static void vpcie66_build_cfg(struct vpcie66_vdev *vh)
{
	u32 dev_vend = (vh->devid << 16) | PCI_VENDOR_ID_BROADCOM;
	u8 *b;
	int i;

	memcpy(vh->cfg, vpcie66_cfg_tpl, sizeof(vh->cfg));

	vh->cfg[PCI_VENDOR_ID / 4] = dev_vend;
	vh->cfg[PCI_REVISION_ID / 4] =
		(PCI_CLASS_NETWORK_OTHER << 16) | vh->rev;
	/* BAR0: 64-bit memory BAR at the radio window base (VENDOR: base|0x04) */
	vh->cfg[PCI_BASE_ADDRESS_0 / 4] =
		(u32)(vh->memwin.start & PCI_BASE_ADDRESS_MEM_MASK) |
		PCI_BASE_ADDRESS_MEM_TYPE_64;
	vh->cfg[PCI_SUBSYSTEM_VENDOR_ID / 4] = dev_vend;
	/* INTA#, interrupt line = D11MAC virq (low byte, like VENDOR) */
	vh->cfg[PCI_INTERRUPT_LINE / 4] =
		0x00000100 | (vh->irq[VPCIE66_IRQ_D11MAC] & 0xff);

	/*
	 * Vendor capability @0x68: cap_id 0x09 / next 0xa0 come from the
	 * template; patch version, length and the IRQ table in DT order
	 * (VENDOR bcmvpcie_hc_parse_slot_dt writes wifi_irq[] the same way).
	 */
	b = (u8 *)vh->cfg;
	b[VPCIE66_CAP_VNDR + 2] = VPCIE66_VNDR_LEN_BASE +
				  vh->nirq * sizeof(u16);
	b[VPCIE66_CAP_VNDR + 3] = 0x01; /* version */
	for (i = 0; i < vh->nirq; i++) {
		u16 virq = (u16)vh->irq[i];

		b[VPCIE66_CAP_VNDR + 4 + i * 2] = virq & 0xff;
		b[VPCIE66_CAP_VNDR + 5 + i * 2] = (virq >> 8) & 0xff;
	}
}

/* Slot/bus match, mirroring VENDOR bcmvpcie_hc_access_valid(). */
static bool vpcie66_access_valid(struct vpcie66_vdev *vh,
				 struct pci_bus *bus, unsigned int devfn)
{
	return bus->number == vh->bus && PCI_SLOT(devfn) == vh->slot;
}

static int vpcie66_cfg_read(struct pci_bus *bus, unsigned int devfn,
			    int where, int size, u32 *val)
{
	struct vpcie66_vdev *vh = bus->sysdata;
	u32 v;

	if (!vpcie66_access_valid(vh, bus, devfn))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (where < 0 || where >= VPCIE66_CFG_SIZE)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	/* memcpy: LE byte copy, no alignment traps on odd IRQ-cap reads. */
	if (size == 1)
		*val = *((u8 *)vh->cfg + where);
	else if (size == 2)
		memcpy(val, (u8 *)vh->cfg + where, 2);
	else if (size == 4)
		memcpy(val, &vh->cfg[where / 4], 4);
	else
		return PCIBIOS_BAD_REGISTER_NUMBER;

	if (size == 4) {
		v = *val;
		/*
		 * BAR sizing protocol (VENDOR bcmvpcie_hc_config_read):
		 * the core writes ~0 then reads back the size mask.
		 */
		if (v == 0xffffffff && where >= PCI_BASE_ADDRESS_0 &&
		    where <= PCI_BASE_ADDRESS_5)
			*val = ~(vh->bar_size[(where - PCI_BASE_ADDRESS_0) / 4] - 1);
		else if (where == PCI_ROM_ADDRESS)
			*val = 0xffffffff; /* no expansion ROM */
	}

	return PCIBIOS_SUCCESSFUL;
}

static int vpcie66_cfg_write(struct pci_bus *bus, unsigned int devfn,
			     int where, int size, u32 val)
{
	struct vpcie66_vdev *vh = bus->sysdata;

	if (!vpcie66_access_valid(vh, bus, devfn))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (where < 0 || where >= VPCIE66_CFG_SIZE)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	/* Blind store, exactly like VENDOR bcmvpcie_hc_config_write. */
	if (size == 1)
		*((u8 *)vh->cfg + where) = val;
	else if (size == 2)
		memcpy((u8 *)vh->cfg + where, &val, 2);
	else if (size == 4)
		vh->cfg[where / 4] = val;
	else
		return PCIBIOS_BAD_REGISTER_NUMBER;

	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops vpcie66_pci_ops = {
	.read = vpcie66_cfg_read,
	.write = vpcie66_cfg_write,
};

/*
 * Legacy INTx mapping: D11MAC IRQ, like VENDOR bcmvpcie_hc_map_irq()
 * (irq[PCIE_VDEV_IRQ_IDX_D11MAC]). Reached via pci_assign_irq() during
 * pci_bus_add_devices() because swizzle_irq is set.
 */
static int vpcie66_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_host_bridge *hb = pci_find_host_bridge(dev->bus);
	struct vpcie66_vdev *vh = pci_host_bridge_priv(hb);
	int irq = vh->irq[VPCIE66_IRQ_D11MAC];

	dev_dbg(&dev->dev, DRV_NAME ": map_irq slot %u pin %u -> %d\n",
		slot, pin, irq);
	return irq > 0 ? irq : -1;
}

static int vpcie66_parse_dt(struct platform_device *pdev, struct vpcie66_vdev *vh)
{
	struct device_node *np = pdev->dev.of_node;
	struct resource mlo;
	u32 v;
	int i, err;

	err = of_property_read_u32(np, "brcm,coreid", &v);
	if (err)
		return dev_err_probe(&pdev->dev, err, "missing brcm,coreid\n");
	vh->coreid = v & 0xf;
	vh->slot = vh->coreid;

	err = of_property_read_u32(np, "brcm,devid", &v);
	if (err)
		return dev_err_probe(&pdev->dev, err, "missing brcm,devid\n");
	vh->devid = v & 0xffff;

	/* Domain: stock DT carries linux,pci-domain (0/1); else use coreid. */
	if (of_property_read_u32(np, "linux,pci-domain", &v))
		v = vh->coreid;
	vh->domain = v;
	vh->bus = 1; /* VENDOR defdev_cfg bus, gives 0000:01:00.0-style BDFs */

	if (!of_property_read_u32(np, "brcm,revid", &v))
		vh->rev = v & 0xff;
	else
		vh->rev = vh->coreid & 0xff;

	/* reg[0] = the 128M radio window, translated (0x90000000/0x98000000). */
	err = of_address_to_resource(np, 0, &vh->memwin);
	if (err)
		return dev_err_probe(&pdev->dev, err, "no translatable reg[0]\n");
	if (resource_size(&vh->memwin) != VPCIE66_WIN_SIZE)
		dev_warn(&pdev->dev, "window %pR is not 128M, using as-is\n",
			 &vh->memwin);
	vh->memwin.name = dev_name(&pdev->dev);
	vh->bar_size[0] = resource_size(&vh->memwin);

	/* reg[1] = MLO window: logged only, never mapped (VENDOR mlo_reg). */
	if (!of_address_to_resource(np, 1, &mlo))
		dev_info(&pdev->dev, "MLO window %pR (not mapped)\n", &mlo);

	/*
	 * DT interrupt order already is the vendor-capability order
	 * [CCM, D11MAC, M2MDMA, WDRST, M2MDMA1, MLC, PHY,
	 *  THERM_HIGH, THERM_LOW, THERM_SHUTDOWN].
	 */
	vh->nirq = 0;
	for (i = 0; i < VPCIE66_IRQ_MAX; i++) {
		err = of_irq_get(np, i);
		if (err == -EPROBE_DEFER)
			return err;
		if (err <= 0) {
			dev_warn(&pdev->dev, "no DT irq index %d, rest zero\n",
				 i);
			break;
		}
		vh->irq[i] = err;
		vh->nirq++;
	}
	if (vh->nirq <= VPCIE66_IRQ_D11MAC ||
	    vh->irq[VPCIE66_IRQ_D11MAC] <= 0)
		return dev_err_probe(&pdev->dev, -ENODEV,
				     "no D11MAC IRQ (got %d irqs)\n", vh->nirq);

	return 0;
}

static int vpcie66_probe(struct platform_device *pdev)
{
	struct pci_host_bridge *bridge;
	struct vpcie66_vdev *vh;
	struct pci_dev *vdev;
	int err;

	bcm96764_mark(VPCIE66_MK_ENTER);

	bridge = pci_alloc_host_bridge(sizeof(*vh));
	if (!bridge)
		return -ENOMEM;
	vh = pci_host_bridge_priv(bridge);
	vh->bridge = bridge;

	err = vpcie66_parse_dt(pdev, vh);
	if (err) {
		bcm96764_mark(VPCIE66_MK_ERR);
		goto err_free;
	}
	bcm96764_mark(VPCIE66_MK_DT_OK);

	dev_info(&pdev->dev,
		 "coreid %u devid 0x%04x domain %u window %pR D11MAC virq %d\n",
		 vh->coreid, vh->devid, vh->domain, &vh->memwin,
		 vh->irq[VPCIE66_IRQ_D11MAC]);

	if (powerup) {
		bcm96764_mark(VPCIE66_MK_PMC_PRE);
		err = pmc6764_wlan_power_up(vh->coreid);
		if (err) {
			dev_warn(&pdev->dev,
				 "pmc6764_wlan_power_up(%u) = %d, continuing (PCI emulation unaffected)\n",
				 vh->coreid, err);
			bcm96764_mark(VPCIE66_MK_WARN_PMC);
			err = 0;
		} else {
			bcm96764_mark(VPCIE66_MK_PMC_OK);
		}
	}

	vpcie66_build_cfg(vh);

	bridge->dev.parent = &pdev->dev;
	bridge->sysdata = vh;
	bridge->busnr = vh->bus;
	bridge->domain_nr = vh->domain;
	bridge->ops = &vpcie66_pci_ops;
	bridge->swizzle_irq = pci_common_swizzle;
	bridge->map_irq = vpcie66_map_irq;

	vh->busn.start = vh->bus;
	vh->busn.end = vh->bus;
	vh->busn.flags = IORESOURCE_BUS;
	vh->busn.name = dev_name(&pdev->dev);
	pci_add_resource(&bridge->windows, &vh->busn);

	vh->memwin.flags &= ~IORESOURCE_UNSET;
	vh->memwin.flags |= IORESOURCE_MEM;
	pci_add_resource(&bridge->windows, &vh->memwin);
	bcm96764_mark(VPCIE66_MK_BRIDGE);

	err = pci_host_probe(bridge);
	if (err) {
		dev_err(&pdev->dev, "pci_host_probe failed: %d\n", err);
		bcm96764_mark(VPCIE66_MK_ERR);
		goto err_windows;
	}
	bcm96764_mark(VPCIE66_MK_SCAN_OK);

	/* M1 self-check: the device the blob will look for must be there. */
	vdev = pci_get_slot(bridge->bus, PCI_DEVFN(vh->slot, 0));
	if (!vdev) {
		dev_err(&pdev->dev, "no pci device at %04x:%02x:%02x.0 after scan\n",
			vh->domain, vh->bus, vh->slot);
		err = -ENODEV;
		bcm96764_mark(VPCIE66_MK_ERR);
		goto err_remove;
	}
	dev_info(&pdev->dev,
		 "pci %04x:%02x:%02x.0 vendor 0x%04x device 0x%04x class 0x%06x BAR0 %pr irq %d\n",
		 vh->domain, vh->bus, vh->slot,
		 vdev->vendor, vdev->device, vdev->class,
		 &vdev->resource[0], vdev->irq);
	if (vdev->vendor != PCI_VENDOR_ID_BROADCOM ||
	    vdev->device != vh->devid ||
	    pci_resource_start(vdev, 0) != (vh->memwin.start & PCI_BASE_ADDRESS_MEM_MASK) ||
	    pci_resource_len(vdev, 0) != resource_size(&vh->memwin) ||
	    vdev->irq != vh->irq[VPCIE66_IRQ_D11MAC]) {
		dev_err(&pdev->dev, "M1 mismatch (want dev 0x%04x BAR0 %#llx/128M irq %d)\n",
			vh->devid, (unsigned long long)vh->memwin.start,
			vh->irq[VPCIE66_IRQ_D11MAC]);
		pci_dev_put(vdev);
		err = -ENODEV;
		bcm96764_mark(VPCIE66_MK_ERR);
		goto err_remove;
	}
	pci_dev_put(vdev);
	bcm96764_mark(VPCIE66_MK_VERIFY_OK);

	platform_set_drvdata(pdev, vh);
	bcm96764_mark(VPCIE66_MK_DONE);
	dev_info(&pdev->dev, DRV_NAME ": hosting %04x:%02x:%02x.0\n",
		 vh->domain, vh->bus, vh->slot);
	return 0;

err_remove:
	pci_stop_root_bus(bridge->bus);
	pci_remove_root_bus(bridge->bus);
err_windows:
	pci_free_resource_list(&bridge->windows);
err_free:
	pci_free_host_bridge(bridge);
	return err;
}

static void vpcie66_remove(struct platform_device *pdev)
{
	struct vpcie66_vdev *vh = platform_get_drvdata(pdev);
	struct pci_host_bridge *bridge;

	if (!vh)
		return;
	bridge = vh->bridge;
	pci_stop_root_bus(bridge->bus);
	pci_remove_root_bus(bridge->bus);
	pci_free_resource_list(&bridge->windows);
	pci_free_host_bridge(bridge);
}

static const struct of_device_id vpcie66_of_match[] = {
	{ .compatible = "brcm,bcm963xx-vpcie" },
	{ }
};
MODULE_DEVICE_TABLE(of, vpcie66_of_match);

static struct platform_driver vpcie66_driver = {
	.probe = vpcie66_probe,
	.remove_new = vpcie66_remove,
	.driver = {
		.name = DRV_NAME,
		.of_match_table = vpcie66_of_match,
	},
};

module_platform_driver(vpcie66_driver);

MODULE_DESCRIPTION("BCM6764 virtual PCI host for on-chip WLAN cores");
MODULE_LICENSE("GPL");
