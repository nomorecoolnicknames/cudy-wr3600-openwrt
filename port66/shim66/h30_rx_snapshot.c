// SPDX-License-Identifier: GPL-2.0-only
/* Read-only snapshot for the audited H30 shim/stock blob pair.
 * Native private prefix: shim_netdev.c. Legacy chain: wl_open and wlc_up.
 * DMA fields: dma_rx/dma_rxfill; all RAM accesses use nofault copies.
 * No stored pointer survives this module init or its native dev reference.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/smp.h>
#include <net/net_namespace.h>

struct prefix {
	struct list_head list;
	struct net_device *native;
	void *old;
};

static bool cpu_only;
module_param(cpu_only, bool, 0444);
MODULE_PARM_DESC(cpu_only, "Read CPU attributes only, without fabric or radio accesses");
static unsigned int radio_idx;
module_param(radio_idx, uint, 0444);
MODULE_PARM_DESC(radio_idx, "Audited legacy radio index, 0 or 1");
static bool state_only;
module_param(state_only, bool, 0444);
MODULE_PARM_DESC(state_only, "Read legacy readiness RAM only, without radio DMA/MMIO");

static void cpu_attributes(void *unused)
{
	u32 sctlr, actlr, prrr, nmrr, ttbr;
	(void)unused;
	asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r" (sctlr));
	asm volatile("mrc p15, 0, %0, c1, c0, 1" : "=r" (actlr));
	asm volatile("mrc p15, 0, %0, c10, c2, 0" : "=r" (prrr));
	asm volatile("mrc p15, 0, %0, c10, c2, 1" : "=r" (nmrr));
	asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r" (ttbr));
	pr_info("H30_CPU_ATTR cpu=%u sctlr=%08x actlr=%08x prrr=%08x nmrr=%08x ttbr=%08x\n",
		smp_processor_id(), sctlr, actlr, prrr, nmrr, ttbr);
}

static u32 get32(const void *p, unsigned int off)
{
	u32 value = 0;
	if (p)
		copy_from_kernel_nofault(&value, (u8 *)p + off, sizeof(value));
	return value;
}

static u16 get16(const u8 *p, unsigned int off)
{
	u16 value;
	memcpy(&value, p + off, sizeof(value));
	return value;
}

static void inspect(void *di, const char *kind, unsigned int channel)
{
	u8 d[400];
	u32 regs, rxd, status[6], desc[4];
	u16 n, in, out;
	unsigned int i;
	if (!di || copy_from_kernel_nofault(d, di, sizeof(d)))
		return;
	n = get16(d, 122);
	in = get16(d, 124);
	out = get16(d, 126);
	regs = get32(d, 56);
	rxd = get32(d, 64);
	pr_info("H30_RXSNAP %s%u di=%px flags=%08x n=%u in=%u out=%u post=%u size=%u offset=%u pool=%u f6=%02x xpm=%u chan=%u descsz=%u regs=%08x rxd=%08x pa=%08x\n",
		kind, channel, di, get32(d, 4), n, in, out, get32(d, 176),
		get16(d, 170), get32(d, 180), d[245], d[246], d[392], d[384],
		get32(d, 316), regs, rxd, get32(d, 160));
	pr_info("H30_RXSNAP mask=%08x cached=%u list=%08x/%08x headroom=%u\n",
		get32(d, 228), get16(d, 232), get32(d, 304), get32(d, 308), get32(d, 172));
	if (channel == 0 && kind[0] == 'd') {
		/* mlc_hwalite_is_enable and mlc_hwalite_rxfifo_cd: mapped cursor table.
		 * MLO RX uses these producer cursors, not the direct RX status. */
		void *mlo = (void *)(unsigned long)get32(d, 320);
		void *cursors = (void *)(unsigned long)get32(mlo, 2652);
		pr_info("H30_RXSNAP hwalite=%u mlo=%px cursors=%px\n",
			get32(mlo, 2644) & 0xff, mlo, cursors);
		for (i = 0; cursors && i < 9; i++)
			pr_info("H30_RXSNAP hwalite_cd[%u]=%08x\n", i, get32(cursors, i * 4));
	}
	if (n < 2 || n > 8192 || !is_power_of_2(n) ||
	    in >= n || out >= n || get32(d, 316) != 16)
		return;
	/* Audited linked-list descriptors (dma_rxfill next@4, data@40).
	 * Only the first 32 bytes of hardware RX metadata; no packet payload.
	 * Concurrent DMA is not stopped: this is a bounded diagnostic snapshot. */
	if (get32(d, 4) & 0x10000) {
		void *skb = (void *)(unsigned long)get32(d, 304);
		for (i = 0; skb && i < 2 && virt_addr_valid(skb); i++) {
			u32 header[8];
			void *data = (void *)(unsigned long)get32(skb, 40);
			if (data && virt_addr_valid(data) &&
			    !copy_from_kernel_nofault(header, data, sizeof(header)))
				pr_info("H30_RXSNAP buffer%u skb=%px data=%px len=%u header=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x\n",
					i, skb, data, get32(skb, 44), header[0], header[1],
					header[2], header[3], header[4], header[5], header[6], header[7]);
			skb = (void *)(unsigned long)get32(skb, 4);
		}
	}
	/* These six read-only RX DMA register words are used by dma_rx.
	 * Avoid treating direct-mapped RAM or a NULL pointer as MMIO. */
	if (regs >= 0xe0000000 && regs < 0xff000000 && !(regs & 3)) {
		for (i = 0; i < ARRAY_SIZE(status); i++)
			status[i] = readl((void __iomem *)(unsigned long)regs + i * 4);
		pr_info("H30_RXSNAP regs control=%08x ptr=%08x base=%08x:%08x status=%08x/%08x\n",
			status[0], status[1], status[3], status[2], status[4], status[5]);
	}
	if (rxd && !copy_from_kernel_nofault(desc, (void *)(unsigned long)(rxd + in * 16), sizeof(desc)))
		pr_info("H30_RXSNAP desc_in=%08x/%08x/%08x/%08x\n", desc[0], desc[1], desc[2], desc[3]);
	for (i = 1; rxd && i <= 3; i++) {
		u32 index = (in + i) & (n - 1);
		if (!copy_from_kernel_nofault(desc, (void *)(unsigned long)(rxd + index * 16), sizeof(desc)))
			pr_info("H30_RXSNAP desc[%u]=%08x/%08x/%08x/%08x\n",
				index, desc[0], desc[1], desc[2], desc[3]);
	}
}

static int __init start(void)
{
	/* Other stock coherent UBUS masters, from stock decode_cfg readback. */
	static const u32 fabric[] = { 0x83020a00, 0x83010a00, 0x83050a00 };
	struct net_device *dev;
	struct prefix e;
	void *wlif, *wl, *wlc, *hw;
	unsigned int i;
	int ret = -EINVAL;
	static_assert(offsetof(struct prefix, native) == 8);
	static_assert(offsetof(struct prefix, old) == 12);
	if (radio_idx > 1)
		return -EINVAL;
	on_each_cpu(cpu_attributes, NULL, 1);
	if (cpu_only)
		return 0;
	for (i = 0; i < ARRAY_SIZE(fabric); i++) {
		void __iomem *p = ioremap(fabric[i], 8);
		if (!p)
			return -ENOMEM;
		pr_info("H30_RXSNAP fabric=%08x ctrl=%08x cache=%08x\n",
			fabric[i], readl(p), readl(p + 4));
		iounmap(p);
	}
	rtnl_lock();
	dev = dev_get_by_name(&init_net, radio_idx ? "wl1" : "wl0");
	if (!dev)
		goto out;
	if (copy_from_kernel_nofault(&e, netdev_priv(dev), sizeof(e)) || e.native != dev || !e.old)
		goto put;
	wlif = (void *)(unsigned long)get32(e.old, 1408);
	wl = (void *)(unsigned long)get32(wlif, 8);
	wlc = (void *)(unsigned long)get32(wl, 8);
	hw = (void *)(unsigned long)get32(wlc, 24);
	if (get32(wl, 16) != (u32)(unsigned long)e.old ||
	    !wlc || !hw || get32(hw, 0) != (u32)(unsigned long)wlc)
		goto put;
	pr_info("H30_RXSNAP links old=%px wlif=%px wl=%px wlc=%px hw=%px running=%d\n",
		e.old, wlif, wl, wlc, hw, netif_running(dev));
	{
		/* wlc_mlo_wlc_up: skip/gate flags and all-radio readiness mask. */
		void *pub = (void *)(unsigned long)get32(wlc, 0);
		void *common = (void *)(unsigned long)get32(wlc, 12);
		void *ctx = (void *)(unsigned long)get32(wlc, 2720);
		/* wl attach +0x30e618 gates wl_mlo_ipc_init on pub[578]. */
		pr_info("H30_RXSNAP PUB radio=%u up28=%u word576=%08x ipc578=%u\n",
			radio_idx, get32(pub, 28) & 0xff, get32(pub, 576),
			(get32(pub, 576) >> 16) & 0xff);
		if (ctx && get32(ctx, 0) == (u32)(unsigned long)wlc)
			pr_info("H30_RXSNAP MLO radio=%u id=%u pub354=%u ready355=%u common8=%u flags452=%08x flags456=%08x upmask462=%02x\n",
				radio_idx, get32(wlc, 36) & 0xffff,
				get32(pub, 354) & 0xff, get32(pub, 355) & 0xff,
				get32(common, 8) & 0xff, get32(ctx, 452), get32(ctx, 456),
				get32(ctx, 462) & 0xff);
	}
	if (!state_only) {
		for (i = 0; i < 3; i++)
			inspect((void *)(unsigned long)get32(hw, 20 + i * 4), "dma", i);
		for (i = 0; i < 2; i++)
			inspect((void *)(unsigned long)get32(hw, 3484 + i * 4), "mlo", i);
	}
	pr_info("H30_RXSNAP DONE\n");
	ret = 0;
put:
	dev_put(dev);
out:
	rtnl_unlock();
	return ret;
}
static void __exit finish(void) { }
module_init(start);
module_exit(finish);
MODULE_LICENSE("GPL");
