// SPDX-License-Identifier: GPL-2.0
/*
 * BCM6764 SYSTEMPORT v2.1 MAC + netdev, and the module entry point for
 * enet6764.ko.
 *
 * Port of UB/drivers/net/bcmbca/bcmbca_sysport_v2.c (copy in
 * port66/bcmbca_sysport_v2.c), with UB = gpl/.../u-boot-2019.07/.
 * The register programming in sp_hw_init() below is __sp_init()
 * (bcmbca_sysport_v2.c:162-278) line for line; the enable/TX/RX paths follow
 * sysport_init() / __sp_send() / __sp_recv().
 *
 * Ordering, mirroring the reference:
 *   probe : map windows -> allocate DMA buffers -> sf2_6764_init()
 *           (which itself does PMC power-up, switch reset, GPHY power-up,
 *           phy_advertise_caps, switch config) -> register_netdev
 *   open  : sf2_6764_open() (port enable + PBVLAN) -> sp_hw_init() ->
 *           enable RDMA -> enable TDMA -> start polling
 *
 * RX and TX completion are polled from NAPI, driven by a periodic hrtimer.
 * No interrupt is claimed: the stock DT puts the six SYSTEMPORT interrupts on
 * a separate "sysport-blk" node (GIC SPI 0x4c..0x51) and the vendor tree does
 * not document which index carries RX buffer-done, so claiming one blind
 * risks an unhandled-IRQ storm during bring-up.
 */

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>

#include "enet6764.h"

/* Fixed MAC. The stock U-Boot environment uses 02:10:18:00:00:01 for its own
 * interface; this one is deliberately different so both can be on the wire.
 */
static const u8 sp_mac_addr[ETH_ALEN] = { 0x02, 0x10, 0x18, 0x00, 0x00, 0x02 };

static unsigned int poll_us = 1000;
module_param(poll_us, uint, 0644);
MODULE_PARM_DESC(poll_us, "RX/TX poll period in microseconds (default 1000)");

#define SP_TX_RING		0	/* the single TX descriptor ring we use */
#define SP_RX_QUEUE		0
#define SP_TX_TIMEOUT_MS	200

/* Per-netdev private area. In split mode there are two of them (WAN and LAN)
 * over one shared SYSTEMPORT: one DMA block, one RX ring, one TX ring, one
 * NAPI instance and one poll timer. The role picks the TX directed-egress
 * map and the RX demux target (REPORT.md §2.1-§2.4). */
struct sp_priv {
	struct sysport6764	*sp;
	struct net_device	*ndev;
	u16			dest_map;
	int			role;
};

struct sysport6764 {
	struct device		*dev;
	struct sf2_6764		*sf2;

	void __iomem		*rbuf;
	void __iomem		*rdma;
	void __iomem		*tdma;
	void __iomem		*topctrl;

	/* one coherent block: [0] = TX buffer, [1..SP_NUM_RX_BUFS] = RX */
	void			*dma_va;
	dma_addr_t		dma_pa;
	size_t			dma_len;

	struct napi_struct	napi;
	struct hrtimer		poll_timer;
	bool			running;

	struct net_device	*ndevs[SP_MAX_NETDEVS];
	int			n_ndevs;
	struct net_device	*napi_ndev;	/* owns the shared NAPI */
	struct net_device	*wan_ndev;
	struct net_device	*lan_ndev;

	/* open/stop refcount: hardware comes up on 0->1, goes down on 1->0,
	 * so closing one netdev never kills the other (risk R5) */
	struct mutex		lock;
	int			open_count;

	spinlock_t		tx_lock;
	bool			tx_busy;
	u16			tx_cidx_pre;
	unsigned int		tx_len;
	unsigned long		tx_start;
	struct net_device	*tx_ndev;	/* owner of the in-flight TX */

	int			tag_fmt;	/* enum sp_tag_fmt */

	bool			seen_tx;
	bool			seen_rx;
	bool			rx_entered;
	bool			rx_done_once;
	bool			budget_hit;
};

/* Broadcom tag (4 bytes after DA+SA). Egress, as the stock impl7 driver
 * does (bcmenet_common.h: BRCM_TAG2_EGRESS 0x2000 = opcode 1 "directed
 * egress", then a 16-bit destination port map): "20 00 <map>". The switch
 * strips it on egress and inserts an ingress tag on frames to the CPU,
 * which we decode (split mode) and strip in software (RBUF is told not to
 * strip it). See triaging/shim/sf2-vlan/REPORT.md.
 */
static int brcm_tag_port = 5;
static int rx_marks = 1;
module_param(rx_marks, int, 0644);
static int tx_marks = 1;
module_param(tx_marks, int, 0644);
MODULE_PARM_DESC(tx_marks, "write 0x70..0x74 stage markers in the TX path (run #65)");
module_param(brcm_tag_port, int, 0444);
MODULE_PARM_DESC(brcm_tag_port, "-1: no tag; else directed-egress port map bit (split=0 only)");

/* WAN/LAN split (triaging/shim/sf2-vlan/REPORT.md). split=0 is the proven
 * single-netdev configuration; split=1 creates eth0=WAN (root P0) and
 * eth1=LAN (root P5 + external 53134) and demuxes RX by ingress tag.
 */
int enet6764_split;
module_param_named(split, enet6764_split, int, 0444);
MODULE_PARM_DESC(split, "1 = separate WAN (P0) and LAN (P5) netdevs; 0 = single eth0 (default)");

unsigned int enet6764_wan_port_sel = SF2_EN_MAN_TO_WAN | (1u << SP_SPLIT_WAN_PORT);
module_param_named(wan_port_sel, enet6764_wan_port_sel, uint, 0444);
MODULE_PARM_DESC(wan_port_sel, "SF2 WAN_PORT_SEL (0x130) in split mode; R2 fallbacks 0x001/0x200");

static int tag_fmt = SP_TAG_FMT_B53;
module_param(tag_fmt, int, 0644);
MODULE_PARM_DESC(tag_fmt, "split RX tag decode: 1 = b53 byte3[4:0], 2 = vendor type2 0x888a bitmap");

static int rx_diag;
module_param(rx_diag, int, 0644);
MODULE_PARM_DESC(rx_diag, "print the first N RX ingress tags (raw bytes + both decodes) to dmesg");

static inline void *sp_tx_va(struct sysport6764 *sp)
{
	return sp->dma_va;
}

static inline dma_addr_t sp_tx_pa(struct sysport6764 *sp)
{
	return sp->dma_pa;
}

static inline void *sp_rx_va(struct sysport6764 *sp, int i)
{
	return sp->dma_va + SP_DMA_BUFSIZE * (SP_NUM_TX_BUFS + i);
}

static inline dma_addr_t sp_rx_pa(struct sysport6764 *sp, int i)
{
	return sp->dma_pa + SP_DMA_BUFSIZE * (SP_NUM_TX_BUFS + i);
}

/* Decode the source port from a 4-byte ingress Broadcom tag. Returns -1 when
 * the tag does not match the selected format. Both formats are documented in
 * REPORT.md §1.4; tag_fmt selects which one is authoritative (risk R1).
 */
static int sp_tag_src_port(const u8 *tag, int fmt)
{
	if (fmt == SP_TAG_FMT_TYPE2) {
		if (tag[0] != SP_TAG_TYPE2_HI || tag[1] != SP_TAG_TYPE2_LO)
			return -1;
		/* HYPOTHESIS: bytes 2..3 hold a source-port bitmap */
		return ffs(((u16)tag[2] << 8) | tag[3]) - 1;
	}

	/* b53: byte0[7:5] == opcode 0 on ingress, byte3[4:0] == source port */
	if ((tag[0] >> 5) & 0x7)
		return -1;
	return tag[3] & SP_TAG_SRC_PORT_MASK;
}

/* ------------------------------------------------------------------ */
/* descriptor helpers                                                 */
/* ------------------------------------------------------------------ */

/*
 * The RX descriptors live in the SYSTEMPORT's own on-chip RAM at the start of
 * the RDMA window, not in DDR, so they are touched with readl/writel.
 * Layout: word0 = buffer address, word1 = { address_hi:8; status:10;
 * length:14 } little-endian -> length occupies bits 31:18
 * (bcmbca_sysport_v2.h:36-41).
 */
static void sp_rx_desc_set(struct sysport6764 *sp, int i, dma_addr_t pa)
{
	void __iomem *d = sp->rdma + RDMA_DESCRIPTOR + i * SP_DESC_STRIDE;
	u32 w1;

	w1 = ((u32)SP_DMA_BUFSIZE << SP_DESC_LEN_SHIFT) |
	     (upper_32_bits((u64)pa) & SP_DESC_ADDR_HI_MASK);

	writel(lower_32_bits(pa), d + 0);
	writel(w1, d + 4);
}

/* init_pkt_desc(), bcmbca_sysport_v2.c:68-80 -- note length = 2048, which the
 * broken earlier draft zeroed. */
static void sp_init_rx_descs(struct sysport6764 *sp)
{
	int i;

	for (i = 0; i < SP_NUM_RX_BUFS; i++)
		sp_rx_desc_set(sp, i, sp_rx_pa(sp, i));
}

/* ------------------------------------------------------------------ */
/* hardware init                                                      */
/* ------------------------------------------------------------------ */

/* __sp_init(), bcmbca_sysport_v2.c:162-278 */
static void sp_hw_init(struct sysport6764 *sp)
{
	u32 v;
	int i;

	/* RBUF: no RSB, no 4-byte IP alignment, keep the BRCM tag, discard
	 * bad packets (v2.c:169-177)
	 */
	v = readl(sp->rbuf + RBUF_CONTROL);
	v &= ~RBUF_CTRL_RSB_MODE_M;
	v &= ~RBUF_CTRL_4B_ALIGN_M;
	v &= ~RBUF_CTRL_BTAG_STRIP_M;
	v |= RBUF_CTRL_BAD_PKT_DISCARD_M;
	writel(v, sp->rbuf + RBUF_CONTROL);
	writel(0x80, sp->rbuf + RBUF_PACKET_READY_THR);

	/* RDMA (v2.c:201-225). RDMA_CONTROL is deliberately left at its chip
	 * default apart from the enable bit, exactly as the reference does.
	 */
	writel(RDMA_RING_EN | SP_NUM_RX_BUFS,
	       sp->rdma + RDMA_LOCRAM_DESCRING_SIZE(SP_RX_QUEUE));
	writel(SP_PKT_LEN_LOG2, sp->rdma + RDMA_PKTBUF_SIZE(SP_RX_QUEUE));
	writel(0, sp->rdma + RDMA_CINDEX(SP_RX_QUEUE));
	/* RDMA_PINDEX is read-only on 6764 (v2.c:208-210) -- do not write it */
	writel(0, sp->rdma + RDMA_DDR_DESC_RING_START(0));
	writel(0, sp->rdma + RDMA_DDR_DESC_RING_START(1));

	sp_init_rx_descs(sp);

	writel(SP_RX_DESC_LOG2, sp->rdma + RDMA_DDR_DESC_RING_SIZE(SP_RX_QUEUE));

	/* TDMA (v2.c:239-274) */
	writel(TDMA_DESC_RING_CONTROL_RING_EN,
	       sp->tdma + TDMA_DESC_RING_CONTROL(SP_TX_RING));
	/* RD_MAX_BURST_SIZE / RD_MIN_BURST_SIZE = 8, for 16-byte descriptors */
	writel(0x0808, sp->tdma + TDMA_DDR_DESC_RING_CTRL(SP_TX_RING));
	writel(0, sp->tdma + TDMA_DESC_RING_PC_INDEX(SP_TX_RING));
	writel(0, sp->tdma + TDMA_DDR_DESC_RING_START(0));
	writel(0, sp->tdma + TDMA_DDR_DESC_RING_START(1));
	writel(0x40, sp->tdma + TDMA_DESC_RING_MAPPING(SP_TX_RING));
	writel(0x1, sp->tdma + TDMA_DDR_DESC_RING_PUSH_TIMER(SP_TX_RING));
	writel(SP_TX_DESC_LOG2, sp->tdma + TDMA_DDR_DESC_RING_SIZE(SP_TX_RING));
	writel(0x3, sp->tdma + TDMA_DESC_RING_INTR_CONTROL(SP_TX_RING));
	writel(0x00100009, sp->tdma + TDMA_DESC_RING_MAX_THRESHOLD(SP_TX_RING));

	writel(0x1, sp->tdma + TDMA_TIER2_ARBITER_CTRL);	/* round robin */
	for (i = 0; i < 4; i++)
		writel(0x1, sp->tdma + TDMA_TIER1_ARBITER_CTRL(i));
	writel(0x000000ff, sp->tdma + TDMA_TIER1_ARBITER_QUEUE_EN(0));
	writel(0x0000ff00, sp->tdma + TDMA_TIER1_ARBITER_QUEUE_EN(1));
	writel(0x00ff0000, sp->tdma + TDMA_TIER1_ARBITER_QUEUE_EN(2));
	writel(0xff000000, sp->tdma + TDMA_TIER1_ARBITER_QUEUE_EN(3));

	v = readl(sp->tdma + TDMA_CONTROL);
	v &= ~TDMA_CONTROL_TSB_EN_M;		/* no TX status block */
	v &= ~TDMA_CONTROL_RING_CFG_M;		/* no DDR descriptor fetch */
	v &= ~TDMA_CONTROL_ACB_EN_M;		/* no ACB */
	writel(v, sp->tdma + TDMA_CONTROL);

	/* v2.c:274 narrows the tier-1 queue enable back to queue 0 */
	writel(0x1, sp->tdma + TDMA_TIER1_ARBITER_QUEUE_EN(0));
}

/* __sp_enable_rdma(), v2.c:122-141, with a real timeout */
static int sp_enable_rdma(struct sysport6764 *sp)
{
	u32 v;
	int i;

	writel(readl(sp->rdma + RDMA_CONTROL) | RDMA_CTRL_RDMA_EN_M,
	       sp->rdma + RDMA_CONTROL);

	for (i = 0; i < 1000; i++) {
		v = readl(sp->rdma + RDMA_STATUS);
		if (!(v & 0x3))
			return 0;
		udelay(10);
	}
	netdev_err(sp->napi_ndev, "RDMA not ready, status 0x%08x\n", v);
	bcm96764_mark(MK_ERR_RDMA);
	return -ETIMEDOUT;
}

/* __sp_enable_tdma(), v2.c:83-102, with a real timeout */
static int sp_enable_tdma(struct sysport6764 *sp)
{
	u32 v;
	int i;

	writel(readl(sp->tdma + TDMA_CONTROL) |
	       TDMA_CONTROL_TDMA_EN_M | TDMA_CONTROL_TPD_16B_EN,
	       sp->tdma + TDMA_CONTROL);

	for (i = 0; i < 1000; i++) {
		v = readl(sp->tdma + TDMA_STATUS);
		if (!(v & 0x3))
			return 0;
		udelay(10);
	}
	netdev_err(sp->napi_ndev, "TDMA not ready, status 0x%08x\n", v);
	bcm96764_mark(MK_ERR_TDMA);
	return -ETIMEDOUT;
}

/* sysport_reset(), v2.c:679-764, minus the GIB/UMAC/xbow blocks which this
 * SoC's DT does not expose.
 */
static void sp_hw_stop(struct sysport6764 *sp)
{
	u32 v;
	u16 p_idx, c_idx;
	int i;

	/* Disable and flush RX */
	writel(readl(sp->rdma + RDMA_CONTROL) & ~RDMA_CTRL_RDMA_EN_M,
	       sp->rdma + RDMA_CONTROL);
	writel(1, sp->topctrl + TOPCTRL_RX_FLUSH_CNTL);

	/* Disable TX and wait for the ring to drain */
	writel(readl(sp->tdma + TDMA_CONTROL) & ~TDMA_CONTROL_TDMA_EN_M,
	       sp->tdma + TDMA_CONTROL);

	for (i = 0; i < 1000; i++) {
		v = readl(sp->tdma + TDMA_DESC_RING_PC_INDEX(SP_TX_RING));
		p_idx = v & 0xffff;
		c_idx = (v >> 16) & 0xffff;
		if (p_idx == c_idx)
			break;
		usleep_range(1000, 2000);
	}
	if (i == 1000)
		netdev_warn(sp->napi_ndev, "TX ring did not drain (p %u c %u)\n",
			    p_idx, c_idx);
	writel(0, sp->tdma + TDMA_DESC_RING_PC_INDEX(SP_TX_RING));

	writel(1, sp->topctrl + TOPCTRL_TX_FLUSH_CNTL);
	usleep_range(100, 200);
	writel(0, sp->topctrl + TOPCTRL_RX_FLUSH_CNTL);
	writel(0, sp->topctrl + TOPCTRL_TX_FLUSH_CNTL);
}

/* ------------------------------------------------------------------ */
/* RX                                                                 */
/* ------------------------------------------------------------------ */

/* __sp_recv(), v2.c:558-589, with the length field read from the right bits.
 * In split mode the ingress Broadcom tag also selects the target netdev:
 * src port 0 = WAN, anything else = LAN (REPORT.md §2.4).
 */
static int sp_rx_one(struct sysport6764 *sp)
{
	void __iomem *d;
	struct sk_buff *skb;
	const u8 *buf;
	struct net_device *ndev = sp->lan_ndev;
	u32 p_idx, c_idx, w1;
	unsigned int idx, len;
	int src_port = -1;
	bool tagged = enet6764_split || brcm_tag_port >= 0;

	p_idx = readl(sp->rdma + RDMA_PINDEX(SP_RX_QUEUE)) & 0xffff;
	c_idx = readl(sp->rdma + RDMA_CINDEX(SP_RX_QUEUE)) & 0xffff;
	if (p_idx == c_idx)
		return -EAGAIN;
	if (!sp->rx_entered) {	/* MK 0x6E: RX ring has work (p != c) */
		sp->rx_entered = true;
		bcm96764_mark(0x6E);
	}

	/* run #70: livelock guard. If the producer index runs more than a ring
	 * ahead, resync the consumer index to the producer instead of spinning. */
	if (((p_idx - c_idx) & 0xffff) > SP_NUM_RX_BUFS) {
		if (rx_marks)
			bcm96764_mark(0x7C);
		ndev->stats.rx_fifo_errors++;
		writel(p_idx, sp->rdma + RDMA_CINDEX(SP_RX_QUEUE));
		return -EAGAIN;
	}
	idx = c_idx % SP_NUM_RX_BUFS;
	d = sp->rdma + RDMA_DESCRIPTOR + idx * SP_DESC_STRIDE;
	w1 = readl(d + 4);
	len = (w1 >> SP_DESC_LEN_SHIFT) & SP_DESC_LEN_MASK;

	if (len < SP_ENET_ZLEN || len > SP_MAX_PKT_LEN) {
		if (rx_marks)
			bcm96764_mark(0x7B);
		ndev->stats.rx_errors++;
		ndev->stats.rx_length_errors++;
		netdev_dbg(ndev, "RX desc %u bad length %u (word1 0x%08x)\n",
			   idx, len, w1);
		goto out;
	}

	buf = sp_rx_va(sp, idx);
	if (tagged && len > 12 + SP_TAG_LEN) {
		const u8 *tag = buf + 12;

		/* R1: print the raw tag and both decodes for the first
		 * rx_diag packets without changing the routing */
		if (rx_diag > 0) {
			int b53 = ((tag[0] >> 5) & 0x7) ? -1 :
				  (tag[3] & SP_TAG_SRC_PORT_MASK);
			int t2 = (tag[0] == SP_TAG_TYPE2_HI &&
				  tag[1] == SP_TAG_TYPE2_LO) ?
				 ffs(((u16)tag[2] << 8) | tag[3]) - 1 : -1;

			rx_diag--;
			dev_info(sp->dev,
				 "rx tag %02x %02x %02x %02x len %u: b53 src %d, type2 src %d\n",
				 tag[0], tag[1], tag[2], tag[3], len, b53, t2);
		}

		if (enet6764_split) {
			src_port = sp_tag_src_port(tag, sp->tag_fmt);
			if (src_port == SP_SPLIT_WAN_PORT && sp->wan_ndev)
				ndev = sp->wan_ndev;
		}
	}

	skb = netdev_alloc_skb_ip_align(ndev, len);
	if (!skb) {
		ndev->stats.rx_dropped++;
		goto out;
	}

	if (tagged && len > 12 + SP_TAG_LEN) {
		memcpy(skb_put(skb, 12), buf, 12);
		memcpy(skb_put(skb, len - 12 - SP_TAG_LEN),
		       buf + 12 + SP_TAG_LEN, len - 12 - SP_TAG_LEN);
	} else {
		memcpy(skb_put(skb, len), buf, len);
	}
	skb->protocol = eth_type_trans(skb, ndev);
	ndev->stats.rx_packets++;
	ndev->stats.rx_bytes += len;

	if (!sp->seen_rx) {
		sp->seen_rx = true;
		bcm96764_mark(MK_FIRST_RX);
		netdev_info(ndev, "first RX packet, %u bytes (src port %d)\n",
			    len, src_port);
	}

	napi_gro_receive(&sp->napi, skb);
	if (rx_marks)
		bcm96764_mark(0x7A);

out:
	/* Re-arm the descriptor. The hardware overwrites status and length in
	 * place, so restore both to the state sp_init_rx_descs() created.
	 */
	sp_rx_desc_set(sp, idx, sp_rx_pa(sp, idx));
	/* v2.c:586: advance the consumer index by one. The upper half is
	 * read-only, so only the low 16 bits are written back.
	 */
	writel((c_idx + 1) & 0xffff, sp->rdma + RDMA_CINDEX(SP_RX_QUEUE));
	if (!sp->rx_done_once) {	/* MK 0x6F: first descriptor consumed */
		sp->rx_done_once = true;
		if (!sp->seen_rx)
			bcm96764_mark(0x6F);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* TX                                                                 */
/* ------------------------------------------------------------------ */

static void sp_tx_reclaim(struct sysport6764 *sp)
{
	struct net_device *ndev;
	unsigned long flags;
	bool done = false, stuck = false;
	u32 v;
	u16 c_idx;
	int i;

	spin_lock_irqsave(&sp->tx_lock, flags);
	/* tx_ndev is set when the netdev registers and read from the TX
	 * completion path, so take it under the same lock that protects the
	 * ring. Without this the first packet after link-up could dereference
	 * a stale/NULL pointer (review S2-11). */
	ndev = sp->tx_ndev;
	if (sp->tx_busy) {
		v = readl(sp->tdma + TDMA_DESC_RING_PC_INDEX(SP_TX_RING));
		c_idx = (v >> 16) & 0xffff;

		if (c_idx != sp->tx_cidx_pre) {
			done = true;
		} else if (time_after(jiffies,
				      sp->tx_start +
				      msecs_to_jiffies(SP_TX_TIMEOUT_MS))) {
			done = true;
			stuck = true;
		}

		if (done) {
			WRITE_ONCE(sp->tx_busy, false);
			if (tx_marks)
				bcm96764_mark(stuck ? 0x74 : 0x73);
			if (stuck) {
				ndev->stats.tx_errors++;
			} else {
				ndev->stats.tx_packets++;
				ndev->stats.tx_bytes += sp->tx_len;
			}
		}
	}
	spin_unlock_irqrestore(&sp->tx_lock, flags);

	if (!done)
		return;

	if (stuck) {
		netdev_err(ndev, "TX descriptor never consumed\n");
		bcm96764_mark(MK_ERR_TX_STUCK);
	} else if (!sp->seen_tx) {
		sp->seen_tx = true;
		bcm96764_mark(MK_FIRST_TX);
		netdev_info(ndev, "first TX completed\n");
	}

	/* wake every netdev whose queue the shared TX ring may have stopped;
	 * with two netdevs both can have been stopped by a NETDEV_TX_BUSY (R4) */
	for (i = 0; i < sp->n_ndevs; i++) {
		if (netif_queue_stopped(sp->ndevs[i]))
			netif_wake_queue(sp->ndevs[i]);
	}
}

/* __sp_send(), v2.c:454-508. Words 2 and 3 of the 16-byte descriptor go to
 * WRITE_PORT[0].LO / .HI a second time -- not to WRITE_PORT[1], which is what
 * the earlier draft did and which would have fed half a descriptor to ring 1.
 */

static netdev_tx_t sp_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct sp_priv *priv = netdev_priv(ndev);
	struct sysport6764 *sp = priv->sp;
	unsigned long flags;
	unsigned int len;
	dma_addr_t pa;
	u32 v;
	int i;

	if (tx_marks)
		bcm96764_mark(0x70);
	if (skb_padto(skb, ETH_ZLEN)) {
		ndev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	len = max_t(unsigned int, skb->len, ETH_ZLEN);

	if (len > SP_MAX_PKT_LEN) {
		ndev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	spin_lock_irqsave(&sp->tx_lock, flags);
	if (sp->tx_busy) {
		netif_stop_queue(ndev);
		spin_unlock_irqrestore(&sp->tx_lock, flags);
		return NETDEV_TX_BUSY;
	}

	if (enet6764_split || brcm_tag_port >= 0) {
		u8 *d = sp_tx_va(sp);
		u16 map;

		if (enet6764_split) {
			/* WAN -> P0, LAN -> P5 (REPORT.md §2.3); the switch
			 * maps this to the role's netdev via the ingress tag */
			map = priv->dest_map;
		} else if (brcm_tag_port == 99) {
			/* diagnostic rotation: P5, IMP loopback, P0 (run #42) */
			static const u16 maps[3] = { 1u << 5, 1u << 8, 1u << 0 };
			static unsigned int tx_seq;

			map = maps[tx_seq++ % 3];
		} else {
			map = 1u << brcm_tag_port;
		}

		memcpy(d, skb->data, 2 * ETH_ALEN);
		d[12] = SP_TAG_EGRESS_OPCODE;	/* opcode 1: egress directed, TC 0 */
		d[13] = 0x00;
		d[14] = map >> 8;
		d[15] = map & 0xff;
		memcpy(d + 12 + SP_TAG_LEN, skb->data + 12, len - 12);
		len += SP_TAG_LEN;
	} else {
		memcpy(sp_tx_va(sp), skb->data, len);
	}
	pa = sp_tx_pa(sp);

	v = readl(sp->tdma + TDMA_DESC_RING_PC_INDEX(SP_TX_RING));
	sp->tx_cidx_pre = (v >> 16) & 0xffff;
	sp->tx_len = len;
	sp->tx_start = jiffies;
	sp->tx_ndev = ndev;		/* stats/first-TX owner (shared ring) */
	WRITE_ONCE(sp->tx_busy, true);

	/* descriptor words 0 and 1 */
	writel(lower_32_bits(pa), sp->tdma + TDMA_WRITE_PORT_LO(SP_TX_RING));
	wmb();
	writel(SP_TXDESC_W1(len) |
	       (upper_32_bits((u64)pa) & SP_DESC_ADDR_HI_MASK),
	       sp->tdma + TDMA_WRITE_PORT_HI(SP_TX_RING));
	wmb();
	/* descriptor words 2 and 3, same two addresses again */
	writel(0, sp->tdma + TDMA_WRITE_PORT_LO(SP_TX_RING));
	wmb();
	writel(0, sp->tdma + TDMA_WRITE_PORT_HI(SP_TX_RING));
	wmb();
	if (tx_marks)
		bcm96764_mark(0x71);

	netif_stop_queue(ndev);
	spin_unlock_irqrestore(&sp->tx_lock, flags);
	if (tx_marks)
		bcm96764_mark(0x72);

	/* the payload has been copied into the coherent TX buffer already */
	dev_kfree_skb_any(skb);

	/* A 60..1518 byte frame is DMA'ed out in microseconds, so give the
	 * hardware a short bounded window to consume the descriptor before
	 * falling back to the poll tick. Without this the queue would stay
	 * stopped for a whole poll period (10 ms on a CONFIG_HZ=100 kernel
	 * without high-resolution timers), capping TX at ~100 pkt/s.
	 * Hard bound: 100 * 2 us = 200 us, and no lock is held across it.
	 */
	for (i = 0; i < 100; i++) {
		if (!READ_ONCE(sp->tx_busy))
			break;
		udelay(2);
		sp_tx_reclaim(sp);
	}

	return NETDEV_TX_OK;
}

static void sp_tx_timeout(struct net_device *ndev, unsigned int txqueue)
{
	struct sp_priv *priv = netdev_priv(ndev);
	struct sysport6764 *sp = priv->sp;

	netdev_err(ndev, "TX watchdog fired\n");
	sp_tx_reclaim(sp);
}

/* ------------------------------------------------------------------ */
/* NAPI / poll tick                                                   */
/* ------------------------------------------------------------------ */

static int sp_napi_poll(struct napi_struct *napi, int budget)
{
	struct sysport6764 *sp = container_of(napi, struct sysport6764, napi);
	int work = 0;

	if (rx_marks)
		bcm96764_mark(0x7D);
	sp_tx_reclaim(sp);

	while (work < budget) {
		if (sp_rx_one(sp))
			break;
		work++;
	}

	if (work >= budget && !sp->budget_hit) {	/* MK 0x6D: poll budget exhausted */
		sp->budget_hit = true;
		if (!sp->seen_rx)
			bcm96764_mark(0x6D);
	}
	if (work < budget)
		napi_complete_done(napi, work);
	if (rx_marks)
		bcm96764_mark(0x7E);

	return work;
}

/* poll_us can be changed at runtime through sysfs; clamp it so a value of 0
 * cannot turn hrtimer_forward_now() into an infinite loop.
 */
static u64 sp_poll_ns(void)
{
	unsigned int us = poll_us;

	if (us < 100)
		us = 100;
	return (u64)us * NSEC_PER_USEC;
}

static enum hrtimer_restart sp_poll_tick(struct hrtimer *t)
{
	struct sysport6764 *sp = container_of(t, struct sysport6764, poll_timer);

	if (!READ_ONCE(sp->running))
		return HRTIMER_NORESTART;
	if (rx_marks)
		bcm96764_mark(0x7F);

	napi_schedule(&sp->napi);
	hrtimer_forward_now(t, ns_to_ktime(sp_poll_ns()));
	return HRTIMER_RESTART;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/* Hand the work to NAPI rather than calling sp_rx_one() directly: RX packets
 * are delivered with napi_gro_receive(), which may only run inside a NAPI
 * poll.
 */
static void sp_poll_controller(struct net_device *ndev)
{
	struct sp_priv *priv = netdev_priv(ndev);
	struct sysport6764 *sp = priv->sp;

	napi_schedule(&sp->napi);
}
#endif

/* ------------------------------------------------------------------ */
/* netdev open / stop                                                 */
/* ------------------------------------------------------------------ */

/* Hardware bring-up/down is refcounted: with two netdevs over one
 * SYSTEMPORT, the first open initialises the MAC and the last close stops it
 * (risk R5).
 */
static int sp_hw_up(struct sysport6764 *sp)
{
	int ret;

	/* sysport_init(), v2.c:389-391: the switch is opened before the MAC */
	ret = sf2_6764_open(sp->sf2);
	if (ret)
		return ret;

	sp_hw_init(sp);

	ret = sp_enable_rdma(sp);
	if (ret)
		goto err;
	ret = sp_enable_tdma(sp);
	if (ret)
		goto err;

	usleep_range(100, 200);		/* v2.c:441 */
	netdev_info(sp->napi_ndev, "sysport init done, RDMA 0x%08x TDMA 0x%08x\n",
		    readl(sp->rdma + RDMA_STATUS),
		    readl(sp->tdma + TDMA_STATUS));
	bcm96764_mark(MK_SYSPORT_INIT);

	sp->tx_busy = false;
	sp->tx_ndev = NULL;
	WRITE_ONCE(sp->running, true);
	napi_enable(&sp->napi);
	hrtimer_start(&sp->poll_timer, ns_to_ktime(sp_poll_ns()),
		      HRTIMER_MODE_REL);
	return 0;

err:
	sp_hw_stop(sp);
	sf2_6764_close(sp->sf2);
	return ret;
}

static void sp_hw_down(struct sysport6764 *sp)
{
	WRITE_ONCE(sp->running, false);
	hrtimer_cancel(&sp->poll_timer);
	napi_disable(&sp->napi);

	sp_hw_stop(sp);
	sf2_6764_close(sp->sf2);
}

static int sp_open(struct net_device *ndev)
{
	struct sp_priv *priv = netdev_priv(ndev);
	struct sysport6764 *sp = priv->sp;
	int ret = 0;

	mutex_lock(&sp->lock);
	if (sp->open_count == 0)
		ret = sp_hw_up(sp);
	if (!ret) {
		sp->open_count++;
		netif_carrier_on(ndev);
		netif_start_queue(ndev);
	}
	mutex_unlock(&sp->lock);
	return ret;
}

static int sp_stop(struct net_device *ndev)
{
	struct sp_priv *priv = netdev_priv(ndev);
	struct sysport6764 *sp = priv->sp;

	mutex_lock(&sp->lock);
	netif_stop_queue(ndev);
	netif_carrier_off(ndev);
	if (sp->open_count > 0 && --sp->open_count == 0)
		sp_hw_down(sp);
	mutex_unlock(&sp->lock);
	return 0;
}

static const struct net_device_ops sp_netdev_ops = {
	.ndo_open		= sp_open,
	.ndo_stop		= sp_stop,
	.ndo_start_xmit		= sp_xmit,
	.ndo_tx_timeout		= sp_tx_timeout,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= sp_poll_controller,
#endif
};

/* ------------------------------------------------------------------ */
/* probe                                                              */
/* ------------------------------------------------------------------ */

/* Allocate one netdev private area + netdev and register it. The first
 * registered netdev owns the shared NAPI instance. In split mode WAN is
 * registered first so it becomes eth0 and LAN eth1, matching the stock
 * board-db (4lans1wan: ethernetWanPort='eth0').
 */
static int sp_register_netdev(struct sysport6764 *sp, int role, const u8 *mac)
{
	struct net_device *ndev;
	struct sp_priv *priv;
	int ret;

	ndev = devm_alloc_etherdev(sp->dev, sizeof(*priv));
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, sp->dev);
	priv = netdev_priv(ndev);
	priv->sp = sp;
	priv->ndev = ndev;
	priv->role = role;
	priv->dest_map = 1u << (role == SP_ROLE_WAN ? SP_SPLIT_WAN_PORT :
						      SP_SPLIT_LAN_PORT);

	eth_hw_addr_set(ndev, mac);
	ndev->netdev_ops = &sp_netdev_ops;
	ndev->watchdog_timeo = msecs_to_jiffies(2000);
	ndev->mtu = ETH_DATA_LEN;
	ndev->max_mtu = SP_MAX_PKT_LEN - ETH_HLEN - ETH_FCS_LEN;

	/* one NAPI instance for the shared RX ring (R6): RX delivery picks
	 * the netdev from the ingress tag, not from the NAPI owner */
	if (sp->n_ndevs == 0) {
		sp->napi_ndev = ndev;
		netif_napi_add(ndev, &sp->napi, sp_napi_poll);
	}

	ret = register_netdev(ndev);
	if (ret) {
		dev_err(sp->dev, "register_netdev failed (%d)\n", ret);
		if (sp->n_ndevs == 0) {
			netif_napi_del(&sp->napi);
			sp->napi_ndev = NULL;
		}
		bcm96764_mark(MK_ERR_NETDEV);
		return ret;
	}

	sp->ndevs[sp->n_ndevs++] = ndev;
	if (role == SP_ROLE_WAN)
		sp->wan_ndev = ndev;
	else
		sp->lan_ndev = ndev;

	dev_info(sp->dev,
		 "BCM6764 SYSTEMPORT registered as %s, MAC %pM, role %s, dest map 0x%04x\n",
		 ndev->name, ndev->dev_addr,
		 role == SP_ROLE_WAN ? "WAN" : "LAN", priv->dest_map);
	return 0;
}

/* Reverse of sp_register_netdev(): used by remove() and by the probe error
 * path when the second netdev cannot be registered. */
static void sp_unregister_netdevs(struct sysport6764 *sp)
{
	int i;

	for (i = sp->n_ndevs - 1; i >= 0; i--)
		unregister_netdev(sp->ndevs[i]);
	if (sp->napi_ndev)
		netif_napi_del(&sp->napi);
	sp->n_ndevs = 0;
	sp->napi_ndev = NULL;
	sp->wan_ndev = NULL;
	sp->lan_ndev = NULL;
}

static int sysport6764_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sysport6764 *sp;
	struct sf2_6764 *sf2;
	int ret, i;

	bcm96764_mark(0x6C);	/* sysport probe entered */
	sf2 = sf2_6764_get();
	if (!sf2) {
		bcm96764_mark(0xF1);	/* sysport probe deferred: sf2 not ready */
		return -EPROBE_DEFER;
	}

	sp = devm_kzalloc(dev, sizeof(*sp), GFP_KERNEL);
	if (!sp)
		return -ENOMEM;
	sp->dev = dev;
	sp->sf2 = sf2;
	sp->tag_fmt = tag_fmt;
	spin_lock_init(&sp->tx_lock);
	mutex_init(&sp->lock);

	/* Stock DTB node systemport@0x340000, reg-names
	 * "systemport-rbuf-base","systemport-rdma-base","systemport-tdma-base",
	 * "systemport-topctrl-base". There is no GIB, UMAC or IPA window on
	 * this SoC, so the corresponding reference blocks are skipped.
	 */
	sp->rbuf = devm_platform_ioremap_resource_byname(pdev, "systemport-rbuf-base");
	if (IS_ERR(sp->rbuf))
		goto err_map;
	sp->rdma = devm_platform_ioremap_resource_byname(pdev, "systemport-rdma-base");
	if (IS_ERR(sp->rdma))
		goto err_map;
	sp->tdma = devm_platform_ioremap_resource_byname(pdev, "systemport-tdma-base");
	if (IS_ERR(sp->tdma))
		goto err_map;
	sp->topctrl = devm_platform_ioremap_resource_byname(pdev, "systemport-topctrl-base");
	if (IS_ERR(sp->topctrl))
		goto err_map;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret) {
		dev_err(dev, "no 32-bit DMA mask\n");
		bcm96764_mark(MK_ERR_SP_DMA);
		return ret;
	}

	sp->dma_len = (size_t)(SP_NUM_TX_BUFS + SP_NUM_RX_BUFS) * SP_DMA_BUFSIZE;
	sp->dma_va = dmam_alloc_coherent(dev, sp->dma_len, &sp->dma_pa,
					 GFP_KERNEL);
	if (!sp->dma_va) {
		dev_err(dev, "cannot allocate %zu bytes of DMA memory\n",
			sp->dma_len);
		bcm96764_mark(MK_ERR_SP_DMA);
		return -ENOMEM;
	}
	if (upper_32_bits((u64)sp->dma_pa +
			  sp->dma_len - 1) > SP_DESC_ADDR_HI_MASK) {
		dev_err(dev, "DMA buffer at 0x%llx is outside the descriptor's address range\n",
			(unsigned long long)sp->dma_pa);
		bcm96764_mark(MK_ERR_SP_DMA);
		return -ERANGE;
	}
	dev_info(dev, "DMA buffers: %zu bytes at pa 0x%llx\n", sp->dma_len,
		 (unsigned long long)sp->dma_pa);

	/* v2.c:909: the switch is initialised from the sysport probe */
	ret = sf2_6764_init(sf2);
	if (ret) {
		dev_err(dev, "switch init failed (%d)\n", ret);
		return ret;
	}

	hrtimer_init(&sp->poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sp->poll_timer.function = sp_poll_tick;

	if (enet6764_split) {
		u8 mac[ETH_ALEN];

		memcpy(mac, sp_mac_addr, ETH_ALEN);
		ret = sp_register_netdev(sp, SP_ROLE_WAN, mac);
		if (ret)
			return ret;
		mac[ETH_ALEN - 1]++;	/* LAN = WAN MAC + 1 */
		ret = sp_register_netdev(sp, SP_ROLE_LAN, mac);
		if (ret) {
			sp_unregister_netdevs(sp);
			return ret;
		}
	} else {
		ret = sp_register_netdev(sp, SP_ROLE_LAN, sp_mac_addr);
		if (ret)
			return ret;
	}

	platform_set_drvdata(pdev, sp);
	for (i = 0; i < sp->n_ndevs; i++)
		netif_carrier_off(sp->ndevs[i]);

	dev_info(dev, "WAN/LAN split %s\n",
		 enet6764_split ? "enabled" : "disabled");
	bcm96764_mark(MK_NETDEV_OK);
	return 0;

err_map:
	dev_err(dev, "cannot map one of the systemport register windows\n");
	bcm96764_mark(MK_ERR_SP_MAP);
	return -ENXIO;
}

static void sysport6764_remove(struct platform_device *pdev)
{
	struct sysport6764 *sp = platform_get_drvdata(pdev);

	sp_unregister_netdevs(sp);
}

static const struct of_device_id sysport6764_of_match[] = {
	{ .compatible = "brcm,bcmbca-systemport-v2.0" },
	{ }
};
MODULE_DEVICE_TABLE(of, sysport6764_of_match);

struct platform_driver sysport6764_driver = {
	.probe	= sysport6764_probe,
	.remove_new = sysport6764_remove,
	.driver	= {
		.name		= "sysport6764",
		.of_match_table	= sysport6764_of_match,
	},
};

/* ------------------------------------------------------------------ */
/* module                                                             */
/* ------------------------------------------------------------------ */

/*
 * All three platform drivers live in one module and are registered in
 * dependency order, so there is no insmod ordering to get wrong. Each probe
 * still returns -EPROBE_DEFER if its dependency is somehow not bound yet.
 */
static struct platform_driver * const enet6764_drivers[] = {
	&pmc6764_driver,
	&sf2_6764_driver,
	&sysport6764_driver,
};

static int __init enet6764_init(void)
{
	return platform_register_drivers(enet6764_drivers,
					 ARRAY_SIZE(enet6764_drivers));
}
module_init(enet6764_init);

static void __exit enet6764_exit(void)
{
	platform_unregister_drivers(enet6764_drivers,
				    ARRAY_SIZE(enet6764_drivers));
}
module_exit(enet6764_exit);

MODULE_DESCRIPTION("Broadcom BCM6764 SYSTEMPORT + SF2 Ethernet bring-up driver");
MODULE_LICENSE("GPL");
