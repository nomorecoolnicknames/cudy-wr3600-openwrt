// SPDX-License-Identifier: GPL-2.0
/*
 * serdes6764.c - Merlin16 "shortfin" serdes bring-up for the BCM6764,
 *                core 0 / lane 0, forced 2500Base-X towards the external
 *                BCM53134 switch.
 *
 * Ported from the vendor U-Boot 2019.07 GPL tree.  The 6764 uses the
 * "146 class" (10GAE) driver, NOT phy_drv_shortfin.c: the stock kernel boot
 * log names (merlin_core_init, merlin16_serdes_init, merline_speed_set_core,
 * merlin_load_firmware, merlin_wait_uc_active) all come from
 *   drivers/net/bcmbca/phy/Serdes146Class/merlin16_shortfin_config.c
 * driven by
 *   drivers/net/bcmbca/phy/phy_drv_146class_serdes.c
 * with register access from
 *   drivers/net/bcmbca/phy/serdes_access.c + serdes_access_6764.h
 * and the register tables from
 *   drivers/net/bcmbca/phy/Serdes146Class/M1_merlin.h
 *
 * See NOTES.md for the step-by-step map back to those files with line
 * numbers, and for what could not be verified without hardware.
 *
 * Register access is memory-mapped, not MDIO: the SoC reaches the Merlin
 * core through an indirect-access window in the "brcm,serdes1" block at
 * phys 0x80282000 (serdes_access.c:99..139).  PRTAD 6 from the DT is only
 * programmed into the control register's prtad field; it is not an MDIO
 * address for us.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "enet66b.h"
#include "merlin16_shortfin_ucode.h"

#define DRV "serdes6764"

/* ------------------------------------------------------- DT / topology -- */

/*
 * From the stock DTB, node phy_serdes0:
 *   phy-type "10GAE", reg <6>, serdes-core <0>, serdes-lane <0>,
 *   phy-extswitch, config-xfi "2500Base-X", config-speed <2500>,
 *   phy-xfi-tx-polarity-inverse, phy-xfi-rx-polarity-inverse,
 *   force-2p5g-10gvco
 */
#define SD_LANE			0

/* Which serdes core to bring up.  Core 0 (PRTAD 6) is the 2.5G link to the
 * external 53134 switch on every WR3600/WR3600H board.  Core 1 (PRTAD 7) is
 * the second serdes, used on the WR3600H (R69) for its 2.5G WAN port, where
 * it feeds an external cascade PHY instead of the switch.  The register map
 * is identical, one SD_CORE_STRIDE apart (see sd_reg() below), so the whole
 * bring-up is shared and only the core/PRTAD pair changes.
 * Defaults keep the WR3600 (R77) behaviour byte-for-byte. */
/* The core currently addressed by sd_reg() and by the exported link/speed
 * helpers.  After bring-up it is left on the primary (lowest) core, which is
 * the uplink to the 53134 on every board, so callers keep their meaning. */
static int sd_core;
static int sd_prtad = 6;

static unsigned int cores = 0x1;
module_param(cores, uint, 0444);
MODULE_PARM_DESC(cores,
		 "bitmask of serdes cores to bring up: 0x1 = core 0 only, the uplink to the 53134 (default); 0x3 = cores 0+1, the WR3600H which also has its 2.5G WAN on core 1");

static int prtad_override;
module_param_named(prtad, prtad_override, int, 0444);
MODULE_PARM_DESC(prtad, "override the PRTAD (0 = derive: 6 for core 0, 7 for core 1)");

static int core_prtad(int core)
{
	return prtad_override ? prtad_override : 6 + core;
}

static unsigned long serdes_base_phys;	/* fallback if DT node missing */
module_param(serdes_base_phys, ulong, 0444);
MODULE_PARM_DESC(serdes_base_phys,
		 "phys addr of the brcm,serdes1 block (0 = from DT; stock 0x80282000)");

static unsigned long ethtop_base_phys;
module_param(ethtop_base_phys, ulong, 0444);
MODULE_PARM_DESC(ethtop_base_phys,
		 "phys addr of the brcm,eth-phy-top block (0 = from DT; stock 0x80280000)");

static int acc_delay_us = 10;
module_param(acc_delay_us, int, 0644);
MODULE_PARM_DESC(acc_delay_us,
		 "settle delay after each indirect serdes access (vendor: 10us)");

static int strict_busy = 1;
module_param(strict_busy, int, 0644);
MODULE_PARM_DESC(strict_busy,
		 "1 = fail when the indirect-access start_busy bit never clears; 0 = vendor behaviour (ignore it)");

static int tx_polarity_inverse = 1;
module_param(tx_polarity_inverse, int, 0444);
MODULE_PARM_DESC(tx_polarity_inverse, "DT phy-xfi-tx-polarity-inverse (stock: 1)");

static int rx_polarity_inverse = 1;
module_param(rx_polarity_inverse, int, 0444);
MODULE_PARM_DESC(rx_polarity_inverse, "DT phy-xfi-rx-polarity-inverse (stock: 1)");

/* STATUS/CONTROL snapshot at the end of the init sequence (run #46 diag) */
static unsigned int st_end, ctrl_end;
/* last marker written by this module (run #50: report the failing stage) */
static unsigned int sd_last_mark;
module_param(sd_last_mark, uint, 0444);
static void sd_mark(u8 m)
{
	sd_last_mark = m;
	bcm96764_mark(m);
}
#define bcm96764_mark(m) sd_mark(m)
static int init_ret = -1000;
module_param(init_ret, int, 0444);
module_param(st_end, uint, 0444);
module_param(ctrl_end, uint, 0444);

/* run #47: VCO for the 2.5G pass. The stock DT says force-2p5g-10gvco; the
 * 12.5GHz choice left the PLL unlocked at the end of init (runs #45/#46). */
static int p2_vco12p5 = 1;	/* stock final state: d0b8 ndiv 0x9c, frac 0x1000 = 12.5GHz VCO (pmidump 2026-09-07) */
module_param(p2_vco12p5, int, 0444);
MODULE_PARM_DESC(p2_vco12p5, "1: 12.5GHz VCO for 2500Base-X pass; 0: 10.3125GHz");

static int autoinit = 1;
module_param(autoinit, int, 0444);
MODULE_PARM_DESC(autoinit, "run serdes6764_init_2p5g() at module load");

static int double_init = 1;
module_param(double_init, int, 0644);
MODULE_PARM_DESC(double_init,
		 "1 = run merlin16_serdes_init() twice like the vendor driver does (see NOTES.md); 0 = once");

static void __iomem *sd_base;		/* brcm,serdes1     phys 0x80282000 */
static void __iomem *ethtop_base;	/* brcm,eth-phy-top phys 0x80280000 */
static DEFINE_MUTEX(sd_lock);
static bool sd_inited;

/* ------------------------------ serdes block register map (core 0) ------ */
/* serdes_access_6764.h:22..36 */
#define SD_INDIR_ACC_ADDR	0x0004
#define SD_INDIR_ACC_MASK	0x0008
#define SD_CONTROL		0x000c
#define SD_STATUS		0x0010
#define SD_AN_STATUS		0x0020
#define SD_STATUS_1		0x0024
#define SD_INDIR_ACC_CNTRL	0x0800
#define SD_CORE_STRIDE		0x1000		/* core 1 is +0x1000 */
#define SD_MAX_CORES		2

/* serdes_access_6764.h:38..39 */
#define SD_DEV_TYPE_SHIFT	27
#define SD_LANE_ADDR_SHIFT	16

/* SD_INDIR_ACC_CNTRL bits, serdes_access_6764.h:126..134 */
#define SD_ACC_DATA_MASK	0xffffu
#define SD_ACC_RW		BIT(16)		/* 1 = read */
#define SD_ACC_START_BUSY	BIT(17)
#define SD_ACC_DELAYED_ACK	BIT(18)

/* SD_CONTROL bits, serdes_access_6764.h:80..102 == phy_drv_ethtop_merlin16.h:147..155 */
#define SD_CTL_IDDQ		BIT(0)
#define SD_CTL_REFCLK_RESET	BIT(1)
#define SD_CTL_SERDES_RESET	BIT(2)
#define SD_CTL_PRTAD_SHIFT	6
#define SD_CTL_PRTAD_MASK	(0x1fu << 6)
#define SD_CTL_TEST_EN		BIT(20)
#define SD_CTL_COMCLK_ENABLE	BIT(28)

/* SD_STATUS bits, serdes_access_6764.h:104..117 */
#define SD_ST_RX_SIGDET		BIT(0)
#define SD_ST_CDR_LOCK		BIT(1)
#define SD_ST_LINK_STATUS	BIT(2)
#define SD_ST_PLL_LOCK		BIT(3)

/* SD_STATUS_1 speed nibbles, serdes_access_6764.h:136..145 */
#define SD_S1_SPEED_10M		0
#define SD_S1_SPEED_100M	4
#define SD_S1_SPEED_1G		8
#define SD_S1_SPEED_2P5G	12
#define SD_S1_SPEED_5G		16
#define SD_S1_SPEED_10G		20

/* eth-phy-top, phy_drv_ethtop_merlin16.h:141 (6764 variant) */
#define ETHTOP_R2PMI_LP_BCAST_MODE_CNTRL	0x01b0

/* ---------------------------------------------- Merlin PMI register map -- */
/* PMD device address used for every "core" register, serdes_wrapper.c:12 */
#define PMD_DEV			0x1
#define PCS_DEV			0x3

/* micro subsystem, merlin16_shortfin_fields.h:987..1020 */
#define REG_MICRO_CLK_CTRL	0xd200	/* [0] master_clk_en, [1] core_clk_en */
#define  MICRO_MASTER_CLK_EN	BIT(0)
#define  MICRO_CORE_CLK_EN	BIT(1)
#define REG_MICRO_RST_CTRL	0xd201	/* [0] master_rstb,   [1] core_rstb   */
#define  MICRO_MASTER_RSTB	BIT(0)
#define  MICRO_CORE_RSTB	BIT(1)
#define REG_MICRO_RAM_CTRL	0xd202	/* [1:0] wrdatasize, [5:4] rddatasize,
					   [9:8] ra_init, [12] autoinc_wr,
					   [13] autoinc_rd */
#define  MICRO_WRDATASIZE_MASK	0x0003
#define  MICRO_RDDATASIZE_MASK	0x0030
#define  MICRO_RDDATASIZE_SHIFT	4
#define  MICRO_RA_INIT_MASK	0x0300
#define  MICRO_RA_INIT_SHIFT	8
#define  MICRO_AUTOINC_WR	0x1000
#define  MICRO_AUTOINC_RD	0x2000
#define REG_MICRO_RAM_STATUS	0xd203	/* [0] ra_initdone: vendor macro
					   rdc_micro_ra_initdone() = _pmd_rde_field(0xd203, 15, 15)
					   = shift_left 15 (msb 0), shift_right 15 (lsb 0);
					   MICRO_A_COM_AHB_STATUS0 extract_field(reg, 0, 0) */
#define  MICRO_RA_INITDONE	BIT(0)
#define REG_MICRO_WRADDR_LSW	0xd204
#define REG_MICRO_WRADDR_MSW	0xd205
#define REG_MICRO_WRDATA_LSW	0xd206
#define REG_MICRO_RDADDR_LSW	0xd208
#define REG_MICRO_RDADDR_MSW	0xd209
#define REG_MICRO_RDDATA_LSW	0xd20a
#define REG_MICRO_D225		0xd225
#define REG_MICRO_PMI_FAST_RD	0xd228	/* [0] pmi_hp_fast_read_en */

/* DSC command interface, merlin16_shortfin_fields.h:612..621, 1837..1838 */
#define REG_DSC_UC_CTRL		0xd00d
#define  DSC_READY_FOR_CMD	BIT(7)
#define  DSC_ERROR_FOUND	BIT(6)
#define REG_DSC_UC_DATA		0xd00e
#define  CMD_CALC_CRC		20	/* srds_api_uc_common.h:100 */

/* misc core registers */
#define REG_UC_ACTIVE		0xd0f4	/* [15] uc_active, [13] core_dp_s_rstb */
#define  UC_ACTIVE		BIT(15)
#define REG_CORE_RESET		0xd0f1	/* PMD + uC reset, config.c (Serdes146Class) :140 */
#define REG_LANE_DP_RSTB	0xd081	/* [0] ln_dp_s_rstb                   */
#define REG_MDIO_BRCST_ADDR	0xffdc	/* [4:0] brcst_port_addr              */
#define REG_MDIO_MULTI_PRTS	0xffdd	/* [15] multi_prts_en                 */

/* XFI polarity, phy_drv_146class_serdes.c:212..225 */
#define REG_XFI_TX_POLARITY	0xd0e3
#define REG_XFI_RX_POLARITY	0xd0d3

/* micro RAM variable windows, merlin16_shortfin_config.c (Serdes146Class) :409,712 */
#define UC_RAM_WINDOW		0x20000000u
#define CORE_VAR_RAM_OFFSET	0x200
#define LANE_VAR_RAM_OFFSET	0x300

/* info table, srds_api_uc_common.h:201,247 + merlin16_shortfin_internal.h:233 */
#define INFO_TABLE_RAM_BASE	0x100
#define INFO_TABLE_END		0x70
#define INFO_TABLE_SIGNATURE	0x666E49	/* "Inf" */

#define UCODE_MAX_SIZE		(84 * 1024)	/* phy_drv_merlin16.h:32 */

/* ------------------------------------------------- indirect PMI access -- */

/*
 * phy_drv_merlin16.h:37..44, _merlin16_shortfin_delay_us(): the library uses
 * mdelay() above 2ms.  ARM's udelay() rejects compile-time constants over
 * 2000us anyway.
 */
static void merlin_delay_us(unsigned int us)
{
	if (us > 2000)
		mdelay(us / 1000);
	else
		udelay(us);
}

static void __iomem *sd_reg(u32 off)
{
	return sd_base + (sd_core * SD_CORE_STRIDE) + off;
}

/*
 * serdes_access.c:141..194.  The vendor writes the mask register with
 * ~mask where mask is a promoted uint16_t, so the top half always ends up
 * all-ones; reproduce that exactly.  A set bit in the mask register means
 * "preserve".
 */
/*
 * On the 6764 the vendor never polls start_busy: serdes_access_6764.h
 * serdes_indirect_access_control_status() returns 0 unconditionally, and
 * serdes_access.c does write -> udelay(10) -> read. Polling the bit here
 * timed out on every access (run #50: E66B_MK_ERR_SD_ACC), so mirror the
 * vendor: fixed 10us settle, optional busy poll behind poll_busy=1.
 */
static int mdio_prts;
module_param(mdio_prts, int, 0444);
MODULE_PARM_DESC(mdio_prts, "1 = write MDIO multi_prts/brcst regs before ucode load (not on 6764)");

static int selftest_d225 = -1;
static int selftest_d202 = -1;
module_param(selftest_d202, int, 0444);
module_param(selftest_d225, int, 0444);

static int pol_tx_end = -1, pol_rx_end = -1, pol_reapply = 1;
module_param(pol_tx_end, int, 0444);
module_param(pol_rx_end, int, 0444);
module_param(pol_reapply, int, 0444);

static int d128_after_lock = -1, d128_end = -1;
module_param(d128_after_lock, int, 0444);
module_param(d128_end, int, 0444);

static int poll_busy;
module_param(poll_busy, int, 0644);
MODULE_PARM_DESC(poll_busy, "1 = poll start_busy after each access (vendor does not on 6764)");

static int sd_acc_wait(void)
{
	u32 v;
	int retry = 200;	/* 200 x 5us = 1ms, bounded */

	udelay(10);
	if (!poll_busy)
		return 0;
	do {
		v = readl(sd_reg(SD_INDIR_ACC_CNTRL));
		if (!(v & SD_ACC_START_BUSY))
			return 0;
		udelay(5);
	} while (--retry);
	pr_err_ratelimited(DRV ": indirect access busy stuck, cntrl=0x%08x\n", v);
	bcm96764_mark(E66B_MK_ERR_SD_ACC);
	return strict_busy ? -ETIMEDOUT : 0;
}

static u32 sd_acc_addr(u16 dev, u16 reg)
{
	return ((u32)dev << SD_DEV_TYPE_SHIFT) |
	       ((u32)SD_LANE << SD_LANE_ADDR_SHIFT) | reg;
}

/* merlin_pmi_write16(core, lane, dev, reg, data, preserve_mask) */
static int sd_pmi_wr(u16 dev, u16 reg, u16 data, u16 preserve)
{
	writel(sd_acc_addr(dev, reg), sd_reg(SD_INDIR_ACC_ADDR));
	writel(0xffff0000u | preserve, sd_reg(SD_INDIR_ACC_MASK));
	writel(SD_ACC_DELAYED_ACK | SD_ACC_START_BUSY | data,
	       sd_reg(SD_INDIR_ACC_CNTRL));

	if (acc_delay_us > 0)
		udelay(acc_delay_us);

	return sd_acc_wait();
}

/* full 16-bit write */
static int sd_wr(u16 dev, u16 reg, u16 val)
{
	return sd_pmi_wr(dev, reg, val, 0);
}

/* read-modify-write of one field: mask is the field mask, val is unshifted */
static int hw_mask;
module_param(hw_mask, int, 0444);
MODULE_PARM_DESC(hw_mask, "1 = use the PMI MASK register for field writes; 0 = software read-modify-write");

static int sd_rd(u16 dev, u16 reg, u16 *val);

static int sd_wr_field(u16 dev, u16 reg, u16 mask, u8 shift, u16 val)
{
	u16 cur;
	int ret;

	if (hw_mask)
		return sd_pmi_wr(dev, reg, (u16)(val << shift), (u16)~mask);
	ret = sd_rd(dev, reg, &cur);
	if (ret)
		return ret;
	cur = (cur & ~mask) | ((val << shift) & mask);
	return sd_pmi_wr(dev, reg, cur, 0);
}

static int sd_rd(u16 dev, u16 reg, u16 *val)
{
	u32 v;
	int ret;

	writel(sd_acc_addr(dev, reg), sd_reg(SD_INDIR_ACC_ADDR));
	writel(SD_ACC_DELAYED_ACK | SD_ACC_START_BUSY | SD_ACC_RW,
	       sd_reg(SD_INDIR_ACC_CNTRL));

	if (acc_delay_us > 0)
		udelay(acc_delay_us);

	ret = sd_acc_wait();
	if (ret)
		return ret;

	v = readl(sd_reg(SD_INDIR_ACC_CNTRL));
	*val = v & SD_ACC_DATA_MASK;
	return 0;
}

/* convenience: read a PMD-device register, return value or negative errno */
static int sd_rdc(u16 reg)
{
	u16 v;
	int ret = sd_rd(PMD_DEV, reg, &v);

	return ret ? ret : v;
}

/* ----------------------------------------------- register program tables -- */

enum seq_type {
	SEQ_REG = 0,		/* write data under data_bit_en                */
	SEQ_NEST,		/* run the nested table                        */
	SEQ_PLL_LOCK,		/* call merlin_chk_pll_lock()                  */
	SEQ_END,
};

struct prog_ent {
	enum seq_type type;
	u16 dev;
	u16 reg;
	u16 data_bit_en;	/* bits this entry writes                      */
	u16 data;		/* already shifted into place                  */
	const struct prog_ent *nest;
	const char *desc;
};

#define R(_dev, _reg, _en, _data, _desc) \
	{ .type = SEQ_REG, .dev = (_dev), .reg = (_reg), \
	  .data_bit_en = (_en), .data = (_data), .desc = (_desc) }
#define NEST(_tbl) { .type = SEQ_NEST, .nest = (_tbl), .desc = #_tbl }
#define PLLLOCK	  { .type = SEQ_PLL_LOCK, .desc = "chk_pll_lock" }
#define ENDTBL	  { .type = SEQ_END }

/* M1_merlin.h:31 - Figure 47 Datapath Reset (per lane), active low */
static const struct prog_ent datapath_reset_lane[] = {
	R(0x1, 0xD081, 0x0001, 0x0001, "ln_dp_s_rstb = 1"),
	ENDTBL
};

/* M1_merlin.h:983 - Figure 46 Datapath Reset (core) */
static const struct prog_ent datapath_reset_core[] = {
	R(0x1, 0xd0f4, 0x2000, 0x2000, "core_dp_s_rstb = 1"),
	ENDTBL
};

/* M1_merlin.h:1003 - Figure 48 LPI Enable */
static const struct prog_ent lpi_enable[] = {
	R(0x3, 0xC450, 0x0004, 0x0004, "LPI_ENABLE = 1"),
	ENDTBL
};

/* M1_merlin.h:37 - Figure 18 Initialize, 12.5G VCO clock counts */
static const struct prog_ent initialize_12p5_vco[] = {
	R(0x3, 0x9201, 0xffff, 0x4888, "os_mode_cl36"),
	R(0x3, 0x9202, 0xffff, 0x9940, "pmd_osr_mode"),
	R(0x3, 0x926A, 0x3fff, 0x0019, "reg1G_ClockCount0"),
	R(0x3, 0x926B, 0x1fff, 0x0006, "reg1G_CGC"),
	R(0x3, 0x926C, 0x00ff, 0x0000, "reg1G_ClockCount1"),
	R(0x3, 0x926C, 0xff00, 0x0100, "reg1G_loopcnt0"),
	R(0x3, 0x926D, 0x1fff, 0x0000, "reg1G_loopcnt1"),
	R(0x3, 0x9232, 0x01ff, 0x0005, "reg1G_modulo"),

	R(0x3, 0x9265, 0x3fff, 0x007D, "reg100M_ClockCount0"),
	R(0x3, 0x9268, 0x1fff, 0x001f, "reg100M_CGC"),
	R(0x3, 0x9266, 0x00ff, 0x0000, "reg100M_ClockCount1"),
	R(0x3, 0x9266, 0xff00, 0x0100, "reg100M_loopcnt0"),
	R(0x3, 0x9269, 0xe000, 0x0000, "reg100M_loopcnt1_Hi"),
	R(0x3, 0x9268, 0xe000, 0x0000, "reg100M_loopcnt1_Lo"),
	R(0x3, 0x9267, 0x3fff, 0x0032, "reg100M_PCS_ClockCount1"),
	R(0x3, 0x9269, 0x1fff, 0x0031, "reg100M_PCS_CGC"),
	R(0x3, 0x9231, 0x01ff, 0x001F, "reg100M_modulo"),

	R(0x3, 0x9260, 0x3fff, 0x0271, "reg10M_ClockCount0"),
	R(0x3, 0x9263, 0x1fff, 0x0138, "reg10M_CGC"),
	R(0x3, 0x9261, 0x00ff, 0x0000, "reg10M_ClockCount1"),
	R(0x3, 0x9261, 0xff00, 0x0100, "reg10M_loopcnt0"),
	R(0x3, 0x9264, 0xe000, 0x0000, "reg10M_loopcnt1_Hi"),
	R(0x3, 0x9263, 0xe000, 0x0000, "reg10M_loopcnt1_Lo"),
	R(0x3, 0x9262, 0x3fff, 0x0032, "reg10M_PCS_ClockCount1"),
	R(0x3, 0x9264, 0x1fff, 0x0031, "reg10M_PCS_CGC"),
	R(0x3, 0x9230, 0x01ff, 0x0138, "reg10M_modulo"),
	ENDTBL
};

/* M1_merlin.h:127 - PMD setup, 80MHz refclk, 10.3125GHz VCO */
static const struct prog_ent pmd_setup_80_10p3125_vco[] = {
	R(0x3, 0x9100, 0xf000, 0x6000, "refclk_sel"),
	R(0x1, 0xD0F4, 0x2000, 0x0000, "core_dp_s_rstb = 0"),
	R(0x1, 0xd0b8, 0x03FF, 0x0080, "ndiv_int = 0x80"),
	R(0x1, 0xd0b8, 0x8000, 0x0000, "dither_en = 0"),
	R(0x1, 0xd0b6, 0x0c00, 0x0800, "pfd setup = 2"),
	R(0x1, 0xd0b6, 0xF000, 0x0000, "ndiv_frac_l = 0"),
	R(0x1, 0xd0b7, 0x3FFF, 0x3A00, "ndiv_frac_h = 0x3A00"),
	R(0x1, 0xd0b9, 0x0078, 0x0078, "f3cap = 0xF"),
	R(0x1, 0xd0b1, 0x000F, 0x0003, "lcap = 3"),
	R(0x1, 0xd0b0, 0x0e00, 0x0200, "rpar = 1"),
	R(0x1, 0xd0b0, 0xc000, 0xc000, "cpar = 3"),
	R(0x1, 0xD0B9, 0x0001, 0x0000, "mmd_rstb = 0"),
	R(0x1, 0xD0B9, 0x0001, 0x0001, "mmd_rstb = 1"),
	ENDTBL
};

/* M1_merlin.h:145 - PMD setup, 80MHz refclk, 12.5GHz VCO */
static const struct prog_ent pmd_setup_80_12p5_vco[] = {
	R(0x3, 0x9100, 0xf000, 0x6000, "refclk_sel"),
	R(0x1, 0xD0F4, 0x2000, 0x0000, "core_dp_s_rstb = 0"),
	R(0x1, 0xd0b8, 0x03FF, 0x009c, "ndiv_int = 0x9c"),
	R(0x1, 0xd0b8, 0x8000, 0x0000, "dither_en = 0"),
	R(0x1, 0xd0b6, 0x0c00, 0x0800, "pfd setup = 2"),
	R(0x1, 0xd0b6, 0xF000, 0x0000, "ndiv_frac_l = 0"),
	R(0x1, 0xd0b7, 0x3FFF, 0x1000, "ndiv_frac_h = 0x1000"),
	R(0x1, 0xd0b9, 0x0078, 0x0078, "f3cap = 0xF"),
	R(0x1, 0xd0b1, 0x000F, 0x0003, "lcap = 3"),
	R(0x1, 0xd0b0, 0x0e00, 0x0200, "rpar = 1"),
	R(0x1, 0xd0b0, 0xc000, 0xc000, "cpar = 3"),
	R(0x1, 0xD0B9, 0x0001, 0x0000, "mmd_rstb = 0"),
	R(0x1, 0xD0B9, 0x0001, 0x0001, "mmd_rstb = 1"),
	ENDTBL
};

/* M1_merlin.h:339 - MLN_SPD_FORCE_1G (1000Base-X, CL36) */
static const struct prog_ent force_speed_1g[] = {
	R(0x3, 0xC30B, 0x087f, 0x0042, "credit_sw_en=0, speed_force_en=1, speed=2"),
	NEST(datapath_reset_lane),
	PLLLOCK,
	R(0x3, 0xC457, 0x0001, 0x0001, "rx rstb_lane = 1"),
	R(0x3, 0xC30B, 0x0080, 0x0080, "mac_creditenable = 1"),
	R(0x3, 0xC433, 0x0003, 0x0003, "tx rstb_lane + enable_tx_lane"),
	ENDTBL
};

/* M1_merlin.h:295 - MLN_SPD_FORCE_2P5G (2500Base-X, CL36) */
static const struct prog_ent force_speed_2p5g[] = {
	R(0x3, 0xC30B, 0x087f, 0x0043, "credit_sw_en=0, speed_force_en=1, speed=3"),
	NEST(datapath_reset_lane),
	PLLLOCK,
	R(0x3, 0xC457, 0x0001, 0x0001, "rx rstb_lane = 1"),
	R(0x3, 0xC456, 0x0010, 0x0010, "C456[4] = 1 for 12.5GHz VCO"),
	R(0x3, 0xC30B, 0x0080, 0x0080, "mac_creditenable = 1"),
	R(0x3, 0xC433, 0x0003, 0x0003, "tx rstb_lane + enable_tx_lane"),
	ENDTBL
};

/* ---------------------------------------------- register save / restore -- */

/*
 * merlin16_shortfin_config.c (Serdes146Class) :238..291.  Every register written through
 * merlin_reg_prog() has its pre-write value remembered (de-duplicated by
 * dev+reg); restore_regs() puts them all back before the next speed pass so
 * settings from the previous speed do not leak.
 */
#define SAVE_MAX 128

struct saved_reg {
	u16 dev, reg, val;
};

static struct saved_reg saved_regs[SAVE_MAX];
static int saved_cnt;
static bool register_dont_save;

static void save_reg(u16 dev, u16 reg)
{
	int i, ret;
	u16 v;

	if (register_dont_save)
		return;

	for (i = 0; i < saved_cnt; i++)
		if (saved_regs[i].dev == dev && saved_regs[i].reg == reg)
			return;

	if (saved_cnt >= SAVE_MAX) {
		pr_warn(DRV ": register save array full, dropping %x.%04x\n",
			dev, reg);
		return;
	}

	ret = sd_rd(dev, reg, &v);
	if (ret)
		return;

	saved_regs[saved_cnt].dev = dev;
	saved_regs[saved_cnt].reg = reg;
	saved_regs[saved_cnt].val = v;
	saved_cnt++;
}

static int restore_regs(void)
{
	int i, ret, core_active;

	core_active = sd_rdc(REG_LANE_DP_RSTB);
	if (core_active < 0)
		return core_active;
	core_active &= 1;

	/* put the serdes in reset first */
	if (core_active) {
		ret = sd_pmi_wr(PMD_DEV, REG_LANE_DP_RSTB, 0, 0xfffe);
		if (ret)
			return ret;
	}

	for (i = 0; i < saved_cnt; i++) {
		ret = sd_wr(saved_regs[i].dev, saved_regs[i].reg,
			    saved_regs[i].val);
		if (ret)
			return ret;
	}

	if (core_active) {
		ret = sd_pmi_wr(PMD_DEV, REG_LANE_DP_RSTB, 1, 0xfffe);
		if (ret)
			return ret;
	}

	saved_cnt = 0;
	return 0;
}

/* ------------------------------------------------------- PLL / link ----- */

/* serdes_access.c:207..226 - 100 x 10ms */
static int merlin_chk_pll_lock(void)
{
	int retry = 100;
	u32 st;

	do {
		msleep(10);
		st = readl(sd_reg(SD_STATUS));
		if (st & SD_ST_PLL_LOCK)
			return 0;
	} while (--retry);

	pr_err(DRV ": PLL lock timeout, status=0x%08x\n", st);
	bcm96764_mark(E66B_MK_ERR_SD_PLL);
	return -ETIMEDOUT;
}

/* ----------------------------------------------- merlin_reg_prog() ------ */

static int merlin_reg_prog(const struct prog_ent *tbl)
{
	int ret;

	for (; tbl->type != SEQ_END; tbl++) {
		switch (tbl->type) {
		case SEQ_NEST:
			ret = merlin_reg_prog(tbl->nest);
			if (ret)
				return ret;
			break;
		case SEQ_PLL_LOCK:
			ret = merlin_chk_pll_lock();
			if (ret)
				return ret;
			break;
		case SEQ_REG:
			save_reg(tbl->dev, tbl->reg);
			/* merlin_reg_prog(): mask = ~data_bitEn = preserve */
			ret = sd_pmi_wr(tbl->dev, tbl->reg, tbl->data,
					(u16)~tbl->data_bit_en);
			if (ret) {
				pr_err(DRV ": write %x.%04x (%s) failed: %d\n",
				       tbl->dev, tbl->reg, tbl->desc, ret);
				return ret;
			}
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/* --------------------------------------------- serdes_access_config() --- */

/*
 * serdes_access.c:251..306.  6764 sets comclk_enable; the ISO/CMOS bits are
 * for 6888/68880/6837 only.
 */
static void serdes_access_config(bool enable)
{
	u32 v;
	bool disable = !enable;

	/* Step 1: everything held in reset */
	v = SD_CTL_IDDQ | SD_CTL_REFCLK_RESET | SD_CTL_SERDES_RESET |
	    SD_CTL_COMCLK_ENABLE;
	writel(v, sd_reg(SD_CONTROL));
	msleep(10);

	/* Step 2: drop IDDQ */
	if (disable)
		v |= SD_CTL_IDDQ;
	else
		v &= ~SD_CTL_IDDQ;
	writel(v, sd_reg(SD_CONTROL));
	msleep(10);

	/* Step 3: release the resets and latch PRTAD */
	if (disable)
		v |= SD_CTL_REFCLK_RESET | SD_CTL_SERDES_RESET;
	else
		v &= ~(SD_CTL_REFCLK_RESET | SD_CTL_SERDES_RESET);

	if (sd_prtad > 0x1f)
		v |= SD_CTL_TEST_EN;
	else
		v = (v & ~SD_CTL_PRTAD_MASK) |
		    ((u32)sd_prtad << SD_CTL_PRTAD_SHIFT);

	writel(v, sd_reg(SD_CONTROL));
	msleep(10);
}

/* -------------------------------------------------- microcontroller ----- */

/* merlin_shortfin/src/merlin16_shortfin_config.c:462..523, uc_reset(enable) */
static int merlin_uc_reset(bool assert_reset)
{
	static const u16 zero_regs[] = {
		0xD200, 0xD201, 0xD202, 0xD204, 0xD205, 0xD206, 0xD207,
		0xD208, 0xD209, 0xD20A, 0xD20B, 0xD20C, 0xD20D, 0xD20E,
		0xD211, 0xD212, 0xD213, 0xD214, 0xD215,
	};
	int ret, i;

	if (assert_reset) {
		/* wrc_micro_micro_s_rstb is not defined for merlin16-shortfin,
		 * so the long form is used (merlin_shortfin/src/merlin16_shortfin_config.c:469..503) */
		ret = sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL,
				  MICRO_CORE_CLK_EN, 1, 0);
		if (ret)
			return ret;
		ret = sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL,
				  MICRO_MASTER_CLK_EN, 0, 0);
		if (ret)
			return ret;

		for (i = 0; i < ARRAY_SIZE(zero_regs); i++) {
			ret = sd_wr(PMD_DEV, zero_regs[i], 0x0000);
			if (ret)
				return ret;
		}
		ret = sd_wr(PMD_DEV, 0xD216, 0x0007);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD217, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD218, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD219, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD21A, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD21B, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD220, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD221, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD224, 0x0000);
		if (ret)
			return ret;
		/* [13:8] micro_dr_size = 2 -> 2KB data RAM, 32KB code RAM */
		ret = sd_wr(PMD_DEV, REG_MICRO_D225, 0x8201);
		if (ret)
			return ret;

		ret = sd_wr(PMD_DEV, 0xD226, 0x0000);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, REG_MICRO_PMI_FAST_RD, 0x0101);
		if (ret)
			return ret;
		ret = sd_wr(PMD_DEV, 0xD229, 0x0000);
		if (ret)
			return ret;
		return sd_wr(PMD_DEV, 0xD22A, 0x0000);
	}

	/* de-assert: start executing code (merlin_shortfin/src/merlin16_shortfin_config.c:511..521) */
	ret = sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL, MICRO_MASTER_CLK_EN, 0, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RST_CTRL, MICRO_MASTER_RSTB, 0, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL, MICRO_CORE_CLK_EN, 1, 1);
	if (ret)
		return ret;
	/* prevent micro exceptions when REFCLK is absent */
	ret = sd_wr_field(PMD_DEV, REG_MICRO_PMI_FAST_RD, 0x0001, 0, 0);
	if (ret)
		return ret;
	return sd_wr_field(PMD_DEV, REG_MICRO_RST_CTRL, MICRO_CORE_RSTB, 1, 1);
}

/* merlin16_shortfin_internal.c:2031..2044, 100 iterations */
static int poll_micro_ra_initdone(void)
{
	int i, v;

	for (i = 0; i <= 100; i++) {
		v = sd_rdc(REG_MICRO_RAM_STATUS);
		if (v < 0)
			return v;
		if (v & MICRO_RA_INITDONE)
			return 0;
		merlin_delay_us(2500);	/* vendor: 10 * timeout_ms(250) us */
	}
	pr_err(DRV ": micro_ra_initdone timeout\n");
	bcm96764_mark(E66B_MK_ERR_SD_UCODE_LOAD);
	return -ETIMEDOUT;
}

/* merlin_shortfin/src/merlin16_shortfin_config.c:691..740, ucode_mdio_load() */
static int merlin_ucode_load(const u8 *img, u32 len)
{
	u32 padded, count = 0;
	int ret;

	if (len > UCODE_MAX_SIZE)
		return -EINVAL;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL, MICRO_MASTER_CLK_EN, 0, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RST_CTRL, MICRO_MASTER_RSTB, 0, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RST_CTRL, MICRO_MASTER_RSTB, 0, 0);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RST_CTRL, MICRO_MASTER_RSTB, 0, 1);
	if (ret)
		return ret;

	/* initialise code RAM, then data RAM */
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RA_INIT_MASK,
			  MICRO_RA_INIT_SHIFT, 1);
	if (ret)
		return ret;
	selftest_d202 = sd_rdc(REG_MICRO_RAM_CTRL);
	pr_info(DRV ": selftest: 0xD202 after ra_init=1 reads 0x%x\n", selftest_d202);
	ret = poll_micro_ra_initdone();
	if (ret)
		return ret;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RA_INIT_MASK,
			  MICRO_RA_INIT_SHIFT, 2);
	if (ret)
		return ret;
	ret = poll_micro_ra_initdone();
	if (ret)
		return ret;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RA_INIT_MASK,
			  MICRO_RA_INIT_SHIFT, 0);
	if (ret)
		return ret;

	padded = (len + 3) & ~3u;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_AUTOINC_WR, 12, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_WRDATASIZE_MASK, 0, 1);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_MSW, 0x0000);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_LSW, 0x0000);
	if (ret)
		return ret;

	do {
		u8 lsb = (count < len) ? img[count] : 0;
		u8 msb;

		count++;
		msb = (count < len) ? img[count] : 0;
		count++;

		ret = sd_wr(PMD_DEV, REG_MICRO_WRDATA_LSW,
			    (u16)((msb << 8) | lsb));
		if (ret)
			return ret;

		if ((count & 0x3ff) == 0)
			cond_resched();
	} while (count < padded);

	/* back to 32-bit transfers, enable the M0 core clock */
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_WRDATASIZE_MASK, 0, 2);
	if (ret)
		return ret;
	return sd_wr_field(PMD_DEV, REG_MICRO_CLK_CTRL, MICRO_CORE_CLK_EN, 1, 1);
}

/* merlin_shortfin/src/merlin16_shortfin_config.c:742..785, ucode_load_verify() */
static int merlin_ucode_verify(const u8 *img, u32 len)
{
	u32 padded = (len + 3) & ~3u;
	u32 count = 0;
	int ret;

	if (padded > UCODE_MAX_SIZE)
		return -EINVAL;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_AUTOINC_RD, 13, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RDDATASIZE_MASK,
			  MICRO_RDDATASIZE_SHIFT, 1);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_RDADDR_MSW, 0x0000);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_RDADDR_LSW, 0x0000);
	if (ret)
		return ret;

	do {
		u8 lsb = (count < len) ? img[count] : 0;
		u8 msb;
		u16 expect;
		int got;

		count++;
		msb = (count < len) ? img[count] : 0;
		count++;
		expect = (u16)((msb << 8) | lsb);

		got = sd_rdc(REG_MICRO_RDDATA_LSW);
		if (got < 0)
			return got;
		if ((u16)got != expect) {
			pr_err(DRV ": ucode verify fail at 0x%x: got 0x%04x want 0x%04x\n",
			       count - 2, got, expect);
			bcm96764_mark(E66B_MK_ERR_SD_UCODE_VERIFY);
			return -EIO;
		}

		if ((count & 0x3ff) == 0)
			cond_resched();
	} while (count < padded);

	return sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RDDATASIZE_MASK,
			   MICRO_RDDATASIZE_SHIFT, 2);
}

/* merlin_shortfin/src/merlin16_shortfin_config.c:525..538, wait_uc_active() */
static int merlin_lib_wait_uc_active(void)
{
	int i, v;

	for (i = 0; i < 10000; i++) {
		v = sd_rdc(REG_UC_ACTIVE);
		if (v < 0)
			return v;
		if (v & UC_ACTIVE)
			return 0;
		if (i > 10)
			udelay(1);
	}
	pr_err(DRV ": uc_active never asserted\n");
	bcm96764_mark(E66B_MK_ERR_SD_UC_ACTIVE);
	return -ETIMEDOUT;
}

/*
 * merlin16_shortfin_config.c (Serdes146Class) :199..224, merlin_wait_uc_active().
 * This is the one that produces the stock "micro is ready for command" line.
 * The vendor calls fatal_log()/BUG() on failure; we return an error instead.
 */
static int merlin_wait_uc_active(void)
{
	int v;

	udelay(12);				/* 12us "comclks" */

	v = sd_rdc(REG_UC_ACTIVE);
	if (v < 0)
		return v;
	if (!(v & UC_ACTIVE)) {
		pr_err(DRV ": uc_active check failed (0xd0f4=0x%04x)\n", v);
		bcm96764_mark(E66B_MK_ERR_SD_UC_ACTIVE);
		return -EIO;
	}

	udelay(20);
	msleep(100);

	v = sd_rdc(REG_DSC_UC_CTRL);
	if (v < 0)
		return v;
	if (!(v & DSC_READY_FOR_CMD)) {
		pr_err(DRV ": uc_dsc_ready_for_cmd not set (0xd00d=0x%04x)\n", v);
		bcm96764_mark(E66B_MK_ERR_SD_DSC);
		return -EIO;
	}
	if (v & DSC_ERROR_FOUND) {
		pr_err(DRV ": uc_dsc_error_found set (0xd00d=0x%04x)\n", v);
		bcm96764_mark(E66B_MK_ERR_SD_DSC);
		return -EIO;
	}

	pr_info(DRV ": micro is ready for command\n");
	return 0;
}

/* merlin16_shortfin_internal.c:1976..2010, poll uc_dsc_ready_for_cmd == 1 */
static int poll_dsc_ready(u32 timeout_ms)
{
	int i, v;

	for (i = 0; i < 100; i++) {
		v = sd_rdc(REG_DSC_UC_CTRL);
		if (v < 0)
			return v;
		if (v & DSC_READY_FOR_CMD) {
			if (v & DSC_ERROR_FOUND) {
				pr_err(DRV ": dsc error found (0x%04x)\n", v);
				bcm96764_mark(E66B_MK_ERR_SD_DSC);
				return -EIO;
			}
			return 0;
		}
		if (i > 10)
			merlin_delay_us(10 * timeout_ms);
	}
	pr_err(DRV ": dsc ready-for-cmd timeout\n");
	bcm96764_mark(E66B_MK_ERR_SD_DSC);
	return -ETIMEDOUT;
}

/*
 * merlin_shortfin/src/merlin16_shortfin_access.c:91..96 + config.c:73..84 - ask the micro to CRC
 * the program RAM and compare against the value shipped with the image.
 */
static int merlin_ucode_crc_verify(u16 len, u16 expect)
{
	int ret, v;

	ret = poll_dsc_ready(1);
	if (ret)
		return ret;

	ret = sd_wr(PMD_DEV, REG_DSC_UC_DATA, len);
	if (ret)
		return ret;
	/* supp_info << 8 | cmd, written as one register write */
	ret = sd_wr(PMD_DEV, REG_DSC_UC_CTRL, CMD_CALC_CRC);
	if (ret)
		return ret;

	ret = poll_dsc_ready(200);
	if (ret)
		return ret;

	v = sd_rdc(REG_DSC_UC_DATA);
	if (v < 0)
		return v;
	if ((u16)v != expect) {
		pr_err(DRV ": ucode CRC mismatch: got 0x%04x want 0x%04x\n",
		       v, expect);
		bcm96764_mark(E66B_MK_ERR_SD_CRC);
		return -EIO;
	}
	return 0;
}

/*
 * merlin_shortfin/src/merlin16_shortfin_config.c:540..614 + access.c:359..369 +
 * internal.c:2086..2150.  The vendor caches the whole info table in a
 * software struct used by the higher-level diag APIs; the bring-up path
 * never reads that struct back, so here it is only a health check on the
 * signature and version, which is what makes the load trustworthy.
 */
static int merlin_check_info_table(void)
{
	u32 sig;
	u8 ver;
	u16 w[2];
	int ret;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_AUTOINC_RD, 13, 1);
	if (ret)
		return ret;
	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RDDATASIZE_MASK,
			  MICRO_RDDATASIZE_SHIFT, 1);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_RDADDR_MSW, 0x0000);
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_RDADDR_LSW, INFO_TABLE_RAM_BASE);
	if (ret)
		return ret;

	/* first u32 of the table is the signature; auto-increment gives us
	 * two consecutive 16-bit reads */
	ret = sd_rd(PMD_DEV, REG_MICRO_RDDATA_LSW, &w[0]);
	if (ret)
		return ret;
	ret = sd_rd(PMD_DEV, REG_MICRO_RDDATA_LSW, &w[1]);
	if (ret)
		return ret;

	ret = sd_wr_field(PMD_DEV, REG_MICRO_RAM_CTRL, MICRO_RDDATASIZE_MASK,
			  MICRO_RDDATASIZE_SHIFT, 2);
	if (ret)
		return ret;

	sig = ((u32)w[1] << 16) | w[0];
	ver = (u8)(sig >> 24);

	if ((sig & 0x00ffffff) != INFO_TABLE_SIGNATURE ||
	    !((ver >= 0x32 && ver <= 0x39) || (ver >= 0x41 && ver <= 0x5A))) {
		pr_err(DRV ": bad ucode info table signature 0x%08x\n", sig);
		bcm96764_mark(E66B_MK_ERR_SD_CRC);
		return -EIO;
	}

	pr_info(DRV ": ucode info table ok (signature 0x%08x, version '%c')\n",
		sig, ver);
	return 0;
}

/* -------------------------------------------------- RAM variable writes -- */

/*
 * merlin16_shortfin_config.c (Serdes146Class) :400..433, cfg_core_ram_var().
 * core_config_word = [6] an_los_workaround | [5:1] vco_rate | [0] cfg_from_pcs
 * with cfg_from_pcs forced to 0 by the vendor.
 *
 * NOTE (unverified): the vendor writes only wrdata_lsw here, while the RAM
 * interface was left in 32-bit auto-increment mode by the ucode load, so it
 * is not certain the word is actually committed on hardware.  Mirrored
 * exactly rather than "fixed", because the stock log shows this path
 * producing a working 2.5G link.
 */
static int merlin_cfg_core_ram_var(u16 vco_rate)
{
	u32 base = UC_RAM_WINDOW + CORE_VAR_RAM_OFFSET;
	u16 word = (u16)(vco_rate << 1);	/* an_los=0, from_pcs=0 */
	int ret;

	pr_info(DRV ": RAM variable vco_rate is %u (core_config_word 0x%04x)\n",
		vco_rate, word);

	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_MSW, (u16)(base >> 16));
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_LSW, (u16)(base & 0xffff));
	if (ret)
		return ret;
	return sd_wr(PMD_DEV, REG_MICRO_WRDATA_LSW, word);
}

/*
 * merlin16_shortfin_config.c (Serdes146Class) :701..767, cfg_lane_ram_var().
 * For USXGMII_S at speeds below 10G with AN off the whole word is zero.
 */
static int merlin_cfg_lane_ram_var(void)
{
	u32 base = UC_RAM_WINDOW + LANE_VAR_RAM_OFFSET;
	int ret;

	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_MSW, (u16)(base >> 16));
	if (ret)
		return ret;
	ret = sd_wr(PMD_DEV, REG_MICRO_WRADDR_LSW, (u16)(base & 0xffff));
	if (ret)
		return ret;
	return sd_wr(PMD_DEV, REG_MICRO_WRDATA_LSW, 0x0000);
}

/* ---------------------------------------------------------- polarity ---- */

/* phy_drv_146class_serdes.c:212..235 */
static int merlin_xfi_polarity(bool tx, bool inverse)
{
	u16 reg = tx ? REG_XFI_TX_POLARITY : REG_XFI_RX_POLARITY;
	int v;

	v = sd_rdc(reg);
	if (v < 0)
		return v;

	v &= ~1;
	v |= inverse ? 1 : 0;
	return sd_wr(PMD_DEV, reg, (u16)v);
}

static int merlin_polarity_config(void)
{
	int ret = 0;

	if (tx_polarity_inverse) {
		pr_info(DRV ": invert XFI Tx polarity\n");
		ret = merlin_xfi_polarity(true, true);
		if (ret)
			return ret;
	}
	if (rx_polarity_inverse) {
		pr_info(DRV ": invert XFI Rx polarity\n");
		ret = merlin_xfi_polarity(false, true);
	}
	return ret;
}

/* --------------------------------------------------- core / speed set --- */

/* merlin16_shortfin_config.c (Serdes146Class) :137..145, serdes_core_reset() */
static int merlin_core_reset(void)
{
	int ret;

	pr_info(DRV ": Toggle Serdes Core #%d PMD and uC reset.\n", sd_core);
	ret = sd_wr(PMD_DEV, REG_CORE_RESET, 0x0000);
	if (ret)
		return ret;
	msleep(1);
	ret = sd_wr(PMD_DEV, REG_CORE_RESET, 0x0001);
	if (ret)
		return ret;
	msleep(1);
	return 0;
}

/* merlin16_shortfin_config.c (Serdes146Class) :147..165, merlin_core_init() */
static int merlin_core_init(void)
{
	int ret;

	/* turn off the R2PMI low-power broadcast mode */
	writel(0, ethtop_base + ETHTOP_R2PMI_LP_BCAST_MODE_CNTRL);

	ret = merlin_core_reset();
	if (ret)
		return ret;

	pr_info(DRV ": merlin_core_init: END. Core #%d with PRTAD = %d, ln_offset_stap = 0\n",
		sd_core, sd_prtad);
	return 0;
}

/* merlin16_shortfin_config.c (Serdes146Class) :100..117, merlin_load_firmware() */
static int merlin_load_firmware(void)
{
	int ret;

	/* The vendor skips the MDIO multi-port / broadcast-address writes on
	 * 6764/6765/6766 (merlin16_shortfin_config.c merlin_load_firmware(),
	 * "#if !defined(CONFIG_BCM96764)"); run #51 died right after them. */
	if (mdio_prts) {
		ret = sd_wr_field(PMD_DEV, REG_MDIO_MULTI_PRTS, 0x8000, 15, 0);
		if (ret)
			return ret;
		ret = sd_wr_field(PMD_DEV, REG_MDIO_BRCST_ADDR, 0x001f, 0, sd_prtad);
		if (ret)
			return ret;
	}

	ret = merlin_uc_reset(true);
	if (ret)
		return ret;
	/* run #53 self-test: read back 0xD225 (just written 0x8201) */
	selftest_d225 = sd_rdc(REG_MICRO_D225);
	pr_info(DRV ": selftest: 0xD225 reads back 0x%x\n", selftest_d225);

	pr_info(DRV ": Step 6. Micro code load and verify (%u bytes, version %s)\n",
		(unsigned int)MERLIN16_UCODE_SIZE, MERLIN16_UCODE_VERSION);

	ret = merlin_ucode_load(merlin16_shortfin_ucode, MERLIN16_UCODE_SIZE);
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_UCODE_LOADED);

	ret = merlin_ucode_verify(merlin16_shortfin_ucode, MERLIN16_UCODE_SIZE);
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_UCODE_VERIFIED);

	ret = merlin_uc_reset(false);
	if (ret)
		return ret;

	ret = merlin_lib_wait_uc_active();
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_UC_ACTIVE);

	ret = merlin_ucode_crc_verify(MERLIN16_UCODE_SIZE, MERLIN16_UCODE_CRC);
	if (ret)
		return ret;

	ret = merlin_check_info_table();
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_UCODE_CRC);

	pr_info(DRV ": merlin_load_firmware: ret = 0\n");
	return 0;
}

/*
 * merlin16_shortfin_config.c (Serdes146Class) :1119..1374,
 * merline_speed_set_core().
 *
 * vco_12p5g is true for the *BASE-X* inter-phy types (1GBASE-X, 2.5GBASE-X,
 * 2500BASE-X, 5GBASE-X, 5000BASE-X) and false otherwise; that is exactly why
 * the stock log has two passes.  Pass 1 uses 1000BASE-X (not in the list) ->
 * 10.3125GHz VCO, vco_rate 19.  Pass 2 uses the DT's config-xfi
 * "2500Base-X" == INTER_PHY_TYPE_2500BASE_X (in the list) -> 12.5GHz VCO,
 * vco_rate 28.
 *
 * The DT's force-2p5g-10gvco has NO effect on this SoC: PhyIsForced2p5g10GVco
 * is only consulted by Serdes6756Class/merlin28_shortfin_config.c:1797, the
 * merlin28 driver for the 6756 family.  On 6764 the property is parsed
 * (dt_parsing.c:240) and then never read.
 */
static int merline_speed_set_core(bool vco_12p5g, const struct prog_ent *speed_tbl,
				  int mln_spd)
{
	u16 vco_rate;
	int ret;

	pr_info(DRV ": merline_speed_set_core: Step 7 Config Speed to %d\n", mln_spd);

	/* restore everything the previous speed pass wrote */
	ret = restore_regs();
	if (ret)
		return ret;

	/* Step 8: PLL / PMD setup.  parse_sim_opts("-d separate_vco") is 1 in
	 * the vendor option table (config.c (Serdes146Class) :50..56), so the 12.5G clock-count
	 * table is programmed before the PMD setup. */
	if (vco_12p5g) {
		ret = merlin_reg_prog(initialize_12p5_vco);
		if (ret)
			return ret;
		pr_info(DRV ": PMD Setup 80MHz, 12.5GHz VCO programming\n");
		ret = merlin_reg_prog(pmd_setup_80_12p5_vco);
	} else {
		pr_info(DRV ": PMD Setup 80MHz, 10.3125GHz VCO programming\n");
		ret = merlin_reg_prog(pmd_setup_80_10p3125_vco);
	}
	if (ret)
		return ret;

	/* the VCO change can knock the micro over */
	ret = merlin_wait_uc_active();
	if (ret)
		return ret;

	/* Step 9 / Step 10: core level registers + core_config_from_pcs.
	 * vco_rate = vco_GHz * 4 - 22, truncated: 28 for 12.5, 19 for 10.3125 */
	pr_info(DRV ": Step 9. Configure Core level regsiter\n");
	pr_info(DRV ": Step 10. Set core_congif_from_pcs\n");
	vco_rate = vco_12p5g ? 28 : 19;
	ret = merlin_cfg_core_ram_var(vco_rate);
	if (ret)
		return ret;

	/* Step 12: datapath reset (core) */
	pr_info(DRV ": Step 12. Reset Datapath (core)\n");
	ret = merlin_reg_prog(datapath_reset_core);
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_CORE_CFG);

	/* Step 13 / 13.a: lane registers.  en_hpf = 0 below 10G. */
	pr_info(DRV ": Step 13. Lane Configuration\n");
	pr_info(DRV ": Step 13.a. Configure lane registers\n");
	ret = sd_pmi_wr(PMD_DEV, 0xd0a2, 0x0000, 0xfff0);
	if (ret)
		return ret;

	/* Step 13.b: lane RAM variables */
	ret = merlin_cfg_lane_ram_var();
	if (ret)
		return ret;

	/* program the lane speed mode */
	ret = merlin_reg_prog(speed_tbl);
	if (ret)
		return ret;

	pr_info(DRV ": Core #%d Lane #%d PMD Lock Speed Up programming\n",
		sd_core, SD_LANE);

	/* final PLL lock check */
	ret = merlin_chk_pll_lock();
	if (ret)
		return ret;

	bcm96764_mark(E66B_MK_SD_LANE_CFG);
	d128_after_lock = sd_rdc(0xd128);
	pr_info(DRV ": d128 after PLL lock check: 0x%x\n", d128_after_lock);
	return 0;
}

/*
 * merlin16_shortfin_config.c (Serdes146Class) :1403..1461, merlin16_serdes_init()
 * plus phy_drv_146class_serdes.c:142..210 (PRTAD latch) and
 * :398..419 (_merlin_core_power_op -> polarity config).
 */
static int merlin16_serdes_init(void)
{
	u32 v;
	int ret;

	pr_info(DRV ": === Start of 10G Active Ethernet Initialization for core %d port 0 ===\n",
		sd_core);

	/* phy_drv_146class_serdes.c:184..188 - latch the serdes MDIO address */
	v = readl(sd_reg(SD_CONTROL));
	v = (v & ~SD_CTL_PRTAD_MASK) | ((u32)sd_prtad << SD_CTL_PRTAD_SHIFT);
	writel(v, sd_reg(SD_CONTROL));

	pr_info(DRV ": --- Step 0 powerup/reset sequence of core #%d at address %d\n",
		sd_core, sd_prtad);

	/*
	 * Power on: up / down / up so a later power-down is not bypassed
	 * (config.c:1417..1419).  The 146class wrapper applies the XFI
	 * polarity inversion after each power-up
	 * (phy_drv_146class_serdes.c:414..417), so do it here too.
	 */
	serdes_access_config(true);
	serdes_access_config(false);
	serdes_access_config(true);
	ret = merlin_polarity_config();
	if (ret)
		return ret;

	saved_cnt = 0;
	register_dont_save = false;

	ret = merlin_core_init();
	if (ret)
		return ret;
	bcm96764_mark(E66B_MK_SD_CORE_RESET);

	udelay(1);				/* timeout_ns(1000) */

	ret = merlin_load_firmware();
	if (ret)
		return ret;

	/*
	 * "Set default 1G speed to fully exercise hardware status"
	 * (config.c:1445..1449).  INTER_PHY_TYPE_1000BASE_X is not a BASE-X
	 * type for the vco_12p5g test, hence the 10.3125GHz first pass in the
	 * stock log.
	 */
	ret = merline_speed_set_core(false, force_speed_1g, 0x0002 /* MLN_SPD_FORCE_1G */);
	if (ret)
		return ret;

	/* enable LPI pass-through */
	ret = merlin_reg_prog(lpi_enable);
	if (ret)
		return ret;

	pr_info(DRV ": END Merlin Initialization procedure\n");
	return 0;
}

/* ------------------------------------------------------------- public --- */

int serdes6764_init_2p5g(void)
{
	int ret;

	if (!sd_base || !ethtop_base) {
		bcm96764_mark(E66B_MK_ERR_SD_MAP);
		return -ENODEV;
	}

	mutex_lock(&sd_lock);

	/* Stock order (obs/stock-dmesg-serdes-2026-09-07.txt): full init at 1G,
	 * XFI polarity inversion, a second full init at 1G, then the speed set
	 * to FORCE 2P5G on the 10.3125GHz VCO (vco_rate 19 in the stock log).
	 * No polarity write afterwards. */
	if (!sd_inited) {
		ret = merlin16_serdes_init();
		if (ret)
			goto out;
		ret = merlin_polarity_config();
		if (ret)
			goto out;
		if (double_init) {
			ret = merlin16_serdes_init();
			if (ret)
				goto out;
		}
		sd_inited = true;
	}

	ret = merline_speed_set_core(!!p2_vco12p5, force_speed_2p5g, 0x0003);
	if (ret)
		goto out;

	/* run #59: does the XFI polarity survive the second full init + speed set? */
	pol_tx_end = sd_rdc(REG_XFI_TX_POLARITY);
	pol_rx_end = sd_rdc(REG_XFI_RX_POLARITY);
	pr_info(DRV ": polarity at end: tx 0x%x rx 0x%x\n", pol_tx_end, pol_rx_end);
	if (pol_reapply) {
		ret = merlin_polarity_config();
		if (ret)
			goto out;
	}

	bcm96764_mark(E66B_MK_SD_2P5G);
	d128_end = sd_rdc(0xd128);
	st_end = readl(sd_reg(SD_STATUS));
	ctrl_end = readl(sd_reg(SD_CONTROL));
	pr_info(DRV ": === End of 10G Active Ethernet Initialization for core %d port 0 ===\n",
		sd_core);

out:
	init_ret = ret;
	if (ret)
		st_end = readl(sd_reg(SD_STATUS));
	mutex_unlock(&sd_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(serdes6764_init_2p5g);

/*
 * phy_drv_146class_serdes.c:332..335 -> merlin_chk_lane_link_status()
 * (config.c (Serdes146Class) :874..).  The AN link status and the speed nibbles live in the
 * serdes block itself: ETH_PHYS_TOP_BASE(0x80280000) + 0x2020/0x2024 is the
 * same address as serdes_base(0x80282000) + 0x20/0x24, i.e. SERDES_0_AN_STATUS
 * and SERDES_0_STATUS_1 from serdes_access_6764.h.
 */
int serdes6764_link_up(void)
{
	u32 an, st1 = 0;
	int i;

	if (!sd_base)
		return -ENODEV;

	/* filter out short false link-ups: 10 consecutive reads must agree */
	for (i = 0; i < 10; i++) {
		an = readl(sd_reg(SD_AN_STATUS));
		if (!(an & (1u << SD_LANE)))
			return 0;
		msleep(1);
	}

	/* wait for the speed field to be populated */
	for (i = 0; i < 10; i++) {
		st1 = readl(sd_reg(SD_STATUS_1));
		if (st1 & ((1u << 24) - 1))
			break;
		msleep(1);
	}
	if (!(st1 & ((1u << 24) - 1)))
		return 0;			/* false link up */

	return 1;
}
EXPORT_SYMBOL_GPL(serdes6764_link_up);

/* returns the negotiated/forced speed in Mbps, 0 when unknown */
static int serdes6764_speed(void)
{
	u32 st1;

	if (!sd_base)
		return 0;

	st1 = readl(sd_reg(SD_STATUS_1));
	if (st1 & (1u << (SD_S1_SPEED_10G + SD_LANE)))
		return 10000;
	if (st1 & (1u << (SD_S1_SPEED_5G + SD_LANE)))
		return 5000;
	if (st1 & (1u << (SD_S1_SPEED_2P5G + SD_LANE)))
		return 2500;
	if (st1 & (1u << (SD_S1_SPEED_1G + SD_LANE)))
		return 1000;
	if (st1 & (1u << (SD_S1_SPEED_100M + SD_LANE)))
		return 100;
	if (st1 & (1u << (SD_S1_SPEED_10M + SD_LANE)))
		return 10;
	return 0;
}

/* ---------------------------------------------------------- module ------ */

static void __iomem *map_block(const char *compat, unsigned long fallback,
			       unsigned int size, const char *what)
{
	struct device_node *np;
	void __iomem *p;

	np = of_find_compatible_node(NULL, NULL, compat);
	if (np) {
		p = of_iomap(np, 0);
		of_node_put(np);
		if (p)
			return p;
		pr_err(DRV ": of_iomap(%s) failed\n", compat);
		return NULL;
	}

	if (!fallback) {
		pr_err(DRV ": no \"%s\" DT node and no %s override\n",
		       compat, what);
		return NULL;
	}

	p = ioremap(fallback, size);
	if (!p) {
		pr_err(DRV ": ioremap(0x%lx) failed\n", fallback);
		return NULL;
	}
	pr_warn(DRV ": no \"%s\" DT node, using %s=0x%lx\n",
		compat, what, fallback);
	return p;
}

static int __init serdes6764_module_init(void)
{
	int ret, c, primary;

	if (!cores)
		cores = 0x1;
	primary = __ffs(cores);
	sd_core = primary;
	sd_prtad = core_prtad(primary);

	sd_base = map_block("brcm,serdes1", serdes_base_phys, 0x1300,
			    "serdes_base_phys");
	if (!sd_base) {
		bcm96764_mark(E66B_MK_ERR_SD_MAP);
		return -ENODEV;
	}

	ethtop_base = map_block("brcm,eth-phy-top", ethtop_base_phys, 0x200,
				"ethtop_base_phys");
	if (!ethtop_base) {
		bcm96764_mark(E66B_MK_ERR_SD_MAP);
		iounmap(sd_base);
		sd_base = NULL;
		return -ENODEV;
	}

	bcm96764_mark(E66B_MK_SD_PROBE);
	pr_info(DRV ": mapped serdes and eth-phy-top\n");

	if (!autoinit)
		return 0;

	/* Bring up every selected core in turn.  A board with two of them (the
	 * WR3600H: core 0 to the 53134, core 1 to the 2.5G WAN cascade PHY)
	 * runs the identical sequence twice, one SD_CORE_STRIDE apart. */
	for (c = 0; c < SD_MAX_CORES; c++) {
		if (!(cores & (1u << c)))
			continue;

		sd_core = c;
		sd_prtad = core_prtad(c);

		ret = serdes6764_init_2p5g();
		if (ret) {
			pr_err(DRV ": core %d: 2.5G bring-up failed: %d\n",
			       c, ret);
			continue;	/* try the next core, stay loaded */
		}

		ret = serdes6764_link_up();
		if (ret > 0) {
			if (c == primary)
				bcm96764_mark(E66B_MK_SD_LINK);
			pr_info(DRV ": core %d: serdes link UP at %d Mbps\n",
				c, serdes6764_speed());
		} else {
			if (c == primary)
				bcm96764_mark(E66B_MK_ERR_SD_LINK);
			pr_warn(DRV ": core %d: serdes link down after bring-up (%d)\n",
				c, ret);
		}
	}

	/* leave the helpers pointing at the primary (LAN uplink) core */
	sd_core = primary;
	sd_prtad = core_prtad(primary);
	return 0;
}

static void __exit serdes6764_module_exit(void)
{
	if (ethtop_base)
		iounmap(ethtop_base);
	if (sd_base)
		iounmap(sd_base);
	ethtop_base = NULL;
	sd_base = NULL;
}

module_init(serdes6764_module_init);
module_exit(serdes6764_module_exit);

MODULE_DESCRIPTION("BCM6764 Merlin16-shortfin serdes bring-up (2500Base-X)");
MODULE_LICENSE("GPL");
