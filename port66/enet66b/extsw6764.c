// SPDX-License-Identifier: GPL-2.0
/*
 * extsw6764.c - bring-up of the external BCM53134-class switch hanging off
 *               the BCM6764's SF2 port 5 (2.5G SGMII / XFI serdes core 0).
 *
 * Ported from the vendor U-Boot 2019.07 GPL tree:
 *   drivers/net/bcmbca/bcm_ethsw_ext.c      (probe, sw_reset, sw_setup, sw_open)
 *   drivers/net/bcmbca/mii_shared.h         (page/register constants)
 *   drivers/net/bcmbca/bcm_ethsw_phy.c      (MDIO primitives)
 *   drivers/net/bcmbca/phy/phy_drv_mii.c    (mii_init / mii_power_set)
 *   drivers/gpio/gpio-bcm-bca.c             (GPIO dir/data register model)
 *
 * Topology, from the stock DTB:
 *   node "0" { compatible = "brcm,bcmbca-extsw"; unit = <1>;
 *              extswsgmii_addr = <6>; switch-reset = <&gpioc 24 1>; }
 *   ports port_ext_gphy0..3 -> reg 0..3, phy-handle -> phy_ext_gphy0..3
 *   phy_ext_gphy0..3        -> "brcm,bcaphy", phy-type "EGPHY", reg 0..3
 *
 * Every switch register access rides the SF2 MDIO bus as a "pseudo PHY"
 * transaction at MDIO address 0x1e (mii_shared.h:355).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/mii.h>

#include "enet66b.h"

#define DRV "extsw6764"

/* --------------------------------------------------------- parameters -- */

/*
 * GPIO block.  There is no upstream driver for "brcm,bca-gpio" in 6.6 and
 * the minimal 6764 DTS does not carry the node yet, so the physical
 * addresses are allowed as a documented fallback:
 *
 *   stock DTB: periph { ranges = <0 0 0xff800000 0x400000>; }
 *              gpioc  { compatible = "brcm,bca-gpio";
 *                       reg = <0x500 0x20 0x520 0x20>;
 *                       reg-names = "gpio-dir", "gpio-data";
 *                       ngpios = <0x62>; }
 *   live /proc/iomem on the stock kernel:
 *              ff800500-ff80051f gpio-dir
 *              ff800520-ff80053f gpio-data
 *
 * Both are still looked up in the DT first; the constants are only used when
 * the node is absent.
 */
#define GPIO_DIR_PHYS_DEFAULT	0xff800500UL
#define GPIO_DATA_PHYS_DEFAULT	0xff800520UL
#define GPIO_BANK_SIZE		0x20

static unsigned long gpio_dir_phys = GPIO_DIR_PHYS_DEFAULT;
module_param(gpio_dir_phys, ulong, 0444);
MODULE_PARM_DESC(gpio_dir_phys, "phys addr of the bca gpio-dir bank (fallback when the DT node is missing)");

static unsigned long gpio_data_phys = GPIO_DATA_PHYS_DEFAULT;
module_param(gpio_data_phys, ulong, 0444);
MODULE_PARM_DESC(gpio_data_phys, "phys addr of the bca gpio-data bank (fallback when the DT node is missing)");

/* switch-reset = <&gpioc 24 GPIO_ACTIVE_LOW> */
static int reset_gpio = 24;
module_param(reset_gpio, int, 0444);
MODULE_PARM_DESC(reset_gpio, "GPIO driving the external switch reset (stock: 24)");

static int reset_active_low = 1;
module_param(reset_active_low, int, 0444);
MODULE_PARM_DESC(reset_active_low, "reset GPIO polarity from the DT flags (stock: 1 = active low)");

/* extswsgmii_addr = <6>: non-zero means the interconnect is SGMII, and the
 * value is the MDIO address of the switch-side serdes. */
static int ext_sw_sgmii = 6;
module_param(ext_sw_sgmii, int, 0444);
MODULE_PARM_DESC(ext_sw_sgmii, "extswsgmii_addr from the DT (0 = RGMII interconnect)");

static int autoinit = 1;
module_param(autoinit, int, 0444);
MODULE_PARM_DESC(autoinit, "run extsw6764_init() at module load");

static int link_wait_ms = 4000;
module_param(link_wait_ms, int, 0644);
MODULE_PARM_DESC(link_wait_ms, "how long to wait for port-8 / LAN link before reporting");

static int pll_afe = 1;
module_param(pll_afe, int, 0444);
static unsigned int afe13_pre, afe16_pre, afe17_pre;
module_param(afe13_pre, uint, 0444);
module_param(afe16_pre, uint, 0444);
module_param(afe17_pre, uint, 0444);

/* ------------------------------------------- pseudo-PHY register model -- */
/* mii_shared.h:355..373 */
#define PSEUDO_PHY_ADDR			0x1e
#define REG_PSEUDO_MII_16		0x10	/* page select              */
#define REG_PSEUDO_MII_17		0x11	/* reg number + op         */
#define REG_PSEUDO_MII_24		0x18	/* data [15:0]             */
#define REG_PSEUDO_MII_25		0x19	/* data [31:16]            */
#define  PPM16_PAGE_SHIFT		8
#define  PPM16_MDIO_ENABLE		0x01
#define  PPM17_REG_SHIFT		8
#define  PPM17_OP_DONE			0x00
#define  PPM17_OP_WRITE			0x01
#define  PPM17_OP_READ			0x02
#define  PPM17_OP_MASK			(PPM17_OP_WRITE | PPM17_OP_READ)

/* switch pages / registers, mii_shared.h:230..330 */
#define PAGE_CONTROL			0x00
#define  PORT_CTRL_PORT			0x00	/* +port                    */
#define   PORT_CTRL_RX_DISABLE		0x01
#define   PORT_CTRL_TX_DISABLE		0x02
#define   PORT_CTRL_RXTX_DISABLE	0x03
#define   PORT_CTRL_STATUS_SHIFT	5
#define   PORT_CTRL_STATUS_MASK		(7 << 5)
#define   PORT_CTRL_NO_STP		(0 << 5)
#define  REG_SWITCH_MODE		0x0b
#define   SWITCH_MODE_FRAME_MANAGE	0x01
#define   SWITCH_MODE_SW_FWDG_EN	0x02
#define   SWITCH_MODE_RETRY_LIMIT_DIS	0x04
#define  REG_MII1_PORT_STATE_OVERRIDE	0x0e	/* IMP / port 8 override    */
#define   MPSO_MII_SW_OVERRIDE		0x80
#define   MPSO_FLOW_CONTROL		0x30
#define   MPSO_SPEED1000		0x08
#define   MPSO_FDX			0x02
#define   MPSO_LINKPASS			0x01
#define  REG_SWITCH_CONTROL		0x22
#define   SWITCH_CONTROL_MII_DUMP_FWD	0x40
#define  REG_PORT5_STATE_OVERRIDE	0x5d
#define  SOFTWARE_RESET_CTRL		0x79
#define   SOFTWARE_RESET		0x80
#define   EN_SW_RST			0x10

#define PAGE_STATUS			0x01
#define  REG_LNKSTS			0x00	/* 2 bytes, bit per port    */
#define  REG_SPDSTS			0x04	/* 2 bits per port          */
#define  REG_DUPSTS			0x08
#define  REG_STRAP_VAL			0x70	/* 4 bytes                  */
#define   STRAP_P8_SEL_SGMII		BIT(9)

#define PAGE_MANAGEMENT			0x02
#define  REG_BRCM_HDR_CTRL		0x03
#define  REG_DEVICE_ID			0x30	/* 4 bytes                  */

#define PAGE_PORT_BASED_VLAN		0x31
#define  REG_VLAN_CTRL_P0		0x00	/* +port*2, 2 bytes         */

/* switch-side serdes page used by sw_setup(), bcm_ethsw_ext.c:318..332 */
#define PAGE_SW_SERDES			0x14
#define PAGE_SW_SERDES_EN		0xe6

#define BP_MAX_SWITCH_PORTS		8	/* bcm_ethsw_ext.c:18       */
#define EXTSW_IMP_PORT			8	/* the 2.5G SGMII uplink    */
#define EXTSW_LAN_PORTS			4	/* MDIO 0..3 = LAN1..LAN4   */
#define PBMAP_MIPS			0x100	/* bcm_ethsw_ext.c:165      */

/*
 * MII_CTRL1000 bit 10 is the 1000BASE-T "port type" bit; Broadcom calls it
 * ADVERTISE_REPEATER_DTE (bcm_ethsw.h:43) and always sets it
 * (bcm_ethsw_phy.c:141..144).
 */
#define ADVERTISE_REPEATER_DTE		BIT(10)

static DEFINE_MUTEX(extsw_lock);
static void __iomem *gpio_dir;
static void __iomem *gpio_data;
static bool gpio_mapped_from_dt;
static u32 ext_sw_id;

/* ------------------------------------------------------ pseudo-PHY I/O -- */

/* bcm_ethsw_ext.c:167..211, sw_rreg() - 20 x 10us poll for op done */
static int sw_wait_op(void)
{
	int i, v;

	for (i = 0; i < 20; i++) {
		v = sf2_mdio_read(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_17);
		if (v < 0)
			return v;
		if ((v & PPM17_OP_MASK) == PPM17_OP_DONE)
			return 0;
		udelay(10);
	}

	pr_err(DRV ": pseudo-PHY op timeout\n");
	bcm96764_mark(E66B_MK_ERR_EXTSW_PSEUDO);
	return -ETIMEDOUT;
}

static int sw_rreg(int page, int reg, int len, u32 *out)
{
	int ret, v;
	u32 data = 0;

	ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_16,
			     (u16)((page << PPM16_PAGE_SHIFT) | PPM16_MDIO_ENABLE));
	if (ret)
		return ret;

	ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_17,
			     (u16)((reg << PPM17_REG_SHIFT) | PPM17_OP_READ));
	if (ret)
		return ret;

	ret = sw_wait_op();
	if (ret)
		return ret;

	v = sf2_mdio_read(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_24);
	if (v < 0)
		return v;

	switch (len) {
	case 1:
		data = (u8)v;
		break;
	case 2:
		data = (u16)v;
		break;
	case 4:
		data = (u16)v;
		v = sf2_mdio_read(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_25);
		if (v < 0)
			return v;
		data |= (u32)(u16)v << 16;
		break;
	default:
		return -EINVAL;
	}

	*out = data;
	return 0;
}

/* bcm_ethsw_ext.c:213..251, sw_wreg() */
static int sw_wreg(int page, int reg, u32 data, int len)
{
	int ret;

	ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_16,
			     (u16)((page << PPM16_PAGE_SHIFT) | PPM16_MDIO_ENABLE));
	if (ret)
		return ret;

	switch (len) {
	case 1:
		ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_24,
				     (u8)data);
		break;
	case 2:
		ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_24,
				     (u16)data);
		break;
	case 4:
		ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_24,
				     (u16)data);
		if (!ret)
			ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_25,
					     (u16)(data >> 16));
		break;
	default:
		return -EINVAL;
	}
	if (ret)
		return ret;

	ret = sf2_mdio_write(PSEUDO_PHY_ADDR, REG_PSEUDO_MII_17,
			     (u16)((reg << PPM17_REG_SHIFT) | PPM17_OP_WRITE));
	if (ret)
		return ret;

	return sw_wait_op();
}

/* ------------------------------------------------------------- GPIO ----- */

/* gpio-bcm-bca.c:15..17 */
#define GPIO_TO_IDX(g)		((g) >> 5)
#define GPIO_TO_MASK(g)		(1u << ((g) & 0x1f))

static int extsw_gpio_map(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, "brcm,bca-gpio");
	if (np) {
		int dir_idx = of_property_match_string(np, "reg-names", "gpio-dir");
		int data_idx = of_property_match_string(np, "reg-names", "gpio-data");

		if (dir_idx < 0)
			dir_idx = 0;
		if (data_idx < 0)
			data_idx = 1;

		gpio_dir = of_iomap(np, dir_idx);
		gpio_data = of_iomap(np, data_idx);
		of_node_put(np);

		if (gpio_dir && gpio_data) {
			gpio_mapped_from_dt = true;
			pr_info(DRV ": GPIO banks mapped from the DT\n");
			return 0;
		}
		if (gpio_dir)
			iounmap(gpio_dir);
		if (gpio_data)
			iounmap(gpio_data);
		gpio_dir = gpio_data = NULL;
		pr_err(DRV ": of_iomap(brcm,bca-gpio) failed\n");
		return -ENOMEM;
	}

	gpio_dir = ioremap(gpio_dir_phys, GPIO_BANK_SIZE);
	gpio_data = ioremap(gpio_data_phys, GPIO_BANK_SIZE);
	if (!gpio_dir || !gpio_data) {
		if (gpio_dir)
			iounmap(gpio_dir);
		if (gpio_data)
			iounmap(gpio_data);
		gpio_dir = gpio_data = NULL;
		return -ENOMEM;
	}

	pr_warn(DRV ": no brcm,bca-gpio node, using dir=0x%lx data=0x%lx\n",
		gpio_dir_phys, gpio_data_phys);
	return 0;
}

static void extsw_gpio_unmap(void)
{
	if (gpio_dir)
		iounmap(gpio_dir);
	if (gpio_data)
		iounmap(gpio_data);
	gpio_dir = gpio_data = NULL;
	gpio_mapped_from_dt = false;
}

/* gpio-bcm-bca.c:43..62, direction_output */
static void extsw_gpio_out(int gpio, int phys_value)
{
	void __iomem *d = gpio_dir + GPIO_TO_IDX(gpio) * 4;
	void __iomem *v = gpio_data + GPIO_TO_IDX(gpio) * 4;
	u32 mask = GPIO_TO_MASK(gpio);
	u32 reg;

	reg = readl(d);
	writel(reg | mask, d);

	reg = readl(v);
	if (phys_value)
		reg |= mask;
	else
		reg &= ~mask;
	writel(reg, v);
}

/*
 * bcm_ethsw_ext.c:564..571.  dm_gpio_set_value() takes the *logical* level,
 * so with GPIO_ACTIVE_LOW in the DT, "1 = reset active" means driving the
 * pin low.  The live stock system shows gpio-24 "SW reset" out hi, i.e.
 * released, which agrees.
 */
static void extsw_reset_set(bool assert_reset)
{
	int logical = assert_reset ? 1 : 0;
	int phys = reset_active_low ? !logical : logical;

	extsw_gpio_out(reset_gpio, phys);
}

/* ------------------------------------------------------- switch setup -- */

/* bcm_ethsw_ext.c:253..266, sw_reset() */
static int sw_reset(void)
{
	u32 val = 0;
	int ret, i;

	ret = sw_rreg(PAGE_MANAGEMENT, REG_DEVICE_ID, 4, &ext_sw_id);
	if (ret)
		return ret;

	if (!ext_sw_id || ext_sw_id == 0xffffffff) {
		pr_err(DRV ": bad switch device ID 0x%08x\n", ext_sw_id);
		bcm96764_mark(E66B_MK_ERR_EXTSW_ID);
		return -ENODEV;
	}

	pr_info(DRV ": external switch id 0x%08x\n", ext_sw_id);
	bcm96764_mark(E66B_MK_EXTSW_ID);

	pr_info(DRV ": Software Resetting Switch (Id=%x) ...\n", ext_sw_id);
	/* bcm_ethsw_ext.c:262 writes the literal 0x83 = SOFTWARE_RESET | 0x03,
	 * not SOFTWARE_RESET | EN_SW_RST; keep the value it actually uses. */
	ret = sw_wreg(PAGE_CONTROL, SOFTWARE_RESET_CTRL, 0x83, 1);
	if (ret)
		return ret;

	/* the vendor spins forever here; bound it at 1s */
	for (i = 0; i < 10000; i++) {
		ret = sw_rreg(PAGE_CONTROL, SOFTWARE_RESET_CTRL, 1, &val);
		if (ret)
			return ret;
		if (!(val & SOFTWARE_RESET))
			break;
		udelay(100);
	}
	if (val & SOFTWARE_RESET) {
		pr_err(DRV ": software reset never cleared (0x%02x)\n", val);
		bcm96764_mark(E66B_MK_ERR_EXTSW_SWRESET);
		return -ETIMEDOUT;
	}

	udelay(1000);
	pr_info(DRV ": software reset done\n");
	return 0;
}

/* bcm_ethsw_ext.c:268..280, sw_hw_ready() - bounded here */
static int sw_hw_ready(void)
{
	u32 val = 0;
	int i, port, ret;

	pr_info(DRV ": waiting for MAC port Rx/Tx to be enabled by hardware\n");

	for (port = 0; port < BP_MAX_SWITCH_PORTS; port++) {
		for (i = 0; i < 10000; i++) {
			ret = sw_rreg(PAGE_CONTROL, PORT_CTRL_PORT + port, 1, &val);
			if (ret)
				return ret;
			if (!(val & PORT_CTRL_RX_DISABLE))
				break;
			udelay(100);
		}
		if (val & PORT_CTRL_RX_DISABLE) {
			pr_err(DRV ": port %d never left rx-disable (0x%02x)\n",
			       port, val);
			bcm96764_mark(E66B_MK_ERR_EXTSW_HWREADY);
			return -ETIMEDOUT;
		}
	}
	return 0;
}

/*
 * bcm_ethsw_ext.c:282..334, sw_setup().
 *
 * The vendor never runs the SoC-side phy_sgmii_init() on this board: the
 * extsw DT node carries no "systemport-serdes-cntrl" resource, so
 * priv->serdes_cntrl stays NULL (bcm_ethsw_ext.c:541..545, 510).  The whole
 * 2.5G interconnect setup therefore lives in the register writes below,
 * which reach the 53134's own serdes through pseudo-PHY page 0x14.
 */
static int sw_setup(void)
{
	u32 val;
	int ret, i;

	ret = sw_rreg(PAGE_STATUS, REG_STRAP_VAL, 4, &val);
	if (ret)
		return ret;

	if (val & STRAP_P8_SEL_SGMII) {
		if (!ext_sw_sgmii) {
			pr_err(DRV ": P8_SEL_SGMII strapped high but configured for RGMII\n");
			bcm96764_mark(E66B_MK_ERR_EXTSW_STRAP);
		}
	} else if (ext_sw_sgmii) {
		pr_err(DRV ": P8_SEL_SGMII strapped low but configured for SGMII (strap=0x%08x)\n",
		       val);
		bcm96764_mark(E66B_MK_ERR_EXTSW_STRAP);
	}

	pr_info(DRV ": disable all switch MAC port Rx/Tx\n");
	for (i = 0; i < BP_MAX_SWITCH_PORTS; i++) {
		ret = sw_rreg(PAGE_CONTROL, PORT_CTRL_PORT + i, 1, &val);
		if (ret)
			return ret;
		ret = sw_wreg(PAGE_CONTROL, PORT_CTRL_PORT + i,
			      val | PORT_CTRL_RXTX_DISABLE, 1);
		if (ret)
			return ret;
	}

	/* unmanaged mode, forwarding enabled */
	ret = sw_rreg(PAGE_CONTROL, REG_SWITCH_MODE, 1, &val);
	if (ret)
		return ret;
	val |= SWITCH_MODE_SW_FWDG_EN | SWITCH_MODE_RETRY_LIMIT_DIS;
	val &= ~SWITCH_MODE_FRAME_MANAGE;
	ret = sw_wreg(PAGE_CONTROL, REG_SWITCH_MODE, val, 1);
	if (ret)
		return ret;

	/* no Broadcom tag header */
	ret = sw_wreg(PAGE_MANAGEMENT, REG_BRCM_HDR_CTRL, 0, 1);
	if (ret)
		return ret;

	ret = sw_rreg(PAGE_CONTROL, REG_SWITCH_CONTROL, 2, &val);
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, REG_SWITCH_CONTROL,
		      val | SWITCH_CONTROL_MII_DUMP_FWD, 2);
	if (ret)
		return ret;

	/* IMP / port 8 forced up at 1G first, as the vendor does */
	ret = sw_wreg(PAGE_CONTROL, REG_MII1_PORT_STATE_OVERRIDE,
		      MPSO_MII_SW_OVERRIDE | MPSO_FLOW_CONTROL |
		      MPSO_SPEED1000 | MPSO_FDX | MPSO_LINKPASS, 1);
	if (ret)
		return ret;

	if (!ext_sw_sgmii)
		goto done;

	/* switch-side serdes: 2.5G fiber mode on port 8 */
	ret = sw_wreg(PAGE_SW_SERDES_EN, 0x00, 0x0001, 1);
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8000, 2);	/* BLK0 block address  */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x20, 0x0c2f, 2);	/* PLL seq off         */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8300, 2);	/* Digital block       */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x20, 0x010d, 2);	/* enable fiber mode   */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x30, 0xc010, 2);	/* force 2.5G, 50MHz   */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8340, 2);	/* Digital5 block      */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x34, 0x0001, 2);	/* os2 mode            */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8000, 2);	/* BLK0 block address  */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x00, 0x0140, 2);	/* AN off, 1G mode     */
	if (ret)
		return ret;
	/* Stock (phy_drv_sgmii_plus2.c refclk50m_vco6p25g[], confirmed by the live
	 * 53134 dump obs/PORT_PLAN_66.md 2026-09-07): Digital refclk_sel = 50 MHz and
	 * the PLL AFE block 0x8050 regs 0x10..0x18. U-Boot never writes them. Record
	 * the pre-write values for the run #67 diagnosis, then program them. */
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8050, 2);
	if (ret)
		return ret;
	sw_rreg(PAGE_SW_SERDES, 0x26, 2, &afe13_pre);	/* pll_afectrl3 (0x13) */
	sw_rreg(PAGE_SW_SERDES, 0x2c, 2, &afe16_pre);	/* pll_afectrl6 (0x16) */
	sw_rreg(PAGE_SW_SERDES, 0x2e, 2, &afe17_pre);	/* pll_afectrl7 (0x17) */
	pr_info(DRV ": 53134 PLL AFE before: ctrl3 0x%04x ctrl6 0x%04x ctrl7 0x%04x\n",
		afe13_pre, afe16_pre, afe17_pre);
	if (pll_afe) {
		static const u16 afe[9] = { 0x5740, 0x01d0, 0x19f0, 0xaab0, 0x8821, 0x0044, 0x8000, 0x0872, 0x0000 };
		int k;

		ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8300, 2);	/* Digital block */
		if (ret)
			return ret;
		ret = sw_wreg(PAGE_SW_SERDES, 0x30, 0xc010, 2);	/* refclk_sel 50MHz + force 2.5G fiber (already) */
		if (ret)
			return ret;
		ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8050, 2);	/* PLL AFE block */
		if (ret)
			return ret;
		for (k = 0; k < 9; k++) {
			ret = sw_wreg(PAGE_SW_SERDES, 0x20 + k * 2, afe[k], 2);
			if (ret)
				return ret;
		}
	}
	ret = sw_wreg(PAGE_SW_SERDES, 0x3e, 0x8000, 2);	/* BLK0 block address  */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_SW_SERDES, 0x20, 0x2c2f, 2);	/* PLL seq on          */
	if (ret)
		return ret;

	/* port 5: no override; IMP port: 2.5G, full duplex, link up */
	ret = sw_wreg(PAGE_CONTROL, REG_PORT5_STATE_OVERRIDE, 0x004a, 1);
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, REG_MII1_PORT_STATE_OVERRIDE, 0x008b, 1);
	if (ret)
		return ret;

done:
	pr_info(DRV ": switch setup done (%s interconnect)\n",
		ext_sw_sgmii ? "SGMII 2.5G" : "RGMII");
	return 0;
}

/* bcm_ethsw_ext.c:369..387, sw_open() */
/* run #57 diagnostics: write 1 to /sys/module/extsw6764/parameters/probe to
 * snapshot 53134 MIB / status registers into the probe_* parameters. */
#define EXTSW_PAGE_MIB(p)	(0x20 + (p))
#define EXTSW_MIB_TXOCTETS	0x00
#define EXTSW_MIB_RXOCTETS_A	0x44	/* internal-switch layout */
#define EXTSW_MIB_RXOCTETS_B	0x50	/* + REG_MIB_P0_EXTSWITCH_OFFSET 0x0c */
static unsigned int probe_p8_rx_a, probe_p8_rx_b, probe_p8_tx, probe_lan_tx, probe_lnk, probe_p8_ctl, probe_pbv8;
module_param(probe_p8_rx_a, uint, 0444);
module_param(probe_p8_rx_b, uint, 0444);
module_param(probe_p8_tx, uint, 0444);
module_param(probe_lan_tx, uint, 0444);
module_param(probe_lnk, uint, 0444);
module_param(probe_p8_ctl, uint, 0444);
module_param(probe_pbv8, uint, 0444);
static unsigned int probe_p8_err_a, probe_p8_err_b;
module_param(probe_p8_err_a, uint, 0444);
module_param(probe_p8_err_b, uint, 0444);
static int probe_dummy;
static int probe_set(const char *val, const struct kernel_param *kp)
{
	u32 v;
	int i;

	if (!sw_rreg(EXTSW_PAGE_MIB(8), EXTSW_MIB_RXOCTETS_A, 4, &v)) probe_p8_rx_a = v;
	if (!sw_rreg(EXTSW_PAGE_MIB(8), EXTSW_MIB_RXOCTETS_B, 4, &v)) probe_p8_rx_b = v;
	if (!sw_rreg(EXTSW_PAGE_MIB(8), EXTSW_MIB_TXOCTETS, 4, &v)) probe_p8_tx = v;
	probe_lan_tx = 0;
	for (i = 0; i < 4; i++)
		if (!sw_rreg(EXTSW_PAGE_MIB(i), EXTSW_MIB_TXOCTETS, 4, &v)) probe_lan_tx |= v;
	/* run #61: port 8 error counters, both MIB layouts (A = internal, B = +0x0c) */
	probe_p8_err_a = 0; probe_p8_err_b = 0;
	for (i = 0; i < 5; i++) {
		static const int offs_a[5] = { 0x4c, 0x6c, 0x70, 0x74, 0x78 };	/* undersize, oversize, jabber, align, fcs */
		if (!sw_rreg(EXTSW_PAGE_MIB(8), offs_a[i], 4, &v)) probe_p8_err_a |= (v ? (1u << i) : 0);
		if (!sw_rreg(EXTSW_PAGE_MIB(8), offs_a[i] + 0x0c, 4, &v)) probe_p8_err_b |= (v ? (1u << i) : 0);
	}
	if (!sw_rreg(PAGE_STATUS, 0x00, 2, &v)) probe_lnk = v;
	if (!sw_rreg(PAGE_CONTROL, PORT_CTRL_PORT + 8, 1, &v)) probe_p8_ctl = v;
	if (!sw_rreg(PAGE_PORT_BASED_VLAN, REG_VLAN_CTRL_P0 + 8 * 2, 2, &v)) probe_pbv8 = v;
	pr_info(DRV ": probe: p8 rx %u/%u tx %u lan tx %u lnk 0x%x p8ctl 0x%x pbv8 0x%x\n",
		probe_p8_rx_a, probe_p8_rx_b, probe_p8_tx, probe_lan_tx, probe_lnk, probe_p8_ctl, probe_pbv8);
	return 0;
}
module_param_call(probe, probe_set, param_get_int, &probe_dummy, 0644);

static int sw_open(void)
{
	u32 val;
	int i, ret;

	pr_info(DRV ": enable switch MAC port Rx/Tx, PBVLAN fan-out, NO-STP\n");

	for (i = 0; i < BP_MAX_SWITCH_PORTS; i++) {
		ret = sw_wreg(PAGE_PORT_BASED_VLAN, REG_VLAN_CTRL_P0 + i * 2,
			      0x1ff /* bring-up: any-to-any (U-Boot: PBMAP_MIPS) */, 2);
		if (ret)
			return ret;

		ret = sw_rreg(PAGE_CONTROL, PORT_CTRL_PORT + i, 1, &val);
		if (ret)
			return ret;
		val &= ~(PORT_CTRL_RXTX_DISABLE | PORT_CTRL_STATUS_MASK);
		ret = sw_wreg(PAGE_CONTROL, PORT_CTRL_PORT + i,
			      val | PORT_CTRL_NO_STP, 1);
		if (ret)
			return ret;
	}
	/* Port 8 (IMP / 2.5G SGMII towards the SoC) is outside the 0..7 loop.
	 * The stock impl7 driver (unit 1) runs IMP_PORTS_ENABLE + REG_MII_PORT_CONTROL
	 * = RX_UCST|RX_MCST|RX_BCST on it; U-Boot never touches it (run #57: port 8
	 * RxOctets stayed 0 while the SoC transmitted). Also make lookup failures
	 * flood per PBVLAN (clear NEW_CTRL selects, open the ULF/MLF/IPMC maps). */
	ret = sw_rreg(PAGE_CONTROL, PORT_CTRL_PORT + 8, 1, &val);
	if (ret)
		return ret;
	val = (val & ~(PORT_CTRL_RXTX_DISABLE | PORT_CTRL_STATUS_MASK)) | 0x1c;
	ret = sw_wreg(PAGE_CONTROL, PORT_CTRL_PORT + 8, val, 1);
	if (ret)
		return ret;
	ret = sw_rreg(PAGE_CONTROL, 0x21, 1, &val);	/* REG_PORT_FORWARD / new ctrl */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, 0x21, val & ~0xc1, 1);
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, 0x32, 0x1ff, 2);	/* ULF */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, 0x34, 0x1ff, 2);	/* MLF */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_CONTROL, 0x36, 0x1ff, 2);	/* IPMC */
	if (ret)
		return ret;
	ret = sw_wreg(PAGE_PORT_BASED_VLAN, REG_VLAN_CTRL_P0 + 8 * 2, 0x1ff, 2);
	if (ret)
		return ret;
	pr_info(DRV ": port 8 enabled (ctrl 0x%02x), lookup-fail maps opened\n", val);
	return 0;
}

/* ----------------------------------------------------- LAN side GPHYs -- */

/*
 * phy_drv_mii.c:313 mii_init() + :185 mii_caps_set() + :64 mii_power_set(),
 * as used by phy_drv_egphy for the "EGPHY" phy-type nodes phy_ext_gphy0..3.
 * These four PHYs live inside the 53134 and answer on the same SF2 MDIO bus
 * at addresses 0..3.
 */
static int extsw_gphy_up(int addr)
{
	int v, i, ret;

	ret = sf2_mdio_write(addr, MII_BMCR, BMCR_RESET);
	if (ret)
		return ret;

	for (i = 0; i < 1000; i++) {
		udelay(10);
		v = sf2_mdio_read(addr, MII_BMCR);
		if (v < 0)
			return v;
		if (!(v & BMCR_RESET))
			break;
	}
	if (v & BMCR_RESET) {
		pr_err(DRV ": GPHY %d reset never cleared\n", addr);
		return -ETIMEDOUT;
	}

	/* advertise everything, plus repeater mode like phy_advertise_caps() */
	v = sf2_mdio_read(addr, MII_ADVERTISE);
	if (v < 0)
		return v;
	ret = sf2_mdio_write(addr, MII_ADVERTISE,
			     (u16)(v | ADVERTISE_ALL | ADVERTISE_PAUSE_CAP |
				   ADVERTISE_PAUSE_ASYM));
	if (ret)
		return ret;

	v = sf2_mdio_read(addr, MII_CTRL1000);
	if (v < 0)
		return v;
	ret = sf2_mdio_write(addr, MII_CTRL1000,
			     (u16)(v | ADVERTISE_1000FULL |
				   ADVERTISE_1000HALF | ADVERTISE_REPEATER_DTE));
	if (ret)
		return ret;

	/* power up and (re)start auto-negotiation */
	v = sf2_mdio_read(addr, MII_BMCR);
	if (v < 0)
		return v;
	v &= ~BMCR_PDOWN;
	v |= BMCR_ANENABLE | BMCR_ANRESTART;
	return sf2_mdio_write(addr, MII_BMCR, (u16)v);
}

static int extsw_gphys_up(void)
{
	int i, ret, ok = 0;

	for (i = 0; i < EXTSW_LAN_PORTS; i++) {
		ret = extsw_gphy_up(i);
		if (ret)
			pr_warn(DRV ": GPHY %d (LAN%d) bring-up failed: %d\n",
				i, i + 1, ret);
		else
			ok++;
	}
	return ok ? 0 : -EIO;
}

/* -------------------------------------------------------- link report -- */

static const char *spd_name(u32 spdsts, int port)
{
	switch ((spdsts >> (port * 2)) & 3) {
	case 0:	return "10";
	case 1:	return "100";
	case 2:	return "1000";
	default: return "?";
	}
}

static int extsw_report_links(void)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(link_wait_ms);
	u32 lnk = 0, spd = 0;
	bool p8 = false, lan = false;
	int i, ret;

	do {
		ret = sw_rreg(PAGE_STATUS, REG_LNKSTS, 2, &lnk);
		if (ret)
			return ret;

		if (!p8 && (lnk & BIT(EXTSW_IMP_PORT))) {
			p8 = true;
			bcm96764_mark(E66B_MK_EXTSW_P8_LINK);
			pr_info(DRV ": switch port %d (IMP/SGMII uplink) link UP\n",
				EXTSW_IMP_PORT);
		}
		if (!lan && (lnk & GENMASK(EXTSW_LAN_PORTS - 1, 0))) {
			lan = true;
			bcm96764_mark(E66B_MK_EXTSW_GPHY_LINK);
		}
		if (p8 && lan)
			break;

		msleep(100);
	} while (time_before(jiffies, deadline));

	ret = sw_rreg(PAGE_STATUS, REG_SPDSTS, 4, &spd);
	if (ret)
		spd = 0;

	for (i = 0; i < EXTSW_LAN_PORTS; i++)
		pr_info(DRV ": LAN%d (switch port %d): link %s%s%s\n",
			i + 1, i, (lnk & BIT(i)) ? "UP" : "down",
			(lnk & BIT(i)) ? " @ " : "",
			(lnk & BIT(i)) ? spd_name(spd, i) : "");

	if (!p8) {
		pr_warn(DRV ": switch port %d never came up (lnksts=0x%04x)\n",
			EXTSW_IMP_PORT, lnk);
		bcm96764_mark(E66B_MK_ERR_EXTSW_LINK);
	}
	if (!lan)
		pr_warn(DRV ": no LAN port link seen (lnksts=0x%04x)\n", lnk);

	return (p8 || lan) ? 0 : -ENOLINK;
}

/* ------------------------------------------------------------- public -- */

int extsw6764_init(void)
{
	int ret;

	if (!gpio_dir || !gpio_data) {
		bcm96764_mark(E66B_MK_ERR_EXTSW_GPIO);
		return -ENODEV;
	}

	mutex_lock(&extsw_lock);

	/* bcm_ethsw_ext.c:564..571: assert 100ms, release, settle 100ms */
	pr_info(DRV ": Lift external switch (sw1) out of Reset\n");
	extsw_reset_set(true);
	msleep(100);
	extsw_reset_set(false);
	msleep(100);
	bcm96764_mark(E66B_MK_EXTSW_RESET_OFF);

	ret = sw_reset();
	if (ret)
		goto out;
	bcm96764_mark(E66B_MK_EXTSW_SWRESET);

	ret = sw_hw_ready();
	if (ret)
		goto out;

	ret = sw_setup();
	if (ret)
		goto out;
	bcm96764_mark(E66B_MK_EXTSW_SETUP);

	ret = sw_open();
	if (ret)
		goto out;
	bcm96764_mark(E66B_MK_EXTSW_PORTS);

	ret = extsw_gphys_up();
	if (ret)
		goto out;

	ret = extsw_report_links();

out:
	mutex_unlock(&extsw_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(extsw6764_init);

/* -------------------------------------------------------------- module -- */

static int __init extsw6764_module_init(void)
{
	int ret;

	ret = extsw_gpio_map();
	if (ret) {
		bcm96764_mark(E66B_MK_ERR_EXTSW_GPIO);
		return ret;
	}
	bcm96764_mark(E66B_MK_EXTSW_PROBE);

	if (!autoinit)
		return 0;

	ret = extsw6764_init();
	if (ret)
		pr_err(DRV ": bring-up failed: %d\n", ret);

	/* stay loaded either way so the state can be inspected */
	return 0;
}

static void __exit extsw6764_module_exit(void)
{
	extsw_gpio_unmap();
}

module_init(extsw6764_module_init);
module_exit(extsw6764_module_exit);

MODULE_DESCRIPTION("BCM6764 external BCM53134 switch bring-up");
MODULE_LICENSE("GPL");
