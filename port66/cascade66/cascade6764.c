// SPDX-License-Identifier: GPL-2.0-only
/*
 * cascade6764 - the external 2.5G "cascade" copper PHY that carries the WAN
 * on the Cudy WR3600H (R69).
 *
 * Wiring (R69 device tree): the internal GPHY is disabled; the WAN is
 *   SF2 port 6 (port_sgmii1) -> serdes core 1 -> external Clause-45 copper PHY
 * at MDIO address 24 (0x18), with enet-phy-lane-swap and an 80 MHz shared
 * reference clock.  The copper part is a Broadcom "Blackfin" (BCM84891L /
 * 54991 class, PHY ID 0x3590:0x50xx) and does nothing at all until its
 * on-chip processor has been given a ~288 KB firmware image over MDIO.
 *
 * Two things can have done that before we run:
 *
 *   - The stock U-Boot.  R69/bcm96764_defconfig has CONFIG_BCM_PHY_BLACKFIN_B0=y
 *     and links blackfin_b0_firmware.h in, and u-boot-2019.07 runs initr_net ->
 *     eth_initialize() on every boot, which probes the bcmbca ethernet driver
 *     and downloads the image.  The vendor Linux driver knows this and checks
 *     for it ("was set in BSP already", GPL phy_drv_ext3.c:3514).
 *   - Nothing, if the bootloader was built differently.  Then we upload it
 *     ourselves from /lib/firmware, if the image is present.
 *
 * So: read the PHY out first, and only touch it when it needs touching.
 *
 * The register sequences below are all transcribed from the vendor GPL driver
 * gpl/openwrt/21.02/package/extra/bcm/src/bcmdrivers/opensource/phy/phy_drv_ext3.c
 * (load_blackfin :3080, _load_firmware_file :2507, default_load_reg :183,
 * _phy_init_pon :2225, cmd_handler :546, _phy_caps_set :1759,
 * _phy_read_status :1595), analysed in triaging/wr3600h/CASCADE_WAN_SPEC.md.
 *
 * Nothing here can hang the SoC: every access is Clause-45 MDIO through the
 * SF2 controller, and a PHY that does not answer just reads back 0xffff.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <asm/unaligned.h>

#define DRV "cascade6764"

/* port66/enet66 (sf2_6764.c) */
extern int sf2_mdio_c45_read(int phy, int dev, int reg);
extern int sf2_mdio_c45_write(int phy, int dev, int reg, u16 val);
extern int sf2_6764_force_port_state(int port, int mbps, bool link);
/* port66/enet66b (serdes6764.c) */
extern int serdes6764_speed_set(int core, int mbps);

static int phy_addr = 24;
module_param_named(phy, phy_addr, int, 0444);
MODULE_PARM_DESC(phy, "MDIO address of the cascade PHY (R69: 24 = 0x18)");

static int sf2_port = 6;
module_param(sf2_port, int, 0444);
MODULE_PARM_DESC(sf2_port, "SF2 port this PHY feeds (R69 WAN: 6); -1 = do not touch");

static int serdes_core = 1;
module_param(serdes_core, int, 0444);
MODULE_PARM_DESC(serdes_core, "serdes core on the host side (R69 WAN: 1); -1 = do not retune");

static char *fw_name = "blackfin_b0_firmware.bin";
module_param(fw_name, charp, 0444);
MODULE_PARM_DESC(fw_name, "firmware image to upload when the PHY has none");

static int load_fw = 1;
module_param(load_fw, int, 0444);
MODULE_PARM_DESC(load_fw, "upload the firmware when no running one is found (default 1)");

static int force_fw;
module_param(force_fw, int, 0444);
MODULE_PARM_DESC(force_fw, "upload the firmware even if one is already running");

static int configure;
module_param(configure, int, 0444);
MODULE_PARM_DESC(configure,
		 "post-firmware config: 0 = only after our own upload (default), 1 = always, -1 = never");

static int swap_pair = 1;
module_param(swap_pair, int, 0444);
MODULE_PARM_DESC(swap_pair, "MDI pair swap (R69 device tree: enet-phy-lane-swap, so 1)");

static int ref_clk_mhz = 80;
module_param(ref_clk_mhz, int, 0444);
MODULE_PARM_DESC(ref_clk_mhz, "shared reference clock in MHz (R69: 80); 0 = leave alone");

static int poll_ms = 2000;
module_param(poll_ms, int, 0644);
MODULE_PARM_DESC(poll_ms, "copper link poll period in ms; 0 = no polling");

static int track_speed = 1;
module_param(track_speed, int, 0644);
MODULE_PARM_DESC(track_speed,
		 "retune the serdes and the SF2 port to the copper speed (default 1)");

/* read-only state, so a tester can get the whole story out of
 * /sys/module/cascade6764/parameters/ without a serial console */
static int st_id1, st_id2, st_proc, st_400d, st_link, st_speed;
static int st_fw_uploaded, st_fw_ret = -1, st_cfg_ret = -1;
module_param(st_id1, int, 0444);
module_param(st_id2, int, 0444);
module_param(st_proc, int, 0444);
module_param(st_400d, int, 0444);
module_param(st_link, int, 0444);
module_param(st_speed, int, 0444);
module_param(st_fw_uploaded, int, 0444);
module_param(st_fw_ret, int, 0444);
module_param(st_cfg_ret, int, 0444);

/* ------------------------------------------------------------- MDIO ----- */

static int rd(int dev, int reg)
{
	int v = sf2_mdio_c45_read(phy_addr, dev, reg);

	if (v < 0)
		pr_warn(DRV ": read %d.%04x failed (%d)\n", dev, reg, v);
	return v;
}

static int wr(int dev, int reg, u16 val)
{
	int ret = sf2_mdio_c45_write(phy_addr, dev, reg, val);

	if (ret)
		pr_warn(DRV ": write %d.%04x = %04x failed (%d)\n",
			dev, reg, val, ret);
	return ret;
}

/* ------------------------------------------------- firmware download ---- */

/* default_load_reg, phy_drv_ext3.c:183 - the on-chip RAM window */
#define LR_DEVID	0x01
#define LR_CTRL		0xa817
#define LR_ADDR_LOW	0xa819
#define LR_ADDR_HIGH	0xa81a
#define LR_DATA_LOW	0xa81b
#define LR_DATA_HIGH	0xa81c
#define LR_RAM_ADDR	0x00000000

#define PROC_RUNNING	0x2040		/* 1.0000 once the processor is up */
#define FW_CRC_MASK	0xc000		/* 30.400d [15:14] */
#define FW_CRC_GOOD	0x4000

static bool fw_running(void)
{
	int proc = rd(0x01, 0x0000);
	int st = rd(0x1e, 0x400d);

	st_proc = proc;
	st_400d = st;
	return proc == PROC_RUNNING && (st & FW_CRC_MASK) == FW_CRC_GOOD;
}

/* load_blackfin() step 1, phy_drv_ext3.c:3091-3110 */
static void halt_processors(void)
{
	wr(0x1e, 0x4110, 0x0001);
	wr(0x1e, 0x418c, 0x0000);
	wr(0x1e, 0x4188, 0x48f0);

	/* single 32-bit write of 0x0121 to internal address 0xf0003000 */
	wr(0x01, LR_ADDR_HIGH, 0xf000);
	wr(0x01, LR_ADDR_LOW, 0x3000);
	wr(0x01, LR_DATA_HIGH, 0x0000);
	wr(0x01, LR_DATA_LOW, 0x0121);
	wr(0x01, LR_CTRL, 0x0009);

	wr(0x1e, 0x80a6, 0x0000);
	wr(0x01, 0xa010, 0x0000);
	wr(0x01, 0x0000, 0x8000);

	udelay(1000);
	wr(0x1e, 0x4110, 0x0001);
	udelay(1000);
}

/* load_blackfin() step 5, phy_drv_ext3.c:3139-3145: same write, value 0x0020 */
static void release_processors(void)
{
	wr(0x01, LR_ADDR_HIGH, 0xf000);
	wr(0x01, LR_ADDR_LOW, 0x3000);
	wr(0x01, LR_DATA_HIGH, 0x0000);
	wr(0x01, LR_DATA_LOW, 0x0020);
	wr(0x01, LR_CTRL, 0x0009);
	udelay(2000);
}

/* phy_config_shared_ref_clk(), phy_drv_ext3.c:3459 */
static void set_shared_ref_clk(void)
{
	int v;

	if (ref_clk_mhz != 80)
		return;
	v = rd(0x1e, 0x80a8);
	if (v < 0)
		return;
	wr(0x1e, 0x80a8, (u16)(v | 1));
}

/* _load_firmware_file(), phy_drv_ext3.c:2507: point the RAM window at 0,
 * open it for auto-incrementing writes (ctrl 0x0038), push the image through
 * as little-endian 32-bit words - high half first - then close the window.
 */
static int upload_firmware(const struct firmware *fw)
{
	size_t i;
	int pct = -1;

	if (fw->size % sizeof(u32)) {
		pr_err(DRV ": firmware size %zu is not a multiple of 4\n",
		       fw->size);
		return -EINVAL;
	}

	pr_info(DRV ": uploading %s (%zu bytes) over MDIO, this takes a while\n",
		fw_name, fw->size);

	wr(LR_DEVID, LR_ADDR_LOW, LR_RAM_ADDR & 0xffff);
	wr(LR_DEVID, LR_ADDR_HIGH, LR_RAM_ADDR >> 16);
	wr(LR_DEVID, LR_CTRL, 0x0038);

	for (i = 0; i < fw->size; i += sizeof(u32)) {
		u32 word = get_unaligned_le32(fw->data + i);
		int ret;

		ret = wr(LR_DEVID, LR_DATA_HIGH, (u16)(word >> 16));
		if (!ret)
			ret = wr(LR_DEVID, LR_DATA_LOW, (u16)(word & 0xffff));
		if (ret) {
			pr_err(DRV ": upload failed at offset %zu (%d)\n",
			       i, ret);
			wr(LR_DEVID, LR_CTRL, 0x0000);
			return ret;
		}

		if (!(i & 0x3ff)) {
			int p = (int)(100 * i / fw->size);

			if (p / 10 != pct / 10) {
				pct = p;
				pr_info(DRV ": upload %d%%\n", p);
			}
			cond_resched();
		}
	}

	wr(LR_DEVID, LR_CTRL, 0x0000);
	pr_info(DRV ": upload done\n");
	return 0;
}

/* load_blackfin() steps 6 and 7 */
static int wait_firmware_alive(void)
{
	int i;

	for (i = 0; i < 1000; i++) {
		udelay(2000);
		if (rd(0x01, 0x0000) == PROC_RUNNING)
			break;
	}
	if (i == 1000) {
		pr_err(DRV ": processor did not start (1.0000 = %04x)\n",
		       rd(0x01, 0x0000) & 0xffff);
		return -ETIMEDOUT;
	}
	pr_info(DRV ": processor running\n");

	for (i = 0; i < 1000; i++) {
		udelay(2000);
		if ((rd(0x1e, 0x400d) & FW_CRC_MASK) == FW_CRC_GOOD)
			break;
	}
	if (i == 1000) {
		pr_err(DRV ": firmware CRC bad (30.400d = %04x)\n",
		       rd(0x1e, 0x400d) & 0xffff);
		return -EIO;
	}
	pr_info(DRV ": firmware CRC good\n");
	return 0;
}

static int download_firmware(void)
{
	const struct firmware *fw;
	struct device *dev;
	int ret;

	dev = root_device_register(DRV);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	ret = request_firmware(&fw, fw_name, dev);
	if (ret) {
		pr_warn(DRV ": %s not found (%d) - if the bootloader did not load one, this WAN port stays dead\n",
			fw_name, ret);
		root_device_unregister(dev);
		return ret;
	}

	halt_processors();
	ret = upload_firmware(fw);
	release_firmware(fw);
	root_device_unregister(dev);
	if (ret)
		return ret;

	set_shared_ref_clk();		/* load_blackfin() step 4.5 */
	release_processors();
	return wait_firmware_alive();
}

/* ------------------------------------------- firmware command handler --- */

#define CMD_STATUS		0x4037
#define CMD_CODE		0x4005
#define CMD_DATA(n)		(0x4038 + (n))
#define CMD_IN_PROGRESS		0x0002
#define CMD_COMPLETE_PASS	0x0004
#define CMD_SYSTEM_BUSY		0xbbbb

#define CMD_SET_PAIR_SWAP		0x8001
#define CMD_SET_XFI_2P5G_5G_MODE	0x8017

/* cmd_handler(), phy_drv_ext3.c:546.  Only the "set" direction is needed
 * here; data[] entries that are negative are left unwritten, as the vendor
 * leaves NULL pointers unwritten. */
static int phy_cmd_set(u16 code, const int *data, int ndata)
{
	int i, v = -EIO;

	for (i = 0; i < 1000; i++) {
		v = rd(0x1e, CMD_STATUS);
		if (v != CMD_IN_PROGRESS && v != CMD_SYSTEM_BUSY)
			break;
		udelay(2000);
	}
	if (i == 1000) {
		pr_err(DRV ": command interface busy\n");
		return -EBUSY;
	}

	for (i = 0; i < ndata; i++)
		if (data[i] >= 0)
			wr(0x1e, CMD_DATA(i), (u16)data[i]);

	wr(0x1e, CMD_CODE, code);

	for (i = 0; i < 1000; i++) {
		v = rd(0x1e, CMD_STATUS);
		if (v != CMD_IN_PROGRESS && v != CMD_SYSTEM_BUSY)
			break;
		udelay(2000);
	}
	if (v != CMD_COMPLETE_PASS) {
		pr_err(DRV ": command 0x%04x failed, status %04x\n", code, v);
		return -EIO;
	}
	return 0;
}

/* --------------------------------------------------- post-fw config ----- */

/* _phy_init_pon(), phy_drv_ext3.c:2247-2280, minus the parts that do not
 * apply to this board: the XFI polarity props sit on the serdes node on R69
 * (and are handled by port66/enet66b), and the LED control is a no-op in the
 * vendor driver too. */
static int post_config(void)
{
	int ret, v;
	int xfi[2] = { 1, 1 };		/* XFI_MODE_BASE_X for 2.5G and 5G */
	int swap[2] = { -1, swap_pair ? 0x1b : 0xe4 };

	/* base-pointer mode = line side (_phy_set_mode(1), :2038) */
	wr(0x1e, 0x4110, 0x0001);
	wr(0x1e, 0x4111, 0x0001);
	wr(0x1e, 0x4113, 0x1002);

	/* 2.5G/5G host-side framing (_phy_inter_phy_types_set, :858) */
	ret = phy_cmd_set(CMD_SET_XFI_2P5G_5G_MODE, xfi, ARRAY_SIZE(xfi));
	if (ret)
		return ret;

	/* Force Auto-MDIX and Ethernet@Wirespeed (:1265, :1296) */
	v = rd(0x07, 0x902f);
	if (v >= 0)
		wr(0x07, 0x902f, (u16)(v | (1 << 9) | (1 << 4)));

	/* MDI pair swap = the device tree's enet-phy-lane-swap (:1327) */
	ret = phy_cmd_set(CMD_SET_PAIR_SWAP, swap, ARRAY_SIZE(swap));
	if (ret)
		return ret;

	/*
	 * Advertisement (_phy_caps_set, :1759).  Capped at 2.5G on purpose:
	 * the host side of this port is one Merlin16 lane that we drive at
	 * 1000Base-X or 2500Base-X, so a 5G or 10G copper link would negotiate
	 * a rate the SoC cannot carry.  10/100/1000 half and full, 2.5G,
	 * pause, asym pause, repeater, autoneg.
	 */
	v = rd(0x07, 0xffe4);		/* copper AN advertisement */
	if (v >= 0) {
		v &= ~((1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) |
		       (1 << 10) | (1 << 11));
		v |= (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) |
		     (1 << 10) | (1 << 11);
		wr(0x07, 0xffe4, (u16)v);
	}

	v = rd(0x07, 0xffe9);		/* 1000Base-T control */
	if (v >= 0) {
		v &= ~((1 << 8) | (1 << 9) | (1 << 10));
		v |= (1 << 8) | (1 << 9) | (1 << 10);
		wr(0x07, 0xffe9, (u16)v);
	}

	v = rd(0x07, 0x0020);		/* multi-gig AN control */
	if (v >= 0) {
		v &= ~((1 << 7) | (1 << 8) | (1 << 12) | (1 << 13));
		v |= (1 << 7) | (1 << 13);	/* 2.5G + repeater, no 5G/10G */
		wr(0x07, 0x0020, (u16)v);
	}

	v = rd(0x07, 0xffe0);		/* MII control, then restart AN */
	if (v >= 0) {
		v &= ~((1 << 6) | (1 << 8) | (1 << 12) | (1 << 13));
		v |= (1 << 6) | (1 << 8) | (1 << 12);
		wr(0x07, 0xffe0, (u16)v);
		wr(0x07, 0xffe0, (u16)(v | (1 << 9)));
	}

	pr_info(DRV ": configured (line-side mode, 2.5G Base-X host framing, pair swap %d, advertising up to 2.5G)\n",
		swap_pair);
	return 0;
}

/* -------------------------------------------------------- link poll ----- */

/* _phy_read_status(), phy_drv_ext3.c:1595: 30.400d bit5 = copper link,
 * bits[4:2] = speed mode. */
static int speed_of(int mode)
{
	switch (mode) {
	case 7: return 10;
	case 2: return 100;
	case 4: return 1000;
	case 1: return 2500;
	case 3: return 5000;
	case 6: return 10000;
	default: return 0;
	}
}

static struct delayed_work poll_work;
static int last_link = -1, last_speed = -1;

static void link_changed(int link, int mbps)
{
	if (!link) {
		pr_info(DRV ": WAN copper link DOWN\n");
		if (sf2_port >= 0)
			sf2_6764_force_port_state(sf2_port, 0, false);
		return;
	}

	pr_info(DRV ": WAN copper link UP at %d Mbps\n", mbps);

	/*
	 * The host side of the PHY follows the copper speed: 2500Base-X above
	 * 1G, 1000Base-X at or below it (the PHY rate-adapts 10/100 up to
	 * 1000Base-X itself).  Retune the serdes lane to match, then tell the
	 * SF2 MAC what to expect - it has no in-band status from this port.
	 */
	if (track_speed && serdes_core >= 0) {
		int line = mbps > 1000 ? 2500 : 1000;
		int ret = serdes6764_speed_set(serdes_core, line);

		if (ret)
			pr_warn(DRV ": serdes core %d retune to %d failed (%d)\n",
				serdes_core, line, ret);
	}

	if (sf2_port >= 0)
		sf2_6764_force_port_state(sf2_port, mbps, true);
}

static void poll_fn(struct work_struct *w)
{
	int v = rd(0x1e, 0x400d);
	int link, mbps;

	if (v >= 0) {
		st_400d = v;
		link = (v >> 5) & 1;
		mbps = link ? speed_of((v >> 2) & 7) : 0;
		st_link = link;
		st_speed = mbps;

		if (link != last_link || mbps != last_speed) {
			last_link = link;
			last_speed = mbps;
			link_changed(link, mbps);
		}
	}

	if (poll_ms > 0)
		schedule_delayed_work(&poll_work, msecs_to_jiffies(poll_ms));
}

/* ------------------------------------------------------------- init ----- */

static int __init cascade6764_init(void)
{
	bool running;
	int ret;

	st_id1 = rd(0x01, 0x0002);
	st_id2 = rd(0x01, 0x0003);

	if (st_id1 < 0 || (st_id1 & 0xffff) == 0xffff) {
		pr_warn(DRV ": no PHY at MDIO %d (0x%02x) - wrong address, or the SF2 MDIO bus is not up\n",
			phy_addr, phy_addr);
		return 0;		/* stay loaded, the read-out is the point */
	}

	running = fw_running();
	pr_info(DRV ": phy %d (0x%02x): id %04x:%04x proc %04x 30.400d %04x -> %s\n",
		phy_addr, phy_addr, st_id1 & 0xffff, st_id2 & 0xffff,
		st_proc & 0xffff, st_400d & 0xffff,
		running ? "firmware already running (loaded by the bootloader)"
			: "NO firmware");

	if ((!running && load_fw) || force_fw) {
		st_fw_ret = ret = download_firmware();
		if (!ret) {
			st_fw_uploaded = 1;
			running = true;
		}
	}

	if (running && configure >= 0 &&
	    (configure > 0 || st_fw_uploaded))
		st_cfg_ret = post_config();

	if (!running) {
		pr_warn(DRV ": PHY has no running firmware; the WAN port will not link\n");
		return 0;
	}

	INIT_DELAYED_WORK(&poll_work, poll_fn);
	schedule_delayed_work(&poll_work, 0);
	return 0;
}

static void __exit cascade6764_exit(void)
{
	cancel_delayed_work_sync(&poll_work);
}

module_init(cascade6764_init);
module_exit(cascade6764_exit);

MODULE_DESCRIPTION("Cudy WR3600H external 2.5G cascade WAN PHY (Clause-45)");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE("blackfin_b0_firmware.bin");
