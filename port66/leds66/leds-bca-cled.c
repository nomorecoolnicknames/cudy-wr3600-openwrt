// SPDX-License-Identifier: GPL-2.0
/*
 * leds-bca-cled - Broadcom BCA "CLED" controller (v2) for the BCM6764.
 *
 * The board has six software-driven parallel LEDs behind the controller at
 * periph+0x3000; on 6.6 nothing claimed them, so /sys/class/leds was empty and
 * the panel showed whatever the bootloader left. The stock DT (which we boot
 * unchanged) already describes everything needed:
 *
 *   led_ctrl { compatible = "brcm,bca-cleds-ctrl,v2"; nleds = <64>;
 *              reg-names = "glbl_ctrl","hw_en","ser_shift","hw_polarity",
 *                          "sw_set","sw_polarity","ch_activate","ch_config",
 *                          "sw_clear","sw_status","out_mux","ser_polarity",
 *                          "par_polarity"; ... }
 *     sw_parallel_led_4 { compatible = "brcm,parallel-cled"; software_led;
 *                         crossbar; bit = <4>; active_low; brightness = <255>;
 *                         pinctrl-0 = <&b_per_led_03_pinmux>;
 *                         label = "oem:green:internet"; }
 *     ... bits 5..9: wifi5g, wifi, lan, wan, status
 *
 * Register semantics are taken from the vendor GPL driver
 * bcmdrivers/opensource/misc/bca_led_ctrl/impl1/bcm_bca_cled_ctrl.c
 * (v2 ops, lines 86-103 and 522-698):
 *
 *   on            write (1 << ch) to sw_set
 *   off           write (1 << ch) to sw_clear
 *   read back     bit ch of sw_status
 *   brightness    ch_config[ch].cfg0 bits [13:6], then write (1 << ch) to
 *                 ch_activate and wait for the bit to clear
 *   polarity      bit ch of par_polarity, set only for "active_high"
 *   sw vs hw      bit ch of hw_en: 0 = driven by software (our case)
 *   crossbar      the channel actually driven is the "crossbar-output" of the
 *                 pin group in pinctrl-0, and out_mux[out >> 2] carries the
 *                 LED number in the byte selected by (out & 3)
 *
 * Not handled here (deliberately): serial (shift-register) LEDs, hardware
 * blink sources and flash_rate - this board's six LEDs are plain software
 * ones. Pin muxing is left to the bootloader, which already lights these LEDs
 * during boot; there is no pinctrl driver for this SoC on 6.6 yet.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/leds.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define CLED_CFG_STRIDE		16		/* struct cled_cfg: cfg0..cfg3 */
#define CLED_CFG0_BRIGHT_SHIFT	6
#define CLED_CFG0_BRIGHT_MASK	(0xffu << CLED_CFG0_BRIGHT_SHIFT)
#define CLED_ACTIVATE_POLLS	1000
#define CLED_MUX_FIELD_MASK	0x3f		/* 6 bits per output on v2 */

struct bca_cled {
	struct device	*dev;
	spinlock_t	lock;
	void __iomem	*hw_en;
	void __iomem	*sw_set;
	void __iomem	*sw_clear;
	void __iomem	*sw_status;
	void __iomem	*ch_activate;
	void __iomem	*ch_config;
	void __iomem	*out_mux;
	void __iomem	*par_polarity;
	u32		nleds;
};

struct bca_cled_led {
	struct led_classdev	cdev;
	struct bca_cled		*ctrl;
	u32			ch;		/* channel actually driven */
};

#define to_bca_led(c) container_of(c, struct bca_cled_led, cdev)

static void bca_cled_activate(struct bca_cled *cled, u32 mask)
{
	int i;

	writel(mask, cled->ch_activate);
	for (i = 0; i < CLED_ACTIVATE_POLLS; i++)
		if (!(readl(cled->ch_activate) & mask))
			return;

	dev_warn_once(cled->dev, "channel activate did not complete (mask 0x%x)\n",
		      mask);
}

static void bca_cled_set_brightness_hw(struct bca_cled *cled, u32 ch, u8 val)
{
	void __iomem *cfg0 = cled->ch_config + ch * CLED_CFG_STRIDE;
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&cled->lock, flags);
	reg = readl(cfg0) & ~CLED_CFG0_BRIGHT_MASK;
	reg |= (u32)val << CLED_CFG0_BRIGHT_SHIFT;
	writel(reg, cfg0);
	bca_cled_activate(cled, BIT(ch));
	spin_unlock_irqrestore(&cled->lock, flags);
}

static void bca_cled_brightness_set(struct led_classdev *cdev,
				    enum led_brightness value)
{
	struct bca_cled_led *led = to_bca_led(cdev);

	writel(BIT(led->ch), value ? led->ctrl->sw_set : led->ctrl->sw_clear);
}

static enum led_brightness bca_cled_brightness_get(struct led_classdev *cdev)
{
	struct bca_cled_led *led = to_bca_led(cdev);

	return (readl(led->ctrl->sw_status) & BIT(led->ch)) ? LED_FULL : LED_OFF;
}

/*
 * With "crossbar" the DT bit is the LED number fed into the mux, and the pad
 * is selected by "crossbar-output" of the referenced pin group; the driven
 * channel is that output. Mirrors setup_crossbar() of the vendor driver.
 */
static int bca_cled_setup_crossbar(struct bca_cled *cled,
				   struct device_node *np, u32 led_num)
{
	struct device_node *pins;
	u32 out, shift;
	unsigned long flags;
	void __iomem *mux;
	u32 reg;

	pins = of_parse_phandle(np, "pinctrl-0", 0);
	if (!pins)
		return -EINVAL;

	if (of_property_read_u32(pins, "crossbar-output", &out)) {
		of_node_put(pins);
		return -EINVAL;
	}
	of_node_put(pins);

	if (out > 31)
		return -EINVAL;

	mux = cled->out_mux + (out >> 2) * sizeof(u32);
	shift = (out & 3) * 8;

	spin_lock_irqsave(&cled->lock, flags);
	reg = readl(mux);
	reg &= ~(CLED_MUX_FIELD_MASK << shift);
	reg |= (led_num & CLED_MUX_FIELD_MASK) << shift;
	writel(reg, mux);
	spin_unlock_irqrestore(&cled->lock, flags);

	return out;
}

static int bca_cled_add_led(struct bca_cled *cled, struct device_node *np)
{
	struct bca_cled_led *led;
	const char *label = NULL;
	u32 bit, brightness = 255;
	unsigned long flags;
	int ch, ret;

	if (of_property_read_u32(np, "bit", &bit))
		return dev_err_probe(cled->dev, -EINVAL, "%pOFn: no bit\n", np);

	of_property_read_string(np, "label", &label);
	of_property_read_u32(np, "brightness", &brightness);

	ch = bit;
	if (of_property_read_bool(np, "crossbar")) {
		ch = bca_cled_setup_crossbar(cled, np, bit);
		if (ch < 0)
			return dev_err_probe(cled->dev, ch,
					     "%pOFn: bad crossbar mapping\n", np);
	}
	if (ch > 31 || ch >= cled->nleds)
		return dev_err_probe(cled->dev, -EINVAL,
				     "%pOFn: channel %d out of range\n", np, ch);

	led = devm_kzalloc(cled->dev, sizeof(*led), GFP_KERNEL);
	if (!led)
		return -ENOMEM;

	led->ctrl = cled;
	led->ch = ch;

	spin_lock_irqsave(&cled->lock, flags);
	/* software controlled: the hardware blink source must not drive it */
	writel(readl(cled->hw_en) & ~BIT(ch), cled->hw_en);
	/* the vendor sets the polarity bit only for "active_high" */
	if (of_property_read_bool(np, "active_high"))
		writel(readl(cled->par_polarity) | BIT(ch), cled->par_polarity);
	else
		writel(readl(cled->par_polarity) & ~BIT(ch), cled->par_polarity);
	spin_unlock_irqrestore(&cled->lock, flags);

	bca_cled_set_brightness_hw(cled, ch, brightness);

	led->cdev.name = label ? label : np->name;
	led->cdev.max_brightness = LED_FULL;
	led->cdev.brightness_set = bca_cled_brightness_set;
	led->cdev.brightness_get = bca_cled_brightness_get;
	led->cdev.brightness = bca_cled_brightness_get(&led->cdev);

	ret = devm_led_classdev_register(cled->dev, &led->cdev);
	if (ret)
		return ret;

	dev_info(cled->dev, "%s: led %u -> channel %d\n", led->cdev.name, bit, ch);
	return 0;
}

static void __iomem *bca_cled_map(struct platform_device *pdev, const char *name)
{
	void __iomem *p = devm_platform_ioremap_resource_byname(pdev, name);

	if (IS_ERR(p))
		dev_err(&pdev->dev, "cannot map %s\n", name);
	return p;
}

static int bca_cled_probe(struct platform_device *pdev)
{
	struct device_node *np;
	struct bca_cled *cled;
	int n = 0;

	cled = devm_kzalloc(&pdev->dev, sizeof(*cled), GFP_KERNEL);
	if (!cled)
		return -ENOMEM;

	cled->dev = &pdev->dev;
	spin_lock_init(&cled->lock);

	cled->hw_en		= bca_cled_map(pdev, "hw_en");
	cled->sw_set		= bca_cled_map(pdev, "sw_set");
	cled->sw_clear		= bca_cled_map(pdev, "sw_clear");
	cled->sw_status		= bca_cled_map(pdev, "sw_status");
	cled->ch_activate	= bca_cled_map(pdev, "ch_activate");
	cled->ch_config		= bca_cled_map(pdev, "ch_config");
	cled->out_mux		= bca_cled_map(pdev, "out_mux");
	cled->par_polarity	= bca_cled_map(pdev, "par_polarity");

	if (IS_ERR(cled->hw_en) || IS_ERR(cled->sw_set) ||
	    IS_ERR(cled->sw_clear) || IS_ERR(cled->sw_status) ||
	    IS_ERR(cled->ch_activate) || IS_ERR(cled->ch_config) ||
	    IS_ERR(cled->out_mux) || IS_ERR(cled->par_polarity))
		return -ENXIO;

	if (of_property_read_u32(pdev->dev.of_node, "nleds", &cled->nleds))
		cled->nleds = 32;

	for_each_available_child_of_node(pdev->dev.of_node, np) {
		if (!of_device_is_compatible(np, "brcm,parallel-cled"))
			continue;
		if (!of_property_read_bool(np, "software_led"))
			continue;	/* hardware-driven ones are not ours */
		if (!bca_cled_add_led(cled, np))
			n++;
	}

	dev_info(&pdev->dev, "%d software LED(s) registered (of %u channels)\n",
		 n, cled->nleds);
	return 0;
}

static const struct of_device_id bca_cled_of_match[] = {
	{ .compatible = "brcm,bca-cleds-ctrl,v2" },
	{ }
};
MODULE_DEVICE_TABLE(of, bca_cled_of_match);

static struct platform_driver bca_cled_driver = {
	.probe	= bca_cled_probe,
	.driver	= {
		.name		= "leds-bca-cled",
		.of_match_table	= bca_cled_of_match,
	},
};
module_platform_driver(bca_cled_driver);

MODULE_DESCRIPTION("Broadcom BCA CLED v2 controller (BCM6764 panel LEDs)");
MODULE_LICENSE("GPL");
