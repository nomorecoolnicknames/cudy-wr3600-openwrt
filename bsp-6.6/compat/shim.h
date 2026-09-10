/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * shim.h — shared definitions for bcm_shim.ko
 *
 * bcm_shim.ko lets the stock Broadcom 4.19 blobs (wl.ko, hnd.ko, emf.ko,
 * igs.ko, bcmmcast.ko, wlshared.ko, bcmlibs.ko, bcm_knvram.ko) resolve their
 * undefined symbols on Linux 6.6.93.
 *
 * Symbol scope (FACT, provider map computed 2026-09-07 from readelf -s UND
 * of radio/wl.ko + __ksymtab parsing of image/rootfs-overlay blobs vs
 * kernel-6.6/build/Module.symvers; see triaging/shim/SHIM_C_SUMMARY.md):
 *   wl.ko UND = 627 = 369 hnd.ko + 156 kernel-6.6 + 53 shim/CONFIG +
 *               34 cfg80211 + 5 emf.ko + 4 wlshared.ko + 4 igs.ko +
 *               2 bcm_pcie_hcd.ko.
 *
 * HARD RULES for every symbol exported from this module:
 *  1. Use EXPORT_SYMBOL, NEVER EXPORT_SYMBOL_GPL. wl.ko is
 *     MODULE_LICENSE("Proprietary") and the kernel refuses GPL-only
 *     symbols to non-GPL modules. (Our module itself stays GPL: a GPL
 *     module may perfectly well export non-GPL symbols.)
 *  2. NEVER export a name the kernel already exports (duplicate export =
 *     insmod failure "exports duplicate symbol"). Before adding an export,
 *     check: grep -w <name> kernel-6.6/build/Module.symvers — must be empty.
 *     In particular do NOT re-export: printk internals (_printk), netif_rx,
 *     dev_hold/dev_put (now static inlines), del_timer/del_timer_sync
 *     (now static inlines), nla_parse (now static inline), PDE_DATA
 *     (now pde_data inline), kfree_skb (now kfree_skb_reason inline),
 *     skb_queue_purge (now _reason inline), __dev_queue_xmit users, etc.
 *     We export wrappers UNDER THE OLD 4.19 NAMES that forward to the
 *     new 6.6 implementations.
 *  3. Stub ABI rule (ARM32 EABI): pointers and int/u32 are all one word.
 *     Opaque BCA structs (Blog_t, d3lut_t, FkBuff_t, ...) are declared as
 *     void * in stubs — ABI-identical, avoids dragging BCA headers (which
 *     clash with 6.6 headers) into the build. What MUST match exactly is
 *     the argument COUNT, order, and return width. Every stub cites the
 *     BCA header file+line its arity was taken from.
 *  4. A stub that silently returns "success" on a data path is worse than
 *     no symbol (SHIM_WORKPLAN §F). Every stub uses shim_warn_once() so
 *     unexpected calls show up in dmesg/logread.
 *
 * Stage markers (bcm96764_mark(), reset_reason[31:24], survives reset):
 *   0x60-0x6A ethernet (enet6764.h), 0xB0-0xBF wlprobe66, 0xE0-0xEF errors.
 *   Wi-Fi shim load path uses 0xC0-0xCF (progress) and 0xD0-0xDF (errors).
 *   0xEE is taken by the kernel panic hook — never use it.
 */
#ifndef _BCM_SHIM_H
#define _BCM_SHIM_H

#include <linux/types.h>
#include <linux/printk.h>

/* Progress markers: one per load_wifi.sh stage, written by the script via
 * /sys/module/bcm_shim/parameters/mark (module param) AND by module_init.
 * The script writes them with `insmod bcm_shim.ko mark=0xCn` so that even
 * if a later blob hangs the bus, the last reached stage is recoverable
 * from the bootmark register on the next boot (read via bootmark.ko).
 */
#define MK_SHIM_BASE		0xC0
#define MK_SHIM_LOAD		0xC0	/* bcm_shim.ko init entered */
#define MK_SHIM_CORE_OK		0xC1	/* core wrappers registered (always) */
#define MK_SHIM_CFG_OK		0xC2	/* cfg80211 compat ready / skipped */
#define MK_SHIM_BCA_OK		0xC3	/* datapath stubs registered */
#define MK_SHIM_NVRAM_OK	0xC4	/* nvram backend ready */
#define MK_SHIM_HNDGAP_OK	0xC5	/* hnd gap symbols ready */
#define MK_SHIM_READY		0xC6	/* bcm_shim fully loaded */
#define MK_WIFI_HND		0xC7	/* hnd.ko loaded */
#define MK_WIFI_WLSHARED	0xC8	/* wlshared.ko loaded */
#define MK_WIFI_BCMMCAST	0xC9	/* bcmmcast.ko loaded */
#define MK_WIFI_EMF		0xCA	/* emf.ko loaded */
#define MK_WIFI_IGS		0xCB	/* igs.ko loaded */
#define MK_WIFI_WL		0xCC	/* wl.ko loaded (M3) */

#define MK_SHIM_ERR_BASE	0xD0
#define MK_SHIM_ERR_CORE	0xD0
#define MK_SHIM_ERR_NVRAM	0xD1
#define MK_SHIM_ERR_PARAM	0xD2

/* Rate-limited "this stub was called" notice. Every stub must call it at
 * least on first invocation (pr_warn_once semantics via printk_ratelimited
 * would spam less, but first-call visibility matters more here).
 */
#define shim_warn_once(fmt, ...) \
	pr_warn_once("bcm_shim: " fmt, ##__VA_ARGS__)

/* Per-file init hooks, all called from shim_core_init() (shim_core.c owns
 * the single module_init/module_exit pair). Each returns 0 on success. */
int cfg80211_compat_subinit(void);
int wl_compat_subinit(void);
int shim_nvram_init(void);
int shim_hnd_gaps_init(void);
int shim_alloc_init(void);

#endif /* _BCM_SHIM_H */
