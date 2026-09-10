/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bcm_compat.h — 6.6 compatibility shims for Broadcom BCA wl.ko ABI.
 *
 * Symbols that existed in 4.19 but are gone/changed in 6.6.
 * This header is included by bcm_compat.c which EXPORT_SYMBOL_GPLs the
 * replacements so that the (4.19) wl.ko blob can link at runtime.
 */
#ifndef _BCM_COMPAT_H
#define _BCM_COMPAT_H

#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/uaccess.h>

/* ---- dev_base_lock: removed ~5.4. wl.ko iterates dev list under it.
 * Replacement: rtnl + RCU. We export a stub that takes rtnl and returns
 * a lockdep-satisfying token. Caller (wl) treats it as a spinlock/rwlock;
 * we can't emulate that, so the shim provides bcm_dev_base_lock_taken()
 * and the module init installs an RCU-safe wrapper.
 */
extern rwlock_t bcm_dev_base_lock_compat;
#define dev_base_lock bcm_dev_base_lock_compat

/* ---- ARM32 user-copy: on ARMv7 wl.ko called arm_copy_from_user.
 * On 6.6 (any arch) use copy_from_user. We export under the old name so
 * the blob's UND is satisfied.
 */
static inline unsigned long
bcm_arm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return copy_from_user(to, from, n) ? n : 0;
}
static inline unsigned long
bcm_arm_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return copy_to_user(to, from, n) ? n : 0;
}

/* ---- __pv_phys_pfn_offset: ARM32 phys offset. 6.6/arm64: PHYS_PFN_OFFSET.
 * wl.ko is ARMv7 (p2v8). Under 6.6 on armv7 (LPAE) this maps to
 * pfn offset of memory start. We export __pv_phys_pfn_offset as a variable
 * initialized from memstart_addr.
 */
extern unsigned long bcm_pv_phys_pfn_offset;
#define __pv_phys_pfn_offset bcm_pv_phys_pfn_offset

/* ---- timers: 4.19 callback style fn(unsigned long data) is gone.
 * wl.ko has its own timer wrappers; where it calls add_timer/etc the
 * function pointer signature is internal to wl and not a kernel UND.
 * We only need to ensure add_timer/mod_timer/del_timer_sync exist (they do).
 */

/* ---- cfg80211_inform_bss_frame_data: 6.6 takes struct cfg80211_inform_bss.
 * The wl blob calls the 4.19 signature. We can't intercept a direct UND
 * without relinking; instead we patch wl.ko's relocation table to point at
 * our compat symbol which adapts arguments. See bcm_cfg80211_compat.c.
 */

/* ---- genl_family: 6.6 split ops into small_ops. Blob uses struct genl_ops.
 * We provide a registration wrapper translating legacy genl_ops array.
 */

#endif /* _BCM_COMPAT_H */
