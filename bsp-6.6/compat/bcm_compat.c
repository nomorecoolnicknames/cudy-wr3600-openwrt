// SPDX-License-Identifier: GPL-2.0
/*
 * bcm_compat.c — runtime shims so that a 4.19 wl.ko blob can bind on 6.6.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include "bcm_compat.h"

rwlock_t bcm_dev_base_lock_compat = __RW_LOCK_UNLOCKED(bcm_dev_base_lock_compat);
EXPORT_SYMBOL_GPL(bcm_dev_base_lock_compat);

unsigned long bcm_pv_phys_pfn_offset;
EXPORT_SYMBOL_GPL(bcm_pv_phys_pfn_offset);

/*
 * arm_copy_from_user / arm_copy_to_user are already exported by the stock
 * 4.19 kernel (the wl.ko blob resolves them directly). They only vanish on
 * 6.6/aarch64. Do not re-export here or insmod fails with
 * "exports duplicate symbol ... (owned by kernel)".
 */

static int __init bcm_compat_init(void)
{
	/* On 4.19 (this tree) __pv_phys_pfn_offset is defined in <linux/pfn.h>;
	 * on 6.6 we compute it from memstart_addr. Keep both paths so the same
	 * source builds under the stock tree for smoke-testing.
	 */
#ifdef CONFIG_PHYS_OFFSET
	bcm_pv_phys_pfn_offset = PHYS_PFN(CONFIG_PHYS_OFFSET);
#else
	extern unsigned long __pv_phys_pfn_offset;
	bcm_pv_phys_pfn_offset = __pv_phys_pfn_offset;
#endif
	pr_info("bcm_compat: 4.19 ABI shim loaded (pfn_offset=%lx)\n",
		bcm_pv_phys_pfn_offset);
	return 0;
}

static void __exit bcm_compat_exit(void)
{
	pr_info("bcm_compat: unloaded\n");
}

module_init(bcm_compat_init);
module_exit(bcm_compat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cudy-be3600 reverse");
MODULE_DESCRIPTION("Broadcom BCA 4.19 ABI compatibility shim for 6.6");
