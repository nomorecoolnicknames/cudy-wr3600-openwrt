// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include "wl_compat.h"

static atomic_t calls = ATOMIC_INIT(0);

/* gbpm_alloc_mult_buf returns -1 on failure, 0 only if array was filled.
 * The prior pointer-returning NULL stub falsely reported success here.
 */
static int reject(u32 num, void **array, u32 prio)
{
	int n = atomic_inc_return(&calls);
	(void)array;
	if (n <= 4 || !(n % 256))
		pr_info("H30_XPM slot=0 call=%d num=%u prio=%u caller=%pS rc=-1\n",
			n, num, prio, __builtin_return_address(0));
	return -1;
}

static int __init start(void)
{
	__module_get(THIS_MODULE);
	WRITE_ONCE(gbpm_g.slot[WL_GBPM_ALLOC_MULT_BUF], reject);
	pr_info("H30_XPM observer ACTIVE pinned=1\n");
	return 0;
}
module_init(start);
MODULE_LICENSE("GPL");
