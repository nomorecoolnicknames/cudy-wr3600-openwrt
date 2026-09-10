// SPDX-License-Identifier: GPL-2.0-only
/* Out-of-line entry points used by the stock blob, inline in kernel #110. */
#include <linux/module.h>
#include <linux/spinlock.h>

#ifndef CONFIG_UNINLINE_SPIN_UNLOCK
#undef _raw_spin_unlock
void _raw_spin_unlock(raw_spinlock_t *lock)
{
	__raw_spin_unlock(lock);
}
EXPORT_SYMBOL(_raw_spin_unlock);
#endif

#ifdef CONFIG_INLINE_READ_UNLOCK
#undef _raw_read_unlock
void _raw_read_unlock(rwlock_t *lock)
{
	__raw_read_unlock(lock);
}
EXPORT_SYMBOL(_raw_read_unlock);
#endif
