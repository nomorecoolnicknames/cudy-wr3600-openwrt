// SPDX-License-Identifier: GPL-2.0-only
/*
 * shim_bcmlog.c - the BCA logging entry points that live in the VENDOR
 * KERNEL, not in any module.
 *
 * Found while bringing the stack up on hardware (2026-09-07): bcmlibs.ko
 * refused to load with
 *     bcmlibs: Unknown symbol bcm_printk (err -2)
 *     bcmlibs: Unknown symbol bcmLog_logIsEnabled (err -2)
 * Both are defined in kernel/bcmkernel/src/bcm_log.c of the vendor GPL tree
 * (EXPORT_SYMBOL at lines 827/838) and are compiled INTO the 4.19 vmlinux, so
 * no stock .ko exports them and the earlier symbol survey - which only looked
 * at modules - did not list them.
 *
 * bcm_printk: vendor forwards to vprintk() verbatim (bcm_log.c:767-790).
 * bcmLog_logIsEnabled: returns &modInfo[logId] when the module's log level is
 * high enough, NULL otherwise (bcm_log.c:513-522). We keep no log-level table,
 * so we always answer "not enabled" (NULL). That is the quiet, safe answer:
 * every caller uses the result only to decide whether to emit a debug line,
 * and a NULL return means "skip it" - no caller dereferences it in that case.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/stdarg.h>

int bcm_printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);

	return r;
}
EXPORT_SYMBOL(bcm_printk);

void *bcmLog_logIsEnabled(int log_id, int log_level)
{
	return NULL;		/* logging disabled: callers skip the message */
}
EXPORT_SYMBOL(bcmLog_logIsEnabled);
