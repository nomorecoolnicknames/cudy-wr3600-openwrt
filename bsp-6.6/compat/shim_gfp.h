/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_GFP_H
#define BCM_SHIM_GFP_H
#include <linux/gfp.h>

/* Bit values from the supplied vendor 4.19 include/linux/gfp.h. */
static inline gfp_t shim_gfp419(unsigned int old)
{
	gfp_t flags = (__force gfp_t)(old & 0xff);
#define MAP(bit, flag) do { if (old & (bit)) flags |= (flag); } while (0)
	MAP(0x100, __GFP_WRITE);
	MAP(0x200, __GFP_NOWARN);
	MAP(0x400, __GFP_RETRY_MAYFAIL);
	MAP(0x800, __GFP_NOFAIL);
	MAP(0x1000, __GFP_NORETRY);
	MAP(0x2000, __GFP_MEMALLOC);
	MAP(0x4000, __GFP_COMP);
	MAP(0x8000, __GFP_ZERO);
	MAP(0x10000, __GFP_NOMEMALLOC);
	MAP(0x20000, __GFP_HARDWALL);
	MAP(0x40000, __GFP_THISNODE);
	/* __GFP_ATOMIC was removed; HIGH plus no DIRECT_RECLAIM is native
	 * GFP_ATOMIC. Preserve this reserve access for old standalone ATOMIC. */
	MAP(0x80000, __GFP_HIGH);
	MAP(0x100000, __GFP_ACCOUNT);
	MAP(0x200000, __GFP_DIRECT_RECLAIM);
	MAP(0x400000, __GFP_KSWAPD_RECLAIM);
	MAP(0x800000, __GFP_NOLOCKDEP);
#undef MAP
	return flags;
}
#endif
