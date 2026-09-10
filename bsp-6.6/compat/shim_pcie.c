// SPDX-License-Identifier: GPL-2.0-only
/*
 * shim_pcie.c — lane E3: M3-blocker stubs for wl.ko's PCIe glue.
 *
 * Covers (FACT per triaging/shim/SHIM_M3_PREP_REPORT.md §3 + §5):
 *   bcm_pcie_config_bar_addr / bcm_pcie_map_bar_addr — wl.ko imports these
 *     2 from stock bcm_pcie_hcd.ko, which CANNOT load on 6.6 (46 gaps +
 *     bcm_enet conflict, SHIM_C_SUMMARY.md §2). Prototypes recovered from
 *     GPL bcm_pcie.c:375,538 + AAPCS audit of the 3 call sites
 *     (0x313564/0x31392c/0x3139a8). phys_addr_t is spelled u64 EXPLICITLY:
 *     the blob was built with CONFIG_ARM_LPAE=y (u64 addr pair in r2+r3,
 *     size 5th word on stack) while our 6.6 has ARM_LPAE=n — a phys_addr_t
 *     prototype would desync AAPCS.
 *   bcm_shim_warn_slowpath_fmt — old-signature (file,line,fmt,...) target
 *     of the tools/modvermagic.py --rename-warn rel-patch (report §5.2).
 *     The 6.6 kernel exports warn_slowpath_fmt with an extra taint arg, so
 *     this name MUST stay distinct (duplicate export = insmod failure).
 *
 * All exports are EXPORT_SYMBOL (never _GPL): wl.ko is Proprietary
 * (shim.h rule 1). None of the 3 names is in kernel-6.6/build/Module.symvers
 * (verified 2026-09-07) nor in the radio blobs' ksymtab (checked by E3) —
 * no duplicate-export risk (shim.h rule 2).
 *
 * Placement note: a new file (not shim_core.c / shim_hnd_gaps.c) keeps
 * lane C's active file untouched and groups the one M3 work item that
 * M5-DMA (SWAM/iwin) will revisit; Kbuild change is one additive line.
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/stdarg.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/bug.h>
#include <linux/panic.h>
#include "shim.h"

/* Bring-up diagnostic: the stock blob maps a lot of small windows at attach
 * time and every mapping used to be logged (1.5k lines per boot). Off by
 * default so a release boot stays readable; enable when chasing a mapping. */
static bool ioremap_trace;
module_param(ioremap_trace, bool, 0644);
MODULE_PARM_DESC(ioremap_trace, "log every shim ioremap (bring-up diagnostic)");

/* Stock ARM LPAE puts address in r0/r1, size in r2. Native non-LPAE
 * ioremap expects address in r0 and size in r1. Keep the wide entry ABI. */
void __iomem *bcm419_ioremap(u64 address, size_t size)
{
	void __iomem *mapped;
	if ((address >> 32) || !size) {
		pr_err("bcm_shim: ioremap invalid address=%llx size=%zu\n",
		       address, size);
		return NULL;
	}
	mapped = ioremap((resource_size_t)address, size);
	if (ioremap_trace)
		pr_info("bcm_shim: ioremap address=%llx size=%zu result=%px\n",
			address, size, mapped);
	return mapped;
}
EXPORT_SYMBOL(bcm419_ioremap);

/* --- bcm_pcie_map_bar_addr: GPL bcm_pcie.c:538
 *   phys_addr_t bcm_pcie_map_bar_addr(struct pci_dev *pdev,
 *                                     phys_addr_t addr, u32 size);
 * Vendor semantic: map BAR incoming address to a UBUS-decodable mapped
 * address; returns mapped addr / addr when unsupported (!SWAM) / -1ull on
 * failure. Our vpcie66 BAR0 window (0x90000000/0x98000000) is already
 * UBUS-decodable, so identity (= vendor !SWAM mode `pci_addr = addr`)
 * is correct. No hardware touched. --- */
u64 bcm_pcie_map_bar_addr(struct pci_dev *pdev, u64 addr, u32 size)
{
	(void)pdev;
	(void)size;
	pr_debug_once("bcm_shim: map_bar_addr identity %llx size %x\n",
		      (unsigned long long)addr, size);
	return addr;
}
EXPORT_SYMBOL(bcm_pcie_map_bar_addr);

/* --- bcm_pcie_config_bar_addr: GPL bcm_pcie.c:375
 *   int bcm_pcie_config_bar_addr(struct pci_dev *pdev, int bar,
 *                                phys_addr_t addr, u32 size);
 * Vendor semantic: configure/unconfigure the PCIe incoming address window;
 * 0 = ok, 1 = ok-with-mapped, <0 = fail; bar==0 scans for a free/existing
 * BAR, size==0 unconfigures. The blob uses bar∈{0,1} with size 0x800000+
 * per core (init) and (0, addr, 0) for deinit (report §3.3).
 * No hardware touched: only validates [addr,addr+size) against the live
 * BAR0 window. E3 judgment call (for lane H to watch): a zero-length BAR0
 * (not yet sized) fails OPEN with a warn instead of -ENOSPC, so a BAR
 * sizing race cannot abort MLO init; the warn makes it visible. --- */
int bcm_pcie_config_bar_addr(struct pci_dev *pdev, int bar, u64 addr,
			     u32 size)
{
	u64 start, len, off;

	if (!pdev)
		return -EINVAL;
	if (size == 0)
		return 0;	/* unconfigure ok (deinit path uses this) */
	start = (u64)pci_resource_start(pdev, 0);
	len = (u64)pci_resource_len(pdev, 0);
	if (len == 0) {
		shim_warn_once("pcie_config: BAR0 unsized, fail-open "
			       "(bar=%d addr=%llx size=%x)\n",
			       bar, (unsigned long long)addr, size);
		return 0;
	}
	off = addr - start;
	if (addr >= start && size <= len && off <= len - size)
		return 0;
	shim_warn_once("pcie_config: window [%llx,%llx) outside BAR0 "
		       "[%llx,%llx) (bar=%d)\n",
		       (unsigned long long)addr,
		       (unsigned long long)(addr + size),
		       (unsigned long long)start,
		       (unsigned long long)(start + len), bar);
	return -ENOSPC;
}
EXPORT_SYMBOL(bcm_pcie_config_bar_addr);

/* --- bcm_shim_warn_slowpath_fmt: 4.19 prototype
 *   void bcm_shim_warn_slowpath_fmt(const char *file, int line,
 *                                   const char *fmt, ...);
 * (BCA linux-4.19.246 include/asm-generic/bug.h:94: warn_slowpath_fmt
 * takes (file,line,fmt); 6.6 kernel/panic.c:697 inserts taint before fmt.)
 * Emulates the 4.19 __warn body with taint hardcoded to TAINT_WARN (what
 * 4.19 did internally): header + fmt + stack + TAINT_WARN, the same taint
 * lane C's warn_slowpath_null wrapper sets. Varargs CANNOT be forwarded
 * into 6.6 warn_slowpath_fmt (taint slot), hence the manual vprintk. --- */
void bcm_shim_warn_slowpath_fmt(const char *file, int line, const char *fmt,
				...)
{
	va_list args;

	if (!file)
		file = "?";
	pr_warn("------------[ bcm_shim WARN %s:%d ]------------\n",
		file, line);
	if (fmt) {
		va_start(args, fmt);
		vprintk(fmt, args);
		va_end(args);
	}
	dump_stack();
	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
}
EXPORT_SYMBOL(bcm_shim_warn_slowpath_fmt);
