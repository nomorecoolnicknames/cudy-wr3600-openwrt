// SPDX-License-Identifier: GPL-2.0-only
/* Remaining vendor file API shim. DMA lives in shim_dma.c. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include "shim.h"

/* --- vfs_statx: static in 6.6 fs/stat.c:232 (no export). hnd uses it
 * once (file-size check in its file helpers). 4.19 prototype
 * (linux-4.19.246 fs/stat.c:166):
 *   int vfs_statx(int dfd, const char __user *filename, int flags,
 *                 struct kstat *, u32 request_mask)
 * Reimplement with exported primitives: copy the user path with
 * strncpy_from_user(), resolve with kern_path(), stat with vfs_getattr()
 * (all three EXPORT_SYMBOL). dfd-relative lookup is not needed by hnd
 * (uses AT_FDCWD); anything else fails loudly. --- */
int vfs_statx(int dfd, const char __user *filename, int flags,
	      struct kstat *stat, u32 request_mask)
{
	char *kname;
	struct path path;
	long len;
	int error;

	if (!filename || !stat)
		return -EINVAL;
	if (dfd != AT_FDCWD) {
		shim_warn_once("vfs_statx: dfd!=AT_FDCWD unsupported\n");
		return -EBADF;
	}
	kname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kname)
		return -ENOMEM;
	len = strncpy_from_user(kname, filename, PATH_MAX);
	if (len <= 0) {
		kfree(kname);
		return len ? (int)len : -ENOENT;
	}
	error = kern_path(kname, flags, &path);
	kfree(kname);
	if (error)
		return error;
	error = vfs_getattr(&path, stat, request_mask, flags);
	path_put(&path);
	return error;
}
EXPORT_SYMBOL(vfs_statx);

/* --- bcm_pcie_config_bar_addr / bcm_pcie_map_bar_addr: wl.ko imports
 * these 2 from stock bcm_pcie_hcd.ko (FACT: wl UND ∩ pcie_hcd exports).
 * Stock bcm_pcie_hcd CANNOT load on 6.6 (46 gaps incl. bcm_enet symbols
 * and PCI-core APIs needing a full host stack) — lane A (vpcie66) owns
 * BAR mapping instead. Signatures not yet recovered (not in BCA headers
 * found so far) → OMITTED from skeleton on purpose (wrong arity =
 * stack corruption). Lane A+E: recover arity from bcm_pcie_hcd.ko
 * disasm, implement against vpcie66 windows, add here. M3-blocker,
 * tracked in SHIM_C_SUMMARY.md. --- */

int shim_hnd_gaps_init(void)
{
	pr_info("bcm_shim: hnd gaps up\n");
	return 0;
}
