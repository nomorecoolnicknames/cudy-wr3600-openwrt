// SPDX-License-Identifier: GPL-2.0-only
/* Audited hnd OSL boundary, see triaging/shim/dma-h9/REPORT.md.
 * Old device pointers are opaque keys, NEVER native struct device pointers.
 * hnd_dmafix.py must also redirect inline ops loads and page arithmetic. */
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "shim_dma.h"
#include "shim_gfp.h"

#define DMA419_ERROR (~0ULL)
#define DMA419_SLOTS 8
static struct {
	void *old;
	struct device *native;
} bindings[DMA419_SLOTS];
static DEFINE_SPINLOCK(bindings_lock);
static struct device *mlo_device;
static void *mlo_key;
static u64 mlo_mask = DMA_BIT_MASK(32);
static bool dma_selftest;
module_param(dma_selftest, bool, 0400);
MODULE_PARM_DESC(dma_selftest, "Exercise legacy DMA ABI without loading vendor blobs");

/* Registry owns a reference. Callers must quiesce DMA before unbinding,
 * just like the native PCI remove contract. Lookup also pins the device. */
int shim_dma_bind(void *old, struct device *native)
{
	unsigned long flags;
	int i, slot = -1, ret = 0;

	if (!old || !native)
		return -EINVAL;
	spin_lock_irqsave(&bindings_lock, flags);
	for (i = 0; i < DMA419_SLOTS; i++) {
		if (bindings[i].old == old) {
			ret = -EEXIST;
			goto out;
		}
		if (!bindings[i].old && slot < 0)
			slot = i;
	}
	if (slot < 0) {
		ret = -ENOSPC;
		goto out;
	}
	bindings[slot].native = get_device(native);
	bindings[slot].old = old;
out:
	spin_unlock_irqrestore(&bindings_lock, flags);
	return ret;
}

void shim_dma_unbind(void *old)
{
	struct device *native = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&bindings_lock, flags);
	for (i = 0; i < DMA419_SLOTS; i++) {
		if (old && bindings[i].old == old) {
			native = bindings[i].native;
			bindings[i].old = NULL;
			bindings[i].native = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&bindings_lock, flags);
	put_device(native);
}

static struct device *dma419_device(void *old)
{
	struct device *native = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&bindings_lock, flags);
	for (i = 0; i < DMA419_SLOTS; i++) {
		if (old && bindings[i].old == old) {
			native = get_device(bindings[i].native);
			break;
		}
	}
	spin_unlock_irqrestore(&bindings_lock, flags);
	if (!native)
		dev_err_ratelimited(mlo_device, "unbound legacy DMA device %p\n", old);
	return native;
}

struct device *shim_dma_get_device(void *old)
{
	return dma419_device(old);
}

/* Only attrs=0 occurs in the audited HND OSL callers. Reject unaudited
 * bits (notably removed NON_CONSISTENT) instead of guessing semantics. */
static bool dma419_args(struct device *dev, u64 addr, unsigned long attrs)
{
	if (addr > U32_MAX || attrs) {
		dev_err_ratelimited(dev, "unsupported legacy DMA address/attrs %llx/%lx\n",
				   addr, attrs);
		return false;
	}
	return true;
}

static void *dma419_alloc(void *old, size_t size, u64 *handle,
			 unsigned int gfp, unsigned long attrs)
{
	struct device *dev = dma419_device(old);
	dma_addr_t native_handle;
	void *cpu = NULL;

	if (handle)
		*handle = DMA419_ERROR;
	if (dev && handle && size && dma419_args(dev, 0, attrs)) {
		cpu = dma_alloc_attrs(dev, size, &native_handle, shim_gfp419(gfp), attrs);
		if (cpu)
			*handle = (u64)native_handle;
	}
	put_device(dev);
	return cpu;
}

static void dma419_free(void *old, size_t size, void *cpu, u64 handle,
			unsigned long attrs)
{
	struct device *dev = dma419_device(old);

	if (dev && dma419_args(dev, handle, attrs))
		dma_free_attrs(dev, size, cpu, (dma_addr_t)handle, attrs);
	put_device(dev);
}

static u64 dma419_map_page(void *old, struct page *page, unsigned long offset,
			  size_t size, enum dma_data_direction dir, unsigned long attrs)
{
	struct device *dev = dma419_device(old);
	dma_addr_t handle;
	u64 result = DMA419_ERROR;

	if (dev && page && size && valid_dma_direction(dir) &&
	    dma419_args(dev, 0, attrs)) {
		handle = dma_map_page_attrs(dev, page, offset, size, dir, attrs);
		if (!dma_mapping_error(dev, handle))
			result = (u64)handle;
	}
	put_device(dev);
	return result;
}

static void dma419_unmap_page(void *old, u64 handle, size_t size,
			    enum dma_data_direction dir, unsigned long attrs)
{
	struct device *dev = dma419_device(old);

	if (dev && valid_dma_direction(dir) && dma419_args(dev, handle, attrs))
		dma_unmap_page_attrs(dev, (dma_addr_t)handle, size, dir, attrs);
	put_device(dev);
}

static void dma419_sync_cpu(void *old, u64 handle, size_t size,
			   enum dma_data_direction dir)
{
	struct device *dev = dma419_device(old);

	if (dev && valid_dma_direction(dir) && dma419_args(dev, handle, 0))
		dma_sync_single_for_cpu(dev, (dma_addr_t)handle, size, dir);
	put_device(dev);
}

static void dma419_sync_device(void *old, u64 handle, size_t size,
			      enum dma_data_direction dir)
{
	struct device *dev = dma419_device(old);

	if (dev && valid_dma_direction(dir) && dma419_args(dev, handle, 0))
		dma_sync_single_for_device(dev, (dma_addr_t)handle, size, dir);
	put_device(dev);
}

static int dma419_mapping_error(void *old, u64 addr)
{
	/* Native DMA_MAPPING_ERROR must be widened to all 64 ones too. */
	return addr >= (u64)DMA_MAPPING_ERROR;
}

static int dma419_supported(void *old, u64 mask)
{
	struct device *dev = dma419_device(old);
	int supported = 0;

	/* Audited caller: MLO asks whether an all-ones mask covers its bus.
	 * Keep the verified native mask; never expand a 32-bit DMA bus to 64. */
	if (dev && dev->dma_mask && *dev->dma_mask)
		supported = mask >= *dev->dma_mask && mask >= dev->coherent_dma_mask;
	put_device(dev);
	return supported;
}

/* Only these eight slots are used by hnd's audited OSL/MLO functions.
 * SG/mmap/resource/cache slots stay NULL: SG has a different layout too. */
const struct dma419_ops arm_dma_ops = {
	.alloc = dma419_alloc,
	.free = dma419_free,
	.map_page = dma419_map_page,
	.unmap_page = dma419_unmap_page,
	.sync_single_for_cpu = dma419_sync_cpu,
	.sync_single_for_device = dma419_sync_device,
	.mapping_error = dma419_mapping_error,
	.dma_supported = dma419_supported,
};
EXPORT_SYMBOL(arm_dma_ops);

/* hnd never declares a per-device coherent pool. Return the actual
 * "not handled" result and let its caller use arm_dma_ops.alloc/free.
 * Do not invent a second allocator or touch a 64-bit handle as u32. */
int bcm419_dma_alloc_from_dev_coherent(void *old, ssize_t size,
				     u64 *handle, void **ret)
{
	return 0;
}
EXPORT_SYMBOL(bcm419_dma_alloc_from_dev_coherent);

int bcm419_dma_release_from_dev_coherent(void *old, int order, void *cpu)
{
	return 0;
}
EXPORT_SYMBOL(bcm419_dma_release_from_dev_coherent);

/* One audited call: MLO owns a zeroed 512-byte old device. It is not a
 * registered native device. Native backing is created in shim init so
 * this void callback has no allocation failure to conceal. */
void bcm419_arch_setup_dma_ops(void *old, u64 base, u64 size,
			      const void *iommu, bool coherent)
{
	int ret;

	if (!old || base || size || iommu || !coherent || READ_ONCE(mlo_key)) {
		dev_err(mlo_device, "unsupported MLO DMA setup\n");
		return;
	}
	ret = shim_dma_bind(old, mlo_device);
	if (ret) {
		dev_err(mlo_device, "MLO DMA bind failed: %d\n", ret);
		return;
	}
	WRITE_ONCE(mlo_key, old);
	*(const struct dma419_ops **)((u8 *)old + 164) = &arm_dma_ops;
	*(u64 *)((u8 *)old + 176) = DMA_BIT_MASK(32);
	dev_info(mlo_device, "legacy MLO DMA bound, coherent 32-bit bus\n");
}
EXPORT_SYMBOL(bcm419_arch_setup_dma_ops);

/* Only hnd's kfree import is redirected. MLO exit frees its fake device
 * after its DMA buffers; discard the opaque key before memory is reused. */
void bcm419_hnd_kfree(const void *ptr)
{
	if (ptr && ptr == READ_ONCE(mlo_key)) {
		WRITE_ONCE(mlo_key, NULL);
		shim_dma_unbind((void *)ptr);
	}
	kfree(ptr);
}
EXPORT_SYMBOL(bcm419_hnd_kfree);

static int dma419_selftest(void)
{
	struct {
		u32 before;
		u64 handle;
		u32 after;
	} guard = { .before = 0x12345678, .handle = DMA419_ERROR,
		    .after = 0xabcdef01 };
	unsigned long key;
	void *cpu = NULL, *stream = NULL;
	u64 mapped = DMA419_ERROR;
	int ret;

	ret = shim_dma_bind(&key, mlo_device);
	if (ret)
		return ret;
	ret = -EIO;
	cpu = arm_dma_ops.alloc(&key, PAGE_SIZE, &guard.handle, 0x6080c0, 0);
	if (!cpu || guard.before != 0x12345678 || guard.after != 0xabcdef01 ||
	    arm_dma_ops.mapping_error(&key, guard.handle) ||
	    memchr_inv(cpu, 0, PAGE_SIZE))
		goto out;
	memset(cpu, 0x5a, PAGE_SIZE);
	stream = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!stream)
		goto out;
	memset(stream, 0xa5, PAGE_SIZE);
	mapped = arm_dma_ops.map_page(&key, virt_to_page(stream),
			offset_in_page(stream), PAGE_SIZE, DMA_BIDIRECTIONAL, 0);
	if (arm_dma_ops.mapping_error(&key, mapped))
		goto out;
	arm_dma_ops.sync_single_for_cpu(&key, mapped, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (memchr_inv(stream, 0xa5, PAGE_SIZE))
		goto out;
	memset(stream, 0x3c, PAGE_SIZE);
	arm_dma_ops.sync_single_for_device(&key, mapped, PAGE_SIZE, DMA_BIDIRECTIONAL);
	/* Root device has direct DMA, no IOMMU/range translation. */
	if (mapped != (u64)virt_to_phys(stream) ||
	    !arm_dma_ops.mapping_error(&key, 0xffffffffULL) ||
	    !arm_dma_ops.mapping_error(&key, 0x100000000ULL) ||
	    !arm_dma_ops.mapping_error(&key, DMA419_ERROR) ||
	    !arm_dma_ops.dma_supported(&key, DMA419_ERROR))
		goto out;
	dev_info(mlo_device, "DMA419_SELFTEST PASS coherent=%llx streaming=%llx handles=64bit guards=OK data=OK\n",
		 guard.handle, mapped);
	ret = 0;
out:
	if (!arm_dma_ops.mapping_error(&key, mapped))
		arm_dma_ops.unmap_page(&key, mapped, PAGE_SIZE, DMA_BIDIRECTIONAL, 0);
	kfree(stream);
	if (cpu)
		arm_dma_ops.free(&key, PAGE_SIZE, cpu, guard.handle, 0);
	shim_dma_unbind(&key);
	if (ret)
		dev_err(mlo_device, "DMA419_SELFTEST FAIL\n");
	return ret;
}

int shim_dma_init(void)
{
	int ret;

	static_assert(sizeof(struct dma419_ops) == 68);
	static_assert(offsetof(struct dma419_ops, map_page) == 16);
	static_assert(offsetof(struct dma419_ops, sync_single_for_cpu) == 40);
	static_assert(offsetof(struct dma419_ops, mapping_error) == 60);
	static_assert(offsetof(struct dma419_ops, dma_supported) == 64);
	static_assert(sizeof(dma_addr_t) == 4);
	static_assert(sizeof(struct page) == 32);
	static_assert(offsetof(struct pci_dev, dev) == 120);
	static_assert(offsetof(struct device, coherent_dma_mask) == 368);
	mlo_device = root_device_register("bcm419-mlo-dma");
	if (IS_ERR(mlo_device))
		return PTR_ERR(mlo_device);
	mlo_device->dma_mask = &mlo_mask;
	/* The only old setup call requests coherent=true, base=size=0 and
 * no IOMMU. Same native ARM setup effect, without calling an unexported
 * arch hook or treating the old fake object as a native struct device. */
	mlo_device->dma_coherent = true;
	ret = dma_set_mask_and_coherent(mlo_device, DMA_BIT_MASK(32));
	if (!ret && dma_selftest)
		ret = dma419_selftest();
	if (ret) {
		root_device_unregister(mlo_device);
		return ret;
	}
	dev_info(mlo_device, "DMA419 table ready (8 audited operations)\n");
	return 0;
}

void shim_dma_exit(void)
{
	int i;

	for (i = 0; i < DMA419_SLOTS; i++)
		shim_dma_unbind(bindings[i].old);
	WRITE_ONCE(mlo_key, NULL);
	root_device_unregister(mlo_device);
}
