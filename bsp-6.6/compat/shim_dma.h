/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_DMA_H
#define BCM_SHIM_DMA_H
#include <linux/device.h>
#include <linux/dma-direction.h>
#include <linux/types.h>

/* Vendor ARM32 ABI: dma_addr_t AND phys_addr_t were 64 bits. Never use
 * native dma_addr_t in this table, including callback arguments/returns. */
struct page;
struct vm_area_struct;
struct dma419_ops {
	void *(*alloc)(void *, size_t, u64 *, unsigned int, unsigned long);
	void (*free)(void *, size_t, void *, u64, unsigned long);
	int (*mmap)(void *, struct vm_area_struct *, void *, u64, size_t, unsigned long);
	int (*get_sgtable)(void *, void *, void *, u64, size_t, unsigned long);
	u64 (*map_page)(void *, struct page *, unsigned long, size_t,
			enum dma_data_direction, unsigned long);
	void (*unmap_page)(void *, u64, size_t, enum dma_data_direction, unsigned long);
	int (*map_sg)(void *, void *, int, enum dma_data_direction, unsigned long);
	void (*unmap_sg)(void *, void *, int, enum dma_data_direction, unsigned long);
	u64 (*map_resource)(void *, u64, size_t, enum dma_data_direction, unsigned long);
	void (*unmap_resource)(void *, u64, size_t, enum dma_data_direction, unsigned long);
	void (*sync_single_for_cpu)(void *, u64, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(void *, u64, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(void *, void *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(void *, void *, int, enum dma_data_direction);
	void (*cache_sync)(void *, void *, size_t, enum dma_data_direction);
	int (*mapping_error)(void *, u64);
	int (*dma_supported)(void *, u64);
};
extern const struct dma419_ops arm_dma_ops;
int shim_dma_init(void);
void shim_dma_exit(void);
int shim_dma_bind(void *old, struct device *native);
void shim_dma_unbind(void *old);
/* Returns a held device reference; caller must put_device(). */
struct device *shim_dma_get_device(void *old);
#endif
