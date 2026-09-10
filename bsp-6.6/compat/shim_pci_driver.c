// SPDX-License-Identifier: GPL-2.0-only
/* Keep the native PCI core from writing its larger driver into wl's .data. */
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include "shim_dma.h"

struct pci419_prefix {
	struct list_head node;
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *, const struct pci_device_id *);
	void (*remove)(struct pci_dev *);
	int (*suspend)(struct pci_dev *, pm_message_t);
	int (*suspend_late)(struct pci_dev *, pm_message_t);
	int (*resume_early)(struct pci_dev *);
	int (*resume)(struct pci_dev *);
	void (*shutdown)(struct pci_dev *);
	int (*sriov_configure)(struct pci_dev *, int);
	const void *err_handler;
	const void *groups;
};

struct pci419_adapter {
	struct list_head list;
	const struct pci419_prefix *old;
	struct pci_driver native;
};
static LIST_HEAD(pci419_drivers);
static DEFINE_MUTEX(pci419_mutex);

static int pci419_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct pci419_adapter *entry = container_of(pdev->driver,
					struct pci419_adapter, native);
	void *old_dev = (u8 *)pdev + 104;
	int ret;

	/* The blob's inline &pdev->dev still forms its old +104 pointer.
	 * Keep it opaque and map to the real +120 object at the DMA boundary. */
	ret = shim_dma_bind(old_dev, &pdev->dev);
	if (ret)
		return ret;
	ret = entry->old->probe(pdev, id);
	if (ret)
		shim_dma_unbind(old_dev);
	return ret;
}

static void pci419_remove(struct pci_dev *pdev)
{
	struct pci419_adapter *entry = container_of(pdev->driver,
					struct pci419_adapter, native);
	if (entry->old->remove)
		entry->old->remove(pdev);
	shim_dma_unbind((u8 *)pdev + 104);
}

int bcm419___pci_register_driver(const struct pci419_prefix *old,
				struct module *owner, const char *mod_name)
{
	struct pci419_adapter *entry, *it;
	int ret;

	static_assert(sizeof(struct pci419_prefix) == 56);
	/* The audited wl driver only populates name/id/probe/remove/shutdown.
	 * Additional old nested interfaces need their own translation. */
	if (!old || old->suspend_late || old->resume_early || old->err_handler ||
	    old->groups || memchr_inv((const u8 *)old + 56, 0, 136 - 56))
		return -EOPNOTSUPP;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->old = old;
	entry->native.name = old->name;
	entry->native.id_table = old->id_table;
	entry->native.probe = old->probe ? pci419_probe : NULL;
	entry->native.remove = pci419_remove;
	entry->native.suspend = old->suspend;
	entry->native.resume = old->resume;
	entry->native.shutdown = old->shutdown;
	entry->native.sriov_configure = old->sriov_configure;
	mutex_lock(&pci419_mutex);
	list_for_each_entry(it, &pci419_drivers, list) {
		if (it->old == old) {
			mutex_unlock(&pci419_mutex);
			kfree(entry);
			return -EBUSY;
		}
	}
	list_add(&entry->list, &pci419_drivers);
	mutex_unlock(&pci419_mutex);
	ret = __pci_register_driver(&entry->native, owner, mod_name);
	if (ret) {
		mutex_lock(&pci419_mutex);
		list_del(&entry->list);
		mutex_unlock(&pci419_mutex);
		kfree(entry);
	}
	return ret;
}
EXPORT_SYMBOL(bcm419___pci_register_driver);

void bcm419_pci_unregister_driver(const struct pci419_prefix *old)
{
	struct pci419_adapter *entry;
	mutex_lock(&pci419_mutex);
	list_for_each_entry(entry, &pci419_drivers, list) {
		if (entry->old == old) {
			list_del(&entry->list);
			mutex_unlock(&pci419_mutex);
			pci_unregister_driver(&entry->native);
			kfree(entry);
			return;
		}
	}
	mutex_unlock(&pci419_mutex);
}
EXPORT_SYMBOL(bcm419_pci_unregister_driver);
