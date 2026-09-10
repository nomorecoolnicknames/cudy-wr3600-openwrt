/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_NETDEV_H
#define BCM_SHIM_NETDEV_H
#include <linux/netdevice.h>
#include <linux/notifier.h>

/* Legacy view owns the blob's private bytes at +1408. Native private
 * storage belongs to this adapter. Neither pointer may be cast to the other. */
struct netdev419_view;
struct netdev419_view *shim_netdev_alloc_ether(int priv_size, const char *name,
					    u8 assign_type, u32 txqs, u32 rxqs);
int shim_netdev_free_unregistered(struct netdev419_view *old);
/* Native ops MUST already translate their callback arguments. This is an
 * internal boundary; never pass the blob's net_device_ops directly. */
int shim_netdev_register(struct netdev419_view *old,
			const struct net_device_ops *native_ops);
int shim_netdev_register_locked(struct netdev419_view *old,
			       const struct net_device_ops *native_ops);
int shim_netdev_unregister(struct netdev419_view *old);
int shim_netdev_unregister_locked(struct netdev419_view *old);
int shim_netdev_free(struct netdev419_view *old);
/* Borrowed pointers: caller must own the interface lifetime/reference,
 * as with netdev_priv. RCU protects lookup, not arbitrary later use. */
struct net_device *shim_netdev_native(const struct netdev419_view *old);
struct netdev419_view *shim_netdev_legacy(const struct net_device *native);
bool shim_netdev_in_rtnl_callback(void);
/* Legacy lookup bridge (P0 vendor30 netdev-lookup lane): wl.ko must be
 * renamed (tools/modvermagic.py --rename-lookup) so its five
 * dev_get_by_name UND relocs resolve here instead of the kernel export
 * (a same-name shim export would be an -ENOEXEC duplicate, and the kernel
 * entry point hands the blob a native 6.6 object whose 4.19-offset reads
 * Oops — vendor30 NULL+8 in wl_bsscfg_find via [native+1408]).
 * Returns the legacy view holding the single lookup ref, which the blob
 * drops exactly once (bcm_dev_put on the blog path, inline pcpu dec via
 * old+892 on the four cfg paths — both reach the same native counter).
 * Missing/foreign names (loopback, Ethernet, anything without a legacy
 * view) return NULL with the lookup ref already dropped: the blob
 * NULL-checks all five sites, and a native pointer must never be handed
 * out as if it were an olddev. */
struct net_device *bcm_shim_dev_get_by_name_legacy(struct net *net,
						   const char *name);
int shim_netdev_init(void);
/* Notifier trampoline (S9/M3): wl.ko must be renamed
 * (tools/modvermagic.py --rename-notifier) so its UND
 * register/unregister_netdevice_notifier resolve here instead of the
 * kernel exports (same-name shim exports would be -ENOEXEC duplicates).
 * The wrappers swap the blob's notifier_block ->notifier_call to an
 * internal trampoline at runtime (file-level pointer rewrites cannot
 * carry a load-time address) and restore it on unregister. */
int bcm_shim_register_netdevice_notifier(struct notifier_block *nb);
int bcm_shim_unregister_netdevice_notifier(struct notifier_block *nb);
/* Alloc/register redirect (H24 netdev-write lane): wl.ko must be renamed
 * (tools/modvermagic.py --rename-netdev) so its UND alloc_netdev_mqs,
 * register_netdev and unregister_netdev resolve here instead of the kernel
 * exports (same-name shim exports would be -ENOEXEC duplicates, and the
 * kernel entry points would hand the blob a native 6.6 object that its
 * 4.19-offset writes corrupt — H24 Oops). The alloc wrapper returns the
 * 4.19 legacy view (1408 bytes, blob-owned +1408 priv); every blob
 * [dev,#off] access then lands in legacy memory by construction, including
 * sites not yet audited. The register wrapper resolves the legacy view to
 * its native object and runs the tested H11 mirror/prepare path, so the
 * stack always operates on a genuine kernel net_device. Until the skb/rxtx
 * lane delivers ndo_start_xmit translation, registration fails cleanly
 * with -EINVAL (no partial state, blob's own bne-fail path) instead of
 * Oopsing; flipping that gate is a one-line H25 handshake. */
struct net_device *bcm_shim_alloc_netdev_mqs(int priv_size, const char *name,
					     u8 assign_type,
					     void (*setup)(struct net_device *),
					     u32 txqs, u32 rxqs);
int bcm_shim_register_netdev(struct net_device *dev);
void bcm_shim_unregister_netdev(struct net_device *dev);
/* Drain leftover UNREGISTERED views via shim_netdev_free(); registered
 * ones are core-owned and only reported. Idempotent, NULL-safe. */
void shim_netdev_exit(void);
#endif
