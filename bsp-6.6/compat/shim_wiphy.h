/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_WIPHY_H
#define BCM_SHIM_WIPHY_H
#include <linux/types.h>
#include <net/cfg80211.h>

/* Legacy 4.19 views: byte buffers at the vendor offsets/sizes measured by
 * triaging/shim/wiphy-h14/probe.py (WP419_* in shim_wiphy_layout.h).
 * The blob owns every byte of the old view including its private tail.
 * Native objects are owned by this adapter. Neither pointer may be cast
 * to the other. All returned pointers are borrowed: the caller must own
 * the object lifetime; RCU protects lookup, not arbitrary later use. */
struct wiphy419_view;
struct wdev419_view;
struct ieee80211_regdomain;

/* Allocate a native wiphy (wiphy_new_nm with caller-supplied NATIVE ops)
 * plus a separate zeroed 4.19 view with priv_size blob-owned tail bytes.
 * native_ops must already be a translated table (lane D wl_66_ops); the
 * blob's raw table is never accepted here. No registration is performed.
 * Returns NULL on any failure. */
struct wiphy419_view *shim_wiphy_alloc(int priv_size,
				       const struct cfg80211_ops *native_ops);
/* Publish validated init-time fields old -> native. Bands, cipher
 * suites, mgmt_stypes, iface combinations and per-band HE iftype_data
 * are deep-translated (re-runnable: a previous translation is dropped
 * first); vendor commands/events, reg_notifier, ht/vht masks, extended
 * capabilities and addresses still have no translator and must be NULL/0
 * or -EOPNOTSUPP is returned. Unknown flag bits are rejected, never
 * fabricated (WDS is stripped from interface_modes with a once-warn:
 * 6.6 removed it). A zero legacy perm_addr is filled from the lane-G
 * nvram MAC chain (band-aware sb/0 vs sb/1, et0macaddr fallback) and
 * written back to the legacy view; non-zero blob values are kept as-is.
 * Requires the native object to be unregistered. */
int shim_wiphy_publish(struct wiphy419_view *old);
/* Copy the published scalar set plus core-owned state (registered) back
 * native -> old for read-back. Embedded struct device / wdev_list are
 * never mirrored: their layouts differ and they are core-owned. */
void shim_wiphy_sync(struct wiphy419_view *old);
/* Free an UNREGISTERED pair. Returns -EBUSY if the native object is
 * registered, -ENOENT for an unknown view. On error ownership is retained. */
int shim_wiphy_free_unregistered(struct wiphy419_view *old);
struct wiphy *shim_wiphy_native(const struct wiphy419_view *old);
struct wiphy419_view *shim_wiphy_legacy(const struct wiphy *native);
/* Borrowed channel pairs; caller holds the published wiphy lifetime. */
struct ieee80211_channel *shim_channel_legacy(const struct ieee80211_channel *native);
struct ieee80211_channel *shim_channel_native(const struct ieee80211_channel *old);

/* Allocate a native wireless_dev (plain kzalloc: no core initialisation
 * exists outside registration, which is a later step) plus a separate
 * zeroed 4.19 view. wiphy/iftype/netdev start NULL; use shim_wdev_bind()
 * for the wiphy link. */
struct wdev419_view *shim_wdev_alloc(void);
/* Adopt blob-owned wdev storage, linking a native netdev. Does not own old. */
struct wireless_dev *shim_wdev_adopt(struct wdev419_view *old,
				   void *old_netdev, struct net_device *native);
/* Bind old_wdev.wiphy to old_wiphy AND native_wdev.wiphy to the matching
 * native wiphy in one step; either side may be NULL (unbind). The two
 * views are never cross-linked. Returns -ENOENT for unknown views. */
int shim_wdev_bind(struct wdev419_view *old_wdev,
		   struct wiphy419_view *old_wiphy);
/* Copy iftype old -> native and native -> old (width-checked, no semantic
 * validation in this stage). */
int shim_wdev_publish(struct wdev419_view *old);
int shim_wdev_publish_iftype(struct wireless_dev *native,
			     enum nl80211_iftype expected);
void shim_wdev_sync(struct wdev419_view *old);
int shim_wdev_free(struct wdev419_view *old);
struct wireless_dev *shim_wdev_native(const struct wdev419_view *old);
struct wdev419_view *shim_wdev_legacy(const struct wireless_dev *native);

int shim_wiphy_init(void);

/* Blob lifecycle entry points (H28 wiphy-reject lane). wl.ko must be
 * renamed (tools/modvermagic.py --rename-wiphy) so its six wiphy UNDs
 * resolve here instead of the kernel exports (same-name shim exports
 * would be -ENOEXEC duplicates, and the kernel entry points would hand
 * the blob a native 6.6 object that its 4.19-offset writes corrupt).
 *
 * The blob always passes legacy views (shim-alloc returns one, and the
 * blob stashes/threads that pointer); every wrapper resolves legacy to
 * native first. Unknown/foreign pointers are loud once-warn no-ops,
 * never a dereference.
 *
 *  new_nm: attach the passed table as the lane-D blob ops, allocate
 *    against the translated wl_66_ops (update_connect_params stripped:
 *    the blob slot is NULL and 6.6 refuses FW_ROAM-less wiphys carrying
 *    that op), return the legacy view. A re-attach with a different
 *    table (wl rmmod/insmod gives a new .data address) drops stale
 *    UNREGISTERED entries of the dead incarnation first; REGISTERED
 *    leftovers are kept and reported (core-owned). Rejects NULL ops
 *    and non-NULL names (the audited site passes table/0x25538/NULL).
 *  register: publish (validate-first deep translation, re-runnable) ->
 *    real wiphy_register(native) -> sync back. Propagates the core
 *    return code (the blob has a clean cmp/bne fail path). Logs the
 *    published band shape (info, per attempt) for HW triage.
 *  free: unregister-first if still registered, then drop the
 *    translation, remove the registry entry and release both objects.
 *    Freeing the last entry detaches the lane-D blob ops (it points
 *    into wl.ko .data). Covers the blob's register-fail unwind
 *    (wiphy_free on a never-registered wiphy) and the detach path.
 *  unregister: real wiphy_unregister(native) + sync; the translation
 *    stays installed for a potential re-register.
 *  apply_custom_regulatory: publish-if-unregistered first (so the
 *    core's handle_band_custom sees real channels), then forward with
 *    the native pointer. The regdomain blob is forwarded as-is: its
 *    layout is header-identical in both trees (rcu_head/n/alpha2[3]/
 *    dfs_region + 96 B rules, compiler-measured) and the 6.6 core
 *    deep-copies it (reg_copy_regd) before use.
 *  regulatory_hint: forward with the native pointer (alpha2 owned by
 *    the caller, copied by the core into its own request).
 *
 * Staged gates inside publish (pr_warn_once, never silent):
 *  - WDS is stripped from interface_modes (removed from cfg80211 in
 *    5.x; 6.6 register rejects it with -EINVAL).
 *  - HT/VHT are stripped on a 6 GHz band (spec: 6G is HE-only; the
 *    4.19 tree had no such gate, 6.6 register rejects with -EINVAL).
 *  - the 6 GHz band is published only with usable HE iftype entries
 *    (6.6 mandates HE on 6G); without them it is skipped loud — 2.4/5
 *    GHz alone satisfy have_band.
 *  - S1G/LC band slots stay NULL (no 4.19 source, no such PHY).
 *  - EHT caps stay zero (no 4.19 source; firmware path blob-internal).
 * All symbols are plain EXPORT_SYMBOL (never _GPL): wl.ko imports them
 * as Proprietary. */
struct wiphy *bcm_shim_wiphy_new_nm(const struct cfg80211_ops *ops,
				    int sizeof_priv,
				    const char *requested_name);
int bcm_shim_wiphy_register(struct wiphy *wiphy);
void bcm_shim_wiphy_free(struct wiphy *wiphy);
void bcm_shim_wiphy_unregister(struct wiphy *wiphy);
void bcm_shim_wiphy_apply_custom_regulatory(
	struct wiphy *wiphy, const struct ieee80211_regdomain *regd);
int bcm_shim_regulatory_hint(struct wiphy *wiphy, const char *alpha2);
/* Drain leftover UNREGISTERED wiphy/wdev pairs via the matching free
 * calls; registered objects are core-owned and only reported.
 * Idempotent, NULL-safe. */
void shim_wiphy_exit(void);
#endif
