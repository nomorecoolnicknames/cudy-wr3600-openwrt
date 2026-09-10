// SPDX-License-Identifier: GPL-2.0-only
/*
 * The optional BCA nlwifi family has not been ported. Its family/ops/info
 * layouts differ, and its builders contain inline legacy skb and net
 * accesses. Passing these objects to native genl corrupts memory (H30/20).
 *
 * Reject registration and message construction explicitly until that entire
 * boundary is translated. Outbound notification builders check genlmsg_put for NULL before their
 * inline skb writes and free the native allocation on failure. No legacy
 * request/dump callbacks are registered. Do not
 * pretend to register the family or consume/free an skb here.
 *
 * Only the wl imports are redirected here. Native nl80211 and the shim's
 * own native netlink calls continue to use the actual kernel API.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>

int bcm419_genl_register_family(struct genl_family *legacy)
{
	pr_info("GENL419: optional vendor family unsupported; registration rejected\n");
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(bcm419_genl_register_family);

int bcm419_genl_unregister_family(struct genl_family *legacy)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(bcm419_genl_unregister_family);

void *bcm419_genlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
			const struct genl_family *legacy, int flags, u8 cmd)
{
	pr_info_once("GENL419: optional vendor message rejected before legacy inline writes\n");
	return NULL;
}
EXPORT_SYMBOL(bcm419_genlmsg_put);
