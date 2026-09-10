/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BCM_SHIM_NETDEV_STATS_H
#define BCM_SHIM_NETDEV_STATS_H
/* Vendor CONFIG_BCM_KF_EXTSTATS inserts six u64 fields before rx_nohandler.
 * Measured in netdev-h11/stats-layouts.json: 240 bytes, nohandler at 232. */
#define ND419_COMMON_STATS(X) \
	X(rx_packets) X(tx_packets) X(rx_bytes) X(tx_bytes) \
	X(rx_errors) X(tx_errors) X(rx_dropped) X(tx_dropped) \
	X(multicast) X(collisions) X(rx_length_errors) X(rx_over_errors) \
	X(rx_crc_errors) X(rx_frame_errors) X(rx_fifo_errors) X(rx_missed_errors) \
	X(tx_aborted_errors) X(tx_carrier_errors) X(tx_fifo_errors) \
	X(tx_heartbeat_errors) X(tx_window_errors) X(rx_compressed) X(tx_compressed)
struct netdev419_stats {
#define FIELD(name) u64 name;
	ND419_COMMON_STATS(FIELD)
#undef FIELD
	u64 extended[6];
	u64 rx_nohandler;
};
#define ND419_EXTSTATS BIT_ULL(57)
#endif
