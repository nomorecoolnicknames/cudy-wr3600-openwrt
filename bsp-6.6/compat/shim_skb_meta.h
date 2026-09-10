/* SPDX-License-Identifier: GPL-2.0-only */
/* Generated from configured headers by triaging/shim/skb-h13/probe_meta.py */
#ifndef BCM_SHIM_SKB_META_H
#define BCM_SHIM_SKB_META_H
enum {
	SKMETA_vlan_present = 4096,
	SKMETA_offset_bcm_ext_vlan_cfi_save = 96,
	SKMETA_mask_bcm_ext_vlan_cfi_save = 1,
	SKMETA_shift_bcm_ext_vlan_cfi_save = 0,
	SKMETA_offset_offload_mr_fwd_mark = 227,
	SKMETA_mask_offload_mr_fwd_mark = 8,
	SKMETA_shift_offload_mr_fwd_mark = 3,
	SKMETA_offset_tc_from_ingress = 227,
	SKMETA_mask_tc_from_ingress = 128,
	SKMETA_shift_tc_from_ingress = 7,
	SKMETA_offset_tc_redirected = 227,
	SKMETA_mask_tc_redirected = 64,
	SKMETA_shift_tc_redirected = 6,
	SKMETA_offset_tc_at_ingress = 227,
	SKMETA_mask_tc_at_ingress = 32,
	SKMETA_shift_tc_at_ingress = 5,
	SKMETA_offset_tc_skip_classify = 227,
	SKMETA_mask_tc_skip_classify = 16,
	SKMETA_shift_tc_skip_classify = 4,
	SKMETA_offset_decrypted = 228,
	SKMETA_mask_decrypted = 1,
	SKMETA_shift_decrypted = 0,
	SKMETA_offset_csum_not_inet = 226,
	SKMETA_mask_csum_not_inet = 8,
	SKMETA_shift_csum_not_inet = 3,
	SKMETA_offset_ipvs_property = 226,
	SKMETA_mask_ipvs_property = 128,
	SKMETA_shift_ipvs_property = 7,
	SKMETA_offset_nf_trace = 224,
	SKMETA_mask_nf_trace = 16,
	SKMETA_shift_nf_trace = 4,
	SKMETA_offset_pfmemalloc = 222,
	SKMETA_mask_pfmemalloc = 128,
	SKMETA_shift_pfmemalloc = 7,
	SKMETA_offset_offload_fwd_mark = 227,
	SKMETA_mask_offload_fwd_mark = 4,
	SKMETA_shift_offload_fwd_mark = 2,
	SKMETA_offset_csum_valid = 225,
	SKMETA_mask_csum_valid = 128,
	SKMETA_shift_csum_valid = 7,
	SKMETA_offset_encap_hdr_csum = 225,
	SKMETA_mask_encap_hdr_csum = 64,
	SKMETA_shift_encap_hdr_csum = 6,
	SKMETA_offset_encapsulation = 225,
	SKMETA_mask_encapsulation = 32,
	SKMETA_shift_encapsulation = 5,
	SKMETA_offset_no_fcs = 225,
	SKMETA_mask_no_fcs = 16,
	SKMETA_shift_no_fcs = 4,
	SKMETA_offset_wifi_acked = 225,
	SKMETA_mask_wifi_acked = 8,
	SKMETA_shift_wifi_acked = 3,
	SKMETA_offset_wifi_acked_valid = 225,
	SKMETA_mask_wifi_acked_valid = 4,
	SKMETA_shift_wifi_acked_valid = 2,
	SKMETA_offset_sw_hash = 225,
	SKMETA_mask_sw_hash = 2,
	SKMETA_shift_sw_hash = 1,
	SKMETA_offset_l4_hash = 225,
	SKMETA_mask_l4_hash = 1,
	SKMETA_shift_l4_hash = 0,
	SKMETA_offset_inner_protocol_type = 227,
	SKMETA_mask_inner_protocol_type = 1,
	SKMETA_shift_inner_protocol_type = 0,
	SKMETA_offset_csum_complete_sw = 226,
	SKMETA_mask_csum_complete_sw = 1,
	SKMETA_shift_csum_complete_sw = 0,
	SKMETA_offset_remcsum_offload = 227,
	SKMETA_mask_remcsum_offload = 2,
	SKMETA_shift_remcsum_offload = 1,
	SKMETA_offset_dst_pending_confirm = 226,
	SKMETA_mask_dst_pending_confirm = 16,
	SKMETA_shift_dst_pending_confirm = 4,
	SKMETA_offset_ooo_okay = 224,
	SKMETA_mask_ooo_okay = 128,
	SKMETA_shift_ooo_okay = 7,
	SKMETA_offset_ignore_df = 224,
	SKMETA_mask_ignore_df = 8,
	SKMETA_shift_ignore_df = 3,
	SKMETA_offset_csum_level = 226,
	SKMETA_mask_csum_level = 6,
	SKMETA_shift_csum_level = 1,
	SKMETA_offset_ip_summed = 224,
	SKMETA_mask_ip_summed = 96,
	SKMETA_shift_ip_summed = 5,
	SKMETA_offset_pkt_type = 224,
	SKMETA_mask_pkt_type = 7,
	SKMETA_shift_pkt_type = 0,
};
#define SKMETA_COMMON(X) \
	X(pkt_type) \
	X(ip_summed) \
	X(csum_level) \
	X(ignore_df) \
	X(ooo_okay) \
	X(dst_pending_confirm) \
	X(remcsum_offload) \
	X(csum_complete_sw) \
	X(inner_protocol_type) \
	X(l4_hash) \
	X(sw_hash) \
	X(wifi_acked_valid) \
	X(wifi_acked) \
	X(no_fcs) \
	X(encapsulation) \
	X(encap_hdr_csum) \
	X(csum_valid) \
	X(offload_fwd_mark) \
	X(pfmemalloc)
#define SKMETA_UNSUPPORTED(X) \
	X(nf_trace) \
	X(ipvs_property) \
	X(csum_not_inet) \
	X(decrypted) \
	X(tc_skip_classify) \
	X(tc_at_ingress) \
	X(tc_redirected) \
	X(tc_from_ingress) \
	X(offload_mr_fwd_mark)
#endif
