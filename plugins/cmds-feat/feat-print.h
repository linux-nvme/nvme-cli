/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct feat_print_ops {
	void (*select_result)(enum nvme_features_id fid, __u64 result);
	void (*show_feature)(enum nvme_features_id fid, int sel,
			     unsigned int result, void *buf, __u32 data_len);
	void (*show_feature_fields)(enum nvme_features_id fid,
				    unsigned int result, unsigned char *buf);
	void (*lba_range)(struct nvme_lba_range_type *lbrt, int nr_ranges);
	void (*lba_status_info)(__u64 result);
	nvme_print_flags_t flags;
};

struct feat_print_ops *feat_get_stdout_print_ops(nvme_print_flags_t flags);
struct feat_print_ops *feat_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct feat_print_ops *feat_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct feat_print_ops *
feat_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_show_feature(enum nvme_features_id fid, int sel, unsigned int result,
		       void *buf, __u32 data_len, nvme_print_flags_t flags);
void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf);
void nvme_show_select_result(enum nvme_features_id fid, __u64 result);
void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges,
			 nvme_print_flags_t flags);
void nvme_show_lba_status_info(__u64 result);

/* The feature fields printers, for the persistent event log of log */
void stdout_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				unsigned char *buf);
#ifdef CONFIG_JSONC
void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf);
#endif

const char *nvme_feature_to_string(enum nvme_features_id feature);
const char *nvme_select_to_string(int sel);
const char *nvme_feature_lba_type_to_string(__u8 type);
const char *nvme_feature_temp_sel_to_string(__u8 sel);
const char *nvme_feature_temp_type_to_string(__u8 type);
const char *nvme_feature_wl_hints_to_string(__u8 wh);
const char *nvme_feature_perfc_attri_to_string(__u8 attri);
const char *nvme_feature_perfc_r4karl_to_string(__u8 r4karl);
const char *nvme_feature_perfc_attrtyp_to_string(__u8 attrtyp);
const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid,
					      __u8 type);
const char *nvme_plm_window_to_string(__u32 plm);
const char *nvme_ns_wp_cfg_to_string(enum nvme_ns_write_protect_cfg state);
const char *nvme_pls_mode_to_string(__u8 mode);
const char *nvme_bpwps_to_string(__u8 bpwps);
const char *nvme_power_measurement_action_to_string(__u8 act);

/* The events of the Asynchronous Event Configuration */
extern const char *feat_ae_dlpcn;
extern const char *feat_ae_hdlpcn;
extern const char *feat_ae_adlpcn;
extern const char *feat_ae_pmdrlpcn;
extern const char *feat_ae_zdcn;
extern const char *feat_ae_rlccn;
extern const char *feat_ae_lhcn;
extern const char *feat_ae_ccrcn;
extern const char *feat_ae_ansan;
extern const char *feat_ae_rgrp0;
extern const char *feat_ae_rassn;
extern const char *feat_ae_tthry;
extern const char *feat_ae_nnsshdn;
extern const char *feat_ae_ega;
extern const char *feat_ae_lbas;
extern const char *feat_ae_pla;
extern const char *feat_ae_ana;
extern const char *feat_ae_telem;
extern const char *feat_ae_fw;
extern const char *feat_ae_nan;
extern const char *feat_ae_smart;
