/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NVME_PRINT_H
#define NVME_PRINT_H

#include "nvme.h"
#include <inttypes.h>

#include <ccan/list/list.h>

typedef struct nvme_effects_log_node {
	enum nvme_csi csi;
	struct nvme_cmd_effects_log effects;
	struct list_node node;
} nvme_effects_log_node_t;

#define nvme_show_error(msg, ...) nvme_show_message(true, msg, ##__VA_ARGS__)
#define nvme_show_result(msg, ...) nvme_show_message(false, msg, ##__VA_ARGS__)

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

void nvme_show_status(int status);
void nvme_show_lba_status_info(__u32 result);
void nvme_show_relatives(const char *name);

void nvme_show_id_iocs(struct nvme_id_iocs *iocs);
void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, enum nvme_print_flags flags,
	void (*vendor_show)(__u8 *vs, struct json_object *root));
void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		unsigned int lba_index, bool cap_only, enum nvme_print_flags flags);
void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	enum nvme_print_flags flags);
void nvme_show_resv_report(struct nvme_resv_status *status, int bytes, bool eds,
	enum nvme_print_flags flags);
void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges);
void nvme_show_supported_log(struct nvme_supported_log_pages *support,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
	enum nvme_print_flags flags, size_t len);
void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
	__u32 size, const char *devname, enum nvme_print_flags flags);
void nvme_show_fw_log(struct nvme_firmware_slot *fw_log, const char *devname,
	enum nvme_print_flags flags);
void nvme_print_effects_log_pages(struct list_head *list, int flags);
void nvme_show_changed_ns_list_log(struct nvme_ns_list *log,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
	__u16 group_id, const char *devname, enum nvme_print_flags flags);
void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname, enum nvme_print_flags flags);
void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_resv_notif_log(struct nvme_resv_notification_log *resv,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, enum nvme_print_flags flags);
void nvme_show_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus,
	enum nvme_print_flags flags);
void nvme_show_supported_cap_config_log(struct nvme_supported_cap_config_list_log *caplog,
				enum nvme_print_flags flags);
void nvme_show_ctrl_registers(void *bar, bool fabrics, enum nvme_print_flags flags);
void nvme_show_single_property(int offset, uint64_t prop, int human);
void nvme_show_id_ns_descs(void *data, unsigned nsid, enum nvme_print_flags flags);
void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
	enum nvme_print_flags flags);
void nvme_show_list_items(nvme_root_t t, enum nvme_print_flags flags);
void nvme_show_subsystem_list(nvme_root_t t, bool show_ana,
			      enum nvme_print_flags flags);
void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id,
	enum nvme_print_flags flags);
void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *cap,
	enum nvme_print_flags flags);
void nvme_show_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, enum nvme_print_flags flags);
void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	enum nvme_print_flags flags);
void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
	enum nvme_print_flags flags);
void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	 enum nvme_print_flags flags);
void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	enum nvme_print_flags flags);
void nvme_show_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list,
	enum nvme_print_flags flags);
void nvme_show_list_ns(struct nvme_ns_list *ns_list,
	enum nvme_print_flags flags);
void nvme_show_topology(nvme_root_t t, enum nvme_print_flags flags,
			enum nvme_cli_topo_ranking ranking);

void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result, unsigned char *buf);
void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len, enum nvme_print_flags flags);
void nvme_show_select_result(__u32 result);

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl, unsigned int mode);
void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	enum nvme_print_flags flags);
void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
						struct nvme_id_ns *ns, unsigned int lba_index,
						bool cap_only, enum nvme_print_flags flags);
void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
	struct nvme_id_ns *id_ns, unsigned long flags);
void nvme_show_zns_changed( struct nvme_zns_changed_zone_log *log,
	unsigned long flags);
void nvme_show_zns_report_zones(void *report, __u32 descs,
	__u8 ext_size, __u32 report_size, unsigned long flags,
	struct json_object *zone_list);
void json_nvme_finish_zone_list(__u64 nr_zones, 
	struct json_object *zone_list);
void nvme_show_list_item(nvme_ns_t n);

void nvme_show_fdp_configs(struct nvme_fdp_config_log *configs, size_t len,
		enum nvme_print_flags flags);
void nvme_show_fdp_stats(struct nvme_fdp_stats_log *log,
		enum nvme_print_flags flags);
void nvme_show_fdp_events(struct nvme_fdp_events_log *log,
		enum nvme_print_flags flags);
void nvme_show_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		enum nvme_print_flags flags);
void nvme_show_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
		enum nvme_print_flags flags);

const char *nvme_ana_state_to_string(enum nvme_ana_state state);
const char *nvme_cmd_to_string(int admin, __u8 opcode);
const char *nvme_fdp_event_to_string(enum nvme_fdp_event_type event);
const char *nvme_feature_lba_type_to_string(__u8 type);
const char *nvme_feature_temp_sel_to_string(__u8 sel);
const char *nvme_feature_temp_type_to_string(__u8 type);
const char *nvme_feature_to_string(enum nvme_features_id feature);
const char *nvme_feature_wl_hints_to_string(__u8 wh);
const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid, __u8 type);
const char *nvme_log_to_string(__u8 lid);
const char *nvme_nss_hw_error_to_string(__u16 error_code);
const char *nvme_pel_event_to_string(int type);
const char *nvme_register_pmr_hsts_to_string(__u8 hsts);
const char *nvme_register_pmr_pmrszu_to_string(__u8 pmrszu);
const char *nvme_register_szu_to_string(__u8 szu);
const char *nvme_register_to_string(int reg);
const char *nvme_resv_notif_to_string(__u8 type);
const char *nvme_select_to_string(int sel);
const char *nvme_sstat_status_to_string(__u16 status);
const char *nvme_trtype_to_string(__u8 trtype);
const char *nvme_zone_state_to_string(__u8 state);
const char *nvme_zone_type_to_string(__u8 cond);
const char *nvme_plm_window_to_string(__u32 plm);
const char *nvme_ns_wp_cfg_to_string(enum nvme_ns_write_protect_cfg state);

void nvme_dev_full_path(nvme_ns_t n, char *path, size_t len);
void nvme_generic_full_path(nvme_ns_t n, char *path, size_t len);
void nvme_show_message(bool error, const char *msg, ...);
void nvme_show_perror(const char *msg);

#endif
