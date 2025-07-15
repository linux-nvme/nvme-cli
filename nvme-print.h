/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NVME_PRINT_H
#define NVME_PRINT_H

#include "nvme.h"
#include <inttypes.h>

#include <ccan/list/list.h>

typedef struct nvme_effects_log_node {
	struct nvme_cmd_effects_log effects; /* needs to be first member because of alignment requirement. */
	enum nvme_csi csi;
	struct list_node node;
} nvme_effects_log_node_t;

#define nvme_show_error(msg, ...) nvme_show_message(true, msg, ##__VA_ARGS__)
#define nvme_show_result(msg, ...) nvme_show_message(false, msg, ##__VA_ARGS__)

#define POWER_OF_TWO(exponent) (1 << (exponent))

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

struct print_ops {
	/* libnvme types.h print functions */
	void (*ana_log)(struct nvme_ana_log *ana_log, const char *devname, size_t len);
	void (*boot_part_log)(void *bp_log, const char *devname, __u32 size);
	void (*phy_rx_eom_log)(struct nvme_phy_rx_eom_log *log, __u16 controller);
	void (*ctrl_list)(struct nvme_ctrl_list *ctrl_list);
	void (*ctrl_registers)(void *bar, bool fabrics);
	void (*ctrl_register)(int offset, uint64_t value);
	void (*directive)(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result, void *buf, __u32 len);
	void (*discovery_log)(struct nvmf_discovery_log *log, int numrec);
	void (*effects_log_list)(struct list_head *list);
	void (*endurance_group_event_agg_log)(struct nvme_aggregate_endurance_group_event *endurance_log, __u64 log_entries, __u32 size, const char *devname);
	void (*endurance_group_list)(struct nvme_id_endurance_group_list *endgrp_list);
	void (*endurance_log)(struct nvme_endurance_group_log *endurance_group, __u16 group_id, const char *devname);
	void (*error_log)(struct nvme_error_log_page *err_log, int entries, const char *devname);
	void (*fdp_config_log)(struct nvme_fdp_config_log *log, size_t len);
	void (*fdp_event_log)(struct nvme_fdp_events_log *log);
	void (*fdp_ruh_status)(struct nvme_fdp_ruh_status *status, size_t len);
	void (*fdp_stats_log)(struct nvme_fdp_stats_log *log);
	void (*fdp_usage_log)(struct nvme_fdp_ruhu_log *log, size_t len);
	void (*fid_supported_effects_log)(struct nvme_fid_supported_effects_log *fid_log, const char *devname);
	void (*fw_log)(struct nvme_firmware_slot *fw_log, const char *devname);
	void (*id_ctrl)(struct nvme_id_ctrl *ctrl, void (*vs)(__u8 *vs, struct json_object *root));
	void (*id_ctrl_nvm)(struct nvme_id_ctrl_nvm *ctrl_nvm);
	void (*id_domain_list)(struct nvme_id_domain_list *id_dom);
	void (*id_independent_id_ns)(struct nvme_id_independent_id_ns *ns, unsigned int nsid);
	void (*id_iocs)(struct nvme_id_iocs *ioscs);
	void (*id_ns)(struct nvme_id_ns *ns, unsigned int nsid, unsigned int lba_index, bool cap_only);
	void (*id_ns_descs)(void *data, unsigned int nsid);
	void (*id_ns_granularity_list)(const struct nvme_id_ns_granularity_list *list);
	void (*id_nvmset_list)(struct nvme_id_nvmset_list *nvmset, unsigned int nvmeset_id);
	void (*id_uuid_list)(const struct nvme_id_uuid_list  *uuid_list);
	void (*lba_status)(struct nvme_lba_status *list, unsigned long len);
	void (*lba_status_log)(void *lba_status, __u32 size, const char *devname);
	void (*media_unit_stat_log)(struct nvme_media_unit_stat_log *mus);
	void (*mi_cmd_support_effects_log)(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log, const char *devname);
	void (*ns_list)(struct nvme_ns_list *ns_list);
	void (*ns_list_log)(struct nvme_ns_list *log, const char *devname, bool alloc);
	void (*nvm_id_ns)(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid, struct nvme_id_ns *ns, unsigned int lba_index, bool cap_only);
	void (*persistent_event_log)(void *pevent_log_info, __u8 action, __u32 size, const char *devname);
	void (*predictable_latency_event_agg_log)(struct nvme_aggregate_predictable_lat_event *pea_log, __u64 log_entries, __u32 size, const char *devname);
	void (*predictable_latency_per_nvmset)(struct nvme_nvmset_predictable_lat_log *plpns_log, __u16 nvmset_id, const char *devname);
	void (*primary_ctrl_cap)(const struct nvme_primary_ctrl_cap *caps);
	void (*relatives)(nvme_root_t r, const char *name);
	void (*resv_notification_log)(struct nvme_resv_notification_log *resv, const char *devname);
	void (*resv_report)(struct nvme_resv_status *status, int bytes, bool eds);
	void (*sanitize_log_page)(struct nvme_sanitize_log_page *sanitize_log, const char *devname);
	void (*secondary_ctrl_list)(const struct nvme_secondary_ctrl_list *sc_list, __u32 count);
	void (*select_result)(enum nvme_features_id fid, __u32 result);
	void (*self_test_log)(struct nvme_self_test_log *self_test, __u8 dst_entries, __u32 size, const char *devname);
	void (*single_property)(int offset, uint64_t value64);
	void (*smart_log)(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
	void (*supported_cap_config_list_log)(struct nvme_supported_cap_config_list_log *cap_log);
	void (*supported_log_pages)(struct nvme_supported_log_pages *support_log, const char *devname);
	void (*zns_start_zone_list)(__u64 nr_zones, struct json_object **zone_list);
	void (*zns_changed_zone_log)(struct nvme_zns_changed_zone_log *log);
	void (*zns_finish_zone_list)(__u64 nr_zones, struct json_object *zone_list);
	void (*zns_id_ctrl)(struct nvme_zns_id_ctrl *ctrl);
	void (*zns_id_ns)(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns);
	void (*zns_report_zones)(void *report, __u32 descs, __u8 ext_size, __u32 report_size, struct json_object *zone_list);
	void (*show_feature)(enum nvme_features_id fid, int sel, unsigned int result);
	void (*show_feature_fields)(enum nvme_features_id fid, unsigned int result, unsigned char *buf);
	void (*id_ctrl_rpmbs)(__le32 ctrl_rpmbs);
	void (*lba_range)(struct nvme_lba_range_type *lbrt, int nr_ranges);
	void (*lba_status_info)(__u32 result);
	void (*d)(unsigned char *buf, int len, int width, int group);
	void (*show_init)(void);
	void (*show_finish)(void);
	void (*mgmt_addr_list_log)(struct nvme_mgmt_addr_list_log *ma_log);
	void (*rotational_media_info_log)(struct nvme_rotational_media_info_log *info);
	void (*dispersed_ns_psub_log)(struct nvme_dispersed_ns_participating_nss_log *log);
	void (*reachability_groups_log)(struct nvme_reachability_groups_log *log, __u64 len);
	void (*reachability_associations_log)(struct nvme_reachability_associations_log *log,
					      __u64 len);
	void (*host_discovery_log)(struct nvme_host_discover_log *log);
	void (*ave_discovery_log)(struct nvme_ave_discover_log *log);
	void (*pull_model_ddc_req_log)(struct nvme_pull_model_ddc_req_log *log);
	void (*log)(const char *devname, struct nvme_get_log_args *args);

	/* libnvme tree print functions */
	void (*list_item)(nvme_ns_t n);
	void (*list_items)(nvme_root_t t);
	void (*print_nvme_subsystem_list)(nvme_root_t r, bool show_ana);
	void (*topology_ctrl)(nvme_root_t r);
	void (*topology_namespace)(nvme_root_t r);

	/* status and error messages */
	void (*connect_msg)(nvme_ctrl_t c);
	void (*show_message)(bool error, const char *msg, va_list ap);
	void (*show_perror)(const char *msg, va_list ap);
	void (*show_status)(int status);
	void (*show_error_status)(int status, const char *msg, va_list ap);
	void (*show_key_value)(const char *key, const char *val, va_list ap);

	nvme_print_flags_t flags;
};

struct nvme_bar_cap {
	__u16	mqes;
	__u8	cqr:1;
	__u8	ams:2;
	__u8	rsvd19:5;
	__u8	to;
	__u16	dstrd:4;
	__u16	nssrs:1;
	__u16	css:8;
	__u16	bps:1;
	__u8	cps:2;
	__u8	mpsmin:4;
	__u8	mpsmax:4;
	__u8	pmrs:1;
	__u8	cmbs:1;
	__u8	nsss:1;
	__u8	crwms:1;
	__u8	crims:1;
	__u8	nsses:1;
	__u8	rsvd62:2;
};

#ifdef CONFIG_JSONC

struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags);

#else /* !CONFIG_JSONC */

static inline struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags) { return NULL; }

#endif /* !CONFIG_JSONC */

struct print_ops *nvme_get_stdout_print_ops(nvme_print_flags_t flags);
struct print_ops *nvme_get_binary_print_ops(nvme_print_flags_t flags);

void nvme_show_status(int status);
void nvme_show_lba_status_info(__u32 result);
void nvme_show_relatives(nvme_root_t r, const char *name, nvme_print_flags_t flags);

void nvme_show_id_iocs(struct nvme_id_iocs *iocs, nvme_print_flags_t flags);
void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, nvme_print_flags_t flags,
	void (*vendor_show)(__u8 *vs, struct json_object *root));
void nvme_show_id_ctrl_rpmbs(__le32 ctrl_rpmbs, nvme_print_flags_t flags);
void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		unsigned int lba_index, bool cap_only, nvme_print_flags_t flags);
void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	nvme_print_flags_t flags);
void nvme_show_resv_report(struct nvme_resv_status *status, int bytes, bool eds,
	nvme_print_flags_t flags);
void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges,
	nvme_print_flags_t flags);
void nvme_show_supported_log(struct nvme_supported_log_pages *support,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname,
			 nvme_print_flags_t flags);
void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		       size_t len, nvme_print_flags_t flags);
void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
	__u32 size, const char *devname, nvme_print_flags_t flags);
void nvme_show_fw_log(struct nvme_firmware_slot *fw_log, const char *devname,
	nvme_print_flags_t flags);
void nvme_print_effects_log_pages(struct list_head *list,
				  nvme_print_flags_t flags);
void nvme_show_changed_ns_list_log(struct nvme_ns_list *log, const char *devname,
				   nvme_print_flags_t flags, bool alloc);
void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
	__u16 group_id, const char *devname, nvme_print_flags_t flags);
void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname, nvme_print_flags_t flags);
void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_endurance_group_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_resv_notif_log(struct nvme_resv_notification_log *resv,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, nvme_print_flags_t flags);
void nvme_show_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log,
	__u16 controller, nvme_print_flags_t flags);
void nvme_show_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus,
	nvme_print_flags_t flags);
void nvme_show_supported_cap_config_log(struct nvme_supported_cap_config_list_log *caplog,
				nvme_print_flags_t flags);
void nvme_show_ctrl_registers(void *bar, bool fabrics, nvme_print_flags_t flags);
void nvme_show_ctrl_register(void *bar, bool fabrics, int offset, nvme_print_flags_t flags);
void nvme_show_single_property(int offset, uint64_t prop, nvme_print_flags_t flags);
void nvme_show_id_ns_descs(void *data, unsigned int nsid, nvme_print_flags_t flags);
void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
	nvme_print_flags_t flags);
void nvme_show_list_items(nvme_root_t t, nvme_print_flags_t flags);
void nvme_show_subsystem_list(nvme_root_t t, bool show_ana,
			      nvme_print_flags_t flags);
void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id,
	nvme_print_flags_t flags);
void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *cap,
	nvme_print_flags_t flags);
void nvme_show_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, nvme_print_flags_t flags);
void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	nvme_print_flags_t flags);
void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
	nvme_print_flags_t flags);
void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	 nvme_print_flags_t flags);
void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	nvme_print_flags_t flags);
void nvme_show_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list,
	nvme_print_flags_t flags);
void nvme_show_list_ns(struct nvme_ns_list *ns_list,
	nvme_print_flags_t flags);
void nvme_show_topology(nvme_root_t t,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags);

void nvme_feature_show(enum nvme_features_id fid, int sel, unsigned int result);
void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result, unsigned char *buf);
void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len, nvme_print_flags_t flags);
void nvme_show_select_result(enum nvme_features_id fid, __u32 result);

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl,
			   nvme_print_flags_t flags);
void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	nvme_print_flags_t flags);
void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
						struct nvme_id_ns *ns, unsigned int lba_index,
						bool cap_only, nvme_print_flags_t flags);
void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
			 struct nvme_id_ns *id_ns, nvme_print_flags_t flags);
void nvme_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list,
			      nvme_print_flags_t flags);
void nvme_show_zns_changed(struct nvme_zns_changed_zone_log *log,
			   nvme_print_flags_t flags);
void nvme_zns_finish_zone_list(__u64 nr_zones, struct json_object *zone_list,
			       nvme_print_flags_t flags);
void nvme_show_zns_report_zones(void *report, __u32 descs,
				__u8 ext_size, __u32 report_size,
				struct json_object *zone_list,
				nvme_print_flags_t flags);
void json_nvme_finish_zone_list(__u64 nr_zones, 
	struct json_object *zone_list);
void nvme_show_list_item(nvme_ns_t n);

void nvme_show_fdp_configs(struct nvme_fdp_config_log *configs, size_t len,
		nvme_print_flags_t flags);
void nvme_show_fdp_stats(struct nvme_fdp_stats_log *log,
		nvme_print_flags_t flags);
void nvme_show_fdp_events(struct nvme_fdp_events_log *log,
		nvme_print_flags_t flags);
void nvme_show_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		nvme_print_flags_t flags);
void nvme_show_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
		nvme_print_flags_t flags);

void nvme_show_discovery_log(struct nvmf_discovery_log *log, uint64_t numrec,
			     nvme_print_flags_t flags);
void nvme_show_connect_msg(nvme_ctrl_t c, nvme_print_flags_t flags);

const char *nvme_ana_state_to_string(enum nvme_ana_state state);
const char *nvme_cmd_to_string(int admin, __u8 opcode);
const char *nvme_fdp_event_to_string(enum nvme_fdp_event_type event);
const char *nvme_feature_lba_type_to_string(__u8 type);
const char *nvme_feature_temp_sel_to_string(__u8 sel);
const char *nvme_feature_temp_type_to_string(__u8 type);
const char *nvme_feature_to_string(enum nvme_features_id feature);
const char *nvme_feature_wl_hints_to_string(__u8 wh);
const char *nvme_feature_perfc_attri_to_string(__u8 attri);
const char *nvme_feature_perfc_r4karl_to_string(__u8 r4karl);
const char *nvme_feature_perfc_attrtyp_to_string(__u8 attrtyp);
const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid, __u8 type);
const char *nvme_log_to_string(__u8 lid);
const char *nvme_nss_hw_error_to_string(__u16 error_code);
const char *nvme_pel_event_to_string(int type);
const char *nvme_register_pmr_hsts_to_string(__u8 hsts);
const char *nvme_register_unit_to_string(__u8 unit);
const char *nvme_register_szu_to_string(__u8 szu);
const char *nvme_register_to_string(int reg);
const char *nvme_register_symbol_to_string(int offset);
const char *nvme_resv_notif_to_string(__u8 type);
const char *nvme_select_to_string(int sel);
const char *nvme_sstat_status_to_string(__u16 status);
const char *nvme_trtype_to_string(__u8 trtype);
const char *nvme_zone_state_to_string(__u8 state);
const char *nvme_zone_type_to_string(__u8 cond);
const char *nvme_plm_window_to_string(__u32 plm);
const char *nvme_ns_wp_cfg_to_string(enum nvme_ns_write_protect_cfg state);
const char *nvme_pel_rci_rcpit_to_string(enum nvme_pel_rci_rcpit rcpit);
const char *nvme_pel_ehai_pit_to_string(enum nvme_pel_ehai_pit pit);
const char *nvme_ssi_state_to_string(__u8 state);
const char *nvme_time_scale_to_string(__u8 ts);
const char *nvme_pls_mode_to_string(__u8 mode);
const char *nvme_bpwps_to_string(__u8 bpwps);

void nvme_dev_full_path(nvme_ns_t n, char *path, size_t len);
void nvme_generic_full_path(nvme_ns_t n, char *path, size_t len);
void nvme_show_message(bool error, const char *msg, ...);
void nvme_show_perror(const char *msg, ...);
void nvme_show_error_status(int status, const char *msg, ...);
void nvme_show_init(void);
void nvme_show_finish(void);
void nvme_show_key_value(const char *key, const char *value, ...);
bool nvme_is_fabrics_reg(int offset);
bool nvme_is_fabrics_optional_reg(int offset);
bool nvme_registers_cmbloc_support(__u32 cmbsz);
bool nvme_registers_pmrctl_ready(__u32 pmrctl);
const char *nvme_degrees_string(long t);
void print_array(char *name, __u8 *data, int size);
void json_print(struct json_object *r);
struct json_object *obj_create_array_obj(struct json_object *o, const char *k);
void nvme_show_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list,
				  nvme_print_flags_t flags);
void nvme_show_rotational_media_info_log(struct nvme_rotational_media_info_log *info,
					 nvme_print_flags_t flags);
void nvme_show_dispersed_ns_psub_log(struct nvme_dispersed_ns_participating_nss_log *log,
				     nvme_print_flags_t flags);
void nvme_show_reachability_groups_log(struct nvme_reachability_groups_log *log,
				       __u64 len, nvme_print_flags_t flags);
void nvme_show_reachability_associations_log(struct nvme_reachability_associations_log *log,
					     __u64 len, nvme_print_flags_t flags);
void nvme_show_host_discovery_log(struct nvme_host_discover_log *log, nvme_print_flags_t flags);
void nvme_show_ave_discovery_log(struct nvme_ave_discover_log *log, nvme_print_flags_t flags);
void nvme_show_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log,
				      nvme_print_flags_t flags);
void nvme_show_log(const char *devname, struct nvme_get_log_args *args, nvme_print_flags_t flags);

extern char *alloc_error;
#endif /* NVME_PRINT_H */
