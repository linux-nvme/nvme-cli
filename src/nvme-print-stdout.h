/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

extern struct print_ops stdout_print_ops;
extern const char dash[100];

void stdout_bits_add_str(struct shr_table *t, const char *bits,
		const char *value, const char *desc_fmt, ...);
char *stdout_power_and_scale_str(__u16 power, __u8 scale);
struct shr_table *stdout_kv_table_create(void);
int stdout_kv_add(struct shr_table *t, const char *name,
		const char *fmt, ...);
void stdout_kv_table_finish(struct shr_table *t, const char *what);
struct shr_table *stdout_bits_table_create(void);
void stdout_bits_add(struct shr_table *t, const char *bits,
		unsigned int val, const char *desc_fmt, ...);
const char *stdout_format_timestamp(__u8 *timestamp_bytes);
void stdout_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				unsigned char *buf);
void stdout_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
	void (*vendor_show)(__u8 *vs, struct json_object *root));
void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm);
void stdout_id_domain_list(struct nvme_id_domain_list *id_dom);
void stdout_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
				      unsigned int nsid);
void stdout_id_iocs(struct nvme_id_iocs *iocs);
void stdout_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		  unsigned int lba_index, bool cap_only);
void stdout_id_ns_descs(void *data, unsigned int nsid);
void stdout_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist);
void stdout_id_nvmset(struct nvme_id_nvmset_list *nvmset,
		      unsigned int nvmset_id);
void stdout_id_uuid_list(const struct nvme_id_uuid_list *uuid_list);
void stdout_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
		      struct nvme_id_ns *ns, unsigned int lba_index,
		      bool cap_only);
void stdout_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl);
void stdout_zns_id_ns(struct nvme_zns_id_ns *ns,
		      struct nvme_id_ns *id_ns);
void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs);
void stdout_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		    size_t len);
void stdout_boot_part_log(void *bp_log, const char *devname, __u32 size);
void stdout_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller,
			   size_t len);
void stdout_effects_log_pages(struct list_head *list);
void stdout_endurance_group_event_agg_log(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname);
void stdout_endurance_log(struct nvme_endurance_group_log *el, __u16 group_id,
			  const char *devname);
void stdout_error_log(struct nvme_error_log_page *err_log, int entries,
		      const char *devname, struct nvme_error_log_filter *flt);
void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len);
void stdout_fdp_events(struct nvme_fdp_events_log *log);
void stdout_fdp_stats(struct nvme_fdp_stats_log *log);
void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len);
void stdout_fid_support_effects_log(
	struct nvme_fid_supported_effects_log *fid_log, const char *devname);
void stdout_fw_log(struct nvme_firmware_slot *fw_log, const char *devname);
void stdout_lba_status_log(void *lba_status, __u32 size, const char *devname);
void stdout_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log);
void stdout_mi_cmd_support_effects_log(
	struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname);
void stdout_changed_ns_list_log(struct nvme_ns_list *log, const char *devname,
				bool alloc);
void stdout_persistent_event_log(void *pevent_log_info, __u8 action, __u32 size,
				 const char *devname);
void stdout_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname);
void stdout_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname);
void stdout_resv_notif_log(struct nvme_resv_notification_log *resv,
			   const char *devname);
void stdout_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			 const char *devname);
void stdout_self_test_log(struct nvme_self_test_log *self_test,
			  __u8 dst_entries, __u32 size, const char *devname);
void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
		      const char *devname);
void stdout_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap, size_t len);
void stdout_supported_log(struct nvme_supported_log_pages *support_log,
			  const char *devname);
void stdout_zns_changed(struct nvme_zns_changed_zone_log *log);
void stdout_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list);
void stdout_rotational_media_info_log(
	struct nvme_rotational_media_info_log *info);
void stdout_dispersed_ns_psub_log(
	struct nvme_dispersed_ns_participating_nss_log *log);
void stdout_reachability_groups_log(struct nvme_reachability_groups_log *log,
				    __u64 len);
void stdout_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len);
void stdout_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log);
void stdout_power_meas_log(struct nvme_power_meas_log *log, __u32 size);
#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec);
void stdout_host_discovery_log(struct nvme_host_discovery_log *log);
void stdout_ave_discovery_log(struct nvme_ave_discovery_log *log);
#else /* CONFIG_FABRICS */
#define stdout_discovery_log NULL
#define stdout_host_discovery_log NULL
#define stdout_ave_discovery_log NULL
#endif /* CONFIG_FABRICS */
