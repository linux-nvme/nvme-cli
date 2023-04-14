#ifndef NVME_PRINT_JSON_H_
#define NVME_PRINT_JSON_H_

#include "nvme-print.h"

#ifdef CONFIG_JSONC

void json_simple_topology(nvme_root_t r);
void json_print_list_items(nvme_root_t r,
			   enum nvme_print_flags flags);
void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log,
                       const char *devname);

void json_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries);
void json_ana_log(struct nvme_ana_log *ana_log, const char *devname);
void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
                    enum nvme_print_flags flags);
void json_support_log(struct nvme_supported_log_pages *support_log);
void json_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id);
void json_effects_log_list(struct list_head *list);
void json_changed_ns_list_log(struct nvme_ns_list *log,
			      const char *devname);
void json_fw_log(struct nvme_firmware_slot *fw_log, const char *devname);
void json_error_log(struct nvme_error_log_page *err_log, int entries);
void json_nvme_resv_report(struct nvme_resv_status *status,
			   int bytes, bool eds);
void json_nvme_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list);
void json_id_domain_list(struct nvme_id_domain_list *id_dom);
void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list);
void json_nvme_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist);
void json_nvme_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
					  __u32 count);
void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps);
void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset);
void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list, __u16 num);
void json_nvme_zns_report_zones(void *report, __u32 descs,
				__u8 ext_size, __u32 report_size,
				struct json_object *zone_list);
void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list, __u16 num);
void json_nvme_list_ns(struct nvme_ns_list *ns_list);
void json_nvme_zns_id_ns(struct nvme_zns_id_ns *ns,
			 struct nvme_id_ns *id_ns);
void json_nvme_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl);
void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
			 struct nvme_id_ns *ns, bool cap_only);
void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm);
void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			void (*vs)(__u8 *vs, struct json_object *root));
void json_nvme_id_ns_descs(void *data);
void json_nvme_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns);
void json_ctrl_registers(void *bar);
void json_nvme_id_ns(struct nvme_id_ns *ns, bool cap_only);
void json_print_nvme_subsystem_list(nvme_root_t r, bool show_ana);
void json_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap_log);
void json_nvme_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len);
void json_nvme_fdp_events(struct nvme_fdp_events_log *log);
void json_nvme_fdp_stats(struct nvme_fdp_stats_log *log);
void json_nvme_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len);
void json_nvme_fdp_configs(struct nvme_fdp_config_log *log, size_t len);
void json_media_unit_stat_log(struct nvme_media_unit_stat_log *mus);
void json_boot_part_log(void *bp_log);
void json_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log);
void json_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log);
void json_resv_notif_log(struct nvme_resv_notification_log *resv);
void json_endurance_group_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *endurance_log,
	__u64 log_entries);
void json_lba_status_log(void *lba_status);
void add_bitmap(int i, __u8 seb, struct json_object *root, int json_flag);
void json_persistent_event_log(void *pevent_log_info, __u32 size);
void json_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries);
void json_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id);
void json_output_status(int status);
void json_output_error(const char *msg, va_list ap);

/* fabrics.c */
void json_discovery_log(struct nvmf_discovery_log *log, int numrec);
void json_connect_msg(nvme_ctrl_t c);

#else /* !CONFIG_JSONC */

#define json_simple_topology(r)
#define json_print_list_items(r, flags)
#define json_sanitize_log(sanitize_log, devname)
#define json_self_test_log(self_test, dst_entries)
#define json_ana_log(ana_log, devname)
#define json_smart_log(smart, nsid, flags)
#define json_support_log(support_log)
#define json_endurance_log(endurance_group, group_id)
#define json_effects_log_list(list)
#define json_changed_ns_list_log(log, devname)
#define json_fw_log(fw_log, devname)
#define json_error_log(err_log, entries)
#define json_nvme_resv_report(status, bytes, eds)
#define json_nvme_endurance_group_list(endgrp_list)
#define json_id_domain_list(id_dom)
#define json_nvme_id_uuid_list(uuid_list)
#define json_nvme_id_ns_granularity_list(glist)
#define json_nvme_list_secondary_ctrl(sc_list, count)
#define json_nvme_primary_ctrl_cap(caps)
#define json_nvme_id_nvmset(nvmset)
#define json_nvme_list_ctrl(ctrl_list, num)
#define json_nvme_zns_report_zones(report, descs, ext_size, report_size, zone_list)
#define json_nvme_list_ctrl(ctrl_list, num)
#define json_nvme_list_ns(ns_list)
#define json_nvme_zns_id_ns(ns, id_ns)
#define json_nvme_zns_id_ctrl(ctrl)
#define json_nvme_nvm_id_ns(nvm_ns, ns, cap_only)
#define json_nvme_id_ctrl_nvm(ctrl_nvm)
#define json_nvme_id_ctrl(ctrl, vs)
#define json_nvme_id_ns_descs(data)
#define json_nvme_cmd_set_independent_id_ns(ns)
#define json_ctrl_registers(bar)
#define json_nvme_id_ns(ns, cap_only)
#define json_print_nvme_subsystem_list(r, show_ana)
#define json_supported_cap_config_log(cap_log)
#define json_nvme_fdp_ruh_status(status, len)
#define json_nvme_fdp_events(log)
#define json_nvme_fdp_stats(log)
#define json_nvme_fdp_usage(log, len)
#define json_nvme_fdp_configs(log, len)
#define json_media_unit_stat_log(mus)
#define json_boot_part_log(bp_log)
#define json_mi_cmd_support_effects_log(mi_cmd_log)
#define json_fid_support_effects_log(fid_log)
#define json_resv_notif_log(resv)
#define json_endurance_group_event_agg_log(endurance_log, log_entries)
#define json_lba_status_log(lba_status)
#define add_bitmap(i, seb, root, json_flag)
#define json_persistent_event_log(pevent_log_info, size)
#define json_predictable_latency_event_agg_log(pea_log, log_entries)
#define json_predictable_latency_per_nvmset(plpns_log, nvmset_id)
#define json_output_status(status)
#define json_output_error(const char *msg, va_list ap)

/* fabrics.c */
#define json_discovery_log(log, numrec)
#define json_connect_msg(c)

#endif /* !CONFIG_JSONC */

#endif // NVME_PRINT_JSON_H_
