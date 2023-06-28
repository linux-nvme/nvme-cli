/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "nvme-print.h"

static struct print_ops binary_print_ops;

static void binary_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname)
{
	d_raw((unsigned char *)plpns_log, sizeof(*plpns_log));
}

static void binary_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname)
{
	d_raw((unsigned char *)pea_log, size);
}

static void binary_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname)
{
	d_raw((unsigned char *)pevent_log_info, size);
}

static void binary_endurance_group_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname)
{
	d_raw((unsigned char *)endurance_log, size);
}

static void binary_lba_status_log(void *lba_status, __u32 size,
	const char *devname)
{
	d_raw((unsigned char *)lba_status, size);
}

static void binary_resv_notif_log(struct nvme_resv_notification_log *resv,
	const char *devname)
{
	 d_raw((unsigned char *)resv, sizeof(*resv));
}

static void binary_fid_support_effects_log(
	struct nvme_fid_supported_effects_log *fid_log,
	const char *devname)
{
	d_raw((unsigned char *)fid_log, sizeof(*fid_log));
}

static void binary_mi_cmd_support_effects_log(
	struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname)
{
	 d_raw((unsigned char *)mi_cmd_log, sizeof(*mi_cmd_log));
}

static void binary_boot_part_log(void *bp_log, const char *devname,
	__u32 size)
{
	d_raw((unsigned char *)bp_log, size);
}

static void binary_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log)
{
	 d_raw((unsigned char *)mus_log, sizeof(*mus_log));
}

static void binary_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	 d_raw((unsigned char *)log, len);
}

static void binary_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{

	d_raw((unsigned char *)log, len);
}

static void binary_fdp_stats(struct nvme_fdp_stats_log *log)
{
	d_raw((unsigned char*)log, sizeof(*log));
}

static void binary_fdp_events(struct nvme_fdp_events_log *log)
{
	d_raw((unsigned char*)log, sizeof(*log));
}

static void binary_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
{
	d_raw((unsigned char *)status, len);
}

static void binary_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap)
{
	d_raw((unsigned char *)cap, sizeof(*cap));
}

static void binary_ctrl_registers(void *bar, bool fabrics)
{
	const unsigned int reg_size = 0x0e1c;  /* 0x0000 to 0x0e1b */

	d_raw((unsigned char *)bar, reg_size);
}

static void binary_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
	unsigned int lba_index, bool cap_only)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}


static void binary_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}

static void binary_id_ns_descs(void *data, unsigned nsid)
{
	d_raw((unsigned char *)data, 0x1000);
}

static void binary_id_ctrl(struct nvme_id_ctrl *ctrl,
	void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	d_raw((unsigned char *)ctrl, sizeof(*ctrl));
}

static void binary_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	d_raw((unsigned char *)ctrl_nvm, sizeof(*ctrl_nvm));
}

static void binary_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
	struct nvme_id_ns *ns, unsigned int lba_index,
	bool cap_only)
{
	d_raw((unsigned char *)nvm_ns, sizeof(*nvm_ns));
}

static void binary_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	d_raw((unsigned char *)ctrl, sizeof(*ctrl));
}

static void binary_zns_id_ns(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}

static void binary_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	d_raw((unsigned char *)log, sizeof(*log));
}

static void binary_zns_report_zones(void *report, __u32 descs,
	__u8 ext_size, __u32 report_size,
	struct json_object *zone_list)
{
	d_raw((unsigned char *)report, report_size);
}

static void binary_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	d_raw((unsigned char *)ctrl_list, sizeof(*ctrl_list));
}

static void binary_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id)
{
	d_raw((unsigned char *)nvmset, sizeof(*nvmset));
}

static void binary_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	d_raw((unsigned char *)caps, sizeof(*caps));
}

static void binary_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count)
{
	d_raw((unsigned char *)sc_list, sizeof(*sc_list));
}

static void binary_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist)
{
	d_raw((unsigned char *)glist, sizeof(*glist));
}

static void binary_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	d_raw((unsigned char *)uuid_list, sizeof(*uuid_list));
}

static void binary_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	d_raw((unsigned char *)id_dom, sizeof(*id_dom));
}

static void binary_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname)
{
	d_raw((unsigned char *)err_log, entries * sizeof(*err_log));
}

static void binary_resv_report(struct nvme_resv_status *status, int bytes,
	bool eds)
{
	d_raw((unsigned char *)status, bytes);
}

static void binary_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname)
{
	d_raw((unsigned char *)fw_log, sizeof(*fw_log));
}

static void binary_changed_ns_list_log(struct nvme_ns_list *log,
				   const char *devname)
{
	d_raw((unsigned char *)log, sizeof(*log));
}


static void binary_supported_log(struct nvme_supported_log_pages *support_log,
	const char *devname)
{
	d_raw((unsigned char *)support_log, sizeof(*support_log));
}

static void binary_endurance_log(struct nvme_endurance_group_log *endurance_log,
	__u16 group_id, const char *devname)
{
	return d_raw((unsigned char *)endurance_log, sizeof(*endurance_log));
}

static void binary_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
	 const char *devname)
{
	d_raw((unsigned char *)smart, sizeof(*smart));
}

static void binary_ana_log(struct nvme_ana_log *ana_log, const char *devname,
       size_t len)
{
	d_raw((unsigned char *)ana_log, len);
}

static void binary_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
				__u32 size, const char *devname)
{
	d_raw((unsigned char *)self_test, size);
}

static void binary_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname)
{
	d_raw((unsigned char *)sanitize, sizeof(*sanitize));
}

static void binary_directive(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len)
{
	if (!buf)
		return;

	d_raw(buf, len);
}

static void binary_lba_status(struct nvme_lba_status *list, unsigned long len)
{
	d_raw((unsigned char *)list, len);
}

static void binary_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	d_raw((unsigned char *)log,
	      sizeof(struct nvmf_discovery_log) +
	      numrec * sizeof(struct nvmf_disc_log_entry));
}

static struct print_ops binary_print_ops = {
	.ana_log			= binary_ana_log,
	.boot_part_log			= binary_boot_part_log,
	.ctrl_list			= binary_list_ctrl,
	.ctrl_registers			= binary_ctrl_registers,
	.directive			= binary_directive,
	.discovery_log			= binary_discovery_log,
	.endurance_group_event_agg_log	= binary_endurance_group_event_agg_log,
	.endurance_log			= binary_endurance_log,
	.error_log			= binary_error_log,
	.fdp_config_log			= binary_fdp_configs,
	.fdp_event_log			= binary_fdp_events,
	.fdp_ruh_status			= binary_fdp_ruh_status,
	.fdp_stats_log			= binary_fdp_stats,
	.fdp_usage_log			= binary_fdp_usage,
	.fid_supported_effects_log	= binary_fid_support_effects_log,
	.fw_log				= binary_fw_log,
	.id_ctrl			= binary_id_ctrl,
	.id_ctrl_nvm			= binary_id_ctrl_nvm,
	.id_domain_list			= binary_id_domain_list,
	.id_independent_id_ns		= binary_cmd_set_independent_id_ns,
	.id_ns				= binary_id_ns,
	.id_ns_descs			= binary_id_ns_descs,
	.id_ns_granularity_list		= binary_id_ns_granularity_list,
	.id_nvmset_list			= binary_id_nvmset,
	.id_uuid_list			= binary_id_uuid_list,
	.lba_status			= binary_lba_status,
	.lba_status_log			= binary_lba_status_log,
	.media_unit_stat_log		= binary_media_unit_stat_log,
	.mi_cmd_support_effects_log	= binary_mi_cmd_support_effects_log,
	.ns_list_log			= binary_changed_ns_list_log,
	.nvm_id_ns			= binary_nvm_id_ns,
	.persistent_event_log		= binary_persistent_event_log,
	.predictable_latency_event_agg_log = binary_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset	= binary_predictable_latency_per_nvmset,
	.primary_ctrl_cap		= binary_primary_ctrl_cap,
	.resv_notification_log		= binary_resv_notif_log,
	.resv_report			= binary_resv_report,
	.sanitize_log_page		= binary_sanitize_log,
	.secondary_ctrl_list		= binary_list_secondary_ctrl,
	.self_test_log 			= binary_self_test_log,
	.smart_log			= binary_smart_log,
	.supported_cap_config_list_log	= binary_supported_cap_config_log,
	.supported_log_pages		= binary_supported_log,
	.zns_changed_zone_log		= binary_zns_changed,
	.zns_id_ctrl			= binary_zns_id_ctrl,
	.zns_id_ns			= binary_zns_id_ns,
	.zns_report_zones		= binary_zns_report_zones,
};

struct print_ops *nvme_get_binary_print_ops(enum nvme_print_flags flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
