// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "log-print.h"
#include "nvme-print.h"

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
	struct nvme_aggregate_endurance_group_event *endurance_log,
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

static void binary_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log,
				  __u16 controller, size_t len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log,
		size_t len)
{
	d_raw((unsigned char *)mus_log, len);
}

static void binary_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap, size_t len)
{
	d_raw((unsigned char *)cap, len);
}

static void binary_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname, struct nvme_error_log_filter *flt)
{
	d_raw((unsigned char *)err_log, entries * sizeof(*err_log));
}

static void binary_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname)
{
	d_raw((unsigned char *)fw_log, sizeof(*fw_log));
}

static void binary_changed_ns_list_log(struct nvme_ns_list *log,
				       const char *devname, bool alloc)
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

static void binary_self_test_log(struct nvme_self_test_log *self_test,
				 __u8 dst_entries, __u32 size,
				 const char *devname)
{
	d_raw((unsigned char *)self_test, size);
}

static void binary_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname)
{
	d_raw((unsigned char *)sanitize, sizeof(*sanitize));
}

static void binary_effects_log_pages(struct list_head *list)
{
	nvme_effects_log_node_t *node = NULL;

	list_for_each(list, node, node) {
		d_raw((unsigned char *)&node->csi, sizeof(node->csi));
		d_raw((unsigned char *)&node->effects, sizeof(node->effects));
	}
}

static void binary_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
{
	d_raw((unsigned char *)ma_list, sizeof(*ma_list));
}

static void
binary_rotational_media_info_log(struct nvme_rotational_media_info_log *info)
{
	d_raw((unsigned char *)info, sizeof(*info));
}

static void binary_dispersed_ns_psub_log(
		struct nvme_dispersed_ns_participating_nss_log *log, __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void
binary_reachability_groups_log(struct nvme_reachability_groups_log *log,
			       __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_host_discovery_log(struct nvme_host_discovery_log *log,
				      __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_ave_discovery_log(struct nvme_ave_discovery_log *log,
				     __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_pull_model_ddc_req_log(
		struct nvme_pull_model_ddc_req_log *log, __u64 len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_power_meas_log(struct nvme_power_meas_log *log, __u32 size)
{
	d_raw((unsigned char *)log, size);
}

static void binary_voltage_meas_log(struct nvme_voltage_measurement_log *log,
				    __u32 size)
{
	d_raw((unsigned char *)log, size);
}

static struct log_print_ops binary_log_print_ops = {
	.ana_log = binary_ana_log,
	.boot_part_log = binary_boot_part_log,
	.phy_rx_eom_log = binary_phy_rx_eom_log,
	.effects_log_list = binary_effects_log_pages,
	.endurance_group_event_agg_log = binary_endurance_group_event_agg_log,
	.endurance_log = binary_endurance_log,
	.error_log = binary_error_log,
	.fid_supported_effects_log = binary_fid_support_effects_log,
	.fw_log = binary_fw_log,
	.lba_status_log = binary_lba_status_log,
	.media_unit_stat_log = binary_media_unit_stat_log,
	.mi_cmd_support_effects_log = binary_mi_cmd_support_effects_log,
	.ns_list_log = binary_changed_ns_list_log,
	.persistent_event_log = binary_persistent_event_log,
	.predictable_latency_event_agg_log =
		binary_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset = binary_predictable_latency_per_nvmset,
	.resv_notification_log = binary_resv_notif_log,
	.sanitize_log_page = binary_sanitize_log,
	.self_test_log = binary_self_test_log,
	.smart_log = binary_smart_log,
	.supported_cap_config_list_log = binary_supported_cap_config_log,
	.supported_log_pages = binary_supported_log,
	.voltage_meas_log = binary_voltage_meas_log,
	.mgmt_addr_list_log = binary_mgmt_addr_list_log,
	.rotational_media_info_log = binary_rotational_media_info_log,
	.dispersed_ns_psub_log = binary_dispersed_ns_psub_log,
	.reachability_groups_log = binary_reachability_groups_log,
	.reachability_associations_log = binary_reachability_associations_log,
	.host_discovery_log = binary_host_discovery_log,
	.ave_discovery_log = binary_ave_discovery_log,
	.pull_model_ddc_req_log = binary_pull_model_ddc_req_log,
	.power_meas_log = binary_power_meas_log,
};

struct log_print_ops *log_get_binary_print_ops(void)
{
	return &binary_log_print_ops;
}
