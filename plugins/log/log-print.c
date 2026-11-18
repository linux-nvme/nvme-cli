// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/minmax/minmax.h>

#include "log-print.h"
#include "nvme-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define log_print(name, flags, ...)					\
	do {								\
		struct log_print_ops *__lops = log_print_ops(flags);	\
									\
		if (__lops && __lops->name)				\
			nvme_print_decoder(__lops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct log_print_ops *log_print_ops(nvme_print_flags_t flags)
{
	struct log_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = log_get_json_print_ops();
	else if (flags & BINARY)
		ops = log_get_binary_print_ops();
	else
		ops = log_get_stdout_print_ops();

	return ops;
}

const char *nvme_ana_state_to_string(enum nvme_ana_state state)
{
	switch (state) {
	case NVME_ANA_STATE_OPTIMIZED:
		return "optimized";
	case NVME_ANA_STATE_NONOPTIMIZED:
		return "non-optimized";
	case NVME_ANA_STATE_INACCESSIBLE:
		return "inaccessible";
	case NVME_ANA_STATE_PERSISTENT_LOSS:
		return "persistent-loss";
	case NVME_ANA_STATE_CHANGE:
		return "change";
	}
	return "invalid state";
}

const char *nvme_sstat_status_to_string(__u16 status)
{
	switch (status & NVME_SANITIZE_SSTAT_STATUS_MASK) {
	case NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED:
		return "NVM Subsystem has never been sanitized.";
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS:
		return "Most Recent Sanitize Command Completed Successfully.";
	case NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS:
		return "Sanitize in Progress.";
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED:
		return "Most Recent Sanitize Command Failed.";
	case NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS:
		return (
			"Most Recent Sanitize Command (No-Deallocate After Sanitize) Completed Successfully.");
	default:
		return "Unknown";
	}
}

void nvme_show_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname,
	nvme_print_flags_t flags)
{
	log_print(predictable_latency_per_nvmset, flags,
		   plpns_log, nvmset_id, devname);
}

void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	log_print(predictable_latency_event_agg_log, flags,
		   pea_log, log_entries, size, devname);
}

static const char *pel_event_to_string(int type)
{
	switch (type) {
	case NVME_PEL_SMART_HEALTH_EVENT:
		return "SMART/Health Log Snapshot Event";
	case NVME_PEL_FW_COMMIT_EVENT:
		return "Firmware Commit Event";
	case NVME_PEL_TIMESTAMP_EVENT:
		return "Timestamp Change Event";
	case NVME_PEL_POWER_ON_RESET_EVENT:
		return "Power-on or Reset Event";
	case NVME_PEL_NSS_HW_ERROR_EVENT:
		return "NVM Subsystem Hardware Error Event";
	case NVME_PEL_CHANGE_NS_EVENT:
		return "Change Namespace Event";
	case NVME_PEL_FORMAT_START_EVENT:
		return "Format NVM Start Event";
	case NVME_PEL_FORMAT_COMPLETION_EVENT:
		return "Format NVM Completion Event";
	case NVME_PEL_SANITIZE_START_EVENT:
		return "Sanitize Start Event";
	case NVME_PEL_SANITIZE_COMPLETION_EVENT:
		return "Sanitize Completion Event";
	case NVME_PEL_SET_FEATURE_EVENT:
		return "Set Feature Event";
	case NVME_PEL_TELEMETRY_CRT:
		return "Set Telemetry CRT Event";
	case NVME_PEL_THERMAL_EXCURSION_EVENT:
		return "Thermal Excursion Event";
	case NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT:
		return "Sanitize Media Verification Event";
	case NVME_PEL_CONF_DEV_PERSONALITY_CHG_EVENT:
		return "Configurable Device Personality Change Event";
	case NVME_PEL_EXPORT_NVMS_CHG_EVENT:
		return "Exported NVM Subsystem Change Event";
	case NVME_PEL_VENDOR_SPECIFIC_EVENT:
		return "Vendor Specific Event";
	case NVME_PEL_TCG_DEFINED_EVENT:
		return "TCG Defined Event";
	default:
		return "Reserved Event";
	}
}

const char *nvme_pel_event_to_string(int type)
{
	static char str[STR_LEN];

	snprintf(str, sizeof(str), "%s(%#x)", pel_event_to_string(type), type);

	return str;
}

const char *nvme_nss_hw_error_to_string(__u16 error_code)
{
	switch (error_code) {
	case 0x01:
		return "PCIe Correctable Error";
	case 0x02:
		return "PCIe Uncorrectable Non fatal Error";
	case 0x03:
		return "PCIe Uncorrectable Fatal Error";
	case 0x04:
		return "PCIe Link Status Change";
	case 0x05:
		return "PCIe Link Not Active";
	case 0x06:
		return "Critical Warning Condition";
	case 0x07:
		return "Endurance Group Critical Warning Condition";
	case 0x08:
		return "Unsafe Shutdown";
	case 0x09:
		return "Controller Fatal Status";
	case 0xA:
		return "Media and Data Integrity Status";
	case 0xB:
		return "Controller Ready Timeout Exceeded";
	default:
		return "Reserved";
	}
}

/*
 * The entries of the Persistent Event log have variable length, so the
 * event data is not aligned. A handler also reads the whole event
 * structure, even if the event data is shorter. Returns an aligned copy
 * of the event data, zero padded to the largest event structure, or NULL.
 * The caller frees the copy.
 */
/*
 * The event at offset of a Persistent Event log of size bytes, or NULL if
 * there is no complete event: its header must hold all header fields, its
 * vendor specific information must fit into the event, and the event into
 * the log.
 */
struct nvme_persistent_event_entry *nvme_pel_event(void *pevent_log_info,
		__u32 size, __u32 offset)
{
	struct nvme_persistent_event_entry *e;
	__u64 len;

	if ((__u64)offset + sizeof(*e) > size)
		return NULL;

	e = pevent_log_info + offset;
	/* The Event Header Length does not count the first 3 bytes */
	if (e->ehl + 3 < sizeof(*e))
		return NULL;
	if (le16_to_cpu(e->vsil) > le16_to_cpu(e->el))
		return NULL;

	len = (__u64)e->ehl + 3 + le16_to_cpu(e->el);
	if (offset + len > size)
		return NULL;

	return e;
}

void *nvme_pel_event_data(void *pevent_log_info, __u32 offset, __u32 len,
		__u32 *buf_len)
{
	__u32 size = max_t(__u32, len, sizeof(struct nvme_smart_log));
	void *buf;

	buf = calloc(1, size);
	if (!buf)
		return NULL;

	memcpy(buf, pevent_log_info + offset, len);
	*buf_len = size;

	return buf;
}

/*
 * The feature printers read a whole data structure from the memory buffer
 * of a Set Feature event, the largest 4 KiB, through an aligned pointer.
 * The buffer follows the dwords of the command in the event data of len
 * bytes, so is neither aligned nor that long. Returns an aligned copy of
 * it, zero padded to 4 KiB, or NULL if the event has none. The caller
 * frees the copy.
 */
void *nvme_pel_set_feature_data(void *data, __u32 len)
{
	struct nvme_set_feature_event *e = data;
	__u32 layout = le32_to_cpu(e->layout);
	__u32 rel;
	void *buf;

	if (!NVME_SET_FEAT_EVENT_MB_COUNT(layout))
		return NULL;
	rel = 4 + NVME_SET_FEAT_EVENT_DW_COUNT(layout) * 4;
	if (rel >= len)
		return NULL;

	buf = calloc(1, NVME_PEL_FEATURE_DATA_SIZE);
	if (!buf)
		return NULL;
	memcpy(buf, data + rel,
	       min_t(__u32, len - rel, NVME_PEL_FEATURE_DATA_SIZE));

	return buf;
}

void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	log_print(persistent_event_log, flags,
		   pevent_log_info, action, size, devname);
}

void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_endurance_group_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	log_print(endurance_group_event_agg_log, flags,
		   endurance_log, log_entries, size, devname);
}

void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, nvme_print_flags_t flags)
{
	log_print(lba_status_log, flags, lba_status, size, devname);
}

const char *nvme_resv_notif_to_string(__u8 type)
{
	switch (type) {
	case 0x0: return "Empty Log Page";
	case 0x1: return "Registration Preempted";
	case 0x2: return "Reservation Released";
	case 0x3: return "Reservation Preempted";
	default:  return "Reserved";
	}
}

void nvme_show_resv_notif_log(struct nvme_resv_notification_log *resv,
	const char *devname, nvme_print_flags_t flags)
{
	log_print(resv_notification_log, flags, resv, devname);
}

void nvme_show_fid_support_effects_log(
	struct nvme_fid_supported_effects_log *fid_log, const char *devname,
	nvme_print_flags_t flags)
{
	log_print(fid_supported_effects_log, flags, fid_log, devname);
}

void nvme_show_mi_cmd_support_effects_log(
	struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, nvme_print_flags_t flags)
{
	log_print(mi_cmd_support_effects_log, flags,
		   mi_cmd_log, devname);
}

void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, nvme_print_flags_t flags)
{
	log_print(boot_part_log, flags, bp_log, devname, size);
}

void nvme_show_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller,
	size_t len, nvme_print_flags_t flags)
{
	log_print(phy_rx_eom_log, flags, log, controller, len);
}

void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log,
	size_t len,
				   nvme_print_flags_t flags)
{
	log_print(media_unit_stat_log, flags, mus_log, len);
}

void nvme_show_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap, size_t len,
	nvme_print_flags_t flags)
{
	log_print(supported_cap_config_list_log, flags, cap, len);
}

const char *nvme_trtype_to_string(__u8 trtype)
{
	switch (trtype) {
	case 0: return (
		"The transport type is not indicated or the error is not transport related");
	case 1: return "RDMA Transport error";
	case 2: return "Fibre Channel Transport error";
	case 3: return "TCP Transport error";
	case 254: return "Intra-host Transport error";
	default: return "Reserved";
	};
}

void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
			 const char *devname, struct nvme_error_log_filter *flt,
			 nvme_print_flags_t flags)
{
	log_print(error_log, flags, err_log, entries, devname, flt);
}

bool nvme_is_error_log_filter(struct nvme_error_log_page *err_log,
			      struct nvme_error_log_filter *flt)
{
	__u16 sts = le16_to_cpu(err_log->status_field);
	__u16 status = NVME_ERR_SF_STATUS_FIELD(sts);
	__u16 sqid = le16_to_cpu(err_log->sqid);
	__u32 nsid = le32_to_cpu(err_log->nsid);
	__u64 lba = le64_to_cpu(err_log->lba);

	if (flt && ((flt->valid && !err_log->error_count) ||
	    (flt->sqid && flt->sqid != sqid) ||
	    (flt->status && flt->status != status) ||
	    (flt->lba && flt->lba != lba) ||
	    (flt->nsid && flt->nsid != nsid) ||
	    (flt->trtype && flt->trtype != err_log->trtype) ||
	    (flt->csi && flt->csi != err_log->csi) ||
	    (flt->opcode && flt->opcode != err_log->opcode)))
		return true;

	return false;
}

void nvme_show_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname, nvme_print_flags_t flags)
{
	log_print(fw_log, flags, fw_log, devname);
}

void nvme_show_changed_ns_list_log(struct nvme_ns_list *log,
				   const char *devname,
				   nvme_print_flags_t flags, bool alloc)
{
	log_print(ns_list_log, flags, log, devname, alloc);
}

void nvme_print_effects_log_pages(struct list_head *list,
				  nvme_print_flags_t flags)
{
	log_print(effects_log_list, flags, list);
}

const char *nvme_log_to_string(__u8 lid)
{
	switch (lid) {
	case NVME_LOG_LID_SUPPORTED_LOG_PAGES:
		return "Supported Log Pages";
	case NVME_LOG_LID_ERROR:
		return "Error Information";
	case NVME_LOG_LID_SMART:
		return "SMART / Health Information";
	case NVME_LOG_LID_FW_SLOT:
		return "Firmware Slot Information";
	case NVME_LOG_LID_CHANGED_ATTACHED_NS:
		return "Changed Attached Namespace List";
	case NVME_LOG_LID_CMD_EFFECTS:
		return "Commands Supported and Effects";
	case NVME_LOG_LID_DEVICE_SELF_TEST:
		return "Device Self-test";
	case NVME_LOG_LID_TELEMETRY_HOST:
		return "Telemetry Host-Initiated";
	case NVME_LOG_LID_TELEMETRY_CTRL:
		return "Telemetry Controller-Initiated";
	case NVME_LOG_LID_ENDURANCE_GROUP:
		return "Endurance Group Information";
	case NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:
		return "Predictable Latency Per NVM Set";
	case NVME_LOG_LID_PREDICTABLE_LAT_AGG:
		return "Predictable Latency Event Aggregate";
	case NVME_LOG_LID_ANA:
		return "Asymmetric Namespace Access";
	case NVME_LOG_LID_PERSISTENT_EVENT:
		return "Persistent Event Log";
	case NVME_LOG_LID_LBA_STATUS:
		return "LBA Status Information";
	case NVME_LOG_LID_ENDURANCE_GRP_EVT:
		return "Endurance Group Event Aggregate";
	case NVME_LOG_LID_MEDIA_UNIT_STATUS:
		return "Media Unit Status";
	case NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST:
		return "Supported Capacity Configuration List";
	case NVME_LOG_LID_FID_SUPPORTED_EFFECTS:
		return "Feature Identifiers Supported and Effects";
	case NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS:
		return "NVMe-MI Commands Supported and Effects";
	case NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN:
		return "Command and Feature Lockdown";
	case NVME_LOG_LID_BOOT_PARTITION:
		return "Boot Partition";
	case NVME_LOG_LID_ROTATIONAL_MEDIA_INFO:
		return "Rotational Media Information";
	case NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS:
		return "Dispersed Namespace Participating NVM Subsystems";
	case NVME_LOG_LID_MGMT_ADDR_LIST:
		return "Management Address List";
	case NVME_LOG_LID_PHY_RX_EOM:
		return "Physical Interface Receiver Eye Opening Measurement";
	case NVME_LOG_LID_REACHABILITY_GROUPS:
		return "Reachability Groups";
	case NVME_LOG_LID_REACHABILITY_ASSOCIATIONS:
		return "Reachability Associations";
	case NVME_LOG_LID_CHANGED_ALLOC_NS:
		return "Changed Allocated Namespace List";
	case NVME_LOG_LID_DEV_PERSONALITY:
		return "Device Personalities";
	case NVME_LOG_LID_CROSS_CTRL_RESET:
		return "Cross-Controller Reset";
	case NVME_LOG_LID_LOST_HOST_COMMUNICATION:
		return "Lost Host Communication";
	case NVME_LOG_LID_FDP_CONFIGS:
		return "FDP Configurations";
	case NVME_LOG_LID_FDP_RUH_USAGE:
		return "Reclaim Unit Handle Usage";
	case NVME_LOG_LID_FDP_STATS:
		return "FDP Statistics";
	case NVME_LOG_LID_FDP_EVENTS:
		return "FDP Events";
	case NVME_LOG_LID_MFG_DEFAULT_CONFIG:
		return "Manufacturer Default Configuration";
	case NVME_LOG_LID_POWER_MEASUREMENT:
		return "Power Measurement";
	case NVME_LOG_LID_VOLTAGE_MEASUREMENT:
		return "Voltage Measurement";
	case NVME_LOG_LID_RATE_LIMITING:
		return "Rate Limiting";
	case NVME_LOG_LID_DISCOVERY:
		return "Discovery";
	case NVME_LOG_LID_HOST_DISCOVERY:
		return "Host Discovery";
	case NVME_LOG_LID_AVE_DISCOVERY:
		return "AVE Discovery";
	case NVME_LOG_LID_PULL_MODEL_DDC_REQ:
		return "Pull Model DDC Request";
	case NVME_LOG_LID_SANITIZE_NS_STATUS_LIST:
		return "Sanitize Namespace Status List";
	case NVME_LOG_LID_RESERVATION:
		return "Reservation Notification";
	case NVME_LOG_LID_SANITIZE:
		return "Sanitize Status";
	case NVME_LOG_LID_ZNS_CHANGED_ZONES:
		return "Changed Zone List";
	default:
		return "Unknown";
	}
}

void nvme_show_supported_log(struct nvme_supported_log_pages *support_log,
	const char *devname, nvme_print_flags_t flags)
{
	log_print(supported_log_pages, flags, support_log, devname);
}

void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
			     __u16 group_id, const char *devname,
			     nvme_print_flags_t flags)
{
	log_print(endurance_log, flags, endurance_log, group_id, devname);
}

void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, nvme_print_flags_t flags)
{
	log_print(smart_log, flags, smart, nsid, devname);
}

void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		       size_t len, nvme_print_flags_t flags)
{
	log_print(ana_log, flags, ana_log, devname, len);
}

void nvme_show_self_test_log(struct nvme_self_test_log *self_test,
			     __u8 dst_entries, __u32 size, const char *devname,
			     nvme_print_flags_t flags)
{
	log_print(self_test_log, flags, self_test, dst_entries, size, devname);
}

void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			    const char *devname, nvme_print_flags_t flags)
{
	log_print(sanitize_log_page, flags, sanitize, devname);
}

const char *nvme_pel_rci_rcpit_to_string(enum nvme_pel_rci_rcpit rcpit)
{
	switch (rcpit) {
	case NVME_PEL_RCI_RCPIT_NOT_EXIST:
		return "Does not already exist";
	case NVME_PEL_RCI_RCPIT_EST_PORT:
		return "NVM subsystem port";
	case NVME_PEL_RCI_RCPIT_EST_ME:
		return "NVMe-MI port";
	default:
		break;
	}
	return "Reserved";
}

const char *nvme_pel_ehai_pit_to_string(enum nvme_pel_ehai_pit pit)
{
	switch (pit) {
	case NVME_PEL_EHAI_PIT_NOT_REPORTED:
		return "PIT not reported and PELPID does not apply";
	case NVME_PEL_EHAI_PIT_NSS_PORT:
		return "NVM subsystem port";
	case NVME_PEL_EHAI_PIT_NMI_PORT:
		return "NVMe-MI port";
	case NVME_PEL_EHAI_PIT_NOT_ASSOCIATED:
		return (
			"Event not associated with any port and PELPID does not apply");
	default:
		break;
	}
	return "Reserved";
}

const char *nvme_ssi_state_to_string(__u8 state)
{
	switch (state) {
	case NVME_SANITIZE_SSI_IDLE:
		return "Idle state";
	case NVME_SANITIZE_SSI_RESTRICT_PROCESSING:
		return "Restricted Processing State";
	case NVME_SANITIZE_SSI_RESTRICT_FAILURE:
		return "Restricted Failure State";
	case NVME_SANITIZE_SSI_UNRESTRICT_PROCESSING:
		return "Unrestricted Processing State";
	case NVME_SANITIZE_SSI_UNRESTRICT_FAILURE:
		return "Unrestricted Failure State";
	case NVME_SANITIZE_SSI_MEDIA_VERIFICATION:
		return "Media Verification State";
	case NVME_SANITIZE_SSI_POST_VERIF_DEALLOC:
		return "Post-Verification Deallocation State";
	default:
		return "Reserved";
	}
}

void nvme_show_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list,
				  nvme_print_flags_t flags)
{
	log_print(mgmt_addr_list_log, flags, ma_list);
}

void nvme_show_power_meas_log(struct nvme_power_meas_log *log, __u32 size,
			      nvme_print_flags_t flags)
{
	log_print(power_meas_log, flags, log, size);
}

void nvme_show_voltage_meas_log(struct nvme_voltage_measurement_log *log,
				__u32 size, nvme_print_flags_t flags)
{
	log_print(voltage_meas_log, flags, log, size);
}

void nvme_show_rotational_media_info_log(
	struct nvme_rotational_media_info_log *info, nvme_print_flags_t flags)
{
	log_print(rotational_media_info_log, flags, info);
}

void nvme_show_dispersed_ns_psub_log(
	struct nvme_dispersed_ns_participating_nss_log *log, __u64 len,
	nvme_print_flags_t flags)
{
	log_print(dispersed_ns_psub_log, flags, log, len);
}

void nvme_show_reachability_groups_log(struct nvme_reachability_groups_log *log,
				       __u64 len, nvme_print_flags_t flags)
{
	log_print(reachability_groups_log, flags, log, len);
}

void nvme_show_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len,
	nvme_print_flags_t flags)
{
	log_print(reachability_associations_log, flags, log, len);
}

void nvme_show_host_discovery_log(struct nvme_host_discovery_log *log,
		__u64 len, nvme_print_flags_t flags)
{
	log_print(host_discovery_log, flags, log, len);
}

void nvme_show_ave_discovery_log(struct nvme_ave_discovery_log *log,
		__u64 len, nvme_print_flags_t flags)
{
	log_print(ave_discovery_log, flags, log, len);
}

void nvme_show_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log,
				      __u64 len, nvme_print_flags_t flags)
{
	log_print(pull_model_ddc_req_log, flags, log, len);
}

bool log_show_log(const char *devname, enum nvme_cmd_get_log_lid lid,
		  __u32 nsid, __u16 lsi, __u8 lsp, void *log, __u32 len,
		  nvme_print_flags_t flags)
{
	switch (lid) {
	case NVME_LOG_LID_ERROR:
		nvme_show_error_log(log,
				    len / sizeof(struct nvme_error_log_page),
				    devname, NULL, flags);
		break;
	case NVME_LOG_LID_SMART:
		nvme_show_smart_log(log, nsid, devname, flags);
		break;
	case NVME_LOG_LID_FW_SLOT:
		nvme_show_fw_log(log, devname, flags);
		break;
	case NVME_LOG_LID_CHANGED_ATTACHED_NS:
		nvme_show_changed_ns_list_log(log, devname, flags, false);
		break;
	case NVME_LOG_LID_DEVICE_SELF_TEST:
		nvme_show_self_test_log(log,
					len / sizeof(struct nvme_self_test_log),
					0, devname, flags);
		break;
	case NVME_LOG_LID_ENDURANCE_GROUP:
		nvme_show_endurance_log(log, lsi, devname, flags);
		break;
	case NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:
		nvme_show_predictable_latency_per_nvmset(log, lsi, devname,
							 flags);
		break;
	case NVME_LOG_LID_PREDICTABLE_LAT_AGG:
		nvme_show_predictable_latency_event_agg_log(
			log,
			len > sizeof(__u64) ?
				(len - sizeof(__u64)) / sizeof(__le16) :
				0,
			len, devname, flags);
		break;
	case NVME_LOG_LID_ANA:
		nvme_show_ana_log(log, devname, len, flags);
		break;
	case NVME_LOG_LID_PERSISTENT_EVENT:
		nvme_show_persistent_event_log(log, lsp, len, devname, flags);
		break;
	case NVME_LOG_LID_LBA_STATUS:
		nvme_show_lba_status_log(log, len, devname, flags);
		break;
	case NVME_LOG_LID_ENDURANCE_GRP_EVT: {
		struct nvme_aggregate_endurance_group_event *end = log;
		/* no more entries than the log holds, before size_t cuts it */
		__u64 nr = min_t(__u64, le64_to_cpu(end->num_entries), len);

		nvme_show_endurance_group_event_agg_log(end,
			nvme_log_nr_entries(nr, len, sizeof(*end),
					    sizeof(end->entries[0])),
			len, devname, flags);
		break;
	}
	case NVME_LOG_LID_MEDIA_UNIT_STATUS:
		nvme_show_media_unit_stat_log(log, len, flags);
		break;
	case NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST:
		nvme_show_supported_cap_config_log(log, len, flags);
		break;
	case NVME_LOG_LID_FID_SUPPORTED_EFFECTS:
		nvme_show_fid_support_effects_log(log, devname, flags);
		break;
	case NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS:
		nvme_show_mi_cmd_support_effects_log(log, devname, flags);
		break;
	case NVME_LOG_LID_BOOT_PARTITION:
		nvme_show_boot_part_log(log, devname, len, flags);
		break;
	case NVME_LOG_LID_ROTATIONAL_MEDIA_INFO:
		nvme_show_rotational_media_info_log(log, flags);
		break;
	case NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS:
		nvme_show_dispersed_ns_psub_log(log, len, flags);
		break;
	case NVME_LOG_LID_MGMT_ADDR_LIST:
		nvme_show_mgmt_addr_list_log(log, flags);
		break;
	case NVME_LOG_LID_PHY_RX_EOM:
		nvme_show_phy_rx_eom_log(log, lsi, len, flags);
		break;
	case NVME_LOG_LID_REACHABILITY_GROUPS:
		nvme_show_reachability_groups_log(log, len, flags);
		break;
	case NVME_LOG_LID_REACHABILITY_ASSOCIATIONS:
		nvme_show_reachability_associations_log(log, len, flags);
		break;
	case NVME_LOG_LID_CHANGED_ALLOC_NS:
		nvme_show_changed_ns_list_log(log, devname, flags, true);
		break;
	case NVME_LOG_LID_HOST_DISCOVERY:
		nvme_show_host_discovery_log(log, len, flags);
		break;
	case NVME_LOG_LID_AVE_DISCOVERY:
		nvme_show_ave_discovery_log(log, len, flags);
		break;
	case NVME_LOG_LID_PULL_MODEL_DDC_REQ:
		nvme_show_pull_model_ddc_req_log(log, len, flags);
		break;
	case NVME_LOG_LID_POWER_MEASUREMENT:
		nvme_show_power_meas_log(log, len, flags);
		break;
	case NVME_LOG_LID_VOLTAGE_MEASUREMENT:
		nvme_show_voltage_meas_log(log, len, flags);
		break;
	case NVME_LOG_LID_RESERVATION:
		nvme_show_resv_notif_log(log, devname, flags);
		break;
	case NVME_LOG_LID_SANITIZE:
		nvme_show_sanitize_log(log, devname, flags);
		break;
	default:
		return false;
	}

	return true;
}
