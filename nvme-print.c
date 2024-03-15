// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "nvme-models.h"
#include "util/suffix.h"
#include "util/types.h"
#include "common.h"

#define nvme_print(name, flags, ...)				\
	do {							\
		struct print_ops *ops = nvme_print_ops(flags);	\
		if (ops && ops->name)				\
			ops->name(__VA_ARGS__);			\
	} while (false)

#define nvme_print_output_format(name, ...)			\
	nvme_print(name, nvme_is_output_format_json() ? JSON : NORMAL, ##__VA_ARGS__);

static struct print_ops *nvme_print_ops(enum nvme_print_flags flags)
{
	struct print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = nvme_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = nvme_get_binary_print_ops(flags);
	else
		ops = nvme_get_stdout_print_ops(flags);

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

const char *nvme_cmd_to_string(int admin, __u8 opcode)
{
	if (admin) {
		switch (opcode) {
		case nvme_admin_delete_sq:	return "Delete I/O Submission Queue";
		case nvme_admin_create_sq:	return "Create I/O Submission Queue";
		case nvme_admin_get_log_page:	return "Get Log Page";
		case nvme_admin_delete_cq:	return "Delete I/O Completion Queue";
		case nvme_admin_create_cq:	return "Create I/O Completion Queue";
		case nvme_admin_identify:	return "Identify";
		case nvme_admin_abort_cmd:	return "Abort";
		case nvme_admin_set_features:	return "Set Features";
		case nvme_admin_get_features:	return "Get Features";
		case nvme_admin_async_event:	return "Asynchronous Event Request";
		case nvme_admin_ns_mgmt:	return "Namespace Management";
		case nvme_admin_fw_commit:	return "Firmware Commit";
		case nvme_admin_fw_download:	return "Firmware Image Download";
		case nvme_admin_dev_self_test:	return "Device Self-test";
		case nvme_admin_ns_attach:	return "Namespace Attachment";
		case nvme_admin_keep_alive:	return "Keep Alive";
		case nvme_admin_directive_send:	return "Directive Send";
		case nvme_admin_directive_recv:	return "Directive Receive";
		case nvme_admin_virtual_mgmt:	return "Virtualization Management";
		case nvme_admin_nvme_mi_send:	return "NVMe-MI Send";
		case nvme_admin_nvme_mi_recv:	return "NVMe-MI Receive";
		case nvme_admin_dbbuf:		return "Doorbell Buffer Config";
		case nvme_admin_format_nvm:	return "Format NVM";
		case nvme_admin_security_send:	return "Security Send";
		case nvme_admin_security_recv:	return "Security Receive";
		case nvme_admin_sanitize_nvm:	return "Sanitize";
		case nvme_admin_get_lba_status:	return "Get LBA Status";
		}
	} else {
		switch (opcode) {
		case nvme_cmd_flush:		return "Flush";
		case nvme_cmd_write:		return "Write";
		case nvme_cmd_read:		return "Read";
		case nvme_cmd_write_uncor:	return "Write Uncorrectable";
		case nvme_cmd_compare:		return "Compare";
		case nvme_cmd_write_zeroes:	return "Write Zeroes";
		case nvme_cmd_dsm:		return "Dataset Management";
		case nvme_cmd_resv_register:	return "Reservation Register";
		case nvme_cmd_resv_report:	return "Reservation Report";
		case nvme_cmd_resv_acquire:	return "Reservation Acquire";
		case nvme_cmd_resv_release:	return "Reservation Release";
		case nvme_cmd_verify:		return "Verify";
		case nvme_cmd_copy:		return "Copy";
		case nvme_zns_cmd_mgmt_send:	return "Zone Management Send";
		case nvme_zns_cmd_mgmt_recv:	return "Zone Management Receive";
		case nvme_zns_cmd_append:	return "Zone Append";
		}
	}

	return "Unknown";
}

const char *nvme_sstat_status_to_string(__u16 status)
{
	switch (status & NVME_SANITIZE_SSTAT_STATUS_MASK) {
	case NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED:
		return "NVM Subsystem has never been sanitized.";
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS:
		return "Most Recent Sanitize Command Completed Successfully.";
	case NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS:
		return "Sanitize in Progress.";
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED:
		return "Most Recent Sanitize Command Failed.";
	case NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS:
		return "Most Recent Sanitize Command (No-Deallocate After Sanitize) Completed Successfully.";
	default:
		return "Unknown";
	}
}

void nvme_show_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname,
	enum nvme_print_flags flags)
{
	nvme_print(predictable_latency_per_nvmset, flags,
		   plpns_log, nvmset_id, devname);
}

void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{
	nvme_print(predictable_latency_event_agg_log, flags,
		   pea_log, log_entries, size, devname);
}

const char *nvme_pel_event_to_string(int type)
{
	switch (type) {
	case NVME_PEL_SMART_HEALTH_EVENT:	return "SMART/Health Log Snapshot Event(0x1)";
	case NVME_PEL_FW_COMMIT_EVENT:	return "Firmware Commit Event(0x2)";
	case NVME_PEL_TIMESTAMP_EVENT:	return "Timestamp Change Event(0x3)";
	case NVME_PEL_POWER_ON_RESET_EVENT:	return "Power-on or Reset Event(0x4)";
	case NVME_PEL_NSS_HW_ERROR_EVENT:	return "NVM Subsystem Hardware Error Event(0x5)";
	case NVME_PEL_CHANGE_NS_EVENT:	return "Change Namespace Event(0x6)";
	case NVME_PEL_FORMAT_START_EVENT:	return "Format NVM Start Event(0x7)";
	case NVME_PEL_FORMAT_COMPLETION_EVENT:	return "Format NVM Completion Event(0x8)";
	case NVME_PEL_SANITIZE_START_EVENT:	return "Sanitize Start Event(0x9)";
	case NVME_PEL_SANITIZE_COMPLETION_EVENT:	return "Sanitize Completion Event(0xa)";
	case NVME_PEL_SET_FEATURE_EVENT:	return "Set Feature Event(0xb)";
	case NVME_PEL_TELEMETRY_CRT:		return "Set Telemetry CRT  Event(0xc)";
	case NVME_PEL_THERMAL_EXCURSION_EVENT:	return "Thermal Excursion Event(0xd)";
	default:			return NULL;
	}
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

void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{
	nvme_print(persistent_event_log, flags,
		   pevent_log_info, action, size, devname);
}

void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{
	nvme_print(endurance_group_event_agg_log, flags,
		   endurance_log, log_entries, size, devname);
}

void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(lba_status_log, flags, lba_status, size, devname);
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
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(resv_notification_log, flags, resv, devname);
}

void nvme_show_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(fid_supported_effects_log, flags, fid_log, devname);
}

void nvme_show_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(mi_cmd_support_effects_log, flags,
		   mi_cmd_log, devname);
}

void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, enum nvme_print_flags flags)
{
	nvme_print(boot_part_log, flags, bp_log, devname, size);
}

void nvme_show_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller,
	enum nvme_print_flags flags)
{
	nvme_print(phy_rx_eom_log, flags, log, controller);
}

void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log,
				   enum nvme_print_flags flags)
{
	nvme_print(media_unit_stat_log, flags, mus_log);
}

void nvme_show_fdp_configs(struct nvme_fdp_config_log *log, size_t len,
		enum nvme_print_flags flags)
{
	nvme_print(fdp_config_log, flags, log, len);
}

void nvme_show_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		enum nvme_print_flags flags)
{
	nvme_print(fdp_usage_log, flags,log, len);
}

void nvme_show_fdp_stats(struct nvme_fdp_stats_log *log,
		enum nvme_print_flags flags)
{
	nvme_print(fdp_stats_log, flags, log);
}

const char *nvme_fdp_event_to_string(enum nvme_fdp_event_type event)
{
	switch (event) {
	case NVME_FDP_EVENT_RUNFW:	return "Reclaim Unit Not Fully Written";
	case NVME_FDP_EVENT_RUTLE:	return "Reclaim Unit Active Time Limit Exceeded";
	case NVME_FDP_EVENT_RESET:	return "Controller Level Reset Modified Reclaim Unit Handles";
	case NVME_FDP_EVENT_PID:	return "Invalid Placement Identifier";
	case NVME_FDP_EVENT_REALLOC:	return "Media Reallocated";
	case NVME_FDP_EVENT_MODIFY:	return "Implicitly Modified Reclaim Unit Handle";
	}

	return "Unknown";
}

void nvme_show_fdp_events(struct nvme_fdp_events_log *log,
		enum nvme_print_flags flags)
{
	nvme_print(fdp_event_log, flags, log);
}

void nvme_show_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
		enum nvme_print_flags flags)
{
	nvme_print(fdp_ruh_status, flags, status, len);
}

void nvme_show_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap,
	enum nvme_print_flags flags)
{
	nvme_print(supported_cap_config_list_log, flags, cap);
}

void nvme_show_subsystem_list(nvme_root_t r, bool show_ana,
			      enum nvme_print_flags flags)
{
	nvme_print(print_nvme_subsystem_list, flags, r, show_ana);
}

const char *nvme_register_szu_to_string(__u8 szu)
{
	switch (szu) {
	case 0:	return "4 KB";
	case 1:	return "64 KB";
	case 2:	return "1 MB";
	case 3:	return "16 MB";
	case 4:	return "256 MB";
	case 5:	return "4 GB";
	case 6:	return "64 GB";
	default:return "Reserved";
	}
}

const char *nvme_register_pmr_hsts_to_string(__u8 hsts)
{
	switch (hsts) {
	case 0: return "Normal Operation";
	case 1: return "Restore Error";
	case 2: return "Read Only";
	case 3: return "Unreliable";
	default: return "Reserved";
	}
}

const char *nvme_register_pmr_pmrszu_to_string(__u8 pmrszu)
{
	switch (pmrszu) {
	case 0: return "Bytes";
	case 1: return "One KB";
	case 2: return "One MB";
	case 3: return "One GB";
	default: return "Reserved";
	}
}

void nvme_show_ctrl_registers(void *bar, bool fabrics, enum nvme_print_flags flags)
{
	nvme_print(ctrl_registers, flags, bar, fabrics);
}

void nvme_show_single_property(int offset, uint64_t value64, enum nvme_print_flags flags)
{
	nvme_print(single_property, flags, offset, value64);
}

void nvme_show_relatives(const char *name)
{
	/* XXX: TBD */
}

void d(unsigned char *buf, int len, int width, int group)
{
	nvme_print(d, NORMAL, buf, len, width, group);
}

void d_raw(unsigned char *buf, unsigned len)
{
	unsigned i;
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
}

void nvme_show_status(int status)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_status)
		ops->show_status(status);
}

void nvme_show_error_status(int status, const char *msg, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	va_list ap;

	va_start(ap, msg);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_status)
		ops->show_error_status(status, msg, ap);

	va_end(ap);
}

void nvme_show_id_ctrl_rpmbs(__le32 ctrl_rpmbs, enum nvme_print_flags flags)
{
	nvme_print(id_ctrl_rpmbs, flags, ctrl_rpmbs);
}

void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		unsigned int lba_index, bool cap_only, enum nvme_print_flags flags)
{
	nvme_print(id_ns, flags, ns, nsid, lba_index, cap_only);
}


void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	enum nvme_print_flags flags)
{
	nvme_print(id_independent_id_ns, flags, ns, nsid);
}

void nvme_show_id_ns_descs(void *data, unsigned nsid, enum nvme_print_flags flags)
{
	nvme_print(id_ns_descs, flags, data, nsid);
}

void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, enum nvme_print_flags flags,
			void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	nvme_print(id_ctrl, flags, ctrl, vendor_show);
}

void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	enum nvme_print_flags flags)
{
	nvme_print(id_ctrl_nvm, flags, ctrl_nvm);
}

void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
						struct nvme_id_ns *ns, unsigned int lba_index,
						bool cap_only, enum nvme_print_flags flags)
{
	nvme_print(nvm_id_ns, flags, nvm_ns, nsid, ns, lba_index, cap_only);
}

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl,
			   enum nvme_print_flags flags)
{
	nvme_print(zns_id_ctrl, flags, ctrl);
}

void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
			 struct nvme_id_ns *id_ns,
			 enum nvme_print_flags flags)
{
	nvme_print(zns_id_ns, flags, ns, id_ns);
}

void nvme_show_list_ns(struct nvme_ns_list *ns_list, enum nvme_print_flags flags)
{
	nvme_print(ns_list, flags, ns_list);
}

void nvme_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list,
			      enum nvme_print_flags flags)
{
	nvme_print(zns_start_zone_list, flags, nr_zones, zone_list);
}

void nvme_show_zns_changed(struct nvme_zns_changed_zone_log *log,
			   enum nvme_print_flags flags)
{
	nvme_print(zns_changed_zone_log, flags, log);
}

void nvme_zns_finish_zone_list(__u64 nr_zones, struct json_object *zone_list,
			       enum nvme_print_flags flags)
{
	nvme_print(zns_finish_zone_list, flags, nr_zones, zone_list);
}

const char *nvme_zone_type_to_string(__u8 cond)
{
	switch (cond) {
	case NVME_ZONE_TYPE_SEQWRITE_REQ:
		return "SEQWRITE_REQ";
	default:
		return "Unknown";
	}
}

const char *nvme_zone_state_to_string(__u8 state)
{
	switch (state) {
	case NVME_ZNS_ZS_EMPTY:
		return "EMPTY";
	case NVME_ZNS_ZS_IMPL_OPEN:
		return "IMP_OPENED";
	case NVME_ZNS_ZS_EXPL_OPEN:
		return "EXP_OPENED";
	case NVME_ZNS_ZS_CLOSED:
		return "CLOSED";
	case NVME_ZNS_ZS_READ_ONLY:
		return "READONLY";
	case NVME_ZNS_ZS_FULL:
		return "FULL";
	case NVME_ZNS_ZS_OFFLINE:
		return "OFFLINE";
	default:
		return "Unknown State";
	}
}

void nvme_show_zns_report_zones(void *report, __u32 descs,
				__u8 ext_size, __u32 report_size,
				struct json_object *zone_list,
				enum nvme_print_flags flags)
{
	nvme_print(zns_report_zones, flags,
		   report, descs, ext_size, report_size, zone_list);
}

void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	enum nvme_print_flags flags)
{
	nvme_print(ctrl_list, flags, ctrl_list);
}

void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id,
	enum nvme_print_flags flags)
{
	nvme_print(id_nvmset_list, flags, nvmset, nvmset_id);
}

void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps,
				enum nvme_print_flags flags)
{
	nvme_print(primary_ctrl_cap, flags, caps);
}

void nvme_show_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, enum nvme_print_flags flags)
{
	__u16 num = sc_list->num;
	__u32 entries = min(num, count);

	nvme_print(secondary_ctrl_list, flags, sc_list, entries);
}

void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	enum nvme_print_flags flags)
{
	nvme_print(id_ns_granularity_list, flags, glist);
}

void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
				enum nvme_print_flags flags)
{
	nvme_print(id_uuid_list, flags, uuid_list);
}

void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	enum nvme_print_flags flags)
{
	nvme_print(id_domain_list, flags, id_dom);
}

void nvme_show_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list,
	enum nvme_print_flags flags)
{
	nvme_print(endurance_group_list, flags, endgrp_list);
}

void nvme_show_id_iocs(struct nvme_id_iocs *iocs, enum nvme_print_flags flags)
{
	nvme_print(id_iocs, flags, iocs);
}

const char *nvme_trtype_to_string(__u8 trtype)
{
	switch (trtype) {
	case 0: return "The transport type is not indicated or the error "\
		"is not transport related.";
	case 1: return "RDMA Transport error.";
	case 2: return "Fibre Channel Transport error.";
	case 3: return "TCP Transport error.";
	case 254: return "Intra-host Transport error.";
	default: return "Reserved";
	};
}

void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
			 const char *devname, enum nvme_print_flags flags)
{
	nvme_print(error_log, flags, err_log, entries, devname);
}

void nvme_show_resv_report(struct nvme_resv_status *status, int bytes,
			   bool eds, enum nvme_print_flags flags)
{
	nvme_print(resv_report, flags, status, bytes, eds);
}

void nvme_show_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(fw_log, flags, fw_log, devname);
}

void nvme_show_changed_ns_list_log(struct nvme_ns_list *log,
				   const char *devname,
				   enum nvme_print_flags flags)
{
	nvme_print(ns_list_log, flags, log, devname);
}

void nvme_print_effects_log_pages(struct list_head *list,
				  enum nvme_print_flags flags)
{
	nvme_print(effects_log_list, flags, list);
}

const char *nvme_log_to_string(__u8 lid)
{
	switch (lid) {
	case NVME_LOG_LID_SUPPORTED_LOG_PAGES:		return "Supported Log Pages";
	case NVME_LOG_LID_ERROR:			return "Error Information";
	case NVME_LOG_LID_SMART:			return "SMART / Health Information";
	case NVME_LOG_LID_FW_SLOT:			return "Firmware Slot Information";
	case NVME_LOG_LID_CHANGED_NS:			return "Changed Namespace List";
	case NVME_LOG_LID_CMD_EFFECTS:			return "Commands Supported and Effects";
	case NVME_LOG_LID_DEVICE_SELF_TEST:		return "Device Self-test";
	case NVME_LOG_LID_TELEMETRY_HOST:		return "Telemetry Host-Initiated";
	case NVME_LOG_LID_TELEMETRY_CTRL:		return "Telemetry Controller-Initiated";
	case NVME_LOG_LID_ENDURANCE_GROUP:		return "Endurance Group Information";
	case NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:	return "Predictable Latency Per NVM Set";
	case NVME_LOG_LID_PREDICTABLE_LAT_AGG:		return "Predictable Latency Event Aggregate";
	case NVME_LOG_LID_MEDIA_UNIT_STATUS:		return "Media Unit Status";
	case NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST:	return "Supported Capacity Configuration List";
	case NVME_LOG_LID_ANA:				return "Asymmetric Namespace Access";
	case NVME_LOG_LID_PERSISTENT_EVENT:		return "Persistent Event Log";
	case NVME_LOG_LID_LBA_STATUS:			return "LBA Status Information";
	case NVME_LOG_LID_ENDURANCE_GRP_EVT:		return "Endurance Group Event Aggregate";
	case NVME_LOG_LID_FID_SUPPORTED_EFFECTS:	return "Feature Identifiers Supported and Effects";
	case NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS:	return "NVMe-MI Commands Supported and Effects";
	case NVME_LOG_LID_BOOT_PARTITION:		return "Boot Partition";
	case NVME_LOG_LID_FDP_CONFIGS:			return "FDP Configurations";
	case NVME_LOG_LID_FDP_RUH_USAGE:		return "Reclaim Unit Handle Usage";
	case NVME_LOG_LID_FDP_STATS:			return "FDP Statistics";
	case NVME_LOG_LID_FDP_EVENTS:			return "FDP Events";
	case NVME_LOG_LID_DISCOVER:			return "Discovery";
	case NVME_LOG_LID_RESERVATION:			return "Reservation Notification";
	case NVME_LOG_LID_SANITIZE:			return "Sanitize Status";
	case NVME_LOG_LID_ZNS_CHANGED_ZONES:		return "Changed Zone List";
	default:					return "Unknown";
	}
}

void nvme_show_supported_log(struct nvme_supported_log_pages *support_log,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print(supported_log_pages, flags, support_log, devname);
}

void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
			     __u16 group_id, const char *devname,
			     enum nvme_print_flags flags)
{
	nvme_print(endurance_log, flags, endurance_log, group_id, devname);
}

void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, enum nvme_print_flags flags)
{
	nvme_print(smart_log, flags, smart, nsid, devname);
}

void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		       size_t len, enum nvme_print_flags flags)
{
	nvme_print(ana_log, flags, ana_log, devname, len);
}

void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
				__u32 size, const char *devname, enum nvme_print_flags flags)
{
	nvme_print(self_test_log, flags, self_test, dst_entries, size, devname);
}

void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			    const char *devname, enum nvme_print_flags flags)
{
	nvme_print(sanitize_log_page, flags, sanitize, devname);
}

const char *nvme_feature_to_string(enum nvme_features_id feature)
{
	switch (feature) {
	case NVME_FEAT_FID_ARBITRATION:	return "Arbitration";
	case NVME_FEAT_FID_POWER_MGMT:	return "Power Management";
	case NVME_FEAT_FID_LBA_RANGE:	return "LBA Range Type";
	case NVME_FEAT_FID_TEMP_THRESH:	return "Temperature Threshold";
	case NVME_FEAT_FID_ERR_RECOVERY:return "Error Recovery";
	case NVME_FEAT_FID_VOLATILE_WC:	return "Volatile Write Cache";
	case NVME_FEAT_FID_NUM_QUEUES:	return "Number of Queues";
	case NVME_FEAT_FID_IRQ_COALESCE:return "Interrupt Coalescing";
	case NVME_FEAT_FID_IRQ_CONFIG:	return "Interrupt Vector Configuration";
	case NVME_FEAT_FID_WRITE_ATOMIC:return "Write Atomicity Normal";
	case NVME_FEAT_FID_ASYNC_EVENT:	return "Async Event Configuration";
	case NVME_FEAT_FID_AUTO_PST:	return "Autonomous Power State Transition";
	case NVME_FEAT_FID_HOST_MEM_BUF:return "Host Memory Buffer";
	case NVME_FEAT_FID_TIMESTAMP:	return "Timestamp";
	case NVME_FEAT_FID_KATO:	return "Keep Alive Timer";
	case NVME_FEAT_FID_HCTM:	return "Host Controlled Thermal Management";
	case NVME_FEAT_FID_NOPSC:	return "Non-Operational Power State Config";
	case NVME_FEAT_FID_RRL:		return "Read Recovery Level";
	case NVME_FEAT_FID_PLM_CONFIG:	return "Predictable Latency Mode Config";
	case NVME_FEAT_FID_PLM_WINDOW:	return "Predictable Latency Mode Window";
	case NVME_FEAT_FID_LBA_STS_INTERVAL:	return "LBA Status Interval";
	case NVME_FEAT_FID_HOST_BEHAVIOR:	return "Host Behavior";
	case NVME_FEAT_FID_SANITIZE:	return "Sanitize";
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:	return "Endurance Event Group Configuration";
	case NVME_FEAT_FID_IOCS_PROFILE:	return "I/O Command Set Profile";
	case NVME_FEAT_FID_SPINUP_CONTROL:	return "Spinup Control";
	case NVME_FEAT_FID_ENH_CTRL_METADATA:	return "Enhanced Controller Metadata";
	case NVME_FEAT_FID_CTRL_METADATA:	return "Controller Metadata";
	case NVME_FEAT_FID_NS_METADATA: return "Namespace Metadata";
	case NVME_FEAT_FID_SW_PROGRESS:	return "Software Progress";
	case NVME_FEAT_FID_HOST_ID:	return "Host Identifier";
	case NVME_FEAT_FID_RESV_MASK:	return "Reservation Notification Mask";
	case NVME_FEAT_FID_RESV_PERSIST:return "Reservation Persistence";
	case NVME_FEAT_FID_WRITE_PROTECT:	return "Namespace Write Protect";
	case NVME_FEAT_FID_FDP:		return "Flexible Direct Placement";
	case NVME_FEAT_FID_FDP_EVENTS:	return "Flexible Direct Placement Events";
	}
	/*
	 * We don't use the "default:" statement to let the compiler warning if
	 * some values of the enum nvme_features_id are missing in the switch().
	 * The following return is acting as the default: statement.
	 */
	return "Unknown";
}

const char *nvme_register_to_string(int reg)
{
	switch (reg) {
	case NVME_REG_CAP:	return "Controller Capabilities";
	case NVME_REG_VS:	return "Version";
	case NVME_REG_INTMS:	return "Interrupt Vector Mask Set";
	case NVME_REG_INTMC:	return "Interrupt Vector Mask Clear";
	case NVME_REG_CC:	return "Controller Configuration";
	case NVME_REG_CSTS:	return "Controller Status";
	case NVME_REG_NSSR:	return "NVM Subsystem Reset";
	case NVME_REG_AQA:	return "Admin Queue Attributes";
	case NVME_REG_ASQ:	return "Admin Submission Queue Base Address";
	case NVME_REG_ACQ:	return "Admin Completion Queue Base Address";
	case NVME_REG_CMBLOC:	return "Controller Memory Buffer Location";
	case NVME_REG_CMBSZ:	return "Controller Memory Buffer Size";
	default:		return "Unknown";
	}
}

const char *nvme_select_to_string(int sel)
{
	switch (sel) {
	case 0:  return "Current";
	case 1:  return "Default";
	case 2:  return "Saved";
	case 3:  return "Supported capabilities";
	case 8:  return "Changed";
	default: return "Reserved";
	}
}

void nvme_show_select_result(enum nvme_features_id fid, __u32 result)
{
	nvme_print(select_result, NORMAL, fid, result);
}

const char *nvme_feature_lba_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Reserved";
	case 1:	return "Filesystem";
	case 2:	return "RAID";
	case 3:	return "Cache";
	case 4:	return "Page / Swap file";
	default:
		if (type >= 0x05 && type <= 0x7f)
			return "Reserved";
		else
			return "Vendor Specific";
	}
}

void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges,
			 enum nvme_print_flags flags)
{
	nvme_print(lba_range, flags, lbrt, nr_ranges);
}

const char *nvme_feature_wl_hints_to_string(__u8 wh)
{
	switch (wh) {
	case 0:	return "No Workload";
	case 1:	return "Extended Idle Period with a Burst of Random Writes";
	case 2:	return "Heavy Sequential Writes";
	default:return "Reserved";
	}
}

const char *nvme_feature_temp_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Over Temperature Threshold";
	case 1:	return "Under Temperature Threshold";
	default:return "Reserved";
	}
}

const char *nvme_feature_temp_sel_to_string(__u8 sel)
{
	switch (sel) {
	case 0:	return "Composite Temperature";
	case 1:	return "Temperature Sensor 1";
	case 2:	return "Temperature Sensor 2";
	case 3:	return "Temperature Sensor 3";
	case 4:	return "Temperature Sensor 4";
	case 5:	return "Temperature Sensor 5";
	case 6:	return "Temperature Sensor 6";
	case 7:	return "Temperature Sensor 7";
	case 8:	return "Temperature Sensor 8";
	default:return "Reserved";
	}
}

const char *nvme_ns_wp_cfg_to_string(enum nvme_ns_write_protect_cfg state)
{
	switch (state) {
	case NVME_NS_WP_CFG_NONE:
		return "No Write Protect";
	case NVME_NS_WP_CFG_PROTECT:
		return "Write Protect";
	case NVME_NS_WP_CFG_PROTECT_POWER_CYCLE:
		return "Write Protect Until Power Cycle";
	case NVME_NS_WP_CFG_PROTECT_PERMANENT:
		return "Permanent Write Protect";
	default:
		return "Reserved";
	}
}

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
			 void *buf, __u32 len, enum nvme_print_flags flags)
{
	nvme_print(directive, flags, type, oper, spec, nsid, result, buf, len);
}

const char *nvme_plm_window_to_string(__u32 plm)
{
	switch (plm & 0x7) {
	case 1:
		return "Deterministic Window (DTWIN)";
	case 2:
		return "Non-deterministic Window (NDWIN)";
	default:
		return "Reserved";
	}
}

void nvme_show_lba_status_info(__u32 result)
{
	nvme_print(lba_status_info, NORMAL, result);
}

const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid, __u8 type)
{
	switch (fid) {
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
		switch (type) {
		case NVME_CTRL_METADATA_OS_CTRL_NAME:
			return "Operating System Controller Name";
		case NVME_CTRL_METADATA_OS_DRIVER_NAME:
			return "Operating System Driver Name";
		case NVME_CTRL_METADATA_OS_DRIVER_VER:
			return "Operating System Driver Version";
		case NVME_CTRL_METADATA_PRE_BOOT_CTRL_NAME:
			return "Pre-boot Controller Name";
		case NVME_CTRL_METADATA_PRE_BOOT_DRIVER_NAME:
			return "Pre-boot Driver Name";
		case NVME_CTRL_METADATA_PRE_BOOT_DRIVER_VER:
			return "Pre-boot Driver Version";
		case NVME_CTRL_METADATA_SYS_PROC_MODEL:
			return "System Processor Model";
		case NVME_CTRL_METADATA_CHIPSET_DRV_NAME:
			return "Chipset Driver Name";
		case NVME_CTRL_METADATA_CHIPSET_DRV_VERSION:
			return "Chipset Driver Version";
		case NVME_CTRL_METADATA_OS_NAME_AND_BUILD:
			return "Operating System Name and Build";
		case NVME_CTRL_METADATA_SYS_PROD_NAME:
			return "System Product Name";
		case NVME_CTRL_METADATA_FIRMWARE_VERSION:
			return "Firmware Version";
		case NVME_CTRL_METADATA_OS_DRIVER_FILENAME:
			return "Operating System Driver Filename";
		case NVME_CTRL_METADATA_DISPLAY_DRV_NAME:
			return "Display Driver Name";
		case NVME_CTRL_METADATA_DISPLAY_DRV_VERSION:
			return "Display Driver Version";
		case NVME_CTRL_METADATA_HOST_DET_FAIL_REC:
			return "Host-Determined Failure Record";
		default:
			return "Unknown Controller Type";
		}
	case NVME_FEAT_FID_NS_METADATA:
		switch (type) {
		case NVME_NS_METADATA_OS_NS_NAME:
			return "Operating System Namespace Name";
		case NVME_NS_METADATA_PRE_BOOT_NS_NAME:
			return "Pre-boot Namespace Name";
		case NVME_NS_METADATA_OS_NS_QUAL_1:
			return "Operating System Namespace Name Qualifier 1";
		case NVME_NS_METADATA_OS_NS_QUAL_2:
			return "Operating System Namespace Name Qualifier 2";
		default:
			return "Unknown Namespace Type";
		}
	default:
		return "Unknown Feature";
	}
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
		return "Event not associated with any port and PELPID does not apply";
	default:
		break;
	}
	return "Reserved";
}

void nvme_feature_show(enum nvme_features_id fid, int sel, unsigned int result)
{
	nvme_print(show_feature, NORMAL, fid, sel, result);
}

void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result, unsigned char *buf)
{
	nvme_print(show_feature_fields, NORMAL, fid, result, buf);
}

void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
			  enum nvme_print_flags flags)
{
	nvme_print(lba_status, flags, list, len);
}

void nvme_dev_full_path(nvme_ns_t n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "/dev/%s", nvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/spdk/%s", nvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;

	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", nvme_ns_get_name(n));
}

void nvme_generic_full_path(nvme_ns_t n, char *path, size_t len)
{
	int head_instance;
	int instance;
	struct stat st;

	sscanf(nvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance);
	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/spdk/ng%dn%d", instance, head_instance);
	if (stat(path, &st) == 0)
		return;
	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "ng%dn%d", instance, head_instance);
}

void nvme_show_list_item(nvme_ns_t n)
{
	nvme_print(list_item, NORMAL, n);
}

void nvme_show_list_items(nvme_root_t r, enum nvme_print_flags flags)
{
	nvme_print(list_items, flags, r);
}

void nvme_show_topology(nvme_root_t r,
			enum nvme_cli_topo_ranking ranking,
			enum nvme_print_flags flags)
{
	if (ranking == NVME_CLI_TOPO_NAMESPACE)
		nvme_print(topology_namespace, flags, r);
	else
		nvme_print(topology_ctrl, flags, r);
}

void nvme_show_message(bool error, const char *msg, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	va_list ap;

	va_start(ap, msg);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_message)
		ops->show_message(error, msg, ap);

	va_end(ap);
}

void nvme_show_perror(const char *msg)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_perror)
		ops->show_perror(msg);
}

void nvme_show_discovery_log(struct nvmf_discovery_log *log, uint64_t numrec,
			     enum nvme_print_flags flags)
{
	nvme_print(discovery_log, flags, log, numrec);
}

void nvme_show_connect_msg(nvme_ctrl_t c, enum nvme_print_flags flags)
{
	nvme_print(connect_msg, flags, c);
}

void nvme_show_init(void)
{
	nvme_print_output_format(show_init);
}

void nvme_show_finish(void)
{
	nvme_print_output_format(show_finish);
}
