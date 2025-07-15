// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <locale.h>

#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "nvme-models.h"
#include "util/suffix.h"
#include "util/types.h"
#include "common.h"
#include "logging.h"

#define nvme_print(name, flags, ...)				\
	do {							\
		struct print_ops *ops = nvme_print_ops(flags);	\
		if (ops && ops->name && !nvme_cfg.dry_run)	\
			ops->name(__VA_ARGS__);			\
	} while (false)

#define nvme_print_output_format(name, ...)			\
	nvme_print(name, nvme_is_output_format_json() ? JSON : NORMAL, ##__VA_ARGS__);

char *alloc_error = "Could not allocate string";

static struct print_ops *nvme_print_ops(nvme_print_flags_t flags)
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
		case nvme_admin_capacity_mgmt:	return "Capacity Management";
		case nvme_admin_discovery_info_mgmt:return "Discovery Information Management (DIM)";
		case nvme_admin_fabric_zoning_recv:return "Fabric Zoning Receive";
		case nvme_admin_lockdown:	return "Lockdown";
		case nvme_admin_fabric_zoning_lookup:return "Fabric Zoning Lookup";
		case nvme_admin_clear_export_nvm_res:
						return "Clear Exported NVM Resource Configuration";
		case nvme_admin_fabric_zoning_send:return "Fabric Zoning Send";
		case nvme_admin_create_export_nvms:return "Create Exported NVM Subsystem";
		case nvme_admin_manage_export_nvms:return "Manage Exported NVM Subsystem";
		case nvme_admin_manage_export_ns:return "Manage Exported Namespace";
		case nvme_admin_manage_export_port:return "Manage Exported Port";
		case nvme_admin_send_disc_log_page:return "Send Discovery Log Page";
		case nvme_admin_track_send:	return "Track Send";
		case nvme_admin_track_receive:	return "Track Receive";
		case nvme_admin_migration_send:	return "Migration Send";
		case nvme_admin_migration_receive:return "Migration Receive";
		case nvme_admin_ctrl_data_queue:return "Controller Data Queue";
		case nvme_admin_dbbuf:		return "Doorbell Buffer Config";
		case nvme_admin_fabrics:	return "Fabrics Commands";
		case nvme_admin_format_nvm:	return "Format NVM";
		case nvme_admin_security_send:	return "Security Send";
		case nvme_admin_security_recv:	return "Security Receive";
		case nvme_admin_sanitize_nvm:	return "Sanitize";
		case nvme_admin_load_program:	return "Load Program";
		case nvme_admin_get_lba_status:	return "Get LBA Status";
		case nvme_admin_program_act_mgmt:return "Program Activation Management";
		case nvme_admin_mem_range_set_mgmt:return "Memory Range Set Management";
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
		case nvme_cmd_cancel:		return "Cancel";
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
	nvme_print_flags_t flags)
{
	nvme_print(predictable_latency_per_nvmset, flags,
		   plpns_log, nvmset_id, devname);
}

void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	nvme_print(predictable_latency_event_agg_log, flags,
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

	sprintf(str, "%s(%#x)", pel_event_to_string(type), type);

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

void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	nvme_print(persistent_event_log, flags,
		   pevent_log_info, action, size, devname);
}

void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_endurance_group_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags)
{
	nvme_print(endurance_group_event_agg_log, flags,
		   endurance_log, log_entries, size, devname);
}

void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, nvme_print_flags_t flags)
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
	const char *devname, nvme_print_flags_t flags)
{
	nvme_print(resv_notification_log, flags, resv, devname);
}

void nvme_show_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
	const char *devname, nvme_print_flags_t flags)
{
	nvme_print(fid_supported_effects_log, flags, fid_log, devname);
}

void nvme_show_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, nvme_print_flags_t flags)
{
	nvme_print(mi_cmd_support_effects_log, flags,
		   mi_cmd_log, devname);
}

void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, nvme_print_flags_t flags)
{
	nvme_print(boot_part_log, flags, bp_log, devname, size);
}

void nvme_show_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller,
	nvme_print_flags_t flags)
{
	nvme_print(phy_rx_eom_log, flags, log, controller);
}

void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log,
				   nvme_print_flags_t flags)
{
	nvme_print(media_unit_stat_log, flags, mus_log);
}

void nvme_show_fdp_configs(struct nvme_fdp_config_log *log, size_t len,
		nvme_print_flags_t flags)
{
	nvme_print(fdp_config_log, flags, log, len);
}

void nvme_show_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		nvme_print_flags_t flags)
{
	nvme_print(fdp_usage_log, flags,log, len);
}

void nvme_show_fdp_stats(struct nvme_fdp_stats_log *log,
		nvme_print_flags_t flags)
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
		nvme_print_flags_t flags)
{
	nvme_print(fdp_event_log, flags, log);
}

void nvme_show_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
		nvme_print_flags_t flags)
{
	nvme_print(fdp_ruh_status, flags, status, len);
}

void nvme_show_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *cap,
	nvme_print_flags_t flags)
{
	nvme_print(supported_cap_config_list_log, flags, cap);
}

void nvme_show_subsystem_list(nvme_root_t r, bool show_ana,
			      nvme_print_flags_t flags)
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

const char *nvme_register_unit_to_string(__u8 unit)
{
	switch (unit) {
	case NVME_UNIT_B:
		return "Bytes";
	case NVME_UNIT_1K:
		return "One KB";
	case NVME_UNIT_1M:
		return "One MB";
	case NVME_UNIT_1G:
		return "One GB";
	default:
		break;
	}

	return "Reserved";
}

bool nvme_is_fabrics_reg(int offset)
{
	switch (offset) {
	case NVME_REG_CAP:
	case NVME_REG_VS:
	case NVME_REG_CC:
	case NVME_REG_CSTS:
	case NVME_REG_NSSR:
		return true;
	default:
		break;
	}

	return false;
}

bool nvme_is_fabrics_optional_reg(int offset)
{
	switch (offset) {
	case NVME_REG_NSSR:
		return true;
	default:
		break;
	}

	return false;
}

bool nvme_registers_cmbloc_support(__u32 cmbsz)
{
	return !!cmbsz;
}

bool nvme_registers_pmrctl_ready(__u32 pmrctl)
{
	return NVME_PMRCTL_EN(pmrctl);
}

void nvme_show_ctrl_register(void *bar, bool fabrics, int offset, nvme_print_flags_t flags)
{
	uint64_t value;

	if (fabrics && !nvme_is_fabrics_reg(offset)) {
		printf("register: %#04x (%s) not fabrics\n", offset,
		       nvme_register_to_string(offset));
		return;
	}

	if (nvme_is_64bit_reg(offset))
		value = mmio_read64(bar + offset);
	else
		value = mmio_read32(bar + offset);

	nvme_print(ctrl_register, flags, offset, value);
}

void nvme_show_ctrl_registers(void *bar, bool fabrics, nvme_print_flags_t flags)
{
	nvme_print(ctrl_registers, flags, bar, fabrics);
}

void nvme_show_single_property(int offset, uint64_t value64, nvme_print_flags_t flags)
{
	nvme_print(single_property, flags, offset, value64);
}

void nvme_show_relatives(nvme_root_t r, const char *name, nvme_print_flags_t flags)
{
	nvme_print(relatives, flags, r, name);
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

void nvme_show_id_ctrl_rpmbs(__le32 ctrl_rpmbs, nvme_print_flags_t flags)
{
	nvme_print(id_ctrl_rpmbs, flags, ctrl_rpmbs);
}

void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		unsigned int lba_index, bool cap_only, nvme_print_flags_t flags)
{
	nvme_print(id_ns, flags, ns, nsid, lba_index, cap_only);
}


void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	nvme_print_flags_t flags)
{
	nvme_print(id_independent_id_ns, flags, ns, nsid);
}

void nvme_show_id_ns_descs(void *data, unsigned int nsid, nvme_print_flags_t flags)
{
	nvme_print(id_ns_descs, flags, data, nsid);
}

void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, nvme_print_flags_t flags,
			void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	nvme_print(id_ctrl, flags, ctrl, vendor_show);
}

void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	nvme_print_flags_t flags)
{
	nvme_print(id_ctrl_nvm, flags, ctrl_nvm);
}

void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
						struct nvme_id_ns *ns, unsigned int lba_index,
						bool cap_only, nvme_print_flags_t flags)
{
	nvme_print(nvm_id_ns, flags, nvm_ns, nsid, ns, lba_index, cap_only);
}

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl,
			   nvme_print_flags_t flags)
{
	nvme_print(zns_id_ctrl, flags, ctrl);
}

void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
			 struct nvme_id_ns *id_ns,
			 nvme_print_flags_t flags)
{
	nvme_print(zns_id_ns, flags, ns, id_ns);
}

void nvme_show_list_ns(struct nvme_ns_list *ns_list, nvme_print_flags_t flags)
{
	nvme_print(ns_list, flags, ns_list);
}

void nvme_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list,
			      nvme_print_flags_t flags)
{
	nvme_print(zns_start_zone_list, flags, nr_zones, zone_list);
}

void nvme_show_zns_changed(struct nvme_zns_changed_zone_log *log,
			   nvme_print_flags_t flags)
{
	nvme_print(zns_changed_zone_log, flags, log);
}

void nvme_zns_finish_zone_list(__u64 nr_zones, struct json_object *zone_list,
			       nvme_print_flags_t flags)
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
				nvme_print_flags_t flags)
{
	nvme_print(zns_report_zones, flags,
		   report, descs, ext_size, report_size, zone_list);
}

void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	nvme_print_flags_t flags)
{
	nvme_print(ctrl_list, flags, ctrl_list);
}

void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id,
	nvme_print_flags_t flags)
{
	nvme_print(id_nvmset_list, flags, nvmset, nvmset_id);
}

void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps,
				nvme_print_flags_t flags)
{
	nvme_print(primary_ctrl_cap, flags, caps);
}

void nvme_show_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, nvme_print_flags_t flags)
{
	__u16 num = sc_list->num;
	__u32 entries = min(num, count);

	nvme_print(secondary_ctrl_list, flags, sc_list, entries);
}

void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	nvme_print_flags_t flags)
{
	nvme_print(id_ns_granularity_list, flags, glist);
}

void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
				nvme_print_flags_t flags)
{
	nvme_print(id_uuid_list, flags, uuid_list);
}

void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	nvme_print_flags_t flags)
{
	nvme_print(id_domain_list, flags, id_dom);
}

void nvme_show_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list,
	nvme_print_flags_t flags)
{
	nvme_print(endurance_group_list, flags, endgrp_list);
}

void nvme_show_id_iocs(struct nvme_id_iocs *iocs, nvme_print_flags_t flags)
{
	nvme_print(id_iocs, flags, iocs);
}

const char *nvme_trtype_to_string(__u8 trtype)
{
	switch (trtype) {
	case 0: return "The transport type is not indicated or the error "\
		"is not transport related";
	case 1: return "RDMA Transport error";
	case 2: return "Fibre Channel Transport error";
	case 3: return "TCP Transport error";
	case 254: return "Intra-host Transport error";
	default: return "Reserved";
	};
}

void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
			 const char *devname, nvme_print_flags_t flags)
{
	nvme_print(error_log, flags, err_log, entries, devname);
}

void nvme_show_resv_report(struct nvme_resv_status *status, int bytes,
			   bool eds, nvme_print_flags_t flags)
{
	nvme_print(resv_report, flags, status, bytes, eds);
}

void nvme_show_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname, nvme_print_flags_t flags)
{
	nvme_print(fw_log, flags, fw_log, devname);
}

void nvme_show_changed_ns_list_log(struct nvme_ns_list *log, const char *devname,
				   nvme_print_flags_t flags, bool alloc)
{
	nvme_print(ns_list_log, flags, log, devname, alloc);
}

void nvme_print_effects_log_pages(struct list_head *list,
				  nvme_print_flags_t flags)
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
	case NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN:	return "Command and Feature Lockdown";
	case NVME_LOG_LID_BOOT_PARTITION:		return "Boot Partition";
	case NVME_LOG_LID_ROTATIONAL_MEDIA_INFO:	return "Rotational Media Information";
	case NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS:return "Dispersed Namespace Participating NVM Subsystems";
	case NVME_LOG_LID_MGMT_ADDR_LIST:		return "Management Address List";
	case NVME_LOG_LID_PHY_RX_EOM:			return "Physical Interface Receiver Eye Opening Measurement";
	case NVME_LOG_LID_REACHABILITY_GROUPS:		return "Reachability Groups";
	case NVME_LOG_LID_REACHABILITY_ASSOCIATIONS:	return "Reachability Associations";
	case NVME_LOG_LID_CHANGED_ALLOC_NS_LIST:	return "Changed Allocated Namespace List";
	case NVME_LOG_LID_FDP_CONFIGS:			return "FDP Configurations";
	case NVME_LOG_LID_FDP_RUH_USAGE:		return "Reclaim Unit Handle Usage";
	case NVME_LOG_LID_FDP_STATS:			return "FDP Statistics";
	case NVME_LOG_LID_FDP_EVENTS:			return "FDP Events";
	case NVME_LOG_LID_DISCOVER:			return "Discovery";
	case NVME_LOG_LID_HOST_DISCOVER:		return "Host Discovery";
	case NVME_LOG_LID_AVE_DISCOVER:			return "AVE Discovery";
	case NVME_LOG_LID_PULL_MODEL_DDC_REQ:		return "Pull Model DDC Request";
	case NVME_LOG_LID_RESERVATION:			return "Reservation Notification";
	case NVME_LOG_LID_SANITIZE:			return "Sanitize Status";
	case NVME_LOG_LID_ZNS_CHANGED_ZONES:		return "Changed Zone List";
	default:					return "Unknown";
	}
}

void nvme_show_supported_log(struct nvme_supported_log_pages *support_log,
	const char *devname, nvme_print_flags_t flags)
{
	nvme_print(supported_log_pages, flags, support_log, devname);
}

void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
			     __u16 group_id, const char *devname,
			     nvme_print_flags_t flags)
{
	nvme_print(endurance_log, flags, endurance_log, group_id, devname);
}

static bool is_fahrenheit_country(const char *country)
{
	static const char * const countries[] = {
		"AQ", "AS", "BS", "BZ", "CY", "FM", "GU", "KN", "KY", "LR",
		"MH", "MP", "MS", "PR", "PW", "TC", "US", "VG", "VI"
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(countries); i++) {
		if (!strcmp(country, countries[i]))
			return true;
	}

	return false;
}

#ifndef LC_MEASUREMENT
#define LC_MEASUREMENT LC_ALL
#endif

static bool is_temperature_fahrenheit(void)
{
	const char *locale, *underscore;
	char country[3] = { 0 };

	setlocale(LC_MEASUREMENT, "");
	locale = setlocale(LC_MEASUREMENT, NULL);

	if (!locale || strlen(locale) < 2)
		return false;

	underscore = strchr(locale, '_');
	if (underscore && strlen(underscore) >= 3)
		locale = underscore + 1;

	memcpy(country, locale, 2);

	return is_fahrenheit_country(country);
}

const char *nvme_degrees_string(long t)
{
	static char str[STR_LEN];
	long val = kelvin_to_celsius(t);
	bool fahrenheit = is_temperature_fahrenheit();

	if (fahrenheit)
		val = kelvin_to_fahrenheit(t);

	if (nvme_is_output_format_json())
		sprintf(str, "%ld %s", val, fahrenheit ? "Fahrenheit" : "Celsius");
	else
		sprintf(str, "%ld °%s", val, fahrenheit ? "F" : "C");

	return str;
}

void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, nvme_print_flags_t flags)
{
	nvme_print(smart_log, flags, smart, nsid, devname);
}

void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		       size_t len, nvme_print_flags_t flags)
{
	nvme_print(ana_log, flags, ana_log, devname, len);
}

void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
				__u32 size, const char *devname, nvme_print_flags_t flags)
{
	nvme_print(self_test_log, flags, self_test, dst_entries, size, devname);
}

void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			    const char *devname, nvme_print_flags_t flags)
{
	nvme_print(sanitize_log_page, flags, sanitize, devname);
}

const char *nvme_feature_to_string(enum nvme_features_id feature)
{
	switch (feature) {
	case NVME_FEAT_FID_ARBITRATION:		return "Arbitration";
	case NVME_FEAT_FID_POWER_MGMT:		return "Power Management";
	case NVME_FEAT_FID_LBA_RANGE:		return "LBA Range Type";
	case NVME_FEAT_FID_TEMP_THRESH:		return "Temperature Threshold";
	case NVME_FEAT_FID_ERR_RECOVERY:	return "Error Recovery";
	case NVME_FEAT_FID_VOLATILE_WC:		return "Volatile Write Cache";
	case NVME_FEAT_FID_NUM_QUEUES:		return "Number of Queues";
	case NVME_FEAT_FID_IRQ_COALESCE:	return "Interrupt Coalescing";
	case NVME_FEAT_FID_IRQ_CONFIG:		return "Interrupt Vector Configuration";
	case NVME_FEAT_FID_WRITE_ATOMIC:	return "Write Atomicity Normal";
	case NVME_FEAT_FID_ASYNC_EVENT:		return "Async Event Configuration";
	case NVME_FEAT_FID_AUTO_PST:		return "Autonomous Power State Transition";
	case NVME_FEAT_FID_HOST_MEM_BUF:	return "Host Memory Buffer";
	case NVME_FEAT_FID_TIMESTAMP:		return "Timestamp";
	case NVME_FEAT_FID_KATO:		return "Keep Alive Timer";
	case NVME_FEAT_FID_HCTM:		return "Host Controlled Thermal Management";
	case NVME_FEAT_FID_NOPSC:		return "Non-Operational Power State Config";
	case NVME_FEAT_FID_RRL:			return "Read Recovery Level";
	case NVME_FEAT_FID_PLM_CONFIG:		return "Predictable Latency Mode Config";
	case NVME_FEAT_FID_PLM_WINDOW:		return "Predictable Latency Mode Window";
	case NVME_FEAT_FID_LBA_STS_INTERVAL:	return "LBA Status Interval";
	case NVME_FEAT_FID_HOST_BEHAVIOR:	return "Host Behavior";
	case NVME_FEAT_FID_SANITIZE:		return "Sanitize";
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:	return "Endurance Event Group Configuration";
	case NVME_FEAT_FID_IOCS_PROFILE:	return "I/O Command Set Profile";
	case NVME_FEAT_FID_SPINUP_CONTROL:	return "Spinup Control";
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:	return "Power Loss Signaling Config";
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:return "Performance Characteristics";
	case NVME_FEAT_FID_FDP:			return "Flexible Direct Placement";
	case NVME_FEAT_FID_FDP_EVENTS:		return "Flexible Direct Placement Events";
	case NVME_FEAT_FID_NS_ADMIN_LABEL:	return "Namespace Admin Label";
	case NVME_FEAT_FID_KEY_VALUE:		return "Key Value Configuration";
	case NVME_FEAT_FID_CTRL_DATA_QUEUE:	return "Controller Data Queue";
	case NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR:	return "Embedded Management Controller Address";
	case NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR:return "Host Management Agent Address";
	case NVME_FEAT_FID_ENH_CTRL_METADATA:	return "Enhanced Controller Metadata";
	case NVME_FEAT_FID_CTRL_METADATA:	return "Controller Metadata";
	case NVME_FEAT_FID_NS_METADATA:		return "Namespace Metadata";
	case NVME_FEAT_FID_SW_PROGRESS:		return "Software Progress";
	case NVME_FEAT_FID_HOST_ID:		return "Host Identifier";
	case NVME_FEAT_FID_RESV_MASK:		return "Reservation Notification Mask";
	case NVME_FEAT_FID_RESV_PERSIST:	return "Reservation Persistence";
	case NVME_FEAT_FID_WRITE_PROTECT:	return "Namespace Write Protect";
	case NVME_FEAT_FID_BP_WRITE_PROTECT:	return "Boot Partition Write Protection Config";
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
	case NVME_REG_CAP:
		return "Controller Capabilities";
	case NVME_REG_VS:
		return "Version";
	case NVME_REG_INTMS:
		return "Interrupt Vector Mask Set";
	case NVME_REG_INTMC:
		return "Interrupt Vector Mask Clear";
	case NVME_REG_CC:
		return "Controller Configuration";
	case NVME_REG_CSTS:
		return "Controller Status";
	case NVME_REG_NSSR:
		return "NVM Subsystem Reset";
	case NVME_REG_AQA:
		return "Admin Queue Attributes";
	case NVME_REG_ASQ:
		return "Admin Submission Queue Base Address";
	case NVME_REG_ACQ:
		return "Admin Completion Queue Base Address";
	case NVME_REG_CMBLOC:
		return "Controller Memory Buffer Location";
	case NVME_REG_CMBSZ:
		return "Controller Memory Buffer Size";
	case NVME_REG_BPINFO:
		return "Boot Partition Information";
	case NVME_REG_BPRSEL:
		return "Boot Partition Read Select";
	case NVME_REG_BPMBL:
		return "Boot Partition Memory Buffer Location";
	case NVME_REG_CMBMSC:
		return "Controller Memory Buffer Memory Space Control";
	case NVME_REG_CMBSTS:
		return "Controller Memory Buffer Status";
	case NVME_REG_CMBEBS:
		return "Controller Memory Buffer Elasticity Buffer Size";
	case NVME_REG_CMBSWTP:
		return "Controller Memory Buffer Sustained Write Throughput";
	case NVME_REG_NSSD:
		return "NVM Subsystem Shutdown";
	case NVME_REG_CRTO:
		return "Controller Ready Timeouts";
	case NVME_REG_PMRCAP:
		return "Persistent Memory Region Capabilities";
	case NVME_REG_PMRCTL:
		return "Persistent Memory Region Control";
	case NVME_REG_PMRSTS:
		return "Persistent Memory Region Status";
	case NVME_REG_PMREBS:
		return "Persistent Memory Region Elasticity Buffer Size";
	case NVME_REG_PMRSWTP:
		return "Persistent Memory Region Sustained Write Throughput";
	case NVME_REG_PMRMSCL:
		return "Persistent Memory Region Memory Space Control Lower";
	case NVME_REG_PMRMSCU:
		return "Persistent Memory Region Memory Space Control Upper";
	default:
		break;
	}

	return "Unknown";
}

const char *nvme_select_to_string(int sel)
{
	switch (sel) {
	case NVME_GET_FEATURES_SEL_CURRENT:
		return "Current";
	case NVME_GET_FEATURES_SEL_DEFAULT:
		return "Default";
	case NVME_GET_FEATURES_SEL_SAVED:
		return "Saved";
	case NVME_GET_FEATURES_SEL_SUPPORTED:
		return "Supported capabilities";
	default:
		break;
	}
	return "Reserved";
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
			 nvme_print_flags_t flags)
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

const char *nvme_feature_perfc_attri_to_string(__u8 attri)
{
	switch (attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		return "standard performance attribute";
	case NVME_FEAT_PERFC_ATTRI_ID_LIST:
		return "performance attribute identifier list";
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		return "vendor specific performance attribute";
	default:
		break;
	}

	return "reserved";
}

const char *nvme_feature_perfc_r4karl_to_string(__u8 r4karl)
{
	switch (r4karl) {
	case NVME_FEAT_PERFC_R4KARL_NO_REPORT:
		return "not reported";
	case NVME_FEAT_PERFC_R4KARL_GE_100_SEC:
		return "greater than or equal to 100 seconds";
	case NVME_FEAT_PERFC_R4KARL_GE_50_SEC:
		return "greater than or equal to 50 seconds and less than 100 seconds";
	case NVME_FEAT_PERFC_R4KARL_GE_10_SEC:
		return "greater than or equal to 10 seconds and less than 50 seconds";
	case NVME_FEAT_PERFC_R4KARL_GE_5_SEC:
		return "greater than or equal to 5 seconds and less than 10 seconds";
	case NVME_FEAT_PERFC_R4KARL_GE_1_SEC:
		return "greater than or equal to 1 second and less than 5 seconds";
	case NVME_FEAT_PERFC_R4KARL_GE_500_MS:
		return "greater than or equal to 500 milliseconds and less than 1 second";
	case NVME_FEAT_PERFC_R4KARL_GE_100_MS:
		return "greater than or equal to 100 milliseconds and less than 500 milliseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_50_MS:
		return "greater than or equal to 50 milliseconds and less than 100 milliseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_10_MS:
		return "greater than or equal to 10 milliseconds and less than 50 milliseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_5_MS:
		return "greater than or equal to 5 milliseconds and less than 10 milliseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_1_MS:
		return "greater than or equal to 1 millisecond and less than 5 milliseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_500_US:
		return "greater than or equal to 500 microseconds and less than 1 millisecond";
	case NVME_FEAT_PERFC_R4KARL_GE_100_US:
		return "greater than or equal to 100 microseconds and less than 500 microseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_50_US:
		return "greater than or equal to 50 microseconds and less than 100 microseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_10_US:
		return "greater than or equal to 10 microseconds and less than 50 microseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_5_US:
		return "greater than or equal to 5 microseconds and less than 10 microseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_1_US:
		return "greater than or equal to 1 microsecond and less than 5 microseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_500_NS:
		return "greater than or equal to 500 nanoseconds and less than 1 microsecond";
	case NVME_FEAT_PERFC_R4KARL_GE_100_NS:
		return "greater than or equal to 100 nanoseconds and less than 500 nanoseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_50_NS:
		return "greater than or equal to 50 nanoseconds and less than 100 nanoseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_10_NS:
		return "greater than or equal to 10 nanoseconds and less than 50 nanoseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_5_NS:
		return "greater than or equal to 5 nanoseconds and less than 10 nanoseconds";
	case NVME_FEAT_PERFC_R4KARL_GE_1_NS:
		return "greater than or equal to 1 nanosecond and less than 5 nanoseconds";
	default:
		break;
	}

	return "reserved";
}

const char *nvme_feature_perfc_attrtyp_to_string(__u8 attrtyp)
{
	switch (attrtyp) {
	case NVME_GET_FEATURES_SEL_CURRENT:
		return "current attribute";
	case NVME_GET_FEATURES_SEL_DEFAULT:
		return "default attribute";
	case NVME_GET_FEATURES_SEL_SAVED:
		return "saved attribute";
	default:
		break;
	}

	return "reserved";
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

const char *nvme_bpwps_to_string(__u8 bpwps)
{
	switch (bpwps) {
	case NVME_FEAT_BPWPS_CHANGE_NOT_REQUESTED:
		return "Change in state not requested";
	case NVME_FEAT_BPWPS_WRITE_UNLOCKED:
		return "Write Unlocked";
	case NVME_FEAT_BPWPS_WRITE_LOCKED:
		return "Write Locked";
	case NVME_FEAT_BPWPS_WRITE_LOCKED_PWR_CYCLE:
		return "Write Locked Until Power Cycle";
	case NVME_FEAT_BPWPS_WRITE_PROTECTION_RPMB:
		return "Write Protection controlled by RPMB";
	default:
		return "Reserved";
	}
}

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
			 void *buf, __u32 len, nvme_print_flags_t flags)
{
	nvme_print(directive, flags, type, oper, spec, nsid, result, buf, len);
}

const char *nvme_plm_window_to_string(__u32 plm)
{
	switch (NVME_FEAT_PLMW_WS(plm)) {
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

const char *nvme_register_symbol_to_string(int offset)
{
	switch (offset) {
	case NVME_REG_CAP:
		return "cap";
	case NVME_REG_VS:
		return "version";
	case NVME_REG_INTMS:
		return "intms";
	case NVME_REG_INTMC:
		return "intmc";
	case NVME_REG_CC:
		return "cc";
	case NVME_REG_CSTS:
		return "csts";
	case NVME_REG_NSSR:
		return "nssr";
	case NVME_REG_AQA:
		return "aqa";
	case NVME_REG_ASQ:
		return "asq";
	case NVME_REG_ACQ:
		return "acq";
	case NVME_REG_CMBLOC:
		return "cmbloc";
	case NVME_REG_CMBSZ:
		return "cmbsz";
	case NVME_REG_BPINFO:
		return "bpinfo";
	case NVME_REG_BPRSEL:
		return "bprsel";
	case NVME_REG_BPMBL:
		return "bpmbl";
	case NVME_REG_CMBMSC:
		return "cmbmsc";
	case NVME_REG_CMBSTS:
		return "cmbsts";
	case NVME_REG_CMBEBS:
		return "cmbebs";
	case NVME_REG_CMBSWTP:
		return "cmbswtp";
	case NVME_REG_NSSD:
		return "nssd";
	case NVME_REG_CRTO:
		return "crto";
	case NVME_REG_PMRCAP:
		return "pmrcap";
	case NVME_REG_PMRCTL:
		return "pmrctl";
	case NVME_REG_PMRSTS:
		return "pmrsts";
	case NVME_REG_PMREBS:
		return "pmrebs";
	case NVME_REG_PMRSWTP:
		return "pmrswtp";
	case NVME_REG_PMRMSCL:
		return "pmrmscl";
	case NVME_REG_PMRMSCU:
		return "pmrmscu";
	default:
		break;
	}

	return "unknown";
}

const char *nvme_time_scale_to_string(__u8 ts)
{
	switch (ts) {
	case 0:
		return "1 microsecond";
	case 1:
		return "10 microseconds";
	case 2:
		return "100 microseconds";
	case 3:
		return "1 millisecond";
	case 4:
		return "10 milliseconds";
	case 5:
		return "100 milliseconds";
	case 6:
		return "1 second";
	case 7:
		return "10 seconds";
	case 8:
		return "100 seconds";
	case 9:
		return "1,000 seconds";
	case 0xa:
		return "10,000 seconds";
	case 0xb:
		return "100,000 seconds";
	case 0xc:
		return "1,000,000 seconds";
	default:
		break;
	}

	return "Reserved";
}

const char *nvme_pls_mode_to_string(__u8 mode)
{
	switch (mode) {
	case 0:
		return "not enabled";
	case 1:
		return "enabled with Emergency Power Fail";
	case 2:
		return "enabled with Forced Quiescence";
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
			  nvme_print_flags_t flags)
{
	nvme_print(lba_status, flags, list, len);
}

void nvme_dev_full_path(nvme_ns_t n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "%s", nvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/%s", nvme_ns_get_name(n));
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

	/*
	 * There is no block devices for SPDK, point generic path to existing
	 * chardevice.
	 */
	snprintf(path, len, "%s", nvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	sscanf(nvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance);
	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

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

void nvme_show_list_items(nvme_root_t r, nvme_print_flags_t flags)
{
	nvme_print(list_items, flags, r);
}

void nvme_show_topology(nvme_root_t r,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags)
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

void nvme_show_perror(const char *msg, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	va_list ap;

	va_start(ap, msg);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_perror)
		ops->show_perror(msg, ap);

	va_end(ap);
}

void nvme_show_key_value(const char *key, const char *val, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	va_list ap;

	va_start(ap, val);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_key_value)
		ops->show_key_value(key, val, ap);

	va_end(ap);
}

void nvme_show_discovery_log(struct nvmf_discovery_log *log, uint64_t numrec,
			     nvme_print_flags_t flags)
{
	nvme_print(discovery_log, flags, log, numrec);
}

void nvme_show_connect_msg(nvme_ctrl_t c, nvme_print_flags_t flags)
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

void nvme_show_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list, nvme_print_flags_t flags)
{
	nvme_print(mgmt_addr_list_log, flags, ma_list);
}

void nvme_show_rotational_media_info_log(struct nvme_rotational_media_info_log *info,
					 nvme_print_flags_t flags)
{
	nvme_print(rotational_media_info_log, flags, info);
}

void nvme_show_dispersed_ns_psub_log(struct nvme_dispersed_ns_participating_nss_log *log,
				     nvme_print_flags_t flags)
{
	nvme_print(dispersed_ns_psub_log, flags, log);
}

void nvme_show_reachability_groups_log(struct nvme_reachability_groups_log *log,
				       __u64 len, nvme_print_flags_t flags)
{
	nvme_print(reachability_groups_log, flags, log, len);
}

void nvme_show_reachability_associations_log(struct nvme_reachability_associations_log *log,
					     __u64 len, nvme_print_flags_t flags)
{
	nvme_print(reachability_associations_log, flags, log, len);
}

void nvme_show_host_discovery_log(struct nvme_host_discover_log *log, nvme_print_flags_t flags)
{
	nvme_print(host_discovery_log, flags, log);
}

void nvme_show_ave_discovery_log(struct nvme_ave_discover_log *log, nvme_print_flags_t flags)
{
	nvme_print(ave_discovery_log, flags, log);
}

void nvme_show_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log,
				      nvme_print_flags_t flags)
{
	nvme_print(pull_model_ddc_req_log, flags, log);
}

void nvme_show_log(const char *devname, struct nvme_get_log_args *args, nvme_print_flags_t flags)
{
	nvme_print(log, flags, devname, args);
}
