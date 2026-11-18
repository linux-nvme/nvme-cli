// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "feat-print.h"
#include "nvme-print.h"

const char *feat_ae_dlpcn = "Discovery Log Page Change Notices";
const char *feat_ae_hdlpcn = "Host Discovery Log Page Change Notification";
const char *feat_ae_adlpcn = "AVE Discovery Log Page Change Notification";
const char *feat_ae_pmdrlpcn =
	"Pull Model DDC Request Log Page Change Notification";
const char *feat_ae_zdcn = "Zone Descriptor Changed Notices";
const char *feat_ae_rlccn = "Rate Limiting Configuration Change Notices";
const char *feat_ae_lhcn = "Lost Host Communication Notices";
const char *feat_ae_ccrcn = "Cross-Controller Reset Completed Notices";
const char *feat_ae_ansan = "Allocated Namespace Attribute Notices";
const char *feat_ae_rgrp0 = "Reachability Group";
const char *feat_ae_rassn = "Reachability Association";
const char *feat_ae_tthry = "Temperature Threshold Hysteresis Recovery";
const char *feat_ae_nnsshdn = "Normal NVM Subsystem Shutdown";
const char *feat_ae_ega = "Endurance Group Event Aggregate Log Change Notices";
const char *feat_ae_lbas = "LBA Status Information Notices";
const char *feat_ae_pla =
	"Predictable Latency Event Aggregate Log Change Notices";
const char *feat_ae_ana = "Asymmetric Namespace Access Change Notices";
const char *feat_ae_telem = "Telemetry Log Notices";
const char *feat_ae_fw = "Firmware Activation Notices";
const char *feat_ae_nan = "Attached Namespace Attribute Notices";
const char *feat_ae_smart = "SMART / Health Critical Warnings";

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define feat_print(name, flags, ...)					\
	do {								\
		struct feat_print_ops *__fops = feat_print_ops(flags);	\
									\
		if (__fops && __fops->name)				\
			nvme_print_decoder(__fops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

/* Like feat_print(), but for dry runs as well */
#define feat_print_always(name, flags, ...)				\
	do {								\
		struct feat_print_ops *__fops = feat_print_ops(flags);	\
									\
		if (__fops && __fops->name)				\
			nvme_print_decoder_always(__fops, name, true,	\
						  flags, ##__VA_ARGS__); \
	} while (false)

static struct feat_print_ops *feat_print_ops(nvme_print_flags_t flags)
{
	struct feat_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = feat_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = feat_get_binary_print_ops(flags);
	else
		ops = feat_get_stdout_print_ops(flags);

	return ops;
}

const char *nvme_feature_to_string(enum nvme_features_id feature)
{
	switch (feature) {
	case NVME_FEAT_FID_ARBITRATION:
		return "Arbitration";
	case NVME_FEAT_FID_POWER_MGMT:
		return "Power Management";
	case NVME_FEAT_FID_LBA_RANGE:
		return "LBA Range Type";
	case NVME_FEAT_FID_TEMP_THRESH:
		return "Temperature Threshold";
	case NVME_FEAT_FID_ERR_RECOVERY:
		return "Error Recovery";
	case NVME_FEAT_FID_VOLATILE_WC:
		return "Volatile Write Cache";
	case NVME_FEAT_FID_NUM_QUEUES:
		return "Number of Queues";
	case NVME_FEAT_FID_IRQ_COALESCE:
		return "Interrupt Coalescing";
	case NVME_FEAT_FID_IRQ_CONFIG:
		return "Interrupt Vector Configuration";
	case NVME_FEAT_FID_WRITE_ATOMIC:
		return "Write Atomicity Normal";
	case NVME_FEAT_FID_ASYNC_EVENT:
		return "Async Event Configuration";
	case NVME_FEAT_FID_AUTO_PST:
		return "Autonomous Power State Transition";
	case NVME_FEAT_FID_HOST_MEM_BUF:
		return "Host Memory Buffer";
	case NVME_FEAT_FID_TIMESTAMP:
		return "Timestamp";
	case NVME_FEAT_FID_KATO:
		return "Keep Alive Timer";
	case NVME_FEAT_FID_HCTM:
		return "Host Controlled Thermal Management";
	case NVME_FEAT_FID_NOPSC:
		return "Non-Operational Power State Config";
	case NVME_FEAT_FID_RRL:
		return "Read Recovery Level";
	case NVME_FEAT_FID_PLM_CONFIG:
		return "Predictable Latency Mode Config";
	case NVME_FEAT_FID_PLM_WINDOW:
		return "Predictable Latency Mode Window";
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		return "LBA Status Interval";
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		return "Host Behavior";
	case NVME_FEAT_FID_SANITIZE:
		return "Sanitize";
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		return "Endurance Event Group Configuration";
	case NVME_FEAT_FID_IOCS_PROFILE:
		return "I/O Command Set Profile";
	case NVME_FEAT_FID_SPINUP_CONTROL:
		return "Spinup Control";
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:
		return "Power Loss Signaling Config";
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		return "Performance Characteristics";
	case NVME_FEAT_FID_FDP:
		return "Flexible Direct Placement";
	case NVME_FEAT_FID_FDP_EVENTS:
		return "Flexible Direct Placement Events";
	case NVME_FEAT_FID_NS_ADMIN_LABEL:
		return "Namespace Admin Label";
	case NVME_FEAT_FID_KEY_VALUE:
		return "Key Value Configuration";
	case NVME_FEAT_FID_CTRL_DATA_QUEUE:
		return "Controller Data Queue";
	case NVME_FEAT_FID_CONF_DEV_PERSONALITY:
		return "Configurable Device Personality";
	case NVME_FEAT_FID_POWER_LIMIT:
		return "Power Limit";
	case NVME_FEAT_FID_POWER_THRESH:
		return "Power Threshold";
	case NVME_FEAT_FID_POWER_MEASUREMENT:
		return "Power Measurement";
	case NVME_FEAT_FID_VOLTAGE_THRESHOLD:
		return "Voltage Threshold";
	case NVME_FEAT_FID_VOLTAGE_MEASUREMENT:
		return "Voltage Measurement";
	case NVME_FEAT_FID_RATE_LIMITING:
		return "Rate Limiting";
	case NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR:
		return "Embedded Management Controller Address";
	case NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR:
		return "Host Management Agent Address";
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
		return "Enhanced Controller Metadata";
	case NVME_FEAT_FID_CTRL_METADATA:
		return "Controller Metadata";
	case NVME_FEAT_FID_NS_METADATA:
		return "Namespace Metadata";
	case NVME_FEAT_FID_SW_PROGRESS:
		return "Software Progress";
	case NVME_FEAT_FID_HOST_ID:
		return "Host Identifier";
	case NVME_FEAT_FID_RESV_NF_MASK:
		return "Reservation Notification Mask";
	case NVME_FEAT_FID_RESV_PERSIST:
		return "Reservation Persistence";
	case NVME_FEAT_FID_WRITE_PROTECT:
		return "Namespace Write Protect";
	case NVME_FEAT_FID_BP_WRITE_PROTECT:
		return "Boot Partition Write Protection Config";
	}
	/*
	 * We don't use the "default:" statement to let the compiler warning if
	 * some values of the enum nvme_features_id are missing in the switch().
	 * The following return is acting as the default: statement.
	 */
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

void nvme_show_select_result(enum nvme_features_id fid, __u64 result)
{
	feat_print(select_result, NORMAL, fid, result);
}

const char *nvme_feature_lba_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "General Purpose";
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
	feat_print(lba_range, flags, lbrt, nr_ranges);
}

const char *nvme_feature_wl_hints_to_string(__u8 wh)
{
	switch (wh) {
	case 0:
		return "No Workload";
	case 1:
		return "Extended Idle Period with a Burst of Random Writes";
	case 2:
		return "Heavy Sequential Writes";
	default:
		return "Reserved";
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
		return (
		"greater than or equal to 50 seconds and less than 100 seconds");
	case NVME_FEAT_PERFC_R4KARL_GE_10_SEC:
		return (
		"greater than or equal to 10 seconds and less than 50 seconds");
	case NVME_FEAT_PERFC_R4KARL_GE_5_SEC:
		return (
		"greater than or equal to 5 seconds and less than 10 seconds");
	case NVME_FEAT_PERFC_R4KARL_GE_1_SEC:
		return (
		"greater than or equal to 1 second and less than 5 seconds");
	case NVME_FEAT_PERFC_R4KARL_GE_500_MS:
		return (
		"greater than or equal to 500 milliseconds and less than 1 second");
	case NVME_FEAT_PERFC_R4KARL_GE_100_MS:
		return (
		"greater than or equal to 100 milliseconds and less than 500 milliseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_50_MS:
		return (
		"greater than or equal to 50 milliseconds and less than 100 milliseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_10_MS:
		return (
		"greater than or equal to 10 milliseconds and less than 50 milliseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_5_MS:
		return (
		"greater than or equal to 5 milliseconds and less than 10 milliseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_1_MS:
		return (
		"greater than or equal to 1 millisecond and less than 5 milliseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_500_US:
		return (
		"greater than or equal to 500 microseconds and less than 1 millisecond");
	case NVME_FEAT_PERFC_R4KARL_GE_100_US:
		return (
		"greater than or equal to 100 microseconds and less than 500 microseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_50_US:
		return (
		"greater than or equal to 50 microseconds and less than 100 microseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_10_US:
		return (
		"greater than or equal to 10 microseconds and less than 50 microseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_5_US:
		return (
		"greater than or equal to 5 microseconds and less than 10 microseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_1_US:
		return (
		"greater than or equal to 1 microsecond and less than 5 microseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_500_NS:
		return (
		"greater than or equal to 500 nanoseconds and less than 1 microsecond");
	case NVME_FEAT_PERFC_R4KARL_GE_100_NS:
		return (
		"greater than or equal to 100 nanoseconds and less than 500 nanoseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_50_NS:
		return (
		"greater than or equal to 50 nanoseconds and less than 100 nanoseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_10_NS:
		return (
		"greater than or equal to 10 nanoseconds and less than 50 nanoseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_5_NS:
		return (
		"greater than or equal to 5 nanoseconds and less than 10 nanoseconds");
	case NVME_FEAT_PERFC_R4KARL_GE_1_NS:
		return (
		"greater than or equal to 1 nanosecond and less than 5 nanoseconds");
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

void nvme_show_lba_status_info(__u64 result)
{
	feat_print(lba_status_info, NORMAL, result);
}

const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid,
					      __u8 type)
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

const char *nvme_power_measurement_action_to_string(__u8 act)
{
	switch (act) {
	case 0:
		return "Stop";
	case 1:
		return "Start";
	default:
		break;
	}

	return "Reserved";
}

void nvme_show_feature(enum nvme_features_id fid, int sel, unsigned int result,
		       void *buf, __u32 data_len, nvme_print_flags_t flags)
{
	feat_print(show_feature, flags, fid, sel, result, buf, data_len);
}

void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf)
{
	/* Always show the fields, the set commands show what they set */
	feat_print_always(show_feature_fields, NORMAL, fid, result, buf);
}
