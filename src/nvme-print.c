// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/int-util.h>
#include <shared/mmio-util.h>
#include <shared/sandbox-util.h>
#include <shared/string-util.h>
#include <shared/temp-util.h>

#include "cleanup.h"
#include "nvme-print.h"

/*
 * A printer runs between nvme_print_begin() and nvme_print_end(). The
 * printers which decode device data run in the sandbox, if enabled. See
 * Documentation/PRIVSEP.md.
 */
#define nvme_print(name, flags, ...)				\
	do {							\
		struct print_ops *ops = nvme_print_ops(flags);	\
		if (nvme_print_check(ops, ops->name) &&		\
		    nvme_print_begin(ops,			\
			nvme_print_sandboxed(ops, ops->name))) {	\
			ops->name(__VA_ARGS__);			\
			nvme_print_end(ops);			\
		}						\
	} while (false)

#define nvme_print_output_format(name, ...)			\
	nvme_print(name, nvme_is_output_format_json() ? JSON : NORMAL, ##__VA_ARGS__);

const char *alloc_error = "Could not allocate string";
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

/* Printer calls in progress, a printer may call another one */
static unsigned int print_depth;

/* In the child of a sandboxed printer */
static bool print_in_child;

/* A printer failed in the sandbox */
static bool print_failed;

bool nvme_show_failed(void)
{
	return print_failed;
}

/*
 * The printers which stay in process: the ones of the libnvme tree, which
 * read sysfs while printing, the ones which hand JSON objects to their
 * caller, the interactive one and the document.
 */
static bool nvme_print_sandboxed(struct print_ops *ops, void *func)
{
	void *in_process[] = {
		ops->relatives, ops->list_item, ops->list_items,
		ops->print_nvme_subsystem_list, ops->topology_ctrl,
		ops->topology_namespace, ops->topology_multipath,
		ops->topology_tabular, ops->config_conn_list, ops->top,
		ops->show_init, ops->show_finish,
		ops->connect_msg,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(in_process); i++)
		if (func == in_process[i])
			return false;

	return true;
}

static void nvme_print_error(int err)
{
	print_failed = true;
	if (err == -ECHILD || err == -EPROTO)
		nvme_show_error(
			"the decoder of the device data crashed or misbehaved in the sandbox");
	else
		nvme_show_error(
			"cannot decode the device data in the sandbox: %s",
			libnvme_strerror(-err));
}

/*
 * Return: true if the caller should run the printer, either in process or,
 * if @sandbox is set, in the sandboxed child. A sandboxed printer writes to
 * stdout as usual. Any other output is captured by the output plugin in the
 * child and added in the parent.
 */
static bool nvme_print_begin(struct print_ops *ops, bool sandbox)
{
	struct shr_sandbox_output out;
	int ret;

	if (print_depth++ || !sandbox)
		return true;

	ret = shr_sandbox_begin(&out);
	switch (ret) {
	case SHR_SANDBOX_OFF:
		return true;
	case SHR_SANDBOX_CHILD:
		print_in_child = true;
		/* the caller notices a child without a result */
		if (ops->capture_begin && ops->capture_begin())
			_exit(1);
		return true;
	case SHR_SANDBOX_DONE:
		if (ops->capture_add)
			ret = ops->capture_add(out.buf, out.len);
		else
			ret = out.len ? -EPROTO : 0;
		free(out.buf);
		break;
	}

	print_depth--;
	if (ret)
		nvme_print_error(ret);
	return false;
}

static void nvme_print_end(struct print_ops *ops)
{
	void *buf = NULL;
	size_t len = 0;

	if (--print_depth || !print_in_child)
		return;

	if (ops->capture_end && ops->capture_end(&buf, &len))
		_exit(1);
	shr_sandbox_end(buf, len);
}

static bool nvme_print_check(struct print_ops *ops, void *func)
{
	if (!ops || !func)
		return false;

	/*
	 * Always run init and the finish hooks to properly initialize
	 * the output plugin.
	 */
	if (func == ops->show_init || func == ops->show_finish)
		return true;

	/* Always dump command datum. */
	if (func == ops->d)
		return true;

	/* Always show feature fields since called set features command */
	if (func == ops->show_feature_fields)
		return true;

	if (nvme_args.dry_run)
		return false;

	return true;
}

bool nvme_print_decoder_begin_always(nvme_print_flags_t flags, bool sandbox)
{
	struct print_ops *ops = nvme_print_ops(flags);

	if (!ops)
		return false;

	return nvme_print_begin(ops, sandbox);
}

bool nvme_print_decoder_begin(nvme_print_flags_t flags, bool sandbox)
{
	if (nvme_args.dry_run)
		return false;

	return nvme_print_decoder_begin_always(flags, sandbox);
}

void nvme_print_decoder_end(nvme_print_flags_t flags)
{
	nvme_print_end(nvme_print_ops(flags));
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
		case nvme_admin_manage_export_nvms_receive:return "Manage Exported NVM Subsystem Receive";
		case nvme_admin_manage_export_nvms_send:return "Manage Exported NVM Subsystem Send";
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

void nvme_show_subsystem_list(struct libnvme_global_ctx *ctx, bool show_ana,
			      nvme_print_flags_t flags)
{
	nvme_print(print_nvme_subsystem_list, flags, ctx, show_ana);
}

void nvme_show_relatives(struct libnvme_global_ctx *ctx, const char *name,
			 nvme_print_flags_t flags)
{
	nvme_print(relatives, flags, ctx, name);
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

static void nvme_show_cmd_err(const char *msg, bool admin, __u8 opcode, int err)
{
	if (!err)
		return;
	else if (err < 0)
		nvme_show_error("%s: %s", msg, libnvme_strerror(-err));
	else if (opcode)
		nvme_show_opcode_status(err, admin, opcode);
	else
		nvme_show_status(err);
}

static void show_err(int err, const char *fmt, va_list ap)
{
	__cleanup_free char *msg = NULL;

	if (vasprintf(&msg, fmt, ap) < 0)
		msg = NULL;

	nvme_show_cmd_err(msg ? msg : alloc_error, false, 0, err);
}

void nvme_show_err(int err, const char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	show_err(err, fmt, ap);
	va_end(ap);
	errno = saved_errno;
}

void nvme_show_io_cmd_err(const char *msg, __u8 opcode, int err)
{
	nvme_show_cmd_err(msg, false, opcode, err);
}

void nvme_show_admin_cmd_err(const char *msg, __u8 opcode, int err)
{
	nvme_show_cmd_err(msg, true, opcode, err);
}

void nvme_show_opcode_status(int status, bool admin, __u8 opcode)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_opcode_status)
		ops->show_opcode_status(status, admin, opcode);
}

void nvme_show_error_status(int status, const char *msg, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	va_list ap;

	va_start(ap, msg);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_error_status)
		ops->show_error_status(status, msg, ap);

	va_end(ap);
}

const char *nvme_degrees_string(long t)
{
	static char str[STR_LEN];
	long val = shr_kelvin_to_celsius(t);

	if (nvme_is_output_format_json())
		snprintf(str, sizeof(str), "%ld %s", val, "Celsius");
	else
		snprintf(str, sizeof(str), "%ld °%s", val, "C");

	return str;
}

const char *nvme_degrees_fahrenheit_string(long t)
{
	static char str[STR_LEN];
	long val = shr_kelvin_to_fahrenheit(t);

	if (nvme_is_output_format_json())
		sprintf(str, "%ld %s", val, "Fahrenheit");
	else
		sprintf(str, "%ld °%s", val, "F");

	return str;
}

const char *nvme_format_timestamp(__u8 *timestamp_bytes)
{
	static char buf[STR_LEN];
	struct tm *tm;
	char timebuf[STR_LEN];
	uint64_t ts_ms = int48_to_long(timestamp_bytes);
	time_t ts_sec = ts_ms / 1000;

	tm = localtime(&ts_sec);
	if (!tm) {
		snprintf(buf, sizeof(buf), "%s", "-");
	} else {
		snprintf(buf, sizeof(buf), "%s",
			 strftime(timebuf, sizeof(timebuf), "%c %Z", tm) ? timebuf : "-");
	}

	return buf;
}

const char *nvme_format_timestamp_origin(__u8 attr)
{
	switch (NVME_TIMESTAMP_ATTR_TO(attr)) {
	case 0:
		return "The Timestamp field was initialized to 0h by a Controller Level Reset.";
	case 1:
		return "The Timestamp field was initialized with a Timestamp value using a Set Features command.";
	default:
		return "Reserved";
	}
}

const char *nvme_format_timestamp_sync(__u8 attr)
{
	return NVME_TIMESTAMP_ATTR_SYNC(attr) ?
		"The controller may have stopped counting during vendor specific intervals after the Timestamp value was initialized." :
		"The controller counted time in milliseconds continuously since the Timestamp value was initialized.";
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
	case NVME_FEAT_FID_CONF_DEV_PERSONALITY:return "Configurable Device Personality";
	case NVME_FEAT_FID_POWER_LIMIT:		return "Power Limit";
	case NVME_FEAT_FID_POWER_THRESH:	return "Power Threshold";
	case NVME_FEAT_FID_POWER_MEASUREMENT:	return "Power Measurement";
	case NVME_FEAT_FID_VOLTAGE_THRESHOLD:	return "Voltage Threshold";
	case NVME_FEAT_FID_VOLTAGE_MEASUREMENT:	return "Voltage Measurement";
	case NVME_FEAT_FID_RATE_LIMITING:	return "Rate Limiting";
	case NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR:	return "Embedded Management Controller Address";
	case NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR:return "Host Management Agent Address";
	case NVME_FEAT_FID_ENH_CTRL_METADATA:	return "Enhanced Controller Metadata";
	case NVME_FEAT_FID_CTRL_METADATA:	return "Controller Metadata";
	case NVME_FEAT_FID_NS_METADATA:		return "Namespace Metadata";
	case NVME_FEAT_FID_SW_PROGRESS:		return "Software Progress";
	case NVME_FEAT_FID_HOST_ID:		return "Host Identifier";
	case NVME_FEAT_FID_RESV_NF_MASK:	return "Reservation Notification Mask";
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
	nvme_print(select_result, NORMAL, fid, result);
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

const char *nvme_feature_power_limit_scale_to_string(__u8 pls)
{
	switch (pls) {
	case NVME_PSD_PS_NOT_REPORTED:
		return "not reported";
	case NVME_PSD_PS_100_MICRO_WATT:
		return "0.0001 W";
	case NVME_PSD_PS_10_MILLI_WATT:
		return "0.01 W";
	default:
		break;
	}

	return "Reserved";
}

const char *nvme_power_measurement_type_to_string(__u8 pmt)
{
	switch (pmt) {
	case NVME_PMT_NSS_TOTAL_POWER:
		return "NVM subsystem total power";
	case NVME_PMT_VS_MIN ... NVME_PMT_VS_MAX:
		return "Vendor Specific";
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

const char *nvme_ipmsr_srs_to_string(__u8 srs)
{
	switch (srs) {
	case 0:
		return "Not reported";
	case 1:
		return "1 microsecond";
	case 2:
		return "10 microseconds";
	case 3:
		return "100 microseconds";
	case 4:
		return "1 millisecond";
	case 5:
		return "10 milliseconds";
	default:
		return "Reserved";
	}
}

void nvme_show_feature(enum nvme_features_id fid, int sel, unsigned int result,
		       void *buf, __u32 data_len, nvme_print_flags_t flags)
{
	nvme_print(show_feature, flags, fid, sel, result, buf, data_len);
}

void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result, unsigned char *buf)
{
	nvme_print(show_feature_fields, NORMAL, fid, result, buf);
}

void nvme_dev_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (shr_startswith(path, "/dev/spdk/") && stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/%s", libnvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;
	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
}

void nvme_generic_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	int head_instance;
	int instance;
	struct stat st;

	/*
	 * There is no block devices for SPDK, point generic path to existing
	 * chardevice.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (shr_startswith(path, "/dev/spdk/") && stat(path, &st) == 0)
		return;

	if (sscanf(libnvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance) != 2)
		return;

	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;
	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_generic_name(n));
}

void nvme_show_list_item(struct libnvme_ns *n, struct shr_table *t)
{
	nvme_print(list_item, NORMAL, n, t);
}

void nvme_show_list_items(struct libnvme_global_ctx *ctx, nvme_print_flags_t flags)
{
	nvme_print(list_items, flags, ctx);
}

void nvme_show_top(nvme_print_flags_t flags, int refresh_interval)
{
	nvme_print(top, flags, refresh_interval);
}

void nvme_show_topology(struct libnvme_global_ctx *ctx,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags)
{
	if (ranking == NVME_CLI_TOPO_NAMESPACE)
		nvme_print(topology_namespace, flags, ctx);
	else if (ranking == NVME_CLI_TOPO_CTRL)
		nvme_print(topology_ctrl, flags, ctx);
	else
		nvme_print(topology_multipath, flags, ctx);
}

void nvme_show_topology_tabular(struct libnvme_global_ctx *ctx, nvme_print_flags_t flags)
{
	nvme_print(topology_tabular, flags, ctx);
}

/*
 * The message helpers keep errno: a caller may report the failure of a
 * call before it returns its errno.
 */
static void show_message(bool error, const char *msg, va_list ap)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	int err = errno;

	if (nvme_args.quiet && !error)
		return;

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_message)
		ops->show_message(error, msg, ap);
	errno = err;
}

void nvme_show_message(bool error, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);

	show_message(error, msg, ap);

	va_end(ap);
}

void nvme_show_verbose_message(const char *msg, ...)
{
	va_list ap;

	if (!nvme_args.verbose)
		return;

	va_start(ap, msg);

	show_message(false, msg, ap);

	va_end(ap);
}

void nvme_show_perror(const char *msg, ...)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);
	int err = errno;
	va_list ap;

	va_start(ap, msg);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_perror)
		ops->show_perror(msg, ap);

	va_end(ap);
	errno = err;
}

static void show_key_value(const char *key, const char *val, va_list ap)
{
	struct print_ops *ops = nvme_print_ops(NORMAL);

	if (nvme_is_output_format_json())
		ops = nvme_print_ops(JSON);

	if (ops && ops->show_key_value)
		ops->show_key_value(key, val, ap);
}

void nvme_show_key_value(const char *key, const char *val, ...)
{
	va_list ap;

	va_start(ap, val);

	show_key_value(key, val, ap);

	va_end(ap);
}
void nvme_show_verbose_key_value(const char *key, const char *val, ...)
{
	va_list ap;

	if (!nvme_args.verbose)
		return;

	va_start(ap, val);

	show_key_value(key, val, ap);

	va_end(ap);
}

void nvme_show_discovery_log(const struct nvmf_discovery_log *log,
			     uint64_t numrec, nvme_print_flags_t flags)
{
	nvme_print(discovery_log, flags, log, numrec);
}

void nvme_show_connect_msg(struct libnvme_ctrl *c, nvme_print_flags_t flags)
{
	nvme_print(connect_msg, flags, c);
}

void nvme_show_config_conn_list(struct libnvmf_config *config,
				 nvme_print_flags_t flags)
{
	nvme_print(config_conn_list, flags, config);
}

void nvme_show_init(void)
{
	nvme_print_output_format(show_init);
}

void nvme_show_finish(void)
{
	nvme_print_output_format(show_finish);
}

static struct nvme_log_decoder *log_decoders;

void nvme_register_log_decoder(struct nvme_log_decoder *dec)
{
	dec->next = log_decoders;
	log_decoders = dec;
}

bool nvme_show_log_decoded(const char *devname, enum nvme_cmd_get_log_lid lid,
			   __u32 nsid, __u16 lsi, __u8 lsp, void *log,
			   __u32 len, nvme_print_flags_t flags)
{
	struct nvme_log_decoder *dec;

	for (dec = log_decoders; dec; dec = dec->next)
		if (dec->show(devname, lid, nsid, lsi, lsp, log, len, flags))
			return true;

	return false;
}

const char *nvme_support_str(bool support)
{
	if (support)
		return "Supported";

	return "Not Supported";
}

const char *nvme_yes_str(bool yes)
{
	if (yes)
		return "Yes";

	return "No";
}

