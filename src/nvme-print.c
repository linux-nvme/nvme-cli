// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/int-util.h>
#include <shared/mmio-util.h>
#include <shared/sandbox-util.h>
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
 * The printers which stay in process: the ones which read sysfs while
 * printing and the hooks of the JSON document.
 */
static bool nvme_print_sandboxed(struct print_ops *ops, void *func)
{
	void *in_process[] = {
		ops->config_conn_list,
		ops->show_init, ops->show_finish,
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

