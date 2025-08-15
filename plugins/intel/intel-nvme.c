// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "intel-nvme.h"

struct __packed nvme_additional_smart_log_item {
	__u8			key;
	__u8			_kp[2];
	__u8			norm;
	__u8			_np;
	union __packed {
		__u8		raw[6];
		struct __packed  wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level;
		struct __packed thermal_throttle {
			__u8	pct;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_rp;
};

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	program_fail_cnt;
	struct nvme_additional_smart_log_item	erase_fail_cnt;
	struct nvme_additional_smart_log_item	wear_leveling_cnt;
	struct nvme_additional_smart_log_item	e2e_err_cnt;
	struct nvme_additional_smart_log_item	crc_err_cnt;
	struct nvme_additional_smart_log_item	timed_workload_media_wear;
	struct nvme_additional_smart_log_item	timed_workload_host_reads;
	struct nvme_additional_smart_log_item	timed_workload_timer;
	struct nvme_additional_smart_log_item	thermal_throttle_status;
	struct nvme_additional_smart_log_item	retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item	pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item	nand_bytes_written;
	struct nvme_additional_smart_log_item	host_bytes_written;
	struct nvme_additional_smart_log_item	host_ctx_wear_used;
	struct nvme_additional_smart_log_item	perf_stat_indicator;
	struct nvme_additional_smart_log_item	re_alloc_sectr_cnt;
	struct nvme_additional_smart_log_item	soft_ecc_err_rate;
	struct nvme_additional_smart_log_item	unexp_power_loss;
	struct nvme_additional_smart_log_item	media_bytes_read;
	struct nvme_additional_smart_log_item	avail_fw_downgrades;
};

struct nvme_vu_id_ctrl_field { /* CDR MR5 */
	__u8			rsvd1[3];
	__u8			ss;
	__u8			health[20];
	__u8			cls;
	__u8			nlw;
	__u8			scap;
	__u8			sstat;
	__u8			bl[8];
	__u8			rsvd2[38];
	__u8			ww[8]; /* little endian */
	__u8			mic_bl[4];
	__u8			mic_fw[4];
};

static void json_intel_id_ctrl(struct nvme_vu_id_ctrl_field *id,
	char *health, char *bl, char *ww, char *mic_bl, char *mic_fw,
	struct json_object *root)
{
	json_object_add_value_int(root, "ss", id->ss);
	json_object_add_value_string(root, "health", health);
	json_object_add_value_int(root, "cls", id->cls);
	json_object_add_value_int(root, "nlw", id->nlw);
	json_object_add_value_int(root, "scap", id->scap);
	json_object_add_value_int(root, "sstat", id->sstat);
	json_object_add_value_string(root, "bl", bl);
	json_object_add_value_string(root, "ww", ww);
	json_object_add_value_string(root, "mic_bl", mic_bl);
	json_object_add_value_string(root, "mic_fw", mic_fw);
}

static void intel_id_ctrl(__u8 *vs, struct json_object *root)
{
	struct nvme_vu_id_ctrl_field *id = (struct nvme_vu_id_ctrl_field *)vs;

	char health[21] = { 0 };
	char bl[9] = { 0 };
	char ww[19] = { 0 };
	char mic_bl[5] = { 0 };
	char mic_fw[5] = { 0 };

	if (id->health[0] == 0)
		snprintf(health, 21, "%s", "healthy");
	else
		snprintf(health, 21, "%s", id->health);

	snprintf(bl, 9, "%s", id->bl);
	snprintf(ww, 19, "%02X%02X%02X%02X%02X%02X%02X%02X", id->ww[7],
		id->ww[6], id->ww[5], id->ww[4], id->ww[3], id->ww[2],
		id->ww[1], id->ww[0]);
	snprintf(mic_bl, 5, "%s", id->mic_bl);
	snprintf(mic_fw, 5, "%s", id->mic_fw);

	if (root) {
		json_intel_id_ctrl(id, health, bl, ww, mic_bl, mic_fw, root);
		return;
	}

	printf("ss        : %d\n", id->ss);
	printf("health    : %s\n", health);
	printf("cls       : %d\n", id->cls);
	printf("nlw       : %d\n", id->nlw);
	printf("scap      : %d\n", id->scap);
	printf("sstat     : %d\n", id->sstat);
	printf("bl        : %s\n", bl);
	printf("ww        : %s\n", ww);
	printf("mic_bl    : %s\n", mic_bl);
	printf("mic_fw    : %s\n", mic_fw);
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, intel_id_ctrl);
}

static void
show_intel_smart_log_jsn(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	struct json_object *root, *entry_stats, *dev_stats, *multi;

	root = json_create_object();
	json_object_add_value_string(root, "Intel Smart log", devname);

	dev_stats = json_create_object();

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->program_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->program_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "program_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->erase_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_cnt.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min", le16_to_cpu(smart->wear_leveling_cnt.wear_level.min));
	json_object_add_value_int(multi, "max", le16_to_cpu(smart->wear_leveling_cnt.wear_level.max));
	json_object_add_value_int(multi, "avg", le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "wear_leveling", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->e2e_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->e2e_err_cnt.raw));
	json_object_add_value_object(dev_stats, "end_to_end_error_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->crc_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->crc_err_cnt.raw));
	json_object_add_value_object(dev_stats, "crc_error_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_media_wear.norm);
	json_object_add_value_double(entry_stats, "raw", ((long double)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	json_object_add_value_object(dev_stats, "timed_workload_media_wear", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_host_reads.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_host_reads.raw));
	json_object_add_value_object(dev_stats, "timed_workload_host_reads", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_timer.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_timer.raw));
	json_object_add_value_object(dev_stats, "timed_workload_timer", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->thermal_throttle_status.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "pct", smart->thermal_throttle_status.thermal_throttle.pct);
	json_object_add_value_int(multi, "cnt", smart->thermal_throttle_status.thermal_throttle.count);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "thermal_throttle_status", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->retry_buffer_overflow_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_object(dev_stats, "retry_buffer_overflow_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->pll_lock_loss_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_object(dev_stats, "pll_lock_loss_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->host_bytes_written.raw));
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_ctx_wear_used.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->host_ctx_wear_used.raw));
	json_object_add_value_object(dev_stats, "host_ctx_wear_used", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->perf_stat_indicator.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->perf_stat_indicator.raw));
	json_object_add_value_object(dev_stats, "perf_stat_indicator", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->re_alloc_sectr_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->re_alloc_sectr_cnt.raw));
	json_object_add_value_object(dev_stats, "re_alloc_sectr_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->soft_ecc_err_rate.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->soft_ecc_err_rate.raw));
	json_object_add_value_object(dev_stats, "soft_ecc_err_rate", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->unexp_power_loss.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->unexp_power_loss.raw));
	json_object_add_value_object(dev_stats, "unexp_power_loss", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->media_bytes_read.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->media_bytes_read.raw));
	json_object_add_value_object(dev_stats, "media_bytes_read", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->avail_fw_downgrades.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->avail_fw_downgrades.raw));
	json_object_add_value_object(dev_stats, "avail_fw_downgrades", entry_stats);

	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static char *id_to_key(__u8 id)
{
	switch (id) {
	case 0xAB:
		return "program_fail_count";
	case 0xAC:
		return "erase_fail_count";
	case 0xAD:
		return "wear_leveling_count";
	case 0xB8:
		return "e2e_error_detect_count";
	case 0xC7:
		return "crc_error_count";
	case 0xE2:
		return "media_wear_percentage";
	case 0xE3:
		return "host_reads";
	case 0xE4:
		return "timed_work_load";
	case 0xEA:
		return "thermal_throttle_status";
	case 0xF0:
		return "retry_buff_overflow_count";
	case 0xF3:
		return "pll_lock_loss_counter";
	case 0xF4:
		return "nand_bytes_written";
	case 0xF5:
		return "host_bytes_written";
	case 0xF6:
		return "host_context_wear_used";
	case 0xF7:
		return "performance_status_indicator";
	case 0xF8:
		return "media_bytes_read";
	case 0xF9:
		return "available_fw_downgrades";
	case 0x05:
		return "re-allocated_sector_count";
	case 0x0D:
		return "soft_ecc_error_rate";
	case 0xAE:
		return "unexpected_power_loss";
	default:
		return "Invalid ID";
	}
}

static void print_intel_smart_log_items(struct nvme_additional_smart_log_item *item)
{
	if (!item->key)
		return;

	printf("%#x    %-45s  %3d         %"PRIu64"\n",
		item->key, id_to_key(item->key),
		item->norm, int48_to_long(item->raw));
}

static void show_intel_smart_log(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	struct nvme_additional_smart_log_item *iter = &smart->program_fail_cnt;
	int num_items = sizeof(struct nvme_additional_smart_log) /
				sizeof(struct nvme_additional_smart_log_item);

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		devname, nsid);
	printf("ID             KEY                                 Normalized     Raw\n");

	for (int i = 0; i < num_items; i++, iter++)
		print_intel_smart_log_items(iter);
}

static int get_additional_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Get Intel vendor specific additional smart log (optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "Dump output in binary format";
#ifdef CONFIG_JSONC
	const char *json = "Dump output in json format";
#endif /* CONFIG_JSONC */

	struct nvme_additional_smart_log smart_log;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u32 namespace_id;
		bool  raw_binary;
		bool  json;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_FLAG_JSON("json",    'j', &cfg.json,         json),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(hdl, 0xca, &smart_log, sizeof(smart_log));
	if (!err) {
		if (cfg.json)
			show_intel_smart_log_jsn(&smart_log, cfg.namespace_id,
						 nvme_transport_handle_get_name(hdl));
		else if (!cfg.raw_binary)
			show_intel_smart_log(&smart_log, cfg.namespace_id,
					     nvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	} else if (err > 0) {
		nvme_show_status(err);
	}
	return err;
}

static int get_market_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get Intel Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	char log[512];
	int err;

	struct config {
		bool  raw_binary;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(hdl, 0xdd, log, sizeof(log));
	if (!err) {
		if (!cfg.raw_binary)
			printf("Intel Marketing Name Log:\n%s\n", log);
		else
			d_raw((unsigned char *)&log, sizeof(log));
	} else if (err > 0)
		nvme_show_status(err);
	return err;
}

struct intel_temp_stats {
	__le64	curr;
	__le64	last_overtemp;
	__le64	life_overtemp;
	__le64	highest_temp;
	__le64	lowest_temp;
	__u8	rsvd[40];
	__le64	max_operating_temp;
	__le64	min_operating_temp;
	__le64	est_offset;
};

static void show_temp_stats(struct intel_temp_stats *stats)
{
	printf("  Intel Temperature Statistics\n");
	printf("--------------------------------\n");
	printf("Current temperature         : %"PRIu64"\n", le64_to_cpu(stats->curr));
	printf("Last critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->last_overtemp));
	printf("Life critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->life_overtemp));
	printf("Highest temperature         : %"PRIu64"\n", le64_to_cpu(stats->highest_temp));
	printf("Lowest temperature          : %"PRIu64"\n", le64_to_cpu(stats->lowest_temp));
	printf("Max operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->max_operating_temp));
	printf("Min operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->min_operating_temp));
	printf("Estimated offset            : %"PRIu64"\n", le64_to_cpu(stats->est_offset));
}

static int get_temp_stats_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct intel_temp_stats stats;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	const char *desc = "Get Temperature Statistics log and show it.";
	const char *raw = "dump output in binary format";
	struct config {
		bool  raw_binary;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(hdl, 0xc5, &stats, sizeof(stats));
	if (!err) {
		if (!cfg.raw_binary)
			show_temp_stats(&stats);
		else
			d_raw((unsigned char *)&stats, sizeof(stats));
	} else if (err > 0)
		nvme_show_status(err);
	return err;
}

struct intel_lat_stats {
	__u16 maj;
	__u16 min;
	__u32 data[1216];
};

struct __packed optane_lat_stats {
	__u16 maj;
	__u16 min;
	__u64 data[9];
};

#define MEDIA_MAJOR_IDX			0
#define MEDIA_MINOR_IDX			1
#define MEDIA_MAX_LEN			2
#define OPTANE_V1000_BUCKET_LEN		8
#define OPTANE_V1000_BUCKET_LEN		8
#define NAND_LAT_STATS_LEN		4868


static struct intel_lat_stats stats;
static struct optane_lat_stats v1000_stats;

struct v1000_thresholds {
	__u32 read[OPTANE_V1000_BUCKET_LEN];
	__u32 write[OPTANE_V1000_BUCKET_LEN];
};

static struct v1000_thresholds v1000_bucket;
static __u16 media_version[MEDIA_MAX_LEN] = {0};

enum FormatUnit {
	US,
	MS,
	S
};

/*
 * COL_WIDTH controls width of columns in human-readable output.
 * BUFSIZE is for local temp char[]
 * US_IN_S and US_IN_MS are for unit conversions when printing.
 */
#define COL_WIDTH 12
#define BUFSIZE 10
#define US_IN_S 1000000
#define US_IN_MS 1000

static enum FormatUnit get_seconds_magnitude(__u32 microseconds)
{
	if (microseconds > US_IN_S)
		return S;
	else if (microseconds > US_IN_MS)
		return MS;
	else
		return US;
}

static float convert_seconds(__u32 microseconds)
{
	float divisor = 1.0;

	if (microseconds > US_IN_S)
		divisor = US_IN_S;
	else if (microseconds > US_IN_MS)
		divisor = US_IN_MS;
	return microseconds / divisor;
}

/*
 * For control over whether a string will format to +/-INF or
 * print out ####.##US normally.
 */
enum inf_bound_type {
	NEGINF,
	POSINF,
	NOINF
};

/*
 * Edge buckets may have range [#s, inf) or (-inf, #US] in some
 * latency statistics formats.
 * Passing in NEGINF to POSINF to bound_type overrides the string to
 * either of "-INF" or "+INF", respectively.
 */
static void set_unit_string(char *buffer, __u32 microseconds,
			    enum FormatUnit unit,
			    enum inf_bound_type bound_type)
{
	char *string;

	if (bound_type != NOINF) {
		snprintf(buffer, BUFSIZE, "%s", bound_type ? "+INF" : "-INF");
		return;
	}

	switch (unit) {
	case US:
		string = "us";
		break;
	case MS:
		string = "ms";
		break;
	case S:
		string = "s";
		break;
	default:
		string = "_s";
		break;
	}

	snprintf(buffer, BUFSIZE, "%4.2f%s", convert_seconds(microseconds),
		 string);
}

static void init_buffer(char *buffer, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		buffer[i] = i + '0';
}

static void show_lat_stats_bucket(struct intel_lat_stats *stats,
	__u32 lower_us, enum inf_bound_type start_type,
	__u32 upper_us, enum inf_bound_type end_type, int i)
{
	enum FormatUnit fu = S;
	char buffer[BUFSIZE];

	init_buffer(buffer, BUFSIZE);
	printf("%-*d", COL_WIDTH, i);

	fu = get_seconds_magnitude(lower_us);
	set_unit_string(buffer, lower_us, fu, start_type);
	printf("%-*s", COL_WIDTH, buffer);

	fu = get_seconds_magnitude(upper_us);
	set_unit_string(buffer, upper_us, fu, end_type);
	printf("%-*s", COL_WIDTH, buffer);

	printf("%-*d\n", COL_WIDTH, stats->data[i]);
}

static void show_optane_lat_stats_bucket(struct optane_lat_stats *stats,
	__u32 lower_us, enum inf_bound_type start_type,
	__u32 upper_us, enum inf_bound_type end_type, int i)
{
	enum FormatUnit fu = S;
	char buffer[BUFSIZE];

	init_buffer(buffer, BUFSIZE);
	printf("%-*d", COL_WIDTH, i);

	fu = get_seconds_magnitude(lower_us);
	set_unit_string(buffer, lower_us, fu, start_type);
	printf("%-*s", COL_WIDTH, buffer);

	fu = get_seconds_magnitude(upper_us);
	set_unit_string(buffer, upper_us, fu, end_type);
	printf("%-*s", COL_WIDTH, buffer);

	printf("%-*lu\n", COL_WIDTH, (unsigned long)stats->data[i]);
}


static void show_lat_stats_linear(struct intel_lat_stats *stats,
	__u32 start_offset, __u32 end_offset, __u32 bytes_per,
	__u32 us_step, bool nonzero_print)
{
	for (int i = (start_offset / bytes_per) - 1;
			i < end_offset / bytes_per; i++) {
		if (nonzero_print && stats->data[i] == 0)
			continue;
		show_lat_stats_bucket(stats, us_step * i, NOINF,
			us_step * (i + 1), NOINF, i);
	}
}

/*
 * For 4.0-4.5 revision.
 */
#define LATENCY_STATS_V4_BASE_BITS	6
#define LATENCY_STATS_V4_BASE_VAL	(1 << LATENCY_STATS_V4_BASE_BITS)

static int lat_stats_log_scale(int i)
{
	// if (i < 128)
	if (i < (LATENCY_STATS_V4_BASE_VAL << 1))
		return i;

	int error_bits = (i >> LATENCY_STATS_V4_BASE_BITS) - 1;
	int base = 1 << (error_bits + LATENCY_STATS_V4_BASE_BITS);
	int k = i % LATENCY_STATS_V4_BASE_VAL;

	return base + ((k + 0.5) * (1 << error_bits));
}

/*
 * Creates a subroot in the following manner:
 * {
 *   "latstats" : {
 *     "type" : "write" or "read",
 *     "values" : {
 */
static void lat_stats_make_json_root(
	struct json_object *root, struct json_object *bucket_list,
	int write)
{
	struct json_object *subroot = json_create_object();

	json_object_add_value_object(root, "latstats", subroot);
	json_object_add_value_string(subroot, "type", write ? "write" : "read");
	json_object_add_value_object(subroot, "values", bucket_list);
}

/*
 * Creates a bucket under the "values" json_object. Format is:
 * "values" : {
 *   "bucket" : {
 *     "id" : #,
 *     "start" : string,
 *     "end" : string,
 *     "value" : 0,
 *   },
 */
static void json_add_bucket(struct intel_lat_stats *stats,
	struct json_object *bucket_list, __u32 id,
	__u32 lower_us, enum inf_bound_type start_type,
	__u32 upper_us, enum inf_bound_type end_type, __u32 val)
{
	char buffer[BUFSIZE];
	struct json_object *bucket = json_create_object();

	init_buffer(buffer, BUFSIZE);

	json_object_array_add(bucket_list, bucket);
	json_object_add_value_int(bucket, "id", id);

	set_unit_string(buffer, lower_us,
		get_seconds_magnitude(lower_us), start_type);
	json_object_add_value_string(bucket, "start", buffer);

	set_unit_string(buffer, upper_us,
		get_seconds_magnitude(upper_us), end_type);
	json_object_add_value_string(bucket, "end", buffer);

	json_object_add_value_int(bucket, "value", val);
}

static void json_add_bucket_optane(struct json_object *bucket_list, __u32 id,
				   __u32 lower_us, enum inf_bound_type start_type,
				   __u32 upper_us, enum inf_bound_type end_type, __u32 val)
{
	char buffer[BUFSIZE];
	struct json_object *bucket = json_create_object();

	init_buffer(buffer, BUFSIZE);

	json_object_array_add(bucket_list, bucket);
	json_object_add_value_int(bucket, "id", id);

	set_unit_string(buffer, lower_us,
		get_seconds_magnitude(lower_us), start_type);
	json_object_add_value_string(bucket, "start", buffer);

	set_unit_string(buffer, upper_us,
		get_seconds_magnitude(upper_us), end_type);
	json_object_add_value_string(bucket, "end", buffer);

	json_object_add_value_uint(bucket, "value", val);

}

static void json_lat_stats_linear(struct intel_lat_stats *stats,
	struct json_object *bucket_list, __u32 start_offset,
	__u32 end_offset, __u32 bytes_per,
	__u32 us_step, bool nonzero_print)
{
	for (int i = (start_offset / bytes_per) - 1;
			i < end_offset / bytes_per; i++) {
		if (nonzero_print && stats->data[i] == 0)
			continue;

		json_add_bucket(stats, bucket_list,
			i, us_step * i, NOINF, us_step * (i + 1),
			NOINF, stats->data[i]);
	}
}

static void json_lat_stats_3_0(struct intel_lat_stats *stats, int write)
{
	struct json_object *root = json_create_object();
	struct json_object *bucket_list = json_object_new_array();

	lat_stats_make_json_root(root, bucket_list, write);

	json_lat_stats_linear(stats, bucket_list, 4, 131, 4, 32, false);
	json_lat_stats_linear(stats, bucket_list, 132, 255, 4, 1024, false);
	json_lat_stats_linear(stats, bucket_list, 256, 379, 4, 32768, false);
	json_lat_stats_linear(stats, bucket_list, 380, 383, 4, 32, true);
	json_lat_stats_linear(stats, bucket_list, 384, 387, 4, 32, true);
	json_lat_stats_linear(stats, bucket_list, 388, 391, 4, 32, true);

	json_print_object(root, NULL);
	json_free_object(root);
}

static void json_lat_stats_4_0(struct intel_lat_stats *stats, int write)
{
	struct json_object *root = json_create_object();
	struct json_object *bucket_list = json_object_new_array();

	lat_stats_make_json_root(root, bucket_list, write);

	__u32 lower_us = 0;
	__u32 upper_us = 1;
	bool end = false;
	int max = 1216;

	for (int i = 0; i < max; i++) {
		lower_us = lat_stats_log_scale(i);
		if (i >= max - 1)
			end = true;
		else
			upper_us = lat_stats_log_scale(i + 1);

		json_add_bucket(stats, bucket_list, i,
			lower_us, NOINF, upper_us,
			end ? POSINF : NOINF, stats->data[i]);
	}
	json_print_object(root, NULL);
	json_free_object(root);
}

static void show_lat_stats_3_0(struct intel_lat_stats *stats)
{
	show_lat_stats_linear(stats, 4, 131, 4, 32, false);
	show_lat_stats_linear(stats, 132, 255, 4, 1024, false);
	show_lat_stats_linear(stats, 256, 379, 4, 32768, false);
	show_lat_stats_linear(stats, 380, 383, 4, 32, true);
	show_lat_stats_linear(stats, 384, 387, 4, 32, true);
	show_lat_stats_linear(stats, 388, 391, 4, 32, true);
}

static void show_lat_stats_4_0(struct intel_lat_stats *stats)
{
	int lower_us = 0;
	int upper_us = 1;
	bool end = false;
	int max = 1216;

	for (int i = 0; i < max; i++) {
		lower_us = lat_stats_log_scale(i);
		if (i >= max - 1)
			end = true;
		else
			upper_us = lat_stats_log_scale(i + 1);

		show_lat_stats_bucket(stats, lower_us, NOINF,
			upper_us, end ? POSINF : NOINF, i);
	}
}

static void json_lat_stats_v1000_0(struct optane_lat_stats *stats, int write)
{
	int i;
	struct json_object *root = json_create_object();
	struct json_object *bucket_list = json_object_new_array();

	lat_stats_make_json_root(root, bucket_list, write);

	if (write) {
		for (i = 0; i < OPTANE_V1000_BUCKET_LEN - 1; i++)
			json_add_bucket_optane(bucket_list, i,
					       v1000_bucket.write[i], NOINF,
					       v1000_bucket.write[i + 1] - 1,
					       NOINF,
					       stats->data[i]);

		json_add_bucket_optane(bucket_list,
				       OPTANE_V1000_BUCKET_LEN - 1,
				       v1000_bucket.write[i],
				       NOINF,
				       v1000_bucket.write[i],
				       POSINF, stats->data[i]);
	} else {
		for (i = 0; i < OPTANE_V1000_BUCKET_LEN - 1; i++)
			json_add_bucket_optane(bucket_list, i,
					       v1000_bucket.read[i], NOINF,
					       v1000_bucket.read[i + 1] - 1,
					       NOINF,
					       stats->data[i]);

		json_add_bucket_optane(bucket_list,
				       OPTANE_V1000_BUCKET_LEN - 1,
				       v1000_bucket.read[i],
				       NOINF,
				       v1000_bucket.read[i],
				       POSINF, stats->data[i]);
	}

	struct json_object *subroot = json_create_object();

	json_object_add_value_object(root, "Average latency since last reset", subroot);

	json_object_add_value_uint(subroot, "value in us", stats->data[8]);

	json_print_object(root, NULL);
	json_free_object(root);

}

static void show_lat_stats_v1000_0(struct optane_lat_stats *stats, int write)
{
	int i;

	if (write) {
		for (i = 0; i < OPTANE_V1000_BUCKET_LEN - 1; i++)
			show_optane_lat_stats_bucket(stats,
						     v1000_bucket.write[i],
						     NOINF,
						     v1000_bucket.write[i + 1] - 1,
						     NOINF, i);

		show_optane_lat_stats_bucket(stats, v1000_bucket.write[i],
					     NOINF, v1000_bucket.write[i],
					     POSINF, i);
	} else {
		for (i = 0; i < OPTANE_V1000_BUCKET_LEN - 1; i++)
			show_optane_lat_stats_bucket(stats,
						     v1000_bucket.read[i],
						     NOINF,
						     v1000_bucket.read[i + 1] - 1,
						     NOINF, i);

		show_optane_lat_stats_bucket(stats, v1000_bucket.read[i],
					     NOINF, v1000_bucket.read[i],
					     POSINF, i);
	}

	printf("Average latency since last reset: %lu us\n", (unsigned long)stats->data[8]);

}

static void json_lat_stats(int write)
{
	switch (media_version[MEDIA_MAJOR_IDX]) {
	case 3:
		json_lat_stats_3_0(&stats, write);
		break;
	case 4:
		switch (media_version[MEDIA_MINOR_IDX]) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			json_lat_stats_4_0(&stats, write);
			break;
		default:
			printf("Unsupported minor revision (%u.%u)\n",
				stats.maj, stats.min);
			break;
		}
		break;
	case 1000:
		switch (media_version[MEDIA_MINOR_IDX]) {
		case 0:
			json_lat_stats_v1000_0(&v1000_stats, write);
			break;
		default:
			printf("Unsupported minor revision (%u.%u)\n",
				stats.maj, stats.min);
			break;
		}
		break;
	default:
		printf("Unsupported revision (%u.%u)\n",
			stats.maj, stats.min);
		break;
	}
	printf("\n");
}

static void
print_dash_separator(int count)
{
	for (int i = 0; i < count; i++)
		putchar('-');
	putchar('\n');
}

static void show_lat_stats(int write)
{
	static const int separator_length = 50;

	printf("Intel IO %s Command Latency Statistics\n",
		write ? "Write" : "Read");
	printf("Major Revision : %u\nMinor Revision : %u\n",
		media_version[MEDIA_MAJOR_IDX], media_version[MEDIA_MINOR_IDX]);
	print_dash_separator(separator_length);
	printf("%-12s%-12s%-12s%-20s\n", "Bucket", "Start", "End", "Value");
	print_dash_separator(separator_length);

	switch (media_version[MEDIA_MAJOR_IDX]) {
	case 3:
		show_lat_stats_3_0(&stats);
		break;
	case 4:
		switch (media_version[MEDIA_MINOR_IDX]) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
			show_lat_stats_4_0(&stats);
			break;
		default:
			printf("Unsupported minor revision (%u.%u)\n",
				stats.maj, stats.min);
			break;
		}
		break;
	case 1000:
		switch (media_version[MEDIA_MINOR_IDX]) {
		case 0:
			show_lat_stats_v1000_0(&v1000_stats, write);
			break;
		default:
			printf("Unsupported minor revision (%u.%u)\n",
				stats.maj, stats.min);
			break;
		}
		break;
	default:
		printf("Unsupported revision (%u.%u)\n",
				stats.maj, stats.min);
		break;
	}
}

static int get_lat_stats_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	__u8 data[NAND_LAT_STATS_LEN];
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	const char *desc = "Get Intel Latency Statistics log and show it.";
	const char *raw = "Dump output in binary format";
#ifdef CONFIG_JSONC
	const char *json = "Dump output in json format";
#endif /* CONFIG_JSONC */
	const char *write = "Get write statistics (read default)";

	struct config {
		bool raw_binary;
		bool json;
		bool write;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("write",	'w', &cfg.write,	write),
		OPT_FLAG("raw-binary",	'b', &cfg.raw_binary,	raw),
		OPT_FLAG_JSON("json",	'j', &cfg.json,		json),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	/* For optate, latency stats are deleted every time their LID is pulled.
	 * Therefore, we query the longest lat_stats log page first.
	 */
	err = nvme_get_log_simple(hdl, cfg.write ? 0xc2 : 0xc1,
				  &data, sizeof(data));

	media_version[0] = (data[1] << 8) | data[0];
	media_version[1] = (data[3] << 8) | data[2];

	if (err)
		return err;

	if (media_version[0] == 1000) {
		__u32 thresholds[OPTANE_V1000_BUCKET_LEN] = {0};
		__u32 result;

		struct nvme_get_features_args args = {
			.args_size	= sizeof(args),
			.fid		= 0xf7,
			.nsid		= 0,
			.sel		= 0,
			.cdw11		= cfg.write ? 0x1 : 0x0,
			.uuidx		= 0,
			.data_len	= sizeof(thresholds),
			.data		= thresholds,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
			.result		= &result,
		};
		err = nvme_get_features(hdl, &args);
		if (err) {
			fprintf(stderr, "Querying thresholds failed. ");
			nvme_show_status(err);
			return err;
		}

		/* Update bucket thresholds to be printed */
		if (cfg.write) {
			for (int i = 0; i < OPTANE_V1000_BUCKET_LEN; i++)
				v1000_bucket.write[i] = thresholds[i];
		} else {
			for (int i = 0; i < OPTANE_V1000_BUCKET_LEN; i++)
				v1000_bucket.read[i] = thresholds[i];

		}

		/* Move counter values to optate stats struct which has a
		 * smaller size
		 */
		memcpy(&v1000_stats, (struct optane_lat_stats *)data,
		       sizeof(struct optane_lat_stats));
	} else {
		memcpy(&stats, (struct intel_lat_stats *)data,
		       sizeof(struct intel_lat_stats));
	}

	if (cfg.json)
		json_lat_stats(cfg.write);
	else if (!cfg.raw_binary)
		show_lat_stats(cfg.write);
	else {
		if (media_version[0] == 1000)
			d_raw((unsigned char *)&v1000_stats,
			      sizeof(v1000_stats));
		else
			d_raw((unsigned char *)&stats,
			      sizeof(stats));
	}

	return 0;
}

struct intel_assert_dump {
	__u32 coreoffset;
	__u32 assertsize;
	__u8  assertdumptype;
	__u8  assertvalid;
	__u8  reserved[2];
};

struct intel_event_dump {
	__u32 numeventdumps;
	__u32 coresize;
	__u32 coreoffset;
	__u32 eventidoffset[16];
	__u8  eventIdValidity[16];
};

struct intel_vu_version {
	__u16    major;
	__u16    minor;
};

struct intel_event_header {
	__u32 eventidsize;
	struct intel_event_dump edumps[0];
};

struct intel_vu_log {
	struct intel_vu_version ver;
	__u32    header;
	__u32    size;
	__u32    numcores;
	__u8     reserved[4080];
};

struct intel_vu_nlog {
	struct intel_vu_version ver;
	__u32 logselect;
	__u32 totalnlogs;
	__u32 nlognum;
	__u32 nlogname;
	__u32 nlogbytesize;
	__u32 nlogprimarybuffsize;
	__u32 tickspersecond;
	__u32 corecount;
	__u32 nlogpausestatus;
	__u32 selectoffsetref;
	__u32 selectnlogpause;
	__u32 selectaddedoffset;
	__u32 nlogbufnum;
	__u32 nlogbufnummax;
	__u32 coreselected;
	__u32 reserved[3];
};

struct intel_cd_log {
	union {
		struct {
			__u32 selectLog  : 3;
			__u32 selectCore : 2;
			__u32 selectNlog : 8;
			__u8  selectOffsetRef : 1;
			__u32 selectNlogPause : 2;
			__u32 reserved2  : 16;
		} fields;
		__u32 entireDword;
	} u;
};

static void print_intel_nlog(struct intel_vu_nlog *intel_nlog)
{
	printf("Version Major %u\n"
	       "Version Minor %u\n"
	       "Log_select %u\n"
	       "totalnlogs %u\n"
	       "nlognum %u\n"
	       "nlogname %u\n"
	       "nlogbytesze %u\n"
	       "nlogprimarybuffsize %u\n"
	       "tickspersecond %u\n"
	       "corecount %u\n"
	       "nlogpausestatus %u\n"
	       "selectoffsetref %u\n"
	       "selectnlogpause %u\n"
	       "selectaddedoffset %u\n"
	       "nlogbufnum %u\n"
	       "nlogbufnummax %u\n"
	       "coreselected %u\n",
	       intel_nlog->ver.major, intel_nlog->ver.minor,
	       intel_nlog->logselect, intel_nlog->totalnlogs, intel_nlog->nlognum,
	       intel_nlog->nlogname, intel_nlog->nlogbytesize,
	       intel_nlog->nlogprimarybuffsize, intel_nlog->tickspersecond,
	       intel_nlog->corecount, intel_nlog->nlogpausestatus,
	       intel_nlog->selectoffsetref, intel_nlog->selectnlogpause,
	       intel_nlog->selectaddedoffset, intel_nlog->nlogbufnum,
	       intel_nlog->nlogbufnummax, intel_nlog->coreselected);
}

static int read_entire_cmd(struct nvme_passthru_cmd *cmd, int total_size,
			   const size_t max_tfer, int out_fd,
			   struct nvme_transport_handle *hdl, __u8 *buf)
{
	int err = 0;
	size_t dword_tfer = 0;

	dword_tfer = min(max_tfer, total_size);
	while (total_size > 0) {
		err = nvme_submit_admin_passthru(hdl, cmd, NULL);
		if (err) {
			fprintf(stderr,
				"failed on cmd.data_len %u cmd.cdw13 %u cmd.cdw12 %x cmd.cdw10 %u err %x remaining size %d\n",
				cmd->data_len, cmd->cdw13, cmd->cdw12,
				cmd->cdw10, err, total_size);
			goto out;
		}

		if (out_fd > 0) {
			err = write(out_fd, buf, cmd->data_len);
			if (err < 0) {
				perror("write failure");
				goto out;
			}
			err = 0;
		}
		total_size -= dword_tfer;
		cmd->cdw13 += dword_tfer;
		cmd->cdw10 = dword_tfer = min(max_tfer, total_size);
		cmd->data_len = (min(max_tfer, total_size)) * 4;
	}

 out:
	return err;
}

static int write_header(__u8 *buf, int fd, size_t amnt)
{
	if (write(fd, buf, amnt) < 0)
		return 1;
	return 0;
}

static int read_header(struct nvme_passthru_cmd *cmd, __u8 *buf,
		       struct nvme_transport_handle *hdl, __u32 dw12, int nsid)
{
	memset(cmd, 0, sizeof(*cmd));
	memset(buf, 0, 4096);
	cmd->opcode = 0xd2;
	cmd->nsid = nsid;
	cmd->cdw10 = 0x400;
	cmd->cdw12 = dw12;
	cmd->data_len = 0x1000;
	cmd->addr = (unsigned long)(void *)buf;
	return read_entire_cmd(cmd, 0x400, 0x400, -1, hdl, buf);
}

static int setup_file(char *f, char *file, struct nvme_transport_handle *hdl, int type)
{
	struct nvme_id_ctrl ctrl;
	int err = 0, i = sizeof(ctrl.sn) - 1;

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err)
		return err;

	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}

	sprintf(f, "%s_%-.*s.bin", type == 0 ? "Nlog" :
		type == 1 ? "EventLog" :  "AssertLog",
		(int)sizeof(ctrl.sn), ctrl.sn);
	return err;
}

static int get_internal_log_old(__u8 *buf, int output,
				struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd)
{
	struct intel_vu_log *intel;
	int err = 0;
	const int dwmax = 0x400;
	const int dmamax = 0x1000;

	intel = (struct intel_vu_log *)buf;

	printf("Log major:%d minor:%d header:%d size:%d\n",
		intel->ver.major, intel->ver.minor, intel->header, intel->size);

	err = write(output, buf, 0x1000);
	if (err < 0) {
		perror("write failure");
		goto out;
	}
	intel->size -= 0x400;
	cmd->opcode = 0xd2;
	cmd->cdw10 = min(dwmax, intel->size);
	cmd->data_len = min(dmamax, intel->size);
	err = read_entire_cmd(cmd, intel->size, dwmax, output, hdl, buf);
	if (err)
		goto out;

	err = 0;
 out:
	return err;
}

static int get_internal_log(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	__u8 buf[0x2000];
	char f[0x100];
	int err, output, i, j, count = 0, core_num = 1;
	struct nvme_passthru_cmd cmd;
	struct intel_cd_log cdlog;
	struct intel_vu_log *intel = malloc(sizeof(struct intel_vu_log));
	struct intel_vu_nlog *intel_nlog = (struct intel_vu_nlog *)buf;
	struct intel_assert_dump *ad = (struct intel_assert_dump *) intel->reserved;
	struct intel_event_header *ehdr = (struct intel_event_header *)intel->reserved;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	const char *desc = "Get Intel Firmware Log and save it.";
	const char *log = "Log type: 0, 1, or 2 for nlog, event log, and assert log, respectively.";
	const char *core = "Select which region log should come from. -1 for all";
	const char *nlognum = "Select which nlog to read. -1 for all nlogs";
	const char *file = "Output file; defaults to device name provided";
	const char *verbose = "To print out verbose nlog info";
	const char *namespace_id = "Namespace to get logs from";

	struct config {
		__u32 namespace_id;
		__u32 log;
		int core;
		int lnum;
		char *file;
		bool verbose;
	};

	struct config cfg = {
		.namespace_id = -1,
		.file = NULL,
		.lnum = -1,
		.core = -1
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log",          'l', &cfg.log,          log),
		OPT_INT("region",        'r', &cfg.core,         core),
		OPT_INT("nlognum",       'm', &cfg.lnum,         nlognum),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FILE("output-file",  'o', &cfg.file,         file),
		OPT_FLAG("verbose-nlog", 'v', &cfg.verbose,      verbose),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		free(intel);
		return err;
	}

	if (cfg.log > 2 || cfg.core > 4 || cfg.lnum > 255) {
		err = -EINVAL;
		goto out_free;
	}

	if (!cfg.file) {
		err = setup_file(f, cfg.file, hdl, cfg.log);
		if (err)
			goto out_free;
		cfg.file = f;
	}

	cdlog.u.entireDword = 0;

	cdlog.u.fields.selectLog = cfg.log;
	cdlog.u.fields.selectCore = cfg.core < 0 ? 0 : cfg.core;
	cdlog.u.fields.selectNlog = cfg.lnum < 0 ? 0 : cfg.lnum;

	output = open(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		err = output;
		goto out_free;
	}

	err = read_header(&cmd, buf, hdl, cdlog.u.entireDword,
			  cfg.namespace_id);
	if (err)
		goto out;
	memcpy(intel, buf, sizeof(*intel));

	/* for 1.1 Fultondales will use old nlog, but current assert/event */
	if ((intel->ver.major < 1 && intel->ver.minor < 1) ||
	    (intel->ver.major <= 1 && intel->ver.minor <= 1 && cfg.log == 0)) {
		cmd.addr = (unsigned long)(void *)buf;
		err = get_internal_log_old(buf, output, hdl, &cmd);
		goto out;
	}

	if (cfg.log == 2) {
		if (cfg.verbose)
			printf("Log major:%d minor:%d header:%d size:%d numcores:%d\n",
			       intel->ver.major, intel->ver.minor,
				intel->header, intel->size, intel->numcores);

		err = write_header(buf, output, 0x1000);
		if (err) {
			perror("write failure");
			goto out;
		}

		count = intel->numcores;
	} else if (cfg.log == 0) {
		if (cfg.lnum < 0)
			count = intel_nlog->totalnlogs;
		else
			count = 1;
		if (cfg.core < 0)
			core_num = intel_nlog->corecount;
	} else if (cfg.log == 1) {
		core_num = intel->numcores;
		count = 1;
		err = write_header(buf, output, sizeof(*intel));
		if (err)
			goto out;
	}

	for (j = (cfg.core < 0 ? 0 : cfg.core);
			j < (cfg.core < 0 ? core_num : cfg.core + 1);
			j++) {
		cdlog.u.fields.selectCore = j;
		for (i = 0; i < count; i++) {
			if (cfg.log == 2) {
				if (!ad[i].assertvalid)
					continue;
				cmd.cdw13 = ad[i].coreoffset;
				cmd.cdw10 = 0x400;
				cmd.data_len = min(0x400, ad[i].assertsize) * 4;
				err = read_entire_cmd(&cmd, ad[i].assertsize,
						      0x400, output,
						      hdl,
						      buf);
				if (err)
					goto out;

			} else if (cfg.log == 0) {
				/* If the user selected to read the entire nlog */
				if (count > 1)
					cdlog.u.fields.selectNlog = i;

				err = read_header(&cmd, buf, hdl,
						  cdlog.u.entireDword,
						  cfg.namespace_id);
				if (err)
					goto out;
				err = write_header(buf, output, sizeof(*intel_nlog));
				if (err)
					goto out;
				if (cfg.verbose)
					print_intel_nlog(intel_nlog);
				cmd.cdw13 = 0x400;
				cmd.cdw10 = 0x400;
				cmd.data_len = min(0x1000, intel_nlog->nlogbytesize);
				err = read_entire_cmd(&cmd, intel_nlog->nlogbytesize / 4,
						      0x400, output,
						      hdl,
						      buf);
				if (err)
					goto out;
			} else if (cfg.log == 1) {
				cmd.cdw13 = ehdr->edumps[j].coreoffset;
				cmd.cdw10 = 0x400;
				cmd.data_len = 0x400;
				err = read_entire_cmd(&cmd, ehdr->edumps[j].coresize,
						      0x400, output,
						      hdl,
						      buf);
				if (err)
					goto out;
			}
		}
	}
	err = 0;
out:
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		perror("intel log");
		err = EIO;
	} else
		printf("Successfully wrote log to %s\n", cfg.file);
	close(output);
out_free:
	free(intel);
	return err;
}

static int enable_lat_stats_tracking(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = (
			"Enable/Disable Intel Latency Statistics Tracking.\n"
			"No argument prints current status.");
	const char *enable_desc = "Enable LST";
	const char *disable_desc = "Disable LST";
	const __u32 nsid = 0;
	const __u8 fid = 0xe2;
	const __u8 sel = 0;
	const __u32 cdw11 = 0x0;
	const __u32 cdw12 = 0x0;
	const __u32 data_len = 32;
	const __u32 save = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	void *buf = NULL;
	__u32 result;
	int err;

	struct config {
		bool enable, disable;
	};

	struct config cfg = {
		.enable = false,
		.disable = false,
	};

	struct argconfig_commandline_options opts[] = {
		{"enable", 'e', "", CFG_FLAG, &cfg.enable, no_argument, enable_desc},
		{"disable", 'd', "", CFG_FLAG, &cfg.disable, no_argument, disable_desc},
		{NULL}
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);

	enum Option {
		None = -1,
		True = 1,
		False = 0,
	};

	enum Option option = None;

	if (cfg.enable && cfg.disable)
		printf("Cannot enable and disable simultaneously.");
	else if (cfg.enable || cfg.disable)
		option = cfg.enable;

	if (err)
		return err;

	struct nvme_get_features_args args_get = {
		.args_size	= sizeof(args_get),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= cdw11,
		.uuidx		= 0,
		.data_len	= data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	struct nvme_set_features_args args_set = {
		.args_size	= sizeof(args_set),
		.fid		= fid,
		.nsid		= nsid,
		.cdw11		= option,
		.cdw12		= cdw12,
		.save		= save,
		.uuidx		= 0,
		.cdw15		= 0,
		.data_len	= data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	switch (option) {
	case None:
		err = nvme_get_features(hdl, &args_get);
		if (!err) {
			printf(
				"Latency Statistics Tracking (FID 0x%X) is currently (%i).\n",
				fid, result);
		} else {
			printf("Could not read feature id 0xE2.\n");
			return err;
		}
		break;
	case True:
	case False:
		err = nvme_set_features(hdl, &args_set);
		if (err > 0) {
			nvme_show_status(err);
		} else if (err < 0) {
			perror("Enable latency tracking");
			fprintf(stderr, "Command failed while parsing.\n");
		} else {
			printf("Successfully set enable bit for FID (0x%X) to %i.\n",
				fid, option);
		}
		break;
	default:
		printf("%d not supported.\n", option);
		return -EINVAL;
	}
	return err;
}

static int set_lat_stats_thresholds(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Write Intel Bucket Thresholds for Latency Statistics Tracking";
	const char *bucket_thresholds = "Bucket Threshold List, comma separated list: 0, 10, 20 ...";
	const char *write = "Set write bucket Thresholds for latency tracking (read default)";

	const __u32 nsid = 0;
	const __u8 fid = 0xf7;
	const __u32 cdw12 = 0x0;
	const __u32 save = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u32 result;
	int err, num;

	struct config {
		bool write;
		char *bucket_thresholds;
	};

	struct config cfg = {
		.write = false,
		.bucket_thresholds = "",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("write",      'w', &cfg.write, write),
		OPT_LIST("bucket-thresholds", 't', &cfg.bucket_thresholds,
			 bucket_thresholds),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);

	if (err)
		return err;

	/* Query maj and minor version first to figure out the amount of
	 * valid buckets a user is allowed to modify. Read or write doesn't
	 * matter
	 */
	err = nvme_get_log_simple(hdl, 0xc2,
				  media_version, sizeof(media_version));
	if (err) {
		fprintf(stderr, "Querying media version failed. ");
		nvme_show_status(err);
		goto close_dev;
	}

	if (media_version[0] == 1000) {
		int thresholds[OPTANE_V1000_BUCKET_LEN] = {0};

		num = argconfig_parse_comma_sep_array(cfg.bucket_thresholds,
						      thresholds,
						      sizeof(thresholds));
		if (num == -1) {
			fprintf(stderr, "ERROR: Bucket list is malformed\n");
			goto close_dev;

		}

		struct nvme_set_features_args args = {
			.args_size	= sizeof(args),
			.fid		= fid,
			.nsid		= nsid,
			.cdw11		= cfg.write ? 0x1 : 0x0,
			.cdw12		= cdw12,
			.save		= save,
			.uuidx		= 0,
			.cdw15		= 0,
			.data_len	= sizeof(thresholds),
			.data		= thresholds,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
			.result		= &result,
		};
		err = nvme_set_features(hdl, &args);

		if (err > 0) {
			nvme_show_status(err);
		} else if (err < 0) {
			perror("Enable latency tracking");
			fprintf(stderr, "Command failed while parsing.\n");
		}
	} else {
		fprintf(stderr, "Unsupported command\n");
	}

close_dev:
	return err;
}

