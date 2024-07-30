// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@meta.com>,
 *          Wei Zhang <wzhang@meta.com>,
 *          Venkat Ramesh <venkatraghavan@meta.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/types.h"
#include "nvme-print.h"
#include "nvme-wrap.h"

#include "ocp-smart-extended-log.h"
#include "ocp-clear-features.h"
#include "ocp-fw-activation-history.h"
#include "ocp-telemetry-decode.h"

#define CREATE_CMD
#include "ocp-nvme.h"
#include "ocp-utils.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Latency Monitor Log

#define C3_LATENCY_MON_LOG_BUF_LEN		0x200
#define C3_LATENCY_MON_OPCODE			0xC3
#define C3_LATENCY_MON_VERSION			0x0001
#define C3_GUID_LENGTH				16
#define NVME_FEAT_OCP_LATENCY_MONITOR		0xC5

#define C3_ACTIVE_BUCKET_TIMER_INCREMENT	5
#define C3_ACTIVE_THRESHOLD_INCREMENT		5
#define C3_MINIMUM_WINDOW_INCREMENT		100
#define C3_BUCKET_NUM				4

static __u8 lat_mon_guid[C3_GUID_LENGTH] = {
	0x92, 0x7a, 0xc0, 0x8c,
	0xd0, 0x84, 0x6c, 0x9c,
	0x70, 0x43, 0xe6, 0xd4,
	0x58, 0x5e, 0xd4, 0x85
};

#define READ		3
#define WRITE		2
#define TRIM		1
#define RESERVED	0

struct __packed ssd_latency_monitor_log {
	__u8	feature_status;			/* 0x00 */
	__u8	rsvd1;				/* 0x01 */
	__le16	active_bucket_timer;		/* 0x02 */
	__le16	active_bucket_timer_threshold;	/* 0x04 */
	__u8	active_threshold_a;		/* 0x06 */
	__u8	active_threshold_b;		/* 0x07 */
	__u8	active_threshold_c;		/* 0x08 */
	__u8	active_threshold_d;		/* 0x09 */
	__le16	active_latency_config;		/* 0x0A */
	__u8	active_latency_min_window;	/* 0x0C */
	__u8	rsvd2[0x13];			/* 0x0D */

	__le32	active_bucket_counter[4][4];	/* 0x20 - 0x5F */
	__le64	active_latency_timestamp[4][3];	/* 0x60 - 0xBF */
	__le16	active_measured_latency[4][3];	/* 0xC0 - 0xD7 */
	__le16	active_latency_stamp_units;	/* 0xD8 */
	__u8	rsvd3[0x16];			/* 0xDA */

	__le32	static_bucket_counter[4][4];	/* 0x0F0 - 0x12F */
	__le64	static_latency_timestamp[4][3];	/* 0x130 - 0x18F */
	__le16	static_measured_latency[4][3];	/* 0x190 - 0x1A7 */
	__le16	static_latency_stamp_units;	/* 0x1A8 */
	__u8	rsvd4[0x16];			/* 0x1AA */

	__le16	debug_log_trigger_enable;	/* 0x1C0 */
	__le16	debug_log_measured_latency;	/* 0x1C2 */
	__le64	debug_log_latency_stamp;	/* 0x1C4 */
	__le16	debug_log_ptr;			/* 0x1CC */
	__le16	debug_log_counter_trigger;	/* 0x1CE */
	__u8	debug_log_stamp_units;		/* 0x1D0 */
	__u8	rsvd5[0x1D];			/* 0x1D1 */

	__le16	log_page_version;		/* 0x1EE */
	__u8	log_page_guid[0x10];		/* 0x1F0 */
};

struct __packed feature_latency_monitor {
	__u16 active_bucket_timer_threshold;
	__u8  active_threshold_a;
	__u8  active_threshold_b;
	__u8  active_threshold_c;
	__u8  active_threshold_d;
	__u16 active_latency_config;
	__u8  active_latency_minimum_window;
	__u16 debug_log_trigger_enable;
	__u8  discard_debug_log;
	__u8  latency_monitor_feature_enable;
	__u8  reserved[4083];
};

struct erri_entry {
	union {
		__u8 flags;
		struct {
			__u8 enable:1;
			__u8 single:1;
			__u8 rsvd2:6;
		};
	};
	__u8 rsvd1;
	__le16 type;
	union {
		__u8 specific[28];
		struct {
			__le16 nrtdp;
			__u8 rsvd4[26];
		};
	};
};

#define ERRI_ENTRIES_MAX 127

enum erri_type {
	ERRI_TYPE_CPU_CTRL_HANG = 1,
	ERRI_TYPE_NAND_HANG,
	ERRI_TYPE_PLP_DEFECT,
	ERRI_TYPE_LOGICAL_FIRMWARE_ERROR,
	ERRI_TYPE_DRAM_CORRUPT_CRIT,
	ERRI_TYPE_DRAM_CORRUPT_NON_CRIT,
	ERRI_TYPE_NAND_CORRUPT,
	ERRI_TYPE_SRAM_CORRUPT,
	ERRI_TYPE_HW_MALFUNCTION,
	ERRI_TYPE_NO_MORE_NAND_SPARES,
	ERRI_TYPE_INCOMPLETE_SHUTDOWN,
};

const char *erri_type_to_string(__le16 type)
{
	switch (type) {
	case ERRI_TYPE_CPU_CTRL_HANG:
		return "CPU/controller hang";
	case ERRI_TYPE_NAND_HANG:
		return "NAND hang";
	case ERRI_TYPE_PLP_DEFECT:
		return "PLP defect";
	case ERRI_TYPE_LOGICAL_FIRMWARE_ERROR:
		return "logical firmware error";
	case ERRI_TYPE_DRAM_CORRUPT_CRIT:
		return "DRAM corruption critical path";
	case ERRI_TYPE_DRAM_CORRUPT_NON_CRIT:
		return "DRAM corruption non-critical path";
	case ERRI_TYPE_NAND_CORRUPT:
		return "NAND corruption";
	case ERRI_TYPE_SRAM_CORRUPT:
		return "SRAM corruption";
	case ERRI_TYPE_HW_MALFUNCTION:
		return "HW malfunction";
	case ERRI_TYPE_NO_MORE_NAND_SPARES:
		return "no more NAND spares available";
	case ERRI_TYPE_INCOMPLETE_SHUTDOWN:
		return "incomplete shutdown";
	default:
		break;
	}

	return "unknown";
}

struct erri_get_cq_entry {
	__u32 nume:7;
	__u32 rsvd7:25;
};

struct erri_config {
	char *file;
	__u8 number;
	__u16 type;
	__u16 nrtdp;
};

static const char *sel = "[0-3]: current/default/saved/supported";
static const char *no_uuid = "Skip UUID index search (UUID index not required for OCP 1.0)";
const char *data = "Error injection data structure entries";
const char *number = "Number of valid error injection data entries";
static const char *type = "Error injection type";
static const char *nrtdp = "Number of reads to trigger device panic";

static int ocp_print_C3_log_normal(struct nvme_dev *dev,
				   struct ssd_latency_monitor_log *log_data)
{
	char ts_buf[128];
	int i, j;

	printf("-Latency Monitor/C3 Log Page Data-\n");
	printf("  Controller   :  %s\n", dev->name);
	printf("  Feature Status                     0x%x\n",
	       log_data->feature_status);
	printf("  Active Bucket Timer                %d min\n",
	       C3_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer));
	printf("  Active Bucket Timer Threshold      %d min\n",
	       C3_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer_threshold));
	printf("  Active Threshold A                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_a+1));
	printf("  Active Threshold B                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_b+1));
	printf("  Active Threshold C                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_c+1));
	printf("  Active Threshold D                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_d+1));
	printf("  Active Latency Configuration       0x%x\n",
	       le16_to_cpu(log_data->active_latency_config));
	printf("  Active Latency Minimum Window      %d ms\n",
	       C3_MINIMUM_WINDOW_INCREMENT *
	       le16_to_cpu(log_data->active_latency_min_window));
	printf("  Active Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->active_latency_stamp_units));
	printf("  Static Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->static_latency_stamp_units));
	printf("  Debug Log Trigger Enable           %d\n",
	       le16_to_cpu(log_data->debug_log_trigger_enable));
	printf("  Debug Log Measured Latency         %d\n",
	       le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1) {
		printf("  Debug Log Latency Time Stamp       N/A\n");
	} else {
		convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
		printf("  Debug Log Latency Time Stamp       %s\n", ts_buf);
	}
	printf("  Debug Log Pointer                  %d\n",
	       le16_to_cpu(log_data->debug_log_ptr));
	printf("  Debug Counter Trigger Source       %d\n",
	       le16_to_cpu(log_data->debug_log_counter_trigger));
	printf("  Debug Log Stamp Units              %d\n",
	       le16_to_cpu(log_data->debug_log_stamp_units));
	printf("  Log Page Version                   %d\n",
	       le16_to_cpu(log_data->log_page_version));

	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];

	for (i = C3_GUID_LENGTH - 1; i >= 0; i--)
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);

	printf("  Log Page GUID                      %s\n", guid);
	printf("\n");

	printf("                                                            Read                           Write                 Deallocate/Trim\n");
	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Bucket Counter: Bucket %d    %27d     %27d     %27d\n",
		       i,
		       le32_to_cpu(log_data->active_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->active_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->active_bucket_counter[i][TRIM]));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[3-i][j]) == -1) {
				printf("                    N/A         ");
			} else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[3-i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->active_measured_latency[3-i][READ-1]),
		       le16_to_cpu(log_data->active_measured_latency[3-i][WRITE-1]),
		       le16_to_cpu(log_data->active_measured_latency[3-i][TRIM-1]));
	}

	printf("\n");
	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Bucket Counter: Bucket %d    %27d     %27d     %27d\n",
		       i,
		       le32_to_cpu(log_data->static_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->static_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->static_bucket_counter[i][TRIM]));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->static_latency_timestamp[3-i][j]) == -1) {
				printf("                    N/A         ");
			} else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[3-i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->static_measured_latency[3-i][READ-1]),
		       le16_to_cpu(log_data->static_measured_latency[3-i][WRITE-1]),
		       le16_to_cpu(log_data->static_measured_latency[3-i][TRIM-1]));
	}

	return 0;
}

static void ocp_print_C3_log_json(struct ssd_latency_monitor_log *log_data)
{
	struct json_object *root;
	char ts_buf[128];
	char buf[128];
	int i, j;
	char *operation[3] = {"Trim", "Write", "Read"};

	root = json_create_object();

	json_object_add_value_uint(root, "Feature Status",
		log_data->feature_status);
	json_object_add_value_uint(root, "Active Bucket Timer",
		C3_ACTIVE_BUCKET_TIMER_INCREMENT *
		le16_to_cpu(log_data->active_bucket_timer));
	json_object_add_value_uint(root, "Active Bucket Timer Threshold",
		C3_ACTIVE_BUCKET_TIMER_INCREMENT *
		le16_to_cpu(log_data->active_bucket_timer_threshold));
	json_object_add_value_uint(root, "Active Threshold A",
		C3_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_a + 1));
	json_object_add_value_uint(root, "Active Threshold B",
		C3_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_b + 1));
	json_object_add_value_uint(root, "Active Threshold C",
		C3_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_c + 1));
	json_object_add_value_uint(root, "Active Threshold D",
		C3_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_d + 1));
	json_object_add_value_uint(root, "Active Latency Configuration",
		le16_to_cpu(log_data->active_latency_config));
	json_object_add_value_uint(root, "Active Latency Minimum Window",
		C3_MINIMUM_WINDOW_INCREMENT *
		le16_to_cpu(log_data->active_latency_min_window));

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Bucket Counter: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
				le32_to_cpu(log_data->active_bucket_counter[i][j+1]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Latency Time Stamp: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[3-i][j]) == -1) {
				json_object_add_value_string(bucket, operation[j], "NA");
			} else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[3-i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Measured Latency: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
				le16_to_cpu(log_data->active_measured_latency[3-i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	json_object_add_value_uint(root, "Active Latency Stamp Units",
		le16_to_cpu(log_data->active_latency_stamp_units));

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Bucket Counter: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
				le32_to_cpu(log_data->static_bucket_counter[i][j+1]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Latency Time Stamp: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->static_latency_timestamp[3-i][j]) == -1) {
				json_object_add_value_string(bucket, operation[j], "NA");
			} else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[3-i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Measured Latency: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
				le16_to_cpu(log_data->static_measured_latency[3-i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	json_object_add_value_uint(root, "Static Latency Stamp Units",
		le16_to_cpu(log_data->static_latency_stamp_units));
	json_object_add_value_uint(root, "Debug Log Trigger Enable",
		le16_to_cpu(log_data->debug_log_trigger_enable));
	json_object_add_value_uint(root, "Debug Log Measured Latency",
		le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1) {
		json_object_add_value_string(root, "Debug Log Latency Time Stamp", "NA");
	} else {
		convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
		json_object_add_value_string(root, "Debug Log Latency Time Stamp", ts_buf);
	}
	json_object_add_value_uint(root, "Debug Log Pointer",
		le16_to_cpu(log_data->debug_log_ptr));
	json_object_add_value_uint(root, "Debug Counter Trigger Source",
		le16_to_cpu(log_data->debug_log_counter_trigger));
	json_object_add_value_uint(root, "Debug Log Stamp Units",
		le16_to_cpu(log_data->debug_log_stamp_units));
	json_object_add_value_uint(root, "Log Page Version",
		le16_to_cpu(log_data->log_page_version));

	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];

	for (i = C3_GUID_LENGTH - 1; i >= 0; i--)
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);

	json_object_add_value_string(root, "Log Page GUID", guid);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

static int get_c3_log_page(struct nvme_dev *dev, char *format)
{
	struct ssd_latency_monitor_log *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = malloc(sizeof(__u8) * C3_LATENCY_MON_LOG_BUF_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C3_LATENCY_MON_LOG_BUF_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C3_LATENCY_MON_OPCODE,
		C3_LATENCY_MON_LOG_BUF_LEN, data);

	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret, false), ret);

	if (!ret) {
		log_data = (struct ssd_latency_monitor_log *)data;

		/* check log page version */
		if (log_data->log_page_version != C3_LATENCY_MON_VERSION) {
			fprintf(stderr,
				"ERROR : OCP : invalid latency monitor version\n");
			ret = -1;
			goto out;
		}

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (lat_mon_guid[i] != log_data->log_page_guid[i]) {
				int j;

				fprintf(stderr, "ERROR : OCP : Unknown GUID in C3 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", lat_mon_guid[j]);

				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_C3_log_normal(dev, log_data);
			break;
		case JSON:
			ocp_print_C3_log_json(log_data);
			break;
		default:
			fprintf(stderr, "unhandled output format\n");

		}
	} else {
		fprintf(stderr,
			"ERROR : OCP : Unable to read C3 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_latency_monitor_log(int argc, char **argv,
				   struct command *command,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve latency monitor log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
			"output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c3_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr,
			"ERROR : OCP : Failure reading the C3 Log Page, ret = %d\n",
			ret);

	dev_close(dev);
	return ret;
}

int ocp_set_latency_monitor_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = -1;
	struct nvme_dev *dev;
	__u32 result;
	struct feature_latency_monitor buf = {0,};
	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	struct nvme_id_ctrl ctrl;

	const char *desc = "Set Latency Monitor feature.";
	const char *active_bucket_timer_threshold = "This is the value that loads the Active Bucket Timer Threshold.";
	const char *active_threshold_a = "This is the value that loads into the Active Threshold A.";
	const char *active_threshold_b = "This is the value that loads into the Active Threshold B.";
	const char *active_threshold_c = "This is the value that loads into the Active Threshold C.";
	const char *active_threshold_d = "This is the value that loads into the Active Threshold D.";
	const char *active_latency_config = "This is the value that loads into the Active Latency Configuration.";
	const char *active_latency_minimum_window = "This is the value that loads into the Active Latency Minimum Window.";
	const char *debug_log_trigger_enable = "This is the value that loads into the Debug Log Trigger Enable.";
	const char *discard_debug_log = "Discard Debug Log.";
	const char *latency_monitor_feature_enable = "Latency Monitor Feature Enable.";

	struct config {
		__u16 active_bucket_timer_threshold;
		__u8 active_threshold_a;
		__u8 active_threshold_b;
		__u8 active_threshold_c;
		__u8 active_threshold_d;
		__u16 active_latency_config;
		__u8 active_latency_minimum_window;
		__u16 debug_log_trigger_enable;
		__u8 discard_debug_log;
		__u8 latency_monitor_feature_enable;
	};

	struct config cfg = {
		.active_bucket_timer_threshold = 0x7E0,
		.active_threshold_a = 0x5,
		.active_threshold_b = 0x13,
		.active_threshold_c = 0x1E,
		.active_threshold_d = 0x2E,
		.active_latency_config = 0xFFF,
		.active_latency_minimum_window = 0xA,
		.debug_log_trigger_enable = 0,
		.discard_debug_log = 0,
		.latency_monitor_feature_enable = 0x7,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("active_bucket_timer_threshold", 't', &cfg.active_bucket_timer_threshold, active_bucket_timer_threshold),
		OPT_UINT("active_threshold_a", 'a', &cfg.active_threshold_a, active_threshold_a),
		OPT_UINT("active_threshold_b", 'b', &cfg.active_threshold_b, active_threshold_b),
		OPT_UINT("active_threshold_c", 'c', &cfg.active_threshold_c, active_threshold_c),
		OPT_UINT("active_threshold_d", 'd', &cfg.active_threshold_d, active_threshold_d),
		OPT_UINT("active_latency_config", 'f', &cfg.active_latency_config, active_latency_config),
		OPT_UINT("active_latency_minimum_window", 'w', &cfg.active_latency_minimum_window, active_latency_minimum_window),
		OPT_UINT("debug_log_trigger_enable", 'r', &cfg.debug_log_trigger_enable, debug_log_trigger_enable),
		OPT_UINT("discard_debug_log", 'l', &cfg.discard_debug_log, discard_debug_log),
		OPT_UINT("latency_monitor_feature_enable", 'e', &cfg.latency_monitor_feature_enable, latency_monitor_feature_enable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = fstat(dev_fd(dev), &nvme_stat);
	if (err < 0)
		return err;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nvme_get_nsid(dev_fd(dev), &nsid);
		if (err < 0) {
			perror("invalid-namespace-id");
			return err;
		}
	}

	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err)
		return err;

	memset(&buf, 0, sizeof(struct feature_latency_monitor));

	buf.active_bucket_timer_threshold = cfg.active_bucket_timer_threshold;
	buf.active_threshold_a = cfg.active_threshold_a;
	buf.active_threshold_b = cfg.active_threshold_b;
	buf.active_threshold_c = cfg.active_threshold_c;
	buf.active_threshold_d = cfg.active_threshold_d;
	buf.active_latency_config = cfg.active_latency_config;
	buf.active_latency_minimum_window = cfg.active_latency_minimum_window;
	buf.debug_log_trigger_enable = cfg.debug_log_trigger_enable;
	buf.discard_debug_log = cfg.discard_debug_log;
	buf.latency_monitor_feature_enable = cfg.latency_monitor_feature_enable;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = NVME_FEAT_OCP_LATENCY_MONITOR,
		.nsid = 0,
		.cdw12 = 0,
		.save = 1,
		.data_len = sizeof(struct feature_latency_monitor),
		.data = (void *)&buf,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("NVME_FEAT_OCP_LATENCY_MONITOR: 0x%02x\n", NVME_FEAT_OCP_LATENCY_MONITOR);
		printf("active bucket timer threshold: 0x%x\n", buf.active_bucket_timer_threshold);
		printf("active threshold a: 0x%x\n", buf.active_threshold_a);
		printf("active threshold b: 0x%x\n", buf.active_threshold_b);
		printf("active threshold c: 0x%x\n", buf.active_threshold_c);
		printf("active threshold d: 0x%x\n", buf.active_threshold_d);
		printf("active latency config: 0x%x\n", buf.active_latency_config);
		printf("active latency minimum window: 0x%x\n", buf.active_latency_minimum_window);
		printf("debug log trigger enable: 0x%x\n", buf.debug_log_trigger_enable);
		printf("discard debug log: 0x%x\n", buf.discard_debug_log);
		printf("latency monitor feature enable: 0x%x\n", buf.latency_monitor_feature_enable);
	} else if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err, false), err);
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// EOL/PLP Failure Mode

static const char *eol_plp_failure_mode_to_string(__u8 mode)
{
	switch (mode) {
	case 1:
		return "Read only mode (ROM)";
	case 2:
		return "Write through mode (WTM)";
	case 3:
		return "Normal mode";
	default:
		break;
	}

	return "Reserved";
}

static int eol_plp_failure_mode_get(struct nvme_dev *dev, const __u32 nsid, const __u8 fid,
				    __u8 sel, bool uuid)
{
	__u32 result;
	int err;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= 0,
		.uuidx		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	err = nvme_get_features(&args);
	if (!err) {
		nvme_show_result("End of Life Behavior (feature: %#0*x): %#0*x (%s: %s)",
				 fid ? 4 : 2, fid, result ? 10 : 8, result,
				 nvme_select_to_string(sel),
				 eol_plp_failure_mode_to_string(result));
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: %#0*x.", fid ? 4 : 2, fid);
	}

	return err;
}

static int eol_plp_failure_mode_set(struct nvme_dev *dev, const __u32 nsid,
				    const __u8 fid, __u8 mode, bool save,
				    bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = mode << 30,
		.cdw12 = 0,
		.save = save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define EOL/PLP failure mode");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		nvme_show_result("Successfully set mode (feature: %#0*x): %#0*x (%s: %s).",
				 fid ? 4 : 2, fid, mode ? 10 : 8, mode,
				 save ? "Save" : "Not save",
				 eol_plp_failure_mode_to_string(mode));
	}

	return err;
}

static int eol_plp_failure_mode(int argc, char **argv, struct command *cmd,
				struct plugin *plugin)
{
	const char *desc = "Define EOL or PLP circuitry failure mode.\n"
			   "No argument prints current mode.";
	const char *mode = "[0-3]: default/rom/wtm/normal";
	const char *save = "Specifies that the controller shall save the attribute";
	const char *sel = "[0-3]: current/default/saved/supported";
	const __u32 nsid = 0;
	const __u8 fid = 0xc2;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 mode;
		bool save;
		__u8 sel;
	};

	struct config cfg = {
		.mode = 0,
		.save = false,
		.sel = 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("mode", 'm', &cfg.mode, mode),
		  OPT_FLAG("save", 's', &cfg.save, save),
		  OPT_BYTE("sel", 'S', &cfg.sel, sel),
		  OPT_FLAG("no-uuid", 'n', NULL,
			   "Skip UUID index search (UUID index not required for OCP 1.0)"));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "mode"))
		err = eol_plp_failure_mode_set(dev, nsid, fid, cfg.mode,
					       cfg.save,
					       !argconfig_parse_seen(opts, "no-uuid"));
	else
		err = eol_plp_failure_mode_get(dev, nsid, fid, cfg.sel,
					       !argconfig_parse_seen(opts, "no-uuid"));

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Telemetry Log
//global buffers
static __le64 total_log_page_sz;
static __u8 *header_data;
static struct telemetry_str_log_format *log_data;

__u8 *ptelemetry_buffer;
__u8 *pstring_buffer;
__u8 *pC9_string_buffer;

static void get_serial_number(struct nvme_id_ctrl *ctrl, char *sn)
{
	int i;
	/* Remove trailing spaces from the name */
	for (i = 0; i < sizeof(ctrl->sn); i++) {
		if (ctrl->sn[i] == ' ')
			break;
		sn[i] = ctrl->sn[i];
	}
}

static void print_telemetry_header(struct telemetry_initiated_log *logheader,
		int tele_type)
{
	if (logheader) {
		unsigned int i = 0, j = 0;
		__u8 dataGenNum;

		if (tele_type == TELEMETRY_TYPE_HOST) {
			printf("============ Telemetry Host Header ============\n");
			dataGenNum = logheader->DataHostGenerationNumber;
		} else {
			printf("========= Telemetry Controller Header =========\n");
			dataGenNum = logheader->DataCtlrGenerationNumber;
		}

		printf("Log Identifier         : 0x%02X\n", logheader->LogIdentifier);
		printf("IEEE                   : 0x%02X%02X%02X\n",
			logheader->IEEE[0], logheader->IEEE[1], logheader->IEEE[2]);
		printf("Data Area 1 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea1LastBlock));
		printf("Data Area 2 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea2LastBlock));
		printf("Data Area 3 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea3LastBlock));
		printf("Data Available         : 0x%02X\n",
			logheader->CtlrDataAvailable);
		printf("Data Generation Number : 0x%02X\n",
			dataGenNum);
		printf("Reason Identifier      :\n");

		for (i = 0; i < 8; i++) {
			for (j = 0; j < 16; j++)
				printf("%02X ",	logheader->ReasonIdentifier[127 - ((i * 16) + j)]);
			printf("\n");
		}
		printf("===============================================\n\n");
	}
}

static int get_telemetry_data(struct nvme_dev *dev, __u32 ns, __u8 tele_type,
							  __u32 data_len, void *data, __u8 nLSP, __u8 nRAE,
							  __u64 offset)
{
	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = ns,
		.addr = (__u64)(uintptr_t) data,
		.data_len = data_len,
	};
	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16;
	__u16 numdl = numd & 0xffff;

	cmd.cdw10 = tele_type |
			(nLSP & 0x0F) << 8 |
			(nRAE & 0x01) << 15 |
			(numdl & 0xFFFF) << 16;
	cmd.cdw11 = numdu;
	cmd.cdw12 = (__u32)(0x00000000FFFFFFFF & offset);
	cmd.cdw13 = (__u32)((0xFFFFFFFF00000000 & offset) >> 8);
	cmd.cdw14 = 0;
	return nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
}
static void print_telemetry_data_area_1(struct telemetry_data_area_1 *da1,
										int tele_type)
{
	if (da1) {
		int i = 0;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("============ Telemetry Host Data area 1 ============\n");
		else
			printf("========= Telemetry Controller Data area 1 =========\n");
		printf("Major Version     : 0x%x\n", le16_to_cpu(da1->major_version));
		printf("Minor Version     : 0x%x\n", le16_to_cpu(da1->minor_version));
		printf("Timestamp         : %"PRIu64"\n", le64_to_cpu(da1->timestamp));
		printf("Log Page GUID     : 0x");
		for (int j = 15; j >= 0; j--)
			printf("%02x", da1->log_page_guid[j]);
		printf("\n");
		printf("Number Telemetry Profiles Supported   : 0x%x\n",
				da1->no_of_tps_supp);
		printf("Telemetry Profile Selected (TPS)      : 0x%x\n",
				da1->tps);
		printf("Telemetry String Log Size (SLS)       : 0x%lx\n",
				le64_to_cpu(da1->sls));
		printf("Firmware Revision                     : ");
		for (i = 0; i < 8; i++)
			printf("%c", (char)da1->fw_revision[i]);
		printf("\n");
		printf("Data Area 1 Statistic Start           : 0x%lx\n",
				le64_to_cpu(da1->da1_stat_start));
		printf("Data Area 1 Statistic Size            : 0x%lx\n",
				le64_to_cpu(da1->da1_stat_size));
		printf("Data Area 2 Statistic Start           : 0x%lx\n",
				le64_to_cpu(da1->da2_stat_start));
		printf("Data Area 2 Statistic Size            : 0x%lx\n",
				le64_to_cpu(da1->da2_stat_size));
		for (i = 0; i < 16; i++) {
			printf("Event FIFO %d Data Area                : 0x%x\n",
					i, da1->event_fifo_da[i]);
			printf("Event FIFO %d Start                    : 0x%"PRIx64"\n",
					i, le64_to_cpu(da1->event_fifos[i].start));
			printf("Event FIFO %d Size                     : 0x%"PRIx64"\n",
					i, le64_to_cpu(da1->event_fifos[i].size));
		}
		printf("SMART / Health Information     :\n");
		printf("0x");
		for (i = 0; i < 512; i++)
			printf("%02x", da1->smart_health_info[i]);
		printf("\n");

		printf("SMART / Health Information Extended     :\n");
		printf("0x");
		for (i = 0; i < 512; i++)
			printf("%02x", da1->smart_health_info_extended[i]);
		printf("\n");

		printf("===============================================\n\n");
	}
}
static void print_telemetry_da_stat(struct telemetry_stats_desc *da_stat,
		int tele_type,
		__u16 buf_size,
		__u8 data_area)
{
	if (da_stat) {
		unsigned int i = 0;
		struct telemetry_stats_desc *next_da_stat = da_stat;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("============ Telemetry Host Data Area %d Statistics ============\n",
				data_area);
		else
			printf("========= Telemetry Controller Data Area %d Statistics =========\n",
				data_area);
		while ((i + 8) < buf_size) {
			print_stats_desc(next_da_stat);
			i += 8 + ((next_da_stat->size) * 4);
			next_da_stat = (struct telemetry_stats_desc *)((__u64)da_stat + i);

			if ((next_da_stat->id == 0) && (next_da_stat->size == 0))
				break;
		}
		printf("===============================================\n\n");
	}
}
static void print_telemetry_da_fifo(struct telemetry_event_desc *da_fifo,
		__le64 buf_size,
		int tele_type,
		int da,
		int index)
{
	if (da_fifo) {
		unsigned int i = 0;
		struct telemetry_event_desc *next_da_fifo = da_fifo;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("========= Telemetry Host Data area %d Event FIFO %d =========\n",
				da, index);
		else
			printf("====== Telemetry Controller Data area %d Event FIFO %d ======\n",
				da, index);


		while ((i + 4) < buf_size) {
			/* Print Event Data */
			print_telemetry_fifo_event(next_da_fifo->class, /* Event class type */
				next_da_fifo->id,                           /* Event ID         */
				next_da_fifo->size,                         /* Event data size  */
				(__u8 *)&next_da_fifo->data);               /* Event data       */

			i += (4 + (next_da_fifo->size * 4));
			next_da_fifo = (struct telemetry_event_desc *)((__u64)da_fifo + i);
		}
		printf("===============================================\n\n");
	}
}
static int extract_dump_get_log(struct nvme_dev *dev, char *featurename, char *filename, char *sn,
				int dumpsize, int transfersize, __u32 nsid, __u8 log_id,
				__u8 lsp, __u64 offset, bool rae)
{
	int i = 0, err = 0;

	char *data = calloc(transfersize, sizeof(char));
	char filepath[FILE_NAME_SIZE] = {0,};
	int output = 0;
	int total_loop_cnt = dumpsize / transfersize;
	int last_xfer_size = dumpsize % transfersize;

	if (last_xfer_size)
		total_loop_cnt++;
	else
		last_xfer_size = transfersize;

	if (filename == 0)
		snprintf(filepath, FILE_NAME_SIZE, "%s_%s.bin", featurename, sn);
	else
		snprintf(filepath, FILE_NAME_SIZE, "%s%s_%s.bin", filename, featurename, sn);

	for (i = 0; i < total_loop_cnt; i++) {
		memset(data, 0, transfersize);

		struct nvme_get_log_args args = {
			.lpo = offset,
			.result = NULL,
			.log = (void *)data,
			.args_size = sizeof(args),
			.fd = dev_fd(dev),
			.lid = log_id,
			.len = transfersize,
			.nsid = nsid,
			.lsp = lsp,
			.uuidx = 0,
			.rae = rae,
			.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
			.csi = NVME_CSI_NVM,
			.ot = false,
		};

		err = nvme_get_log(&args);
		if (err) {
			if (i > 0)
				goto close_output;
			else
				goto end;
		}

		if (i != total_loop_cnt - 1) {
			if (!i) {
				output = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
				if (output < 0) {
					err = -13;
					goto end;
				}
			}
			if (write(output, data, transfersize) < 0) {
				err = -10;
				goto close_output;
			}
		} else {
			if (write(output, data, last_xfer_size) < 0) {
				err = -10;
				goto close_output;
			}
		}
		offset += transfersize;
		printf("%d%%\r", (i + 1) * 100 / total_loop_cnt);
	}
	printf("100%%\nThe log file was saved at \"%s\"\n", filepath);

close_output:
	close(output);

end:
	free(data);
	return err;
}

static int get_telemetry_dump(struct nvme_dev *dev, char *filename, char *sn,
			      enum TELEMETRY_TYPE tele_type, int data_area, bool header_print)
{
	__u32 err = 0, nsid = 0;
	__le64 da1_sz = 512, m_512_sz = 0, da1_off = 0, m_512_off = 0, diff = 0,
		temp_sz = 0, temp_ofst = 0;
	__u8 lsp = 0, rae = 0, flag = 0;
	__u8 data[TELEMETRY_HEADER_SIZE] = { 0 };
	unsigned int i = 0;
	char data1[TELEMETRY_DATA_SIZE] = { 0 };
	char *featurename = 0;
	struct telemetry_initiated_log *logheader = (struct telemetry_initiated_log *)data;
	struct telemetry_data_area_1 *da1 = (struct telemetry_data_area_1 *)data1;
	__u64 offset = 0, size = 0;
	char dumpname[FILE_NAME_SIZE] = { 0 };

	if (tele_type == TELEMETRY_TYPE_HOST_0) {
		featurename = "Host(0)";
		lsp = 0;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else if (tele_type == TELEMETRY_TYPE_HOST_1) {
		featurename = "Host(1)";
		lsp = 1;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else {
		featurename = "Controller";
		lsp = 0;
		rae = 1;
	}

	/* Get the telemetry header */
	err = get_telemetry_data(dev, nsid, tele_type, TELEMETRY_HEADER_SIZE,
				(void *)data, lsp, rae, 0);
	if (err) {
		printf("get_telemetry_header failed, err: %d.\n", err);
		return err;
	}

	if (header_print)
		print_telemetry_header(logheader, tele_type);

	/* Get the telemetry data */
	err = get_telemetry_data(dev, nsid, tele_type, TELEMETRY_DATA_SIZE,
				(void *)data1, lsp, rae, 512);
	if (err) {
		printf("get_telemetry_data failed for type: 0x%x, err: %d.\n", tele_type, err);
		return err;
	}

	print_telemetry_data_area_1(da1, tele_type);

	/* Print the Data Area 1 Stats */
	if (da1->da1_stat_size != 0) {
		diff = 0;
		da1_sz = (da1->da1_stat_size) * 4;
		m_512_sz = (da1->da1_stat_size) * 4;
		da1_off = (da1->da1_stat_start) * 4;
		m_512_off = (da1->da1_stat_start) * 4;
		temp_sz = (da1->da1_stat_size) * 4;
		temp_ofst = (da1->da1_stat_start) * 4;
		flag = 0;

		if ((da1_off % 512) > 0) {
			m_512_off = (__le64) ((da1_off / 512));
			da1_off = m_512_off * 512;
			diff = temp_ofst - da1_off;
			flag = 1;
		}

		if (da1_sz < 512)
			da1_sz = 512;
		else if ((da1_sz % 512) > 0) {
			if (flag == 0) {
				m_512_sz = (__le64) ((da1_sz / 512) + 1);
				da1_sz = m_512_sz * 512;
			} else {
				if (diff < 512)
					diff = 1;
				else
					diff = (diff / 512) * 512;

				m_512_sz = (__le64) ((da1_sz / 512) + 1 + diff + 1);
				da1_sz = m_512_sz * 512;
			}
		}

		char *da1_stat = calloc(da1_sz, sizeof(char));

		err = get_telemetry_data(dev, nsid, tele_type, da1_sz,
				(void *)da1_stat, lsp, rae, da1_off);
		if (err) {
			printf("get_telemetry_data da1 stats failed, err: %d.\n", err);
			return err;
		}

		print_telemetry_da_stat((void *)(da1_stat + (temp_ofst - da1_off)),
				tele_type, (da1->da1_stat_size) * 4, 1);
	}

	/* Print the Data Area 1 Event FIFO's */
	for (i = 0; i < 16 ; i++) {
		if ((da1->event_fifo_da[i] == 1) && (da1->event_fifos[i].size != 0)) {
			diff = 0;
			da1_sz = da1->event_fifos[i].size * 4;
			m_512_sz = da1->event_fifos[i].size * 4;
			da1_off = da1->event_fifos[i].start * 4;
			m_512_off = da1->event_fifos[i].start * 4;
			temp_sz = da1->event_fifos[i].size * 4;
			temp_ofst = da1->event_fifos[i].start * 4;
			flag = 0;

			if ((da1_off % 512) > 0) {
				m_512_off = (__le64) ((da1_off / 512));
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}

			if (da1_sz < 512)
				da1_sz = 512;
			else if ((da1_sz % 512) > 0) {
				if (flag == 0) {
					m_512_sz = (__le64) ((da1_sz / 512) + 1);
					da1_sz = m_512_sz * 512;
				} else {
					if (diff < 512)
						diff = 1;
					else
						diff = (diff / 512) * 512;

					m_512_sz = (__le64) ((da1_sz / 512) + 1 + diff + 1);
					da1_sz = m_512_sz * 512;
				}
			}

			char *da1_fifo = calloc(da1_sz, sizeof(char));

			err = get_telemetry_data(dev, nsid, tele_type,
					(da1->event_fifos[i].size) * 4,
					(void *)da1_fifo, lsp, rae, da1_off);
			if (err) {
				printf("get_telemetry_data da1 event fifos failed, err: %d.\n",
					err);
				return err;
			}
			print_telemetry_da_fifo((void *)(da1_fifo + (temp_ofst - da1_off)),
					temp_sz,
					tele_type,
					da1->event_fifo_da[i],
					i);
		}
	}

	/* Print the Data Area 2 Stats */
	if (da1->da2_stat_size != 0) {
		da1_off = (da1->da2_stat_start) * 4;
		temp_ofst = (da1->da2_stat_start) * 4;
		da1_sz = (da1->da2_stat_size) * 4;
		diff = 0;
		flag = 0;

		if (da1->da2_stat_start == 0) {
			da1_off = 512 + (logheader->DataArea1LastBlock * 512);
			temp_ofst = 512 + (le16_to_cpu(logheader->DataArea1LastBlock) * 512);
			if ((da1_off % 512) == 0) {
				m_512_off = (__le64) (((da1_off) / 512));
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}
		} else {

			if (((da1_off * 4) % 512) > 0) {
				m_512_off = (__le64) ((((da1->da2_stat_start) * 4) / 512));
				da1_off = m_512_off * 512;
				diff = ((da1->da2_stat_start) * 4) - da1_off;
				flag = 1;
			}
		}

		if (da1_sz < 512)
			da1_sz = 512;
		else if ((da1_sz % 512) > 0) {
			if (flag == 0) {
				m_512_sz = (__le64) ((da1->da2_stat_size / 512) + 1);
				da1_sz = m_512_sz * 512;
			} else {
				if (diff < 512)
					diff = 1;
				else
					diff = (diff / 512) * 512;
				m_512_sz = (__le64) ((da1->da2_stat_size / 512) + 1 + diff + 1);
				da1_sz = m_512_sz * 512;
			}
		}

		char *da2_stat = calloc(da1_sz, sizeof(char));

		err = get_telemetry_data(dev, nsid, tele_type, da1_sz,
				(void *)da2_stat, lsp, rae, da1_off);
		if (err) {
			printf("get_telemetry_data da2 stats failed, err: %d.\n", err);
			return err;
		}

		print_telemetry_da_stat((void *)(da2_stat + (temp_ofst - da1_off)),
			tele_type,
			(da1->da2_stat_size) * 4,
			2);
	}

	/* Print the Data Area 2 Event FIFO's */
	for (i = 0; i < 16 ; i++) {
		if ((da1->event_fifo_da[i] == 2) && (da1->event_fifos[i].size != 0)) {
			diff = 0;
			da1_sz = da1->event_fifos[i].size * 4;
			m_512_sz = da1->event_fifos[i].size * 4;
			da1_off = da1->event_fifos[i].start * 4;
			m_512_off = da1->event_fifos[i].start * 4;
			temp_sz = da1->event_fifos[i].size * 4;
			temp_ofst = da1->event_fifos[i].start * 4;
			flag = 0;

			if ((da1_off % 512) > 0) {
				m_512_off = (__le64) ((da1_off / 512));
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}

			if (da1_sz < 512)
				da1_sz = 512;
			else if ((da1_sz % 512) > 0) {
				if (flag == 0) {
					m_512_sz = (__le64) ((da1_sz / 512) + 1);
					da1_sz = m_512_sz * 512;
				}

				else {
					if (diff < 512)
						diff = 1;
					else
						diff = (diff / 512) * 512;

					m_512_sz = (__le64) ((da1_sz / 512) + 1 + diff + 1);
					da1_sz = m_512_sz * 512;
				}
			}

			char *da1_fifo = calloc(da1_sz, sizeof(char));

			err = get_telemetry_data(dev, nsid, tele_type,
					(da1->event_fifos[i].size) * 4,
					(void *)da1_fifo, lsp, rae, da1_off);
			if (err) {
				printf("get_telemetry_data da2 event fifos failed, err: %d.\n",
					err);
				return err;
			}
			print_telemetry_da_fifo((void *)(da1_fifo + (temp_ofst - da1_off)),
					temp_sz,
					tele_type,
					da1->event_fifo_da[i],
					i);
		}
	}

	printf("------------------------------FIFO End---------------------------\n");

	switch (data_area) {
	case 1:
		offset  = TELEMETRY_HEADER_SIZE;
		size    = le16_to_cpu(logheader->DataArea1LastBlock);
		break;
	case 2:
		offset  = TELEMETRY_HEADER_SIZE
				+ (le16_to_cpu(logheader->DataArea1LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size    = le16_to_cpu(logheader->DataArea2LastBlock)
				- le16_to_cpu(logheader->DataArea1LastBlock);
		break;
	case 3:
		offset  = TELEMETRY_HEADER_SIZE
				+ (le16_to_cpu(logheader->DataArea2LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size    = le16_to_cpu(logheader->DataArea3LastBlock)
				- le16_to_cpu(logheader->DataArea2LastBlock);
		break;
	default:
		break;
	}

	if (!size) {
		printf("Telemetry %s Area %d is empty.\n", featurename, data_area);
		return err;
	}

	snprintf(dumpname, FILE_NAME_SIZE,
					"Telemetry_%s_Area_%d", featurename, data_area);
	err = extract_dump_get_log(dev, dumpname, filename, sn, size * TELEMETRY_BYTE_PER_BLOCK,
			TELEMETRY_TRANSFER_SIZE, nsid, tele_type,
			0, offset, rae);

	return err;
}

static int get_telemetry_log_page_data(struct nvme_dev *dev, int tele_type)
{
	char file_path[PATH_MAX];
	void *telemetry_log;
	const size_t bs = 512;
	struct nvme_telemetry_log *hdr;
	size_t full_size, offset = bs;
	int err, fd;

	if ((tele_type == TELEMETRY_TYPE_HOST_0) || (tele_type == TELEMETRY_TYPE_HOST_1))
		tele_type = TELEMETRY_TYPE_HOST;

	int log_id = (tele_type == TELEMETRY_TYPE_HOST ? NVME_LOG_LID_TELEMETRY_HOST :
			NVME_LOG_LID_TELEMETRY_CTRL);

	hdr = malloc(bs);
	telemetry_log = malloc(bs);
	if (!hdr || !telemetry_log) {
		fprintf(stderr, "Failed to allocate %zu bytes for log: %s\n",
			bs, strerror(errno));
		err = -ENOMEM;
		goto exit_status;
	}
	memset(hdr, 0, bs);

	sprintf(file_path, DEFAULT_TELEMETRY_BIN);
	fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
			file_path, strerror(errno));
		err = fd;
		goto exit_status;
	}

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = hdr,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = log_id,
		.len = bs,
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_LOG_TELEM_HOST_LSP_CREATE,
		.uuidx = NVME_UUID_NONE,
		.rae = true,
		.ot = false,
	};

	err = nvme_get_log(&args);
	if (err < 0)
		nvme_show_error("Failed to fetch the log from drive.\n");
	else if (err > 0) {
		nvme_show_status(err);
		nvme_show_error("Failed to fetch telemetry-header. Error:%d.\n", err);
		goto close_fd;
	}

	err = write(fd, (void *)hdr, bs);
	if (err != bs) {
		nvme_show_error("Failed to write data to file.\n");
		goto close_fd;
	}

	full_size = (le16_to_cpu(hdr->dalb3) * bs) + offset;

	while (offset != full_size) {
		args.log = telemetry_log;
		args.lpo = offset;
		args.lsp = NVME_LOG_LSP_NONE;
		err = nvme_get_log(&args);
		if (err < 0) {
			nvme_show_error("Failed to fetch the log from drive.\n");
			break;
		} else if (err > 0) {
			nvme_show_error("Failed to fetch telemetry-log.\n");
			nvme_show_status(err);
			break;
		}

		err = write(fd, (void *)telemetry_log, bs);
		if (err != bs) {
			nvme_show_error("Failed to write data to file.\n");
			break;
		}
		err = 0;
		offset += bs;
	}

close_fd:
	close(fd);
exit_status:
	free(hdr);
	free(telemetry_log);

	return err;
}

static int get_c9_log_page_data(struct nvme_dev *dev, int print_data, int save_bin)
{
	int ret = 0, fd;
	__le64 stat_id_str_table_ofst = 0;
	__le64 event_str_table_ofst = 0;
	__le64 vu_event_str_table_ofst = 0;
	__le64 ascii_table_ofst = 0;
	char file_path[PATH_MAX];

	header_data = (__u8 *)malloc(sizeof(__u8) * C9_TELEMETRY_STR_LOG_LEN);
	if (!header_data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(header_data, 0, sizeof(__u8) * C9_TELEMETRY_STR_LOG_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C9_TELEMETRY_STRING_LOG_ENABLE_OPCODE,
				  C9_TELEMETRY_STR_LOG_LEN, header_data);

	if (!ret) {
		log_data = (struct telemetry_str_log_format *)header_data;
		if (print_data) {
			printf("Statistics Identifier String Table Size = %lld\n",
			       log_data->sitsz);
			printf("Event String Table Size = %lld\n", log_data->estsz);
			printf("VU Event String Table Size = %lld\n", log_data->vu_eve_st_sz);
			printf("ASCII Table Size = %lld\n", log_data->asctsz);
		}

		//Calculating the offset for dynamic fields.

		stat_id_str_table_ofst = log_data->sits * 4;
		event_str_table_ofst = log_data->ests * 4;
		vu_event_str_table_ofst = log_data->vu_eve_sts * 4;
		ascii_table_ofst = log_data->ascts * 4;
		total_log_page_sz = C9_TELEMETRY_STR_LOG_LEN +
		(log_data->sitsz * 4) + (log_data->estsz * 4) +
		(log_data->vu_eve_st_sz * 4) + (log_data->asctsz * 4);

		if (print_data) {
			printf("stat_id_str_table_ofst = %lld\n", stat_id_str_table_ofst);
			printf("event_str_table_ofst = %lld\n", event_str_table_ofst);
			printf("vu_event_str_table_ofst = %lld\n", vu_event_str_table_ofst);
			printf("ascii_table_ofst = %lld\n", ascii_table_ofst);
			printf("total_log_page_sz = %lld\n", total_log_page_sz);
		}

		pC9_string_buffer = (__u8 *)malloc(sizeof(__u8) * total_log_page_sz);
		if (!pC9_string_buffer) {
			fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
			return -1;
		}
		memset(pC9_string_buffer, 0, sizeof(__u8) * total_log_page_sz);

		ret = nvme_get_log_simple(dev_fd(dev), C9_TELEMETRY_STRING_LOG_ENABLE_OPCODE,
					  total_log_page_sz, pC9_string_buffer);
	} else
		fprintf(stderr, "ERROR : OCP : Unable to read C9 data.\n");

	if (save_bin) {
		sprintf(file_path, DEFAULT_STRING_BIN);
		fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd < 0) {
			fprintf(stderr, "Failed to open output file %s: %s!\n",
				file_path, strerror(errno));
			goto exit_status;
		}

		ret = write(fd, (void *)pC9_string_buffer, total_log_page_sz);
		if (ret != total_log_page_sz)
			fprintf(stderr, "Failed to flush all data to file!\n");

		close(fd);
	}

exit_status:
	return 0;
}

int parse_ocp_telemetry_log(struct ocp_telemetry_parse_options *options)
{
	int status = 0;
	long telemetry_buffer_size = 0;
	long string_buffer_size = 0;
	enum nvme_print_flags fmt;
	unsigned char log_id;

	if (options->telemetry_log) {
		if (strstr((const char *)options->telemetry_log, "bin")) {
			// Read the data from the telemetry binary file
			ptelemetry_buffer =
				read_binary_file(NULL, (const char *)options->telemetry_log,
						 &telemetry_buffer_size, 1);
			if (ptelemetry_buffer == NULL) {
				nvme_show_error("Failed to read telemetry-log.\n");
				return -1;
			}
		}
	} else {
		nvme_show_error("telemetry-log is empty.\n");
		return -1;
	}

	log_id = ptelemetry_buffer[0];
	if ((log_id != NVME_LOG_LID_TELEMETRY_HOST) && (log_id != NVME_LOG_LID_TELEMETRY_CTRL)) {
		nvme_show_error("Invalid LogPageId [0x%02X]\n", log_id);
		return -1;
	}

	if (options->string_log) {
		// Read the data from the string binary file
		if (strstr((const char *)options->string_log, "bin")) {
			pstring_buffer = read_binary_file(NULL, (const char *)options->string_log,
							  &string_buffer_size, 1);
			if (pstring_buffer == NULL) {
				nvme_show_error("Failed to read string-log.\n");
				return -1;
			}
		}
	} else {
		nvme_show_error("string-log is empty.\n");
		return -1;
	}

	status = validate_output_format(options->output_format, &fmt);
	if (status < 0) {
		nvme_show_error("Invalid output format\n");
		return status;
	}

	switch (fmt) {
	case NORMAL:
		print_ocp_telemetry_normal(options);
		break;
	case JSON:
		print_ocp_telemetry_json(options);
		break;
	default:
		break;
	}

	return 0;
}

static int ocp_telemetry_log(int argc, char **argv, struct command *cmd,
			      struct plugin *plugin)
{
	const char *desc = "Retrieve and parse OCP Telemetry log.";
	const char *telemetry_log = "Telemetry log binary;\n 'host.bin' or 'controller.bin'";
	const char *string_log = "String log binary; 'C9.bin'";
	const char *output_file = "Output file name with path;\n"
			"e.g. '-o ./path/name'\n'-o ./path1/path2/';\n"
			"If requested path does not exist, the directory will be newly created.";
	const char *output_format = "output format normal|json";
	const char *data_area = "Telemetry Data Area; 1 or 2;\n"
			"e.g. '-a 1 for Data Area 1.'\n'-a 2 for Data Areas 1 and 2.';\n";
	const char *telemetry_type = "Telemetry Type; 'host' or 'controller'";

	struct nvme_dev *dev;
	int err = 0;
	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	char sn[21] = {0,};
	struct nvme_id_ctrl ctrl;
	bool is_support_telemetry_controller;
	struct ocp_telemetry_parse_options opt;
	int tele_type = 0;
	int tele_area = 0;

	OPT_ARGS(opts) = {
		OPT_STR("telemetry-log", 'l', &opt.telemetry_log, telemetry_log),
		OPT_STR("string-log", 's', &opt.string_log, string_log),
		OPT_FILE("output-file", 'o', &opt.output_file, output_file),
		OPT_FMT("output-format", 'f', &opt.output_format, output_format),
		OPT_INT("data-area", 'a', &opt.data_area, data_area),
		OPT_STR("telemetry-type", 't', &opt.telemetry_type, telemetry_type),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = fstat(dev_fd(dev), &nvme_stat);
	if (err < 0)
		return err;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nvme_get_nsid(dev_fd(dev), &nsid);
		if (err < 0)
			return err;
	}

	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err)
		return err;

	get_serial_number(&ctrl, sn);

	is_support_telemetry_controller = ((ctrl.lpa & 0x8) >> 3);

	if (!opt.data_area) {
		nvme_show_result("Missing data-area. Using default data area 1.\n");
		opt.data_area = DATA_AREA_1;//Default data area 1
	} else if (opt.data_area != 1 && opt.data_area != 2) {
		nvme_show_result("Invalid data-area specified. Please specify 1 or 2.\n");
		goto out;
	}

	tele_area = opt.data_area;

	if (opt.telemetry_type) {
		if (!strcmp(opt.telemetry_type, "host0"))
			tele_type = TELEMETRY_TYPE_HOST_0;
		else if (!strcmp(opt.telemetry_type, "host1"))
			tele_type = TELEMETRY_TYPE_HOST_1;
		else if (!strcmp(opt.telemetry_type, "host"))
			tele_type = TELEMETRY_TYPE_HOST;
		else if (!strcmp(opt.telemetry_type, "controller"))
			tele_type = TELEMETRY_TYPE_CONTROLLER;
		else {
			nvme_show_error("telemetry-type should be host or controller.\n");
			goto out;
		}
	} else {
		tele_type = TELEMETRY_TYPE_HOST; //Default Type - Host
		nvme_show_result("Missing telemetry-type. Using default - host.\n");
	}

	if (!opt.telemetry_log) {
		nvme_show_result("\nMissing telemetry-log. Fetching from drive...\n");
		err = get_telemetry_log_page_data(dev, tele_type);//Pull Telemetry log
		if (err) {
			nvme_show_error("Failed to fetch telemetry-log from the drive.\n");
			goto out;
		}
		nvme_show_result("telemetry.bin generated. Proceeding with next steps.\n");
		opt.telemetry_log = DEFAULT_TELEMETRY_BIN;
	}

	if (!opt.string_log) {
		nvme_show_result("Missing string-log. Fetching from drive...\n");
		err = get_c9_log_page_data(dev, 0, 1); //Pull String log
		if (err) {
			nvme_show_error("Failed to fetch string-log from the drive.\n");
			goto out;
		}
		nvme_show_result("string.bin generated. Proceeding with next steps.\n");
		opt.string_log = DEFAULT_STRING_BIN;
	}

	if (!opt.output_format) {
		nvme_show_result("Missing format. Using default format - JSON.\n");
		opt.output_format = DEFAULT_OUTPUT_FORMAT_JSON;
	}

	switch (tele_type) {
	case TELEMETRY_TYPE_HOST: {
		printf("Extracting Telemetry Host Dump (Data Area %d)...\n", tele_area);
		err = parse_ocp_telemetry_log(&opt);
		if (err)
			nvme_show_result("Status:(%x)\n", err);
	}
	break;
	case TELEMETRY_TYPE_CONTROLLER: {
		printf("Extracting Telemetry Controller Dump (Data Area %d)...\n", tele_area);
		if (is_support_telemetry_controller == true) {
			err = parse_ocp_telemetry_log(&opt);
			if (err)
				nvme_show_result("Status:(%x)\n", err);
		}
	}
	break;
	case TELEMETRY_TYPE_NONE: {
		printf("\n-------------------------------------------------------------\n");
		/* Host 0 (lsp == 0) must be executed before Host 1 (lsp == 1). */
		printf("\nExtracting Telemetry Host 0 Dump (Data Area 1)...\n");

		err = get_telemetry_dump(dev, opt.output_file, sn,
				TELEMETRY_TYPE_HOST_0, 1, true);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 0 Dump (Data Area 3)...\n");

		err = get_telemetry_dump(dev, opt.output_file, sn,
				TELEMETRY_TYPE_HOST_0, 3, false);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 1 Dump (Data Area 1)...\n");

		err = get_telemetry_dump(dev, opt.output_file, sn,
				TELEMETRY_TYPE_HOST_1, 1, true);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 1 Dump (Data Area 3)...\n");

		err = get_telemetry_dump(dev, opt.output_file, sn,
				TELEMETRY_TYPE_HOST_1, 3, false);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Controller Dump (Data Area 3)...\n");

		if (is_support_telemetry_controller == true) {
			err = get_telemetry_dump(dev, opt.output_file, sn,
					TELEMETRY_TYPE_CONTROLLER, 3, true);
			if (err)
				fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);
		}

		printf("\n-------------------------------------------------------------\n");
	}
	break;
	case TELEMETRY_TYPE_HOST_0:
	case TELEMETRY_TYPE_HOST_1:
	default: {
		printf("Extracting Telemetry Host(%d) Dump (Data Area %d)...\n",
				(tele_type == TELEMETRY_TYPE_HOST_0) ? 0 : 1, tele_area);

		err = get_telemetry_dump(dev, opt.output_file, sn, tele_type, tele_area, true);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false), err);
	}
	break;
	}

	printf("ocp internal-log command completed.\n");
out:
	dev_close(dev);
	return err;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Unsupported Requirement Log Page (LID : C5h)

/* C5 Unsupported Requirement Log Page */
#define C5_GUID_LENGTH                     16
#define C5_UNSUPPORTED_REQS_LEN            4096
#define C5_UNSUPPORTED_REQS_OPCODE         0xC5
#define C5_UNSUPPORTED_REQS_LOG_VERSION    0x1
#define C5_NUM_UNSUPPORTED_REQ_ENTRIES     253

static __u8 unsupported_req_guid[C5_GUID_LENGTH] = {
	0x2F, 0x72, 0x9C, 0x0E,
	0x99, 0x23, 0x2C, 0xBB,
	0x63, 0x48, 0x32, 0xD0,
	0xB7, 0x98, 0xBB, 0xC7
};

/*
 * struct unsupported_requirement_log - unsupported requirement list
 * @unsupported_count:        Number of Unsupported Requirement IDs
 * @rsvd1:                    Reserved
 * @unsupported_req_list:     Unsupported Requirements lists upto 253.
 * @rsvd2:                    Reserved
 * @log_page_version:         indicates the version of the mapping this log page uses.
 *                            Shall be set to 0001h
 * @log_page_guid:            Shall be set to C7BB98B7D0324863BB2C23990E9C722Fh.
 */
struct __packed unsupported_requirement_log {
	__le16  unsupported_count;
	__u8    rsvd1[14];
	__u8    unsupported_req_list[C5_NUM_UNSUPPORTED_REQ_ENTRIES][16];
	__u8    rsvd2[14];
	__le16  log_page_version;
	__u8    log_page_guid[C5_GUID_LENGTH];
};

/* Function declaration for unsupported requirement log page (LID:C5h) */
static int ocp_unsupported_requirements_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin);

static int ocp_print_C5_log_normal(struct nvme_dev *dev,
				   struct unsupported_requirement_log *log_data)
{
	int j;

	printf("Unsupported Requirement-C5 Log Page Data-\n");

	printf("  Number Unsupported Req IDs		: 0x%x\n", le16_to_cpu(log_data->unsupported_count));

	for (j = 0; j < le16_to_cpu(log_data->unsupported_count); j++)
		printf("  Unsupported Requirement List %d	: %s\n", j, log_data->unsupported_req_list[j]);

	printf("  Log Page Version			: 0x%x\n", le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID				: 0x");
	for (j = C5_GUID_LENGTH - 1; j >= 0; j--)
		printf("%x", log_data->log_page_guid[j]);
	printf("\n");

	return 0;
}

static void ocp_print_C5_log_json(struct unsupported_requirement_log *log_data)
{
	int j;
	struct json_object *root;
	char unsup_req_list_str[40];
	char guid_buf[C5_GUID_LENGTH];
	char *guid = guid_buf;

	root = json_create_object();

	json_object_add_value_int(root, "Number Unsupported Req IDs", le16_to_cpu(log_data->unsupported_count));

	memset((void *)unsup_req_list_str, 0, 40);
	for (j = 0; j < le16_to_cpu(log_data->unsupported_count); j++) {
		sprintf((char *)unsup_req_list_str, "Unsupported Requirement List %d", j);
		json_object_add_value_string(root, unsup_req_list_str, (char *)log_data->unsupported_req_list[j]);
	}

	json_object_add_value_int(root, "Log Page Version", le16_to_cpu(log_data->log_page_version));

	memset((void *)guid, 0, C5_GUID_LENGTH);
	for (j = C5_GUID_LENGTH - 1; j >= 0; j--)
		guid += sprintf(guid, "%02x", log_data->log_page_guid[j]);
	json_object_add_value_string(root, "Log page GUID", guid_buf);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

static void ocp_print_c5_log_binary(struct unsupported_requirement_log *log_data)
{
	return d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static int get_c5_log_page(struct nvme_dev *dev, char *format)
{
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;
	struct unsupported_requirement_log *log_data;
	int j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C5_UNSUPPORTED_REQS_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C5_UNSUPPORTED_REQS_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C5_UNSUPPORTED_REQS_OPCODE,
				  C5_UNSUPPORTED_REQS_LEN, data);
	if (!ret) {
		log_data = (struct unsupported_requirement_log *)data;

		/* check log page version */
		if (log_data->log_page_version != C5_UNSUPPORTED_REQS_LOG_VERSION) {
			fprintf(stderr, "ERROR : OCP : invalid unsupported requirement version\n");
			ret = -1;
			goto out;
		}

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (unsupported_req_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C5 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", unsupported_req_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_C5_log_normal(dev, log_data);
			break;
		case JSON:
			ocp_print_C5_log_json(log_data);
			break;
		case BINARY:
			ocp_print_c5_log_binary(log_data);
			break;
		default:
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C3 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_unsupported_requirements_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin)
{
	const char *desc = "Retrieve unsupported requirements log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c5_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C5 Log Page, ret = %d\n", ret);

	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Error Recovery Log Page(0xC1)

#define C1_ERROR_RECOVERY_LOG_BUF_LEN       0x200
#define C1_ERROR_RECOVERY_OPCODE            0xC1
#define C1_ERROR_RECOVERY_VERSION           0x0002
#define C1_GUID_LENGTH                      16
static __u8 error_recovery_guid[C1_GUID_LENGTH] = {
	0x44, 0xd9, 0x31, 0x21,
	0xfe, 0x30, 0x34, 0xae,
	0xab, 0x4d, 0xfd, 0x3d,
	0xba, 0x83, 0x19, 0x5a
};

/**
 * struct ocp_error_recovery_log_page -	Error Recovery Log Page
 * @panic_reset_wait_time:		Panic Reset Wait Time
 * @panic_reset_action:			Panic Reset Action
 * @device_recover_action_1:		Device Recovery Action 1
 * @panic_id:				Panic ID
 * @device_capabilities:		Device Capabilities
 * @vendor_specific_recovery_opcode:	Vendor Specific Recovery Opcode
 * @reserved:				Reserved
 * @vendor_specific_command_cdw12:	Vendor Specific Command CDW12
 * @vendor_specific_command_cdw13:	Vendor Specific Command CDW13
 * @vendor_specific_command_timeout:	Vendor Specific Command Timeout
 * @device_recover_action_2:		Device Recovery Action 2
 * @device_recover_action_2_timeout:	Device Recovery Action 2 Timeout
 * @reserved2:				Reserved
 * @log_page_version:			Log Page Version
 * @log_page_guid:			Log Page GUID
 */
struct __packed ocp_error_recovery_log_page {
	__le16  panic_reset_wait_time;                   /* 2 bytes      - 0x00 - 0x01 */
	__u8    panic_reset_action;                      /* 1 byte       - 0x02 */
	__u8    device_recover_action_1;                 /* 1 byte       - 0x03 */
	__le64  panic_id;                                /* 8 bytes      - 0x04 - 0x0B */
	__le32  device_capabilities;                     /* 4 bytes      - 0x0C - 0x0F */
	__u8    vendor_specific_recovery_opcode;         /* 1 byte       - 0x10 */
	__u8    reserved[0x3];                           /* 3 bytes      - 0x11 - 0x13 */
	__le32  vendor_specific_command_cdw12;           /* 4 bytes      - 0x14 - 0x17 */
	__le32  vendor_specific_command_cdw13;           /* 4 bytes      - 0x18 - 0x1B */
	__u8    vendor_specific_command_timeout;         /* 1 byte       - 0x1C */
	__u8    device_recover_action_2;                 /* 1 byte       - 0x1D */
	__u8    device_recover_action_2_timeout;         /* 1 byte       - 0x1E */
	__u8    reserved2[0x1cf];                        /* 463 bytes    - 0x1F - 0x1ED */
	__le16  log_page_version;                        /* 2 bytes      - 0x1EE - 0x1EF */
	__u8    log_page_guid[0x10];                     /* 16 bytes     - 0x1F0 - 0x1FF */
};

static void ocp_print_c1_log_normal(struct ocp_error_recovery_log_page *log_data);
static void ocp_print_c1_log_json(struct ocp_error_recovery_log_page *log_data);
static void ocp_print_c1_log_binary(struct ocp_error_recovery_log_page *log_data);
static int get_c1_log_page(struct nvme_dev *dev, char *format);
static int ocp_error_recovery_log(int argc, char **argv, struct command *cmd, struct plugin *plugin);

static void ocp_print_c1_log_normal(struct ocp_error_recovery_log_page *log_data)
{
	int i;

	printf("  Error Recovery/C1 Log Page Data\n");
	printf("  Panic Reset Wait Time             : 0x%x\n", le16_to_cpu(log_data->panic_reset_wait_time));
	printf("  Panic Reset Action                : 0x%x\n", log_data->panic_reset_action);
	printf("  Device Recovery Action 1          : 0x%x\n", log_data->device_recover_action_1);
	printf("  Panic ID                          : 0x%x\n", le32_to_cpu(log_data->panic_id));
	printf("  Device Capabilities               : 0x%x\n", le32_to_cpu(log_data->device_capabilities));
	printf("  Vendor Specific Recovery Opcode   : 0x%x\n", log_data->vendor_specific_recovery_opcode);
	printf("  Vendor Specific Command CDW12     : 0x%x\n", le32_to_cpu(log_data->vendor_specific_command_cdw12));
	printf("  Vendor Specific Command CDW13     : 0x%x\n", le32_to_cpu(log_data->vendor_specific_command_cdw13));
	printf("  Vendor Specific Command Timeout   : 0x%x\n", log_data->vendor_specific_command_timeout);
	printf("  Device Recovery Action 2          : 0x%x\n", log_data->device_recover_action_2);
	printf("  Device Recovery Action 2 Timeout  : 0x%x\n", log_data->device_recover_action_2_timeout);
	printf("  Log Page Version                  : 0x%x\n", le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID			    : 0x");
	for (i = C1_GUID_LENGTH - 1; i >= 0; i--)
		printf("%x", log_data->log_page_guid[i]);
	printf("\n");
}

static void ocp_print_c1_log_json(struct ocp_error_recovery_log_page *log_data)
{
	struct json_object *root;

	root = json_create_object();
	char guid[64];

	json_object_add_value_int(root, "Panic Reset Wait Time", le16_to_cpu(log_data->panic_reset_wait_time));
	json_object_add_value_int(root, "Panic Reset Action", log_data->panic_reset_action);
	json_object_add_value_int(root, "Device Recovery Action 1", log_data->device_recover_action_1);
	json_object_add_value_int(root, "Panic ID", le32_to_cpu(log_data->panic_id));
	json_object_add_value_int(root, "Device Capabilities", le32_to_cpu(log_data->device_capabilities));
	json_object_add_value_int(root, "Vendor Specific Recovery Opcode", log_data->vendor_specific_recovery_opcode);
	json_object_add_value_int(root, "Vendor Specific Command CDW12", le32_to_cpu(log_data->vendor_specific_command_cdw12));
	json_object_add_value_int(root, "Vendor Specific Command CDW13", le32_to_cpu(log_data->vendor_specific_command_cdw13));
	json_object_add_value_int(root, "Vendor Specific Command Timeout", log_data->vendor_specific_command_timeout);
	json_object_add_value_int(root, "Device Recovery Action 2", log_data->device_recover_action_2);
	json_object_add_value_int(root, "Device Recovery Action 2 Timeout", log_data->device_recover_action_2_timeout);
	json_object_add_value_int(root, "Log Page Version", le16_to_cpu(log_data->log_page_version));

	memset((void *)guid, 0, 64);
	sprintf((char *)guid, "0x%"PRIx64"%"PRIx64"", (uint64_t)le64_to_cpu(*(uint64_t *)&log_data->log_page_guid[8]),
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data->log_page_guid[0]));
	json_object_add_value_string(root, "Log page GUID", guid);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void ocp_print_c1_log_binary(struct ocp_error_recovery_log_page *log_data)
{
	return d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static int get_c1_log_page(struct nvme_dev *dev, char *format)
{
	struct ocp_error_recovery_log_page *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i, j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C1_ERROR_RECOVERY_LOG_BUF_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C1_ERROR_RECOVERY_LOG_BUF_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C1_ERROR_RECOVERY_OPCODE, C1_ERROR_RECOVERY_LOG_BUF_LEN, data);

	if (!ret) {
		log_data = (struct ocp_error_recovery_log_page *)data;

		/* check log page version */
		if (log_data->log_page_version != C1_ERROR_RECOVERY_VERSION) {
			fprintf(stderr, "ERROR : OCP : invalid error recovery log page version\n");
			ret = -1;
			goto out;
		}

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (error_recovery_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C1 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", error_recovery_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_c1_log_normal(log_data);
			break;
		case JSON:
			ocp_print_c1_log_json(log_data);
			break;
		case BINARY:
			ocp_print_c1_log_binary(log_data);
			break;
		default:
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C1 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_error_recovery_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve C1h Error Recovery Log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json|binary"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c1_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C1h Log Page, ret = %d\n", ret);
	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Device Capabilities (Log Identifier C4h) Requirements

#define C4_DEV_CAP_REQ_LEN			0x1000
#define C4_DEV_CAP_REQ_OPCODE		0xC4
#define C4_DEV_CAP_REQ_VERSION		0x0001
#define C4_GUID_LENGTH				16
static __u8 dev_cap_req_guid[C4_GUID_LENGTH] = {
	0x97, 0x42, 0x05, 0x0d,
	0xd1, 0xe1, 0xc9, 0x98,
	0x5d, 0x49, 0x58, 0x4b,
	0x91, 0x3c, 0x05, 0xb7
};

/**
 * struct ocp_device_capabilities_log_page -	Device Capability Log page
 * @pcie_exp_port:						PCI Express Ports
 * @oob_management_support:				OOB Management Support
 * @wz_cmd_support:						Write Zeroes Command Support
 * @sanitize_cmd_support:				Sanitize Command Support
 * @dsm_cmd_support:					Dataset Management Command Support
 * @wu_cmd_support:						Write Uncorrectable Command Support
 * @fused_operation_support:			Fused Operation Support
 * @min_valid_dssd_pwr_state:			Minimum Valid DSSD Power State
 * @dssd_pwr_state_desc:				DSSD Power State Descriptors
 * @vendor_specific_command_timeout:	Vendor Specific Command Timeout
 * @reserved:							Reserved
 * @log_page_version:					Log Page Version
 * @log_page_guid:						Log Page GUID
 */
struct __packed ocp_device_capabilities_log_page {
	__le16  pcie_exp_port;
	__le16  oob_management_support;
	__le16  wz_cmd_support;
	__le16  sanitize_cmd_support;
	__le16  dsm_cmd_support;
	__le16  wu_cmd_support;
	__le16  fused_operation_support;
	__le16  min_valid_dssd_pwr_state;
	__u8    dssd_pwr_state_desc[128];
	__u8    reserved[3934];
	__le16  log_page_version;
	__u8    log_page_guid[16];
};

static void ocp_print_c4_log_normal(struct ocp_device_capabilities_log_page *log_data);
static void ocp_print_c4_log_json(struct ocp_device_capabilities_log_page *log_data);
static void ocp_print_c4_log_binary(struct ocp_device_capabilities_log_page *log_data);
static int get_c4_log_page(struct nvme_dev *dev, char *format);
static int ocp_device_capabilities_log(int argc, char **argv, struct command *cmd, struct plugin *plugin);

static void ocp_print_c4_log_normal(struct ocp_device_capabilities_log_page *log_data)
{
	int i;

	printf("  Device Capability/C4 Log Page Data\n");
	printf("  PCI Express Ports						: 0x%x\n", le16_to_cpu(log_data->pcie_exp_port));
	printf("  OOB Management Support				: 0x%x\n", le16_to_cpu(log_data->oob_management_support));
	printf("  Write Zeroes Command Support			: 0x%x\n", le16_to_cpu(log_data->wz_cmd_support));
	printf("  Sanitize Command Support				: 0x%x\n", le16_to_cpu(log_data->sanitize_cmd_support));
	printf("  Dataset Management Command Support	: 0x%x\n", le16_to_cpu(log_data->dsm_cmd_support));
	printf("  Write Uncorrectable Command Support	: 0x%x\n", le16_to_cpu(log_data->wu_cmd_support));
	printf("  Fused Operation Support				: 0x%x\n", le16_to_cpu(log_data->fused_operation_support));
	printf("  Minimum Valid DSSD Power State		: 0x%x\n", le16_to_cpu(log_data->min_valid_dssd_pwr_state));
	printf("  DSSD Power State Descriptors					: 0x");
	for (i = 0; i <= 127; i++)
		printf("%x", log_data->dssd_pwr_state_desc[i]);
	printf("\n");
	printf("  Log Page Version						: 0x%x\n", le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID							: 0x");
	for (i = C4_GUID_LENGTH - 1; i >= 0; i--)
		printf("%x", log_data->log_page_guid[i]);
	printf("\n");
}

static void ocp_print_c4_log_json(struct ocp_device_capabilities_log_page *log_data)
{
	struct json_object *root = json_create_object();
	char guid[64];
	int i;

	json_object_add_value_int(root, "PCI Express Ports", le16_to_cpu(log_data->pcie_exp_port));
	json_object_add_value_int(root, "OOB Management Support", le16_to_cpu(log_data->oob_management_support));
	json_object_add_value_int(root, "Write Zeroes Command Support", le16_to_cpu(log_data->wz_cmd_support));
	json_object_add_value_int(root, "Sanitize Command Support", le16_to_cpu(log_data->sanitize_cmd_support));
	json_object_add_value_int(root, "Dataset Management Command Support", le16_to_cpu(log_data->dsm_cmd_support));
	json_object_add_value_int(root, "Write Uncorrectable Command Support", le16_to_cpu(log_data->wu_cmd_support));
	json_object_add_value_int(root, "Fused Operation Support", le16_to_cpu(log_data->fused_operation_support));
	json_object_add_value_int(root, "Minimum Valid DSSD Power State", le16_to_cpu(log_data->min_valid_dssd_pwr_state));
	for (i = 0; i <= 127; i++)
		json_object_add_value_int(root, "DSSD Power State Descriptors", log_data->dssd_pwr_state_desc[i]);
	json_object_add_value_int(root, "Log Page Version", le16_to_cpu(log_data->log_page_version));

	memset((void *)guid, 0, 64);
	sprintf((char *)guid, "0x%"PRIx64"%"PRIx64"", (uint64_t)le64_to_cpu(*(uint64_t *)&log_data->log_page_guid[8]),
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data->log_page_guid[0]));
	json_object_add_value_string(root, "Log page GUID", guid);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void ocp_print_c4_log_binary(struct ocp_device_capabilities_log_page *log_data)
{
	return d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static int get_c4_log_page(struct nvme_dev *dev, char *format)
{
	struct ocp_device_capabilities_log_page *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i, j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C4_DEV_CAP_REQ_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C4_DEV_CAP_REQ_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C4_DEV_CAP_REQ_OPCODE, C4_DEV_CAP_REQ_LEN, data);

	if (!ret) {
		log_data = (struct ocp_device_capabilities_log_page *)data;

		/* check log page version */
		if (log_data->log_page_version != C4_DEV_CAP_REQ_VERSION) {
			fprintf(stderr, "ERROR : OCP : invalid device capabilities log page version\n");
			ret = -1;
			goto out;
		}

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (dev_cap_req_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C4 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", dev_cap_req_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_c4_log_normal(log_data);
			break;
		case JSON:
			ocp_print_c4_log_json(log_data);
			break;
		case BINARY:
			ocp_print_c4_log_binary(log_data);
			break;
		default:
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C4 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_device_capabilities_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve C4h Device Capabilities Log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json|binary"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c4_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C4h Log Page, ret = %d\n", ret);
	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Set Telemetry Profile (Feature Identifier C8h) Set Feature

static int ocp_set_telemetry_profile(struct nvme_dev *dev, __u8 tps)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	/* OCP 2.0 requires UUID index support */
	err = ocp_get_uuid_index(dev, &uuid_index);
	if (err || !uuid_index) {
		nvme_show_error("ERROR: No OCP UUID index found");
		return err;
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = 0xC8,
		.nsid = 0xFFFFFFFF,
		.cdw11 = tps,
		.cdw12 = 0,
		.save = true,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set Telemetry Profile");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully Set Telemetry Profile (feature: 0xC8) to below values\n");
		printf("Telemetry Profile Select: 0x%x\n", tps);
	}

	return err;
}

static int ocp_set_telemetry_profile_feature(int argc, char **argv, struct command *cmd,
					     struct plugin *plugin)
{
	const char *desc = "Set Telemetry Profile (Feature Identifier C8h) Set Feature.";
	const char *tps = "Telemetry Profile Select for device debug data collection";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 tps;
	};

	struct config cfg = {
		.tps = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("telemetry-profile-select", 't', &cfg.tps, tps),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "telemetry-profile-select"))
		err = ocp_set_telemetry_profile(dev, cfg.tps);
	else
		nvme_show_error("Telemetry Profile Select is a required argument");

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// DSSD Power State (Feature Identifier C7h) Set Feature

static int set_dssd_power_state(struct nvme_dev *dev, const __u32 nsid,
				const __u8 fid, __u8 power_state, bool save,
				bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = power_state,
		.cdw12 = 0,
		.save = save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define DSSD Power State");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set DSSD Power State (feature: 0xC7) to below values\n");
		printf("DSSD Power State: 0x%x\n", power_state);
		printf("Save bit Value: 0x%x\n", save);
	}

	return err;
}

static int set_dssd_power_state_feature(int argc, char **argv, struct command *cmd,
										struct plugin *plugin)
{
	const char *desc = "Define DSSD Power State (Feature Identifier C7h) Set Feature.";
	const char *power_state = "DSSD Power State to set in watts";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	const __u8 fid = 0xC7;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 power_state;
		bool save;
	};

	struct config cfg = {
		.power_state = 0,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("power-state", 'p', &cfg.power_state, power_state),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "power-state"))
		err = set_dssd_power_state(dev, nsid, fid, cfg.power_state,
					       cfg.save,
					       !argconfig_parse_seen(opts, "no-uuid"));

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// DSSD Power State (Feature Identifier C7h) Get Feature

static int get_dssd_power_state(struct nvme_dev *dev, const __u32 nsid,
				const __u8 fid, __u8 sel, bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= 0,
		.uuidx		= uuid_index,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC7 %s value: %#08x\n", nvme_select_to_string(sel), result);

		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC7 with sel: %d\n", sel);
	}

	return err;
}

static int get_dssd_power_state_feature(int argc, char **argv, struct command *cmd,
										struct plugin *plugin)
{
	const char *desc = "Define DSSD Power State (Feature Identifier C7h) Get Feature.";
	const char *all = "Print out all 3 values at once - Current, Default, and Saved";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const __u32 nsid = 0;
	const __u8 fid = 0xC7;
	struct nvme_dev *dev;
	int i, err;

	struct config {
		__u8 sel;
		bool all;
	};

	struct config cfg = {
		.sel = 0,
		.all = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_FLAG("all", 'a', NULL, all),
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "all")) {
		for (i = 0; i < 3; i++) {
			err = get_dssd_power_state(dev, nsid, fid, i,
							!argconfig_parse_seen(opts, "no-uuid"));
			if (err)
				break;
		}
	} else if (argconfig_parse_seen(opts, "sel"))
		err = get_dssd_power_state(dev, nsid, fid, cfg.sel,
					       !argconfig_parse_seen(opts, "no-uuid"));
	else
		nvme_show_error("Required to have --sel as an argument, or pass the --all flag.");

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// plp_health_check_interval

static int set_plp_health_check_interval(int argc, char **argv, struct command *cmd,
					 struct plugin *plugin)
{

	const char *desc = "Define Issue Set Feature command (FID : 0xC6) PLP Health Check Interval";
	const char *plp_health_interval = "[31:16]:PLP Health Check Interval";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	const __u8 fid = 0xc6;
	struct nvme_dev *dev;
	int err;
	__u32 result;
	__u8 uuid_index = 0;

	struct config {
		__le16 plp_health_interval;
		bool save;
	};

	struct config cfg = {
		.plp_health_interval = 0,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("plp_health_interval", 'p', &cfg.plp_health_interval, plp_health_interval),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_FLAG("no-uuid", 'n', NULL,
			"Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	if (!argconfig_parse_seen(opts, "no-uuid")) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			printf("ERROR: No OCP UUID index found");
			return err;
		}
	}


	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = cfg.plp_health_interval << 16,
		.cdw12 = 0,
		.save = cfg.save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define PLP Health Check Interval");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set the PLP Health Check Interval");
		printf("PLP Health Check Interval: 0x%x\n", cfg.plp_health_interval);
		printf("Save bit Value: 0x%x\n", cfg.save);
	}
	return err;
}

static int get_plp_health_check_interval(int argc, char **argv, struct command *cmd,
					 struct plugin *plugin)
{

	const char *desc = "Define Issue Get Feature command (FID : 0xC6) PLP Health Check Interval";
	const char *sel = "[0-3,8]: current/default/saved/supported/changed";
	const __u32 nsid = 0;
	const __u8 fid = 0xc6;
	struct nvme_dev *dev;
	__u32 result;
	int err;

	struct config {
		__u8 sel;
	};

	struct config cfg = {
		.sel = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = fid,
		.nsid       = nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = 0,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC6 %s value: %#08x\n", nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC6");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// dssd_async_event_config

static int set_dssd_async_event_config(int argc, char **argv, struct command *cmd,
				       struct plugin *plugin)
{

	const char *desc = "Issue Set Feature command (FID : 0xC9) DSSD Async Event Config";
	const char *epn = "[0]:Enable Panic Notices";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	const __u8 fid = 0xc9;
	struct nvme_dev *dev;
	int err;
	__u32 result;
	__u8 uuid_index = 0;

	struct config {
		bool epn;
		bool save;
	};

	struct config cfg = {
		.epn = false,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("enable-panic-notices", 'e', &cfg.epn, epn),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	/* OCP 2.0 requires UUID index support */
	err = ocp_get_uuid_index(dev, &uuid_index);
	if (err || !uuid_index) {
		printf("ERROR: No OCP UUID index found\n");
		return err;
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = cfg.epn ? 1 : 0,
		.cdw12 = 0,
		.save = cfg.save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set DSSD Asynchronous Event Configuration\n");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set the DSSD Asynchronous Event Configuration\n");
		printf("Enable Panic Notices bit Value: 0x%x\n", cfg.epn);
		printf("Save bit Value: 0x%x\n", cfg.save);
	}
	return err;
}

static int get_dssd_async_event_config(int argc, char **argv, struct command *cmd,
				       struct plugin *plugin)
{

	const char *desc = "Issue Get Feature command (FID : 0xC9) DSSD Async Event Config";
	const char *sel = "[0-3]: current/default/saved/supported";
	const __u32 nsid = 0;
	const __u8 fid = 0xc9;
	struct nvme_dev *dev;
	__u32 result;
	int err;

	struct config {
		__u8 sel;
	};

	struct config cfg = {
		.sel = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = fid,
		.nsid       = nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = 0,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC9 %s value: %#08x\n", nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC9\n");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Telemetry String Log Format Log Page (LID : C9h)

/* Function declaration for Telemetry String Log Format (LID:C9h) */
static int ocp_telemetry_str_log_format(int argc, char **argv, struct command *cmd,
					struct plugin *plugin);


static int ocp_print_C9_log_normal(struct telemetry_str_log_format *log_data, __u8 *log_data_buf)
{
	//calculating the index value for array
	__le64 stat_id_index = (log_data->sitsz * 4) / 16;
	__le64 eve_id_index = (log_data->estsz * 4) / 16;
	__le64 vu_eve_index = (log_data->vu_eve_st_sz * 4) / 16;
	__le64 ascii_table_index = (log_data->asctsz * 4);
	//Calculating the offset for dynamic fields.
	__le64 stat_id_str_table_ofst = log_data->sits * 4;
	__le64 event_str_table_ofst = log_data->ests * 4;
	__le64 vu_event_str_table_ofst = log_data->vu_eve_sts * 4;
	__le64 ascii_table_ofst = log_data->ascts * 4;
	struct statistics_id_str_table_entry stat_id_str_table_arr[stat_id_index];
	struct event_id_str_table_entry event_id_str_table_arr[eve_id_index];
	struct vu_event_id_str_table_entry vu_event_id_str_table_arr[vu_eve_index];
	int j;

	printf("  Log Page Version                                : 0x%x\n", log_data->log_page_version);

	printf("  Reserved                                        : ");
	for (j = 0; j < 15; j++)
		printf("%d", log_data->reserved1[j]);
	printf("\n");

	printf("  Log page GUID                                   : 0x");
	for (j = C9_GUID_LENGTH - 1; j >= 0; j--)
		printf("%x", log_data->log_page_guid[j]);
	printf("\n");

	printf("  Telemetry String Log Size                       : 0x%lx\n", le64_to_cpu(log_data->sls));

	printf("  Reserved                                        : ");
	for (j = 0; j < 24; j++)
		printf("%d", log_data->reserved2[j]);
	printf("\n");

	printf("  Statistics Identifier String Table Start        : 0x%lx\n", le64_to_cpu(log_data->sits));
	printf("  Statistics Identifier String Table Size         : 0x%lx\n", le64_to_cpu(log_data->sitsz));
	printf("  Event String Table Start                        : 0x%lx\n", le64_to_cpu(log_data->ests));
	printf("  Event String Table Size                         : 0x%lx\n", le64_to_cpu(log_data->estsz));
	printf("  VU Event String Table Start                     : 0x%lx\n", le64_to_cpu(log_data->vu_eve_sts));
	printf("  VU Event String Table Size                      : 0x%lx\n", le64_to_cpu(log_data->vu_eve_st_sz));
	printf("  ASCII Table Start                               : 0x%lx\n", le64_to_cpu(log_data->ascts));
	printf("  ASCII Table Size                                : 0x%lx\n", le64_to_cpu(log_data->asctsz));

	printf("  FIFO 1 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo1[j], log_data->fifo1[j]);

	printf("  FIFO 2 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo2[j], log_data->fifo2[j]);

	printf("  FIFO 3 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo3[j], log_data->fifo3[j]);

	printf("  FIFO 4 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo4[j], log_data->fifo4[j]);

	printf("  FIFO 5 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo5[j], log_data->fifo5[j]);

	printf("  FIFO 6 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo6[j], log_data->fifo6[j]);

	printf("  FIFO 7 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo7[j], log_data->fifo7[j]);

	printf("  FIFO 8 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo8[j], log_data->fifo8[j]);

	printf("  FIFO 9 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo9[j], log_data->fifo9[j]);

	printf("  FIFO 10 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo10[j], log_data->fifo10[j]);

	printf("  FIFO 11 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo11[j], log_data->fifo11[j]);

	printf("  FIFO 12 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo12[j], log_data->fifo12[j]);

	printf("  FIFO 13 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo13[j], log_data->fifo13[j]);

	printf("  FIFO 14 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo14[j], log_data->fifo14[j]);

	printf("  FIFO 15 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo15[j], log_data->fifo16[j]);

	printf("  FIFO 16 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c    \n", j, log_data->fifo16[j], log_data->fifo16[j]);

	printf("  Reserved                                        : ");
	for (j = 0; j < 48; j++)
		printf("%d", log_data->reserved3[j]);
	printf("\n");


	if (log_data->sitsz != 0) {
		memcpy(stat_id_str_table_arr,
		(__u8 *)log_data_buf + stat_id_str_table_ofst,
		(log_data->sitsz * 4));
		printf("  Statistics Identifier String Table\n");
		for (j = 0; j < stat_id_index; j++) {
			printf("   Vendor Specific Statistic Identifier : 0x%x\n",
			le16_to_cpu(stat_id_str_table_arr[j].vs_si));
			printf("   Reserved                             : 0x%x\n",
			stat_id_str_table_arr[j].reserved1);
			printf("   ASCII ID Length                      : 0x%x\n",
			stat_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset                      : 0x%lx\n",
			le64_to_cpu(stat_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                             : 0x%x\n",
			stat_id_str_table_arr[j].reserved2);
		}
	}


	if (log_data->estsz != 0) {
		memcpy(event_id_str_table_arr, (__u8 *)log_data_buf +
		event_str_table_ofst, (log_data->estsz * 4));
		printf("  Event Identifier String Table Entry\n");
		for (j = 0; j < eve_id_index; j++) {
			printf("   Debug Event Class        : 0x%x\n",
			event_id_str_table_arr[j].deb_eve_class);
			printf("   Event Identifier         : 0x%x\n",
			le16_to_cpu(event_id_str_table_arr[j].ei));
			printf("   ASCII ID Length          : 0x%x\n",
			event_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset          : 0x%lx\n",
			le64_to_cpu(event_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                 : 0x%x\n",
			event_id_str_table_arr[j].reserved2);

		}
	}

	if (log_data->vu_eve_st_sz != 0) {
		memcpy(vu_event_id_str_table_arr, (__u8 *)log_data_buf +
		vu_event_str_table_ofst, (log_data->vu_eve_st_sz * 4));
		printf("  VU Event Identifier String Table Entry\n");
		for (j = 0; j < vu_eve_index; j++) {
			printf("   Debug Event Class        : 0x%x\n",
			vu_event_id_str_table_arr[j].deb_eve_class);
			printf("   VU Event Identifier      : 0x%x\n",
			le16_to_cpu(vu_event_id_str_table_arr[j].vu_ei));
			printf("   ASCII ID Length          : 0x%x\n",
			vu_event_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset          : 0x%lx\n",
			le64_to_cpu(vu_event_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                 : 0x%x\n",
			vu_event_id_str_table_arr[j].reserved);

		}
	}

	if (log_data->asctsz != 0) {
		printf("  ASCII Table\n");
		printf("   Byte    Data_Byte    ASCII_Character\n");
		for (j = 0; j < ascii_table_index; j++)
			printf("    %lld        %d             %c\n",
			ascii_table_ofst+j, log_data_buf[ascii_table_ofst + j],
			(char)log_data_buf[ascii_table_ofst + j]);
	}

	return 0;
}

static int ocp_print_C9_log_json(struct telemetry_str_log_format *log_data, __u8 *log_data_buf)
{
	struct json_object *root = json_create_object();
	char res_arr[48];
	char *res = res_arr;
	char guid_buf[C9_GUID_LENGTH];
	char *guid = guid_buf;
	char fifo_arr[16];
	char *fifo = fifo_arr;
	char buf[128];
	//calculating the index value for array
	__le64 stat_id_index = (log_data->sitsz * 4) / 16;
	__le64 eve_id_index = (log_data->estsz * 4) / 16;
	__le64 vu_eve_index = (log_data->vu_eve_st_sz * 4) / 16;
	__le64 ascii_table_index = (log_data->asctsz * 4);
	//Calculating the offset for dynamic fields.
	__le64 stat_id_str_table_ofst = log_data->sits * 4;
	__le64 event_str_table_ofst = log_data->ests * 4;
	__le64 vu_event_str_table_ofst = log_data->vu_eve_sts * 4;
	__le64 ascii_table_ofst = log_data->ascts * 4;
	struct statistics_id_str_table_entry stat_id_str_table_arr[stat_id_index];
	struct event_id_str_table_entry event_id_str_table_arr[eve_id_index];
	struct vu_event_id_str_table_entry vu_event_id_str_table_arr[vu_eve_index];
	__u8 ascii_table_info_arr[ascii_table_index];
	char ascii_buf[ascii_table_index];
	char *ascii = ascii_buf;
	int j;

	json_object_add_value_int(root, "Log Page Version", le16_to_cpu(log_data->log_page_version));

	memset((__u8 *)res, 0, 15);
	for (j = 0; j < 15; j++)
		res += sprintf(res, "%d", log_data->reserved1[j]);
	json_object_add_value_string(root, "Reserved", res_arr);

	memset((void *)guid, 0, C9_GUID_LENGTH);
	for (j = C9_GUID_LENGTH - 1; j >= 0; j--)
		guid += sprintf(guid, "%02x", log_data->log_page_guid[j]);
	json_object_add_value_string(root, "Log page GUID", guid_buf);

	json_object_add_value_int(root, "Telemetry String Log Size", le64_to_cpu(log_data->sls));

	memset((__u8 *)res, 0, 24);
	for (j = 0; j < 24; j++)
		res += sprintf(res, "%d", log_data->reserved2[j]);
	json_object_add_value_string(root, "Reserved", res_arr);

	json_object_add_value_int(root, "Statistics Identifier String Table Start", le64_to_cpu(log_data->sits));
	json_object_add_value_int(root, "Event String Table Start", le64_to_cpu(log_data->ests));
	json_object_add_value_int(root, "Event String Table Size", le64_to_cpu(log_data->estsz));
	json_object_add_value_int(root, "VU Event String Table Start", le64_to_cpu(log_data->vu_eve_sts));
	json_object_add_value_int(root, "VU Event String Table Size", le64_to_cpu(log_data->vu_eve_st_sz));
	json_object_add_value_int(root, "ASCII Table Start", le64_to_cpu(log_data->ascts));
	json_object_add_value_int(root, "ASCII Table Size", le64_to_cpu(log_data->asctsz));

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo1[j]);
	json_object_add_value_string(root, "FIFO 1 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo2[j]);
	json_object_add_value_string(root, "FIFO 2 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo3[j]);
	json_object_add_value_string(root, "FIFO 3 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo4[j]);
	json_object_add_value_string(root, "FIFO 4 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo5[j]);
	json_object_add_value_string(root, "FIFO 5 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo6[j]);
	json_object_add_value_string(root, "FIFO 6 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo7[j]);
	json_object_add_value_string(root, "FIFO 7 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo8[j]);
	json_object_add_value_string(root, "FIFO 8 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo9[j]);
	json_object_add_value_string(root, "FIFO 9 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo10[j]);
	json_object_add_value_string(root, "FIFO 10 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo11[j]);
	json_object_add_value_string(root, "FIFO 11 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo12[j]);
	json_object_add_value_string(root, "FIFO 12 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo13[j]);
	json_object_add_value_string(root, "FIFO 13 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo14[j]);
	json_object_add_value_string(root, "FIFO 14 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo15[j]);
	json_object_add_value_string(root, "FIFO 15 ASCII String", fifo_arr);

	memset((void *)fifo, 0, 16);
	for (j = 0; j < 16; j++)
		fifo += sprintf(fifo, "%c", log_data->fifo16[j]);
	json_object_add_value_string(root, "FIFO 16 ASCII String", fifo_arr);

	memset((__u8 *)res, 0, 48);
	for (j = 0; j < 48; j++)
		res += sprintf(res, "%d", log_data->reserved3[j]);
	json_object_add_value_string(root, "Reserved", res_arr);

	if (log_data->sitsz != 0) {

		memcpy(stat_id_str_table_arr,
		(__u8 *)log_data_buf + stat_id_str_table_ofst,
		(log_data->sitsz * 4));
		struct json_object *stat_table = json_create_object();

		for (j = 0; j < stat_id_index; j++) {
			struct json_object *entry = json_create_object();

			json_object_add_value_uint(entry, "Vendor Specific Statistic Identifier",
			le16_to_cpu(stat_id_str_table_arr[j].vs_si));
			json_object_add_value_uint(entry, "Reserved",
			le64_to_cpu(stat_id_str_table_arr[j].reserved1));
			json_object_add_value_uint(entry, "ASCII ID Length",
			le64_to_cpu(stat_id_str_table_arr[j].ascii_id_len));
			json_object_add_value_uint(entry, "ASCII ID offset",
			le64_to_cpu(stat_id_str_table_arr[j].ascii_id_ofst));
			json_object_add_value_uint(entry, "Reserved2",
			le64_to_cpu(stat_id_str_table_arr[j].reserved2));
			sprintf(buf, "Statistics Identifier String Table %d", j);
			json_object_add_value_object(stat_table, buf, entry);
		}

		json_object_add_value_object(root,
		"Statistics Identifier String Table", stat_table);
	}

	if (log_data->estsz != 0) {
		struct json_object *eve_table = json_create_object();

		memcpy(event_id_str_table_arr,
		(__u8 *)log_data_buf + event_str_table_ofst,
		(log_data->estsz * 4));
		for (j = 0; j < eve_id_index; j++) {
			struct json_object *entry = json_create_object();

			json_object_add_value_int(entry, "Debug Event Class",
			le16_to_cpu(event_id_str_table_arr[j].deb_eve_class));
			json_object_add_value_int(entry, "Event Identifier",
			le16_to_cpu(event_id_str_table_arr[j].ei));
			json_object_add_value_int(entry, "ASCII ID Length",
			le64_to_cpu(event_id_str_table_arr[j].ascii_id_len));
			json_object_add_value_int(entry, "ASCII ID offset",
			le64_to_cpu(event_id_str_table_arr[j].ascii_id_ofst));
			json_object_add_value_int(entry, "Reserved",
			le64_to_cpu(event_id_str_table_arr[j].reserved2));
			sprintf(buf, "Event Identifier String Table Entry %d", j);
			json_object_add_value_object(eve_table, buf, entry);
		}
		json_object_add_value_object(root,
		"Event Identifier String Table Entry",
		eve_table);
	}

	if (log_data->vu_eve_st_sz != 0) {
		struct json_object *vu_eve_table = json_create_object();

		memcpy(vu_event_id_str_table_arr,
		(__u8 *)log_data_buf + vu_event_str_table_ofst,
		(log_data->vu_eve_st_sz * 4));
		for (j = 0; j < vu_eve_index; j++) {
			struct json_object *entry = json_create_object();

			json_object_add_value_int(entry, "Debug Event Class",
			le16_to_cpu(vu_event_id_str_table_arr[j].deb_eve_class));
			json_object_add_value_int(entry, "VU Event Identifier",
			le16_to_cpu(vu_event_id_str_table_arr[j].vu_ei));
			json_object_add_value_int(entry, "ASCII ID Length",
			le64_to_cpu(vu_event_id_str_table_arr[j].ascii_id_len));
			json_object_add_value_int(entry, "ASCII ID offset",
			le64_to_cpu(vu_event_id_str_table_arr[j].ascii_id_ofst));
			json_object_add_value_int(entry, "Reserved",
			le64_to_cpu(vu_event_id_str_table_arr[j].reserved));
			sprintf(buf, "VU Event Identifier String Table Entry %d", j);
			json_object_add_value_object(vu_eve_table, buf, entry);
		}
		json_object_add_value_object(root,
		"VU Event Identifier String Table Entry",
		vu_eve_table);
	}

	if (log_data->asctsz != 0) {
		memcpy(ascii_table_info_arr,
		(__u8 *)log_data_buf + ascii_table_ofst,
		(log_data->asctsz * 4));
		memset((void *)ascii, 0, ascii_table_index);
		for (j = 0; j < ascii_table_index; j++)
			ascii += sprintf(ascii, "%c", ascii_table_info_arr[j]);
		json_object_add_value_string(root, "ASCII Table", ascii_buf);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);

	return 0;
}

static void ocp_print_c9_log_binary(__u8 *log_data_buf, int total_log_page_size)
{
	return d_raw((unsigned char *)log_data_buf, total_log_page_size);
}

static int get_c9_log_page(struct nvme_dev *dev, char *format)
{

	int ret = 0;

	nvme_print_flags_t fmt;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	get_c9_log_page_data(dev, 1, 0);

	if (!ret) {
		switch (fmt) {
		case NORMAL:
			ocp_print_C9_log_normal(log_data, pC9_string_buffer);
			break;
		case JSON:
			ocp_print_C9_log_json(log_data, pC9_string_buffer);
			break;
		case BINARY:
			ocp_print_c9_log_binary(pC9_string_buffer, total_log_page_sz);
			break;
		default:
			fprintf(stderr, "unhandled output format\n");
			break;
		}
	} else
		fprintf(stderr, "ERROR : OCP : Unable to read C9 data from buffer\n");
	free(header_data);
	return ret;
}

static int ocp_telemetry_str_log_format(int argc, char **argv, struct command *cmd,
					struct plugin *plugin)
{
	struct nvme_dev *dev;
	int ret = 0;
	const char *desc = "Retrieve telemetry string log format";

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c9_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C9 Log Page, ret = %d\n", ret);

	dev_close(dev);

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// TCG Configuration Log Page (LID : C7h)

/* C7 TCG Configuration Log Page */
#define C7_GUID_LENGTH                     16
#define C7_TCG_CONFIGURATION_LEN           512
#define C7_TCG_CONFIGURATION_OPCODE        0xC7
#define C7_TCG_CONFIGURATION_LOG_VERSION   0x1

static __u8 tcg_configuration_guid[C7_GUID_LENGTH] = {
	0x06, 0x40, 0x24, 0xBD,
	0x7E, 0xE0, 0xE6, 0x83,
	0xC0, 0x47, 0x54, 0xFA,
	0x9D, 0x2A, 0xE0, 0x54
};

/*
 * struct tcg_configuration_log - TCG Configuration Log Page Structure
 * @state:                            state
 * @rsvd1:                            Reserved1
 * @locking_sp_act_count:             Locking SP Activation Count
 * @type_rev_count:                   Tper Revert Count
 * @locking_sp_rev_count:             Locking SP Revert Count.
 * @no_of_locking_obj:                Number of Locking Objects
 * @no_of_single_um_locking_obj:      Number of Single User Mode Locking Objects
 * @no_of_range_prov_locking_obj:     Number of Range Provisioned Locking Objects
 * @no_of_ns_prov_locking_obj:        Number of Namespace Provisioned Locking Objects
 * @no_of_read_lock_locking_obj:      Number of Read Locked Locking Objects
 * @no_of_write_lock_locking_obj:     Number of Write Locked Locking Objects
 * @no_of_read_unlock_locking_obj:    Number of Read Unlocked Locking Objects
 * @no_of_read_unlock_locking_obj:    Number of Write Unlocked Locking Objects
 * @rsvd2:                            Reserved2
 * @sid_auth_try_count:               SID Authentication Try Count
 * @sid_auth_try_limit:               SID Authentication Try Limit
 * @pro_tcg_rc:                       Programmatic TCG Reset Count
 * @pro_rlc:                          Programmatic Reset Lock Count
 * @tcg_ec:                           TCG Error Count
 * @rsvd3:                            Reserved3
 * @log_page_version:                 Log Page Version
 */
struct __packed tcg_configuration_log {
	__u8    state;
	__u8    rsvd1[3];
	__u8    locking_sp_act_count;
	__u8    type_rev_count;
	__u8    locking_sp_rev_count;
	__u8    no_of_locking_obj;
	__u8    no_of_single_um_locking_obj;
	__u8    no_of_range_prov_locking_obj;
	__u8    no_of_ns_prov_locking_obj;
	__u8    no_of_read_lock_locking_obj;
	__u8    no_of_write_lock_locking_obj;
	__u8    no_of_read_unlock_locking_obj;
	__u8    no_of_write_unlock_locking_obj;
	__u8    rsvd2;
	__u32   sid_auth_try_count;
	__u32   sid_auth_try_limit;
	__u32   pro_tcg_rc;
	__u32   pro_rlc;
	__u32   tcg_ec;
	__u8    rsvd3[458];
	__le16  log_page_version;
	__u8    log_page_guid[C7_GUID_LENGTH];

};

/* Function declaration for TCG Configuration log page (LID:C7h) */
static int ocp_tcg_configuration_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin);

static int ocp_print_C7_log_normal(struct nvme_dev *dev,
				   struct tcg_configuration_log *log_data)
{
	int j;

	printf("TCG Configuration C7 Log Page Data-\n");

	printf("  State                                                  : 0x%x\n", log_data->state);
	printf("  Reserved1                                              : 0x");
	for (j = 0; j < 3; j++)
		printf("%d", log_data->rsvd1[j]);
	printf("\n");
	printf("  Locking SP Activation Count                            : 0x%x\n", log_data->locking_sp_act_count);
	printf("  Tper Revert Count                                      : 0x%x\n", log_data->type_rev_count);
	printf("  Locking SP Revert Count                                : 0x%x\n", log_data->locking_sp_rev_count);
	printf("  Number of Locking Objects                              : 0x%x\n", log_data->no_of_locking_obj);
	printf("  Number of Single User Mode Locking Objects             : 0x%x\n", log_data->no_of_single_um_locking_obj);
	printf("  Number of Range Provisioned Locking Objects            : 0x%x\n", log_data->no_of_range_prov_locking_obj);
	printf("  Number of Namespace Provisioned Locking Objects        : 0x%x\n", log_data->no_of_ns_prov_locking_obj);
	printf("  Number of Read Locked Locking Objects                  : 0x%x\n", log_data->no_of_read_lock_locking_obj);
	printf("  Number of Write Locked Locking Objects                 : 0x%x\n", log_data->no_of_write_lock_locking_obj);
	printf("  Number of Read Unlocked Locking Objects                : 0x%x\n", log_data->no_of_read_unlock_locking_obj);
	printf("  Number of Write Unlocked Locking Objects               : 0x%x\n", log_data->no_of_write_unlock_locking_obj);
	printf("  Reserved2                                              : 0x%x\n", log_data->rsvd2);

	printf("  SID Authentication Try Count                           : 0x%x\n", le32_to_cpu(log_data->sid_auth_try_count));
	printf("  SID Authentication Try Limit                           : 0x%x\n", le32_to_cpu(log_data->sid_auth_try_limit));
	printf("  Programmatic TCG Reset Count                           : 0x%x\n", le32_to_cpu(log_data->pro_tcg_rc));
	printf("  Programmatic Reset Lock Count                          : 0x%x\n", le32_to_cpu(log_data->pro_rlc));
	printf("  TCG Error Count                                        : 0x%x\n", le32_to_cpu(log_data->tcg_ec));

	printf("  Reserved3                                              : 0x");
	for (j = 0; j < 458; j++)
		printf("%d", log_data->rsvd3[j]);
	printf("\n");

	printf("  Log Page Version                                       : 0x%x\n", le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID                                          : 0x");
	for (j = C7_GUID_LENGTH - 1; j >= 0; j--)
		printf("%x", log_data->log_page_guid[j]);
	printf("\n");

	return 0;
}

static void ocp_print_C7_log_json(struct tcg_configuration_log *log_data)
{
	int j;
	struct json_object *root;
	char guid_buf[C7_GUID_LENGTH];
	char *guid = guid_buf;
	char res_arr[458];
	char *res = res_arr;

	root = json_create_object();

	json_object_add_value_int(root, "State", le16_to_cpu(log_data->state));
	memset((__u8 *)res, 0, 3);
	for (j = 0; j < 3; j++)
		res += sprintf(res, "%d", log_data->rsvd1[j]);
	json_object_add_value_string(root, "Reserved1", res_arr);
	json_object_add_value_int(root, "Locking SP Activation Count", le16_to_cpu(log_data->locking_sp_act_count));
	json_object_add_value_int(root, "Tper Revert Count", le16_to_cpu(log_data->locking_sp_rev_count));
	json_object_add_value_int(root, "Number of Locking Objects", le16_to_cpu(log_data->no_of_locking_obj));
	json_object_add_value_int(root, "Number of Single User Mode Locking Objects", le16_to_cpu(log_data->no_of_single_um_locking_obj));
	json_object_add_value_int(root, "Number of Range Provisioned Locking Objects", le16_to_cpu(log_data->no_of_range_prov_locking_obj));
	json_object_add_value_int(root, "Number of Namespace Provisioned Locking Objects", le16_to_cpu(log_data->no_of_ns_prov_locking_obj));
	json_object_add_value_int(root, "Number of Read Locked Locking Objects", le16_to_cpu(log_data->no_of_read_lock_locking_obj));
	json_object_add_value_int(root, "Number of Write Locked Locking Objects", le16_to_cpu(log_data->no_of_write_lock_locking_obj));
	json_object_add_value_int(root, "Number of Read Unlocked Locking Objects", le16_to_cpu(log_data->no_of_read_unlock_locking_obj));
	json_object_add_value_int(root, "Number of Write Unlocked Locking Objects", le16_to_cpu(log_data->no_of_write_unlock_locking_obj));
	json_object_add_value_int(root, "Reserved2", le16_to_cpu(log_data->rsvd2));

	json_object_add_value_int(root, "SID Authentication Try Count", le16_to_cpu(log_data->sid_auth_try_count));
	json_object_add_value_int(root, "SID Authentication Try Limit", le16_to_cpu(log_data->sid_auth_try_limit));
	json_object_add_value_int(root, "Programmatic TCG Reset Count", le16_to_cpu(log_data->pro_tcg_rc));
	json_object_add_value_int(root, "Programmatic Reset Lock Count", le16_to_cpu(log_data->pro_rlc));
	json_object_add_value_int(root, "TCG Error Count", le16_to_cpu(log_data->tcg_ec));

	memset((__u8 *)res, 0, 458);
	for (j = 0; j < 458; j++)
		res += sprintf(res, "%d", log_data->rsvd3[j]);
	json_object_add_value_string(root, "Reserved3", res_arr);

	json_object_add_value_int(root, "Log Page Version", le16_to_cpu(log_data->log_page_version));

	memset((void *)guid, 0, C7_GUID_LENGTH);
	for (j = C7_GUID_LENGTH - 1; j >= 0; j--)
		guid += sprintf(guid, "%02x", log_data->log_page_guid[j]);
	json_object_add_value_string(root, "Log page GUID", guid_buf);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

static void ocp_print_c7_log_binary(struct tcg_configuration_log *log_data)
{
	return d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static int get_c7_log_page(struct nvme_dev *dev, char *format)
{
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;
	struct tcg_configuration_log *log_data;
	int j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C7_TCG_CONFIGURATION_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C7_TCG_CONFIGURATION_LEN);

	ret = nvme_get_log_simple(dev_fd(dev), C7_TCG_CONFIGURATION_OPCODE,
				  C7_TCG_CONFIGURATION_LEN, data);
	if (!ret) {
		log_data = (struct tcg_configuration_log *)data;

		/* check log page version */
		if (log_data->log_page_version != C7_TCG_CONFIGURATION_LOG_VERSION) {
			fprintf(stderr, "ERROR : OCP : invalid TCG Configuration Log Page version\n");
			ret = -1;
			goto out;
		}

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (tcg_configuration_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C7 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", tcg_configuration_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_C7_log_normal(dev, log_data);
			break;
		case JSON:
			ocp_print_C7_log_json(log_data);
			break;
		case BINARY:
			ocp_print_c7_log_binary(log_data);
			break;
		default:
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C7 data from buffer\n");
	}

out:
	free(data);
	return ret;
}


static int ocp_tcg_configuration_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin)
{
	const char *desc = "Retrieve TCG Configuration Log Page Data";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c7_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C7 Log Page, ret = %d\n", ret);

	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Misc

static int clear_fw_update_history(int argc, char **argv,
				   struct command *cmd, struct plugin *plugin)
{
	return ocp_clear_fw_update_history(argc, argv, cmd, plugin);
}

static int smart_add_log(int argc, char **argv, struct command *cmd,
			 struct plugin *plugin)
{
	return ocp_smart_add_log(argc, argv, cmd, plugin);
}

static int clear_pcie_correctable_error_counters(int argc, char **argv, struct command *cmd,
						struct plugin *plugin)
{
	return ocp_clear_pcie_correctable_errors(argc, argv, cmd, plugin);
}

static int fw_activation_history_log(int argc, char **argv, struct command *cmd,
				     struct plugin *plugin)
{
	return ocp_fw_activation_history_log(argc, argv, cmd, plugin);
}

static int error_injection_get(struct nvme_dev *dev, const __u8 sel, bool uuid)
{
	struct erri_get_cq_entry cq_entry;
	int err;
	int i;
	const __u8 fid = 0xc0;

	_cleanup_free_ struct erri_entry *entry = NULL;

	struct nvme_get_features_args args = {
		.result = (__u32 *)&cq_entry,
		.data = entry,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.sel = sel,
		.data_len = sizeof(*entry) * ERRI_ENTRIES_MAX,
		.fid = fid,
	};

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	entry = nvme_alloc(args.data_len);
	if (!entry) {
		nvme_show_error("malloc: %s", strerror(errno));
		return -errno;
	}

	err = nvme_cli_get_features(dev, &args);
	if (!err) {
		nvme_show_result("Number of Error Injecttions (feature: %#0*x): %#0*x (%s: %d)",
				 fid ? 4 : 2, fid, cq_entry.nume ? 10 : 8, cq_entry.nume,
				 nvme_select_to_string(sel), cq_entry.nume);
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, *args.result);
		for (i = 0; i < cq_entry.nume; i++) {
			printf("Entry: %d, Flags: %x (%s%s), Type: %x (%s), NRTDP: %d\n", i,
			       entry->flags, entry->enable ? "Enabled" : "Disabled",
			       entry->single ? ", Single instance" : "", entry->type,
			       erri_type_to_string(entry->type), entry->nrtdp);
		}
	} else {
		nvme_show_error("Could not get feature: %#0*x.", fid ? 4 : 2, fid);
	}

	return err;
}

static int get_error_injection(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Return set of error injection";
	int err;
	struct config {
		__u8 sel;
	};
	struct config cfg = { 0 };

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	return error_injection_get(dev, cfg.sel, !argconfig_parse_seen(opts, "no-uuid"));
}

static int error_injection_set(struct nvme_dev *dev, struct erri_config *cfg, bool uuid)
{
	int err;
	__u32 result;
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = 0xc0,
		.cdw11 = cfg->number,
		.data_len = cfg->number * sizeof(struct erri_entry),
		.timeout = nvme_cfg.timeout,
		.result = &result,
	};

	_cleanup_fd_ int ffd = -1;

	_cleanup_free_ struct erri_entry *entry = NULL;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	entry = nvme_alloc(args.data_len);
	if (!entry) {
		nvme_show_error("malloc: %s", strerror(errno));
		return -errno;
	}

	if (cfg->file && strlen(cfg->file)) {
		ffd = open(cfg->file, O_RDONLY);
		if (ffd < 0) {
			nvme_show_error("Failed to open file %s: %s", cfg->file, strerror(errno));
			return -EINVAL;
		}
		err = read(ffd, entry, args.data_len);
		if (err < 0) {
			nvme_show_error("failed to read data buffer from input file: %s",
					strerror(errno));
			return -errno;
		}
	} else {
		entry->enable = 1;
		entry->single = 1;
		entry->type = cfg->type;
		entry->nrtdp = cfg->nrtdp;
	}

	args.data = entry;

	err = nvme_set_features(&args);
	if (err) {
		if (err < 0)
			nvme_show_error("set-error-injection: %s", nvme_strerror(errno));
		else if (err > 0)
			nvme_show_status(err);
		return err;
	}

	printf("set-error-injection, data: %s, number: %d, uuid: %d, type: %d, nrtdp: %d\n",
	       cfg->file, cfg->number, args.uuidx, cfg->type, cfg->nrtdp);
	if (args.data)
		d(args.data, args.data_len, 16, 1);

	return 0;
}

static int set_error_injection(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Inject error conditions";
	int err;
	struct erri_config cfg = {
		.number = 1,
	};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	NVME_ARGS(opts,
		  OPT_FILE("data", 'd', &cfg.file, data),
		  OPT_BYTE("number", 'n', &cfg.number, number),
		  OPT_FLAG("no-uuid", 'N', NULL, no_uuid),
		  OPT_SHRT("type", 't', &cfg.type, type),
		  OPT_SHRT("nrtdp", 'r', &cfg.nrtdp, nrtdp));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	return error_injection_set(dev, &cfg, !argconfig_parse_seen(opts, "no-uuid"));
}
