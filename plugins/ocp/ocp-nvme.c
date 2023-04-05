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

#include "ocp-smart-extended-log.h"
#include "ocp-clear-fw-update-history.h"
#include "ocp-fw-activation-history.h"

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

struct __attribute__((__packed__)) ssd_latency_monitor_log {
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

struct __attribute__((__packed__)) feature_latency_monitor {
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

static int convert_ts(time_t time, char *ts_buf)
{
	struct tm gmTimeInfo;
	time_t time_Human, time_ms;
	char buf[80];

	time_Human = time/1000;
	time_ms = time % 1000;

	gmtime_r((const time_t *)&time_Human, &gmTimeInfo);

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &gmTimeInfo);
	sprintf(ts_buf, "%s.%03ld GMT", buf, time_ms);

	return 0;
}

static int ocp_print_C3_log_normal(struct nvme_dev *dev,
				   struct ssd_latency_monitor_log *log_data)
{
	char ts_buf[128];
	int i, j;
	int pos = 0;

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
	printf("  Active Latency Minimum Window      %d ms\n",
	       C3_MINIMUM_WINDOW_INCREMENT *
	       le16_to_cpu(log_data->active_latency_min_window));
	printf("  Active Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->active_latency_stamp_units));
	printf("  Static Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->static_latency_stamp_units));
	printf("  Debug Log Trigger Enable           %d\n",
	       le16_to_cpu(log_data->debug_log_trigger_enable));
	printf("  Debug Log Measured Latency         %d \n",
	       le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1)
	       printf("  Debug Log Latency Time Stamp       N/A \n");
	else {
	       convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
	       printf("  Debug Log Latency Time Stamp       %s \n", ts_buf);
	}
	printf("  Debug Log Pointer                  %d \n",
	       le16_to_cpu(log_data->debug_log_ptr));
	printf("  Debug Counter Trigger Source       %d \n",
	       le16_to_cpu(log_data->debug_log_counter_trigger));
	printf("  Debug Log Stamp Units              %d \n",
	       le16_to_cpu(log_data->debug_log_stamp_units));
	printf("  Log Page Version                   %d \n",
	       le16_to_cpu(log_data->log_page_version));

	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];
	for (i = C3_GUID_LENGTH - 1; i >= 0; i--) {
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);
	}
	printf("  Log Page GUID                      %s \n", guid);
	printf("\n");

	printf("                                                            Read                           Write                 Deallocate/Trim \n");
	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Latency Mode: Bucket %d      %27d     %27d     %27d\n",
		       i,
		       log_data->active_latency_config & (1 << pos),
		       log_data->active_latency_config & (1 << pos),
		       log_data->active_latency_config & (1 << pos));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Bucket Counter: Bucket %d    %27d     %27d     %27d \n",
		       i,
		       le32_to_cpu(log_data->active_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->active_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->active_bucket_counter[i][TRIM]));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->active_measured_latency[i][READ-1]),
		       le16_to_cpu(log_data->active_measured_latency[i][WRITE-1]),
		       le16_to_cpu(log_data->active_measured_latency[i][TRIM-1]));
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
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms \n",
		       i,
		       le16_to_cpu(log_data->static_measured_latency[i][READ-1]),
		       le16_to_cpu(log_data->static_measured_latency[i][WRITE-1]),
		       le16_to_cpu(log_data->static_measured_latency[i][TRIM-1]));
	}

	return 0;
}

static void ocp_print_C3_log_json(struct ssd_latency_monitor_log *log_data)
{
	struct json_object *root;
	char ts_buf[128];
	char buf[128];
	int i, j;
	int pos = 0;
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

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Latency Mode: Bucket %d", i);
		for (j = 2; j >= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
						   log_data->active_latency_config & (1 << pos));
		}
		json_object_add_value_object(root, buf, bucket);
	}

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
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
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
				le16_to_cpu(log_data->active_measured_latency[i][j]));
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
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
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
				le16_to_cpu(log_data->static_measured_latency[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	json_object_add_value_uint(root, "Static Latency Stamp Units",
		le16_to_cpu(log_data->static_latency_stamp_units));
	json_object_add_value_uint(root, "Debug Log Trigger Enable",
		le16_to_cpu(log_data->debug_log_trigger_enable));
	json_object_add_value_uint(root, "Debug Log Measured Latency",
		le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1)
		json_object_add_value_string(root, "Debug Log Latency Time Stamp", "NA");
	else {
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
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	int i;

	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return fmt;
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
		fprintf(stderr,
			"NVMe Status:%s(%x)\n",
			nvme_status_to_string(ret, false),
			ret);

	if (ret == 0) {
		log_data = (struct ssd_latency_monitor_log *)data;

		/* check log page version */
		if (log_data->log_page_version != C3_LATENCY_MON_VERSION) {
			fprintf(stderr,
				"ERROR : OCP : invalid latency monitor version\n");
			ret = -1;
			goto out;
		}

		/* check log page guid */
		/* Verify GUID matches */
		for (i = 0; i < 16; i++) {
			if (lat_mon_guid[i] != log_data->log_page_guid[i]) {
				int j;

				fprintf(stderr, "ERROR : OCP : Unknown GUID in C3 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++) {
					fprintf(stderr, "%x", lat_mon_guid[j]);
				}

				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++) {
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				}
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
		.data = (void*)&buf,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("NVME_FEAT_OCP_LATENCY_MONITOR: 0x%02x \n", NVME_FEAT_OCP_LATENCY_MONITOR);
		printf("active bucket timer threshold: 0x%x \n", buf.active_bucket_timer_threshold);
		printf("active threshold a: 0x%x \n", buf.active_threshold_a);
		printf("active threshold b: 0x%x \n", buf.active_threshold_b);
		printf("active threshold c: 0x%x \n", buf.active_threshold_c);
		printf("active threshold d: 0x%x \n", buf.active_threshold_d);
		printf("active latency config: 0x%x \n", buf.active_latency_config);
		printf("active latency minimum window: 0x%x \n", buf.active_latency_minimum_window);
		printf("debug log trigger enable: 0x%x \n", buf.debug_log_trigger_enable);
		printf("discard debug log: 0x%x \n", buf.discard_debug_log);
		printf("latency monitor feature enable: 0x%x \n", buf.latency_monitor_feature_enable);
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

static int eol_plp_failure_mode_get(struct nvme_dev *dev, const __u32 nsid,
				    const __u8 fid, __u8 sel)
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

	err = nvme_get_features(&args);
	if (!err) {
		printf("End of Life Behavior (feature: %#0*x): %#0*x (%s: %s)\n",
		       fid ? 4 : 2, fid, result ? 10 : 8, result,
		       nvme_select_to_string(sel),
		       eol_plp_failure_mode_to_string(result));
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(result);
	} else {
		printf("Could not get feature: %#0*x.\n", fid ? 4 : 2, fid);
	}

	return err;
}

static int eol_plp_failure_mode_set(struct nvme_dev *dev, const __u32 nsid,
				    const __u8 fid, __u8 mode, bool save,
				    bool uuid)
{
	__u32 result;
	int err;
	int uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			fprintf(stderr, "ERROR: No OCP UUID index found\n");
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
		perror("Define EOL/PLP failure mode");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set mode (feature: %#0*x): %#0*x (%s: %s).\n",
		       fid ? 4 : 2, fid, mode ? 10 : 8, mode,
		       save ? "Save" : "Not save",
		       eol_plp_failure_mode_to_string(mode));
	}

	return err;
}

static int eol_plp_failure_mode(int argc, char **argv, struct command *cmd,
				struct plugin *plugin)
{
	const char *desc = "Define EOL or PLP circuitry failure mode.\n"\
			   "No argument prints current mode.";
	const char *mode = "[0-3]: default/rom/wtm/normal";
	const char *save = "Specifies that the controller shall save the attribute";
	const char *sel = "[0-3,8]: current/default/saved/supported/changed";
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

	OPT_ARGS(opts) = {
		OPT_BYTE("mode", 'm', &cfg.mode, mode),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "mode"))
		err = eol_plp_failure_mode_set(dev, nsid, fid, cfg.mode,
					       cfg.save,
					       !argconfig_parse_seen(opts, "no-uuid"));
	else
		err = eol_plp_failure_mode_get(dev, nsid, fid, cfg.sel);

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Misc

static const __u8 OCP_FID_CLEAR_PCIE_CORRECTABLE_ERROR_COUNTERS = 0xC3;

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

static int clear_pcie_corectable_error_counters(int argc, char **argv,
						struct command *cmd,
						struct plugin *plugin)
{
	const char *desc = "OCP Clear PCIe Correctable Error Counters";

	return ocp_clear_feature(argc, argv, desc,
				 OCP_FID_CLEAR_PCIE_CORRECTABLE_ERROR_COUNTERS);
}

static int fw_activation_history_log(int argc, char **argv, struct command *cmd,
				     struct plugin *plugin)
{
	return ocp_fw_activation_history_log(argc, argv, cmd, plugin);
}
