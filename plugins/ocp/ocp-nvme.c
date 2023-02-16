// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
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
#include "ocp-clear-fw-update-history.h"

#define CREATE_CMD
#include "ocp-nvme.h"

/* C0 SCAO Log Page */
#define C0_SMART_CLOUD_ATTR_LEN			0x200
#define C0_SMART_CLOUD_ATTR_OPCODE		0xC0
#define C0_GUID_LENGTH				16
#define C0_ACTIVE_BUCKET_TIMER_INCREMENT	5
#define C0_ACTIVE_THRESHOLD_INCREMENT		5
#define C0_MINIMUM_WINDOW_INCREMENT		100

static __u8 scao_guid[C0_GUID_LENGTH] = {
	0xC5, 0xAF, 0x10, 0x28,
	0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C,
	0xC9, 0x14, 0xD5, 0xAF
};

/* C3 Latency Monitor Log Page */
#define C3_LATENCY_MON_LOG_BUF_LEN		0x200
#define C3_LATENCY_MON_OPCODE			0xC3
#define C3_LATENCY_MON_VERSION			0x0001
#define C3_GUID_LENGTH				16
static __u8 lat_mon_guid[C3_GUID_LENGTH] = {
	0x92, 0x7a, 0xc0, 0x8c,
	0xd0, 0x84, 0x6c, 0x9c,
	0x70, 0x43, 0xe6, 0xd4,
	0x58, 0x5e, 0xd4, 0x85
};

#define READ		0
#define WRITE		1
#define TRIM		2
#define RESERVED	3

typedef enum {
	SCAO_PMUW	= 0,	/* Physical media units written */
	SCAO_PMUR	= 16,	/* Physical media units read */
	SCAO_BUNBR	= 32,	/* Bad user nand blocks raw */
	SCAO_BUNBN	= 38,	/* Bad user nand blocks normalized */
	SCAO_BSNBR	= 40,	/* Bad system nand blocks raw */
	SCAO_BSNBN	= 46,	/* Bad system nand blocks normalized */
	SCAO_XRC	= 48,	/* XOR recovery count */
	SCAO_UREC	= 56,	/* Uncorrectable read error count */
	SCAO_SEEC	= 64,	/* Soft ecc error count */
	SCAO_EECE	= 72,	/* End to end corrected errors */
	SCAO_EEDC	= 76,	/* End to end detected errors */
	SCAO_SDPU	= 80,	/* System data percent used */
	SCAO_RFSC	= 81,	/* Refresh counts */
	SCAO_MXUDEC	= 88,	/* Max User data erase counts */
	SCAO_MNUDEC	= 92,	/* Min User data erase counts */
	SCAO_NTTE	= 96,	/* Number of Thermal throttling events */
	SCAO_CTS	= 97,	/* Current throttling status */
	SCAO_EVF	= 98,	/* Errata Version Field */
	SCAO_PVF	= 99,	/* Point Version Field */
	SCAO_MIVF	= 101,	/* Minor Version Field */
	SCAO_MAVF	= 103,	/* Major Version Field */
	SCAO_PCEC	= 104,	/* PCIe correctable error count */
	SCAO_ICS	= 112,	/* Incomplete shutdowns */
	SCAO_PFB	= 120,	/* Percent free blocks */
	SCAO_CPH	= 128,	/* Capacitor health */
	SCAO_NEV	= 130,  /* NVMe Errata Version */
	SCAO_UIO	= 136,	/* Unaligned I/O */
	SCAO_SVN	= 144,	/* Security Version Number */
	SCAO_NUSE	= 152,	/* NUSE - Namespace utilization */
	SCAO_PSC	= 160,	/* PLP start count */
	SCAO_EEST	= 176,	/* Endurance estimate */
	SCAO_PLRC	= 192,  /* PCIe Link Retraining Count */
	SCAO_LPV	= 494,	/* Log page version */
	SCAO_LPG	= 496,	/* Log page GUID */
} SMART_CLOUD_ATTRIBUTE_OFFSETS;

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

static void ocp_print_C0_log_normal(void *data)
{
	uint16_t smart_log_ver = 0;
	__u8 *log_data = data;

	printf("SMART Cloud Attributes :-\n");

	printf("  Physical media units written -   	        %"PRIu64" %"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW + 8] & 0xFFFFFFFFFFFFFFFF),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	printf("  Physical media units read    - 	        %"PRIu64" %"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR + 8] & 0xFFFFFFFFFFFFFFFF),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR] & 0xFFFFFFFFFFFFFFFF));
	printf("  Bad user nand blocks - Raw			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad user nand blocks - Normalized		%d\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	printf("  Bad system nand blocks - Raw			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad system nand blocks - Normalized		%d\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	printf("  XOR recovery count				%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	printf("  Uncorrectable read error count		%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	printf("  Soft ecc error count				%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	printf("  End to end corrected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	printf("  End to end detected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	printf("  System data percent used			%d\n",
	       (__u8)log_data[SCAO_SDPU]);
	printf("  Refresh counts				%"PRIu64"\n",
	       (uint64_t)(le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC]) & 0x00FFFFFFFFFFFFFF));
	printf("  Max User data erase counts			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	printf("  Min User data erase counts			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	printf("  Number of Thermal throttling events		%d\n",
	       (__u8)log_data[SCAO_NTTE]);
	printf("  Current throttling status		  	0x%x\n",
	       (__u8)log_data[SCAO_CTS]);
	printf("  PCIe correctable error count			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	printf("  Incomplete shutdowns				%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	printf("  Percent free blocks				%d\n",
	       (__u8)log_data[SCAO_PFB]);
	printf("  Capacitor health				%"PRIu16"\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  Unaligned I/O					%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	printf("  Security Version Number			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	printf("  NUSE - Namespace utilization			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	printf("  PLP start count				%s\n",
	       uint128_t_to_string(le128_to_cpu(&log_data[SCAO_PSC])));
	printf("  Endurance estimate				%s\n",
	       uint128_t_to_string(le128_to_cpu(&log_data[SCAO_EEST])));
	smart_log_ver = (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);
	printf("  Log page version				%"PRIu16"\n", smart_log_ver);
	printf("  Log page GUID					0x");
	printf("%"PRIx64"%"PRIx64"\n", (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	if (smart_log_ver > 2) {
		printf("  Errata Version Field                          %d\n",
		       (__u8)log_data[SCAO_EVF]);
		printf("  Point Version Field                           %"PRIu16"\n",
		       (uint16_t)log_data[SCAO_PVF]);
		printf("  Minor Version Field                           %"PRIu16"\n",
		       (uint16_t)log_data[SCAO_MIVF]);
		printf("  Major Version Field                           %d\n",
		       (__u8)log_data[SCAO_MAVF]);
		printf("  NVMe Errata Version				%d\n",
		       (__u8)log_data[SCAO_NEV]);
		printf("  PCIe Link Retraining Count			%"PRIu64"\n",
		       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
	}
	printf("\n");
}

static void ocp_print_C0_log_json(void *data)
{
	struct json_object *root;
	struct json_object *pmuw;
	struct json_object *pmur;
	uint16_t smart_log_ver = 0;
	__u8 *log_data = data;
	char guid[40];

	root = json_create_object();
	pmuw = json_create_object();
	pmur = json_create_object();

	json_object_add_value_uint64(pmuw, "hi",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW + 8] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_uint64(pmuw, "lo",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_object(root, "Physical media units written", pmuw);
	json_object_add_value_uint64(pmur, "hi",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR + 8] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_uint64(pmur, "lo",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_object(root, "Physical media units read", pmur);
	json_object_add_value_uint64(root, "Bad user nand blocks - Raw",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(root, "Bad user nand blocks - Normalized",
		(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	json_object_add_value_uint64(root, "Bad system nand blocks - Raw",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(root, "Bad system nand blocks - Normalized",
		(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	json_object_add_value_uint64(root, "XOR recovery count",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	json_object_add_value_uint64(root, "Uncorrectable read error count",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	json_object_add_value_uint64(root, "Soft ecc error count",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	json_object_add_value_uint(root, "End to end corrected errors",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	json_object_add_value_uint(root, "End to end detected errors",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	json_object_add_value_uint(root, "System data percent used",
		(__u8)log_data[SCAO_SDPU]);
	json_object_add_value_uint64(root, "Refresh counts",
		(uint64_t)(le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC]) & 0x00FFFFFFFFFFFFFF));
	json_object_add_value_uint(root, "Max User data erase counts",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	json_object_add_value_uint(root, "Min User data erase counts",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	json_object_add_value_uint(root, "Number of Thermal throttling events",
		(__u8)log_data[SCAO_NTTE]);
	json_object_add_value_uint(root, "Current throttling status",
		(__u8)log_data[SCAO_CTS]);
	json_object_add_value_uint64(root, "PCIe correctable error count",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	json_object_add_value_uint(root, "Incomplete shutdowns",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	json_object_add_value_uint(root, "Percent free blocks",
		(__u8)log_data[SCAO_PFB]);
	json_object_add_value_uint(root, "Capacitor health",
		(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	json_object_add_value_uint64(root, "Unaligned I/O",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	json_object_add_value_uint64(root, "Security Version Number",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	json_object_add_value_uint64(root, "NUSE - Namespace utilization",
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	json_object_add_value_uint128(root, "PLP start count",
		le128_to_cpu(&log_data[SCAO_PSC]));
	json_object_add_value_uint128(root, "Endurance estimate",
		le128_to_cpu(&log_data[SCAO_EEST]));
	smart_log_ver = (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);

	json_object_add_value_uint(root, "Log page version", smart_log_ver);

	memset((void *)guid, 0, 40);
	sprintf((char *)guid, "0x%"PRIx64"%"PRIx64"", (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	json_object_add_value_string(root, "Log page GUID", guid);

	if (smart_log_ver > 2) {
		json_object_add_value_uint(root, "Errata Version Field",
					   (__u8)log_data[SCAO_EVF]);
		json_object_add_value_uint(root, "Point Version Field",
					   (uint16_t)log_data[SCAO_PVF]);
		json_object_add_value_uint(root, "Minor Version Field",
					   (uint16_t)log_data[SCAO_MIVF]);
		json_object_add_value_uint(root, "Major Version Field",
					   (__u8)log_data[SCAO_MAVF]);
		json_object_add_value_uint(root, "NVMe Errata Version",
					   (__u8)log_data[SCAO_NEV]);
		json_object_add_value_uint(root, "PCIe Link Retraining Count",
					   (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int get_c0_log_page(int fd, char *format)
{
	__u8 *data;
	int i;
	int ret = 0;
	int fmt = -1;

	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return fmt;
	}

	data = malloc(sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);

	ret = nvme_get_log_simple(fd, C0_SMART_CLOUD_ATTR_OPCODE,
		C0_SMART_CLOUD_ATTR_LEN, data);

	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(ret, false), ret);

	if (ret == 0) {
		/* check log page guid */
		/* Verify GUID matches */
		for (i = 0; i < 16; i++) {
			if (scao_guid[i] != data[SCAO_LPG + i])	{
				int j;

				fprintf(stderr, "ERROR : OCP : Unknown GUID in C0 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID:  0x");
				for (j = 0; j < 16; j++) {
					fprintf(stderr, "%x", scao_guid[j]);
				}

				fprintf(stderr, "\nERROR : OCP : Actual GUID:    0x");
				for (j = 0; j < 16; j++) {
					fprintf(stderr, "%x", data[SCAO_LPG + j]);
				}
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		/* print the data */
		switch (fmt) {
		case NORMAL:
			ocp_print_C0_log_normal(data);
			break;
		case JSON:
			ocp_print_C0_log_json(data);
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C0 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
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
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c0_log_page(dev_fd(dev), cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C0 Log Page, ret = %d\n",
			ret);
	dev_close(dev);
	return ret;
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
	       C0_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer));
	printf("  Active Bucket Timer Threshold      %d min\n",
	       C0_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer_threshold));
	printf("  Active Threshold A                 %d ms\n",
	       C0_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_a+1));
	printf("  Active Threshold B                 %d ms\n",
	       C0_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_b+1));
	printf("  Active Threshold C                 %d ms\n",
	       C0_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_c+1));
	printf("  Active Threshold D                 %d ms\n",
	       C0_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_d+1));
	printf("  Active Latency Minimum Window      %d ms\n",
	       C0_MINIMUM_WINDOW_INCREMENT *
	       le16_to_cpu(log_data->active_latency_min_window));
	printf("  Active Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->active_latency_stamp_units));
	printf("  Static Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->static_latency_stamp_units));
	printf("  Debug Log Trigger Enable           %d\n",
	       le16_to_cpu(log_data->debug_log_trigger_enable));

	printf("                                                            Read                           Write                 Deallocate/Trim \n");
	for (i = 0; i <= 3; i++) {
		printf("  Active Latency Mode: Bucket %d      %27d     %27d     %27d\n",
		       i,
		       log_data->active_latency_config & (1 << pos),
		       log_data->active_latency_config & (1 << pos),
		       log_data->active_latency_config & (1 << pos));
	}
	printf("\n");

	for (i = 0; i <= 3; i++) {
		printf("  Active Bucket Counter: Bucket %d    %27d     %27d     %27d \n",
		       i,
		       le32_to_cpu(log_data->active_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->active_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->active_bucket_counter[i][TRIM]));
	}

	for (i = 0; i <= 3; i++) {
		printf("  Active Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->active_measured_latency[i][READ]),
		       le16_to_cpu(log_data->active_measured_latency[i][WRITE]),
		       le16_to_cpu(log_data->active_measured_latency[i][TRIM]));
	}

	for (i = 0; i <= 3; i++) {
		printf("  Active Latency Time Stamp: Bucket %d    ", i);
		for (j = 0; j <= 2; j++) {
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i <= 3; i++) {
		printf("  Static Bucket Counter: Bucket %d    %27d     %27d     %27d\n",
		       i,
		       le32_to_cpu(log_data->static_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->static_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->static_bucket_counter[i][TRIM]));
	}

	for (i = 0; i <= 3; i++) {
		printf("  Static Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms \n",
		       i,
		       le16_to_cpu(log_data->static_measured_latency[i][READ]),
		       le16_to_cpu(log_data->static_measured_latency[i][WRITE]),
		       le16_to_cpu(log_data->static_measured_latency[i][TRIM]));
	}

	for (i = 0; i <= 3; i++) {
		printf("  Static Latency Time Stamp: Bucket %d    ", i);
		for (j = 0; j <= 2; j++) {
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
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
	char *operation[3] = {"Read", "Write", "Trim"};

	root = json_create_object();

	json_object_add_value_uint(root, "Feature Status",
		log_data->feature_status);
	json_object_add_value_uint(root, "Active Bucket Timer",
		C0_ACTIVE_BUCKET_TIMER_INCREMENT *
		le16_to_cpu(log_data->active_bucket_timer));
	json_object_add_value_uint(root, "Active Bucket Timer Threshold",
		C0_ACTIVE_BUCKET_TIMER_INCREMENT *
		le16_to_cpu(log_data->active_bucket_timer_threshold));
	json_object_add_value_uint(root, "Active Threshold A",
		C0_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_a + 1));
	json_object_add_value_uint(root, "Active Threshold B",
		C0_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_b + 1));
	json_object_add_value_uint(root, "Active Threshold C",
		C0_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_c + 1));
	json_object_add_value_uint(root, "Active Threshold D",
		C0_ACTIVE_THRESHOLD_INCREMENT *
		le16_to_cpu(log_data->active_threshold_d + 1));
	json_object_add_value_uint(root, "Active Lantency Minimum Window",
		C0_MINIMUM_WINDOW_INCREMENT *
		le16_to_cpu(log_data->active_latency_min_window));
	json_object_add_value_uint(root, "Active Latency Stamp Units",
		le16_to_cpu(log_data->active_latency_stamp_units));
	json_object_add_value_uint(root, "Static Latency Stamp Units",
		le16_to_cpu(log_data->static_latency_stamp_units));
	json_object_add_value_uint(root, "Debug Log Trigger Enable",
		le16_to_cpu(log_data->debug_log_trigger_enable));

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Latency Mode: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			json_object_add_value_uint(bucket, operation[j],
						   log_data->active_latency_config & (1 << pos));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Bucket Counter: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			json_object_add_value_uint(bucket, operation[j],
				le32_to_cpu(log_data->active_bucket_counter[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Measured Latency: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			json_object_add_value_uint(bucket, operation[j],
				le16_to_cpu(log_data->active_measured_latency[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Active Latency Time Stamp: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Bucket Counter: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			json_object_add_value_uint(bucket, operation[j],
				le32_to_cpu(log_data->static_bucket_counter[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Measured Latency: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			json_object_add_value_uint(bucket, operation[j],
				le16_to_cpu(log_data->static_measured_latency[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}

	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;

		bucket = json_create_object();
		sprintf(buf, "Static Latency Time Stamp: Bucket %d", i);
		for (j = 0; j <= 2; j++) {
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}

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

static int clear_fw_update_history(int argc, char **argv,
				   struct command *cmd, struct plugin *plugin)
{
	return ocp_clear_fw_update_history(argc, argv, cmd, plugin);
}
