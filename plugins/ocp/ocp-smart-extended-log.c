// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#include "ocp-smart-extended-log.h"

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"

/* C0 SCAO Log Page */
#define C0_SMART_CLOUD_ATTR_LEN			0x200
#define C0_SMART_CLOUD_ATTR_OPCODE		0xC0
#define C0_GUID_LENGTH				16

static __u8 scao_guid[C0_GUID_LENGTH] = {
	0xC5, 0xAF, 0x10, 0x28,
	0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C,
	0xC9, 0x14, 0xD5, 0xAF
};

enum {
	SCAO_PMUW	= 0,	/* Physical media units written */
	SCAO_PMUR	= 16,	/* Physical media units read */
	SCAO_BUNBR	= 32,	/* Bad user nand blocks raw */
	SCAO_BUNBN	= 38,	/* Bad user nand blocks normalized */
	SCAO_BSNBR	= 40,	/* Bad system nand blocks raw */
	SCAO_BSNBN	= 46,	/* Bad system nand blocks normalized */
	SCAO_XRC	= 48,	/* XOR recovery count */
	SCAO_UREC	= 56,	/* Uncorrectable read error count */
	SCAO_SEEC	= 64,	/* Soft ecc error count */
	SCAO_EEDC	= 72,	/* End to end detected errors */
	SCAO_EECE	= 76,	/* End to end corrected errors */
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
	SCAO_PLRC	= 192,	/* PCIe Link Retraining Count */
	SCAO_PSCC	= 200,	/* Power State Change Count */
	SCAO_LPV	= 494,	/* Log page version */
	SCAO_LPG	= 496,	/* Log page GUID */
};

static void ocp_print_C0_log_normal(void *data)
{
	uint16_t smart_log_ver = 0;
	__u8 *log_data = data;

	printf("SMART Cloud Attributes :-\n");

	printf("  Physical media units written -		%"PRIu64" %"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW + 8] & 0xFFFFFFFFFFFFFFFF),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	printf("  Physical media units read    -		%"PRIu64" %"PRIu64"\n",
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
	printf("  End to end detected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	printf("  End to end corrected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
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
	printf("  Current throttling status			0x%x\n",
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
		       le16_to_cpu(*(uint16_t *)&log_data[SCAO_PVF]));
		printf("  Minor Version Field                           %"PRIu16"\n",
		       le16_to_cpu(*(uint16_t *)&log_data[SCAO_MIVF]));
		printf("  Major Version Field                           %d\n",
		       (__u8)log_data[SCAO_MAVF]);
		printf("  NVMe Errata Version				%d\n",
		       (__u8)log_data[SCAO_NEV]);
		printf("  PCIe Link Retraining Count			%"PRIu64"\n",
		       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
		printf("  Power State Change Count			%"PRIu64"\n",
		       le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
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
	json_object_add_value_uint(root, "End to end detected errors",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	json_object_add_value_uint(root, "End to end corrected errors",
		(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
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
					   le16_to_cpu(*(uint16_t *)&log_data[SCAO_PVF]));
		json_object_add_value_uint(root, "Minor Version Field",
					   le16_to_cpu(*(uint16_t *)&log_data[SCAO_MIVF]));
		json_object_add_value_uint(root, "Major Version Field",
					   (__u8)log_data[SCAO_MAVF]);
		json_object_add_value_uint(root, "NVMe Errata Version",
					   (__u8)log_data[SCAO_NEV]);
		json_object_add_value_uint(root, "PCIe Link Retraining Count",
					   (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
		json_object_add_value_uint(root, "Power State Change Count",
					   le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int get_c0_log_page(int fd, char *format)
{
	nvme_print_flags_t fmt;
	__u8 *data;
	int i;
	int ret;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
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
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", scao_guid[j]);

				fprintf(stderr, "\nERROR : OCP : Actual GUID:    0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", data[SCAO_LPG + j]);
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
		default:
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C0 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
			     struct plugin *plugin)
{
	const char *desc = "Retrieve the extended SMART health data.";
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
