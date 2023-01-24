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

#include "ocp-utils.h"

#define C0_SMART_CLOUD_ATTR_LEN		0x200
#define C0_SMART_CLOUD_ATTR_OPCODE	0xC0
#define C0_GUID_LENGTH	16

static __u8 scao_guid[C0_GUID_LENGTH] = { 0xC5, 0xAF, 0x10, 0x28, 0xEA, 0xBF,
				0xF2, 0xA4, 0x9C, 0x4F, 0x6F, 0x7C, 0xC9, 0x14, 0xD5, 0xAF };

enum {
	SCAO_PMUW               =  0,	/* Physical media units written */
	SCAO_PMUR               = 16,	/* Physical media units read */
	SCAO_BUNBR              = 32,	/* Bad user nand blocks raw */
	SCAO_BUNBN              = 38,	/* Bad user nand blocks normalized */
	SCAO_BSNBR              = 40,	/* Bad system nand blocks raw */
	SCAO_BSNBN              = 46,	/* Bad system nand blocks normalized */
	SCAO_XRC                = 48,	/* XOR recovery count */
	SCAO_UREC               = 56,	/* Uncorrectable read error count */
	SCAO_SEEC               = 64,	/* Soft ecc error count */
	SCAO_EECE               = 72,	/* End to end corrected errors */
	SCAO_EEDC               = 76,	/* End to end detected errors */
	SCAO_SDPU               = 80,	/* System data percent used */
	SCAO_RFSC               = 81,	/* Refresh counts */
	SCAO_MXUDEC             = 88,	/* Max User data erase counts */
	SCAO_MNUDEC             = 92,	/* Min User data erase counts */
	SCAO_NTTE               = 96,	/* Number of Thermal throttling events */
	SCAO_CTS                = 97,	/* Current throttling status */
	SCAO_EVF                = 98,   /* Errata Version Field */
	SCAO_PVF                = 99,   /* Point Version Field */
	SCAO_MIVF               = 101,  /* Minor Version Field */
	SCAO_MAVF               = 103,  /* Major Version Field */
	SCAO_PCEC               = 104,	/* PCIe correctable error count */
	SCAO_ICS                = 112,	/* Incomplete shutdowns */
	SCAO_PFB                = 120,	/* Percent free blocks */
	SCAO_CPH                = 128,	/* Capacitor health */
	SCAO_NEV                = 130,  /* NVMe Errata Version */
	SCAO_UIO                = 136,	/* Unaligned I/O */
	SCAO_SVN                = 144,	/* Security Version Number */
	SCAO_NUSE               = 152,	/* NUSE - Namespace utilization */
	SCAO_PSC                = 160,	/* PLP start count */
	SCAO_EEST               = 176,	/* Endurance estimate */
	SCAO_PLRC               = 192,  /* PCIe Link Retraining Count */
	SCAO_PSCC               = 200,  /* Power State Change Count */
	SCAO_LPV                = 494,	/* Log page version */
	SCAO_LPG                = 496,	/* Log page GUID */
} SMART_CLOUD_ATTRIBUTE_OFFSETS;

static void print_C0_log_json(__u8 *log_data)
{
	struct json_object *root = json_create_object();
	struct json_object *pmuw = json_create_object();
	struct json_object *pmur = json_create_object();
	struct json_object *bunb = json_create_object();
	struct json_object *bsnb = json_create_object();

	json_object_add_value_uint64(pmuw, "hi",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW + 8]));
	json_object_add_value_uint64(pmuw, "lo",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW]));
	json_object_add_value_object(root, "Physical media units written", pmuw);

	json_object_add_value_uint64(pmur, "hi",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR + 8]));
	json_object_add_value_uint64(pmur, "lo",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR]));
	json_object_add_value_object(root, "Physical media units read", pmur);

	json_object_add_value_uint64(bunb, "raw",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(bunb, "normalized",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	json_object_add_value_object(root, "Bad user nand blocks", bunb);

	json_object_add_value_uint64(bsnb, "raw",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(bsnb, "normalized",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	json_object_add_value_object(root, "Bad system nand blocks", bsnb);

	json_object_add_value_uint64(root, "XOR recovery count",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	json_object_add_value_uint64(root, "Uncorrectable read error count",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	json_object_add_value_uint64(root, "Soft ecc error count",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	json_object_add_value_uint(root, "End to end corrected errors",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	json_object_add_value_uint(root, "End to end detected errors",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	json_object_add_value_uint(root, "System data percent used", log_data[SCAO_SDPU]);
	json_object_add_value_uint64(root, "Refresh counts",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC] & 0x00FFFFFFFFFFFFFF));
	json_object_add_value_uint(root, "Max user data erase counts",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	json_object_add_value_uint(root, "Min user data erase counts",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	json_object_add_value_uint(root, "Number of thermal throttling events",
		log_data[SCAO_NTTE]);
	json_object_add_value_uint(root, "Current throttling status",
		log_data[SCAO_CTS]);
	json_object_add_value_uint64(root, "PCIe correctable error count",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	json_object_add_value_uint(root, "Incomplete shutdowns",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	json_object_add_value_uint(root, "Percent free blocks", log_data[SCAO_PFB]);
	json_object_add_value_uint(root, "Capacitor health",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	json_object_add_value_uint64(root, "Unaligned I/O",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	json_object_add_value_uint64(root, "Security version number",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	json_object_add_value_uint64(root, "Namespace utilization",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	json_object_add_value_uint128(root, "PLP start count",
		le128_to_cpu(&log_data[SCAO_PSC]));
	json_object_add_value_uint128(root, "Endurance estimate",
		le128_to_cpu(&log_data[SCAO_EEST]));

	__u16 smart_log_ver = le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);

	json_object_add_value_uint(root, "Log page version", smart_log_ver);

	char guid[40] = { 0 };

	sprintf(guid, "0x%"PRIx64"%"PRIx64"",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	json_object_add_value_string(root, "Log page GUID", guid);

	if (smart_log_ver > 2) {
		json_object_add_value_uint(root, "Errata version field", log_data[SCAO_EVF]);
		json_object_add_value_uint(root, "Point version field",
			le16_to_cpu(*(uint16_t *)&log_data[SCAO_PVF]));
		json_object_add_value_uint(root, "Minor version field",
			le16_to_cpu(*(uint16_t *)&log_data[SCAO_MIVF]));
		json_object_add_value_uint(root, "Major version field", log_data[SCAO_MAVF]);
		json_object_add_value_uint(root, "NVMe errata version", log_data[SCAO_NEV]);
		json_object_add_value_uint(root, "PCIe link retraining count",
			le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
		json_object_add_value_uint(root, "Power state change count",
			le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
	}

	json_print_object(root, NULL);
	json_free_object(root);

	printf("\n");
}

static void print_C0_log_normal(__u8 *log_data)
{
	printf("SMART Cloud Attributes:\n");

	printf("  %-40s%s\n", "Physical media units written:",
		uint128_t_to_string(le128_to_cpu(&log_data[SCAO_PMUW])));
	printf("  %-40s%s\n", "Physical media units read:",
		uint128_t_to_string(le128_to_cpu(&log_data[SCAO_PMUR])));
	printf("  %-40s%"PRIu64"\n", "Bad user nand blocks - raw:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	printf("  %-40s%d\n", "Bad user nand blocks - normalized:",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	printf("  %-40s%"PRIu64"\n", "Bad system nand blocks - raw:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	printf("  %-40s%d\n", "Bad system nand blocks - normalized:",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	printf("  %-40s%"PRIu64"\n", "XOR recovery count:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	printf("  %-40s%"PRIu64"\n", "Uncorrectable read error count:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	printf("  %-40s%"PRIu64"\n", "Soft ecc error count:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	printf("  %-40s%"PRIu32"\n", "End to end corrected errors:",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	printf("  %-40s%"PRIu32"\n", "End to end detected errors:",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	printf("  %-40s%d\n", "System data percent used:", log_data[SCAO_SDPU]);
	printf("  %-40s%"PRIu64"\n", "Refresh counts:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC] & 0x00FFFFFFFFFFFFFF));
	printf("  %-40s%"PRIu32"\n", "Max user data erase counts:",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	printf("  %-40s%"PRIu32"\n", "Min user data erase counts:",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	printf("  %-40s%d\n", "Number of thermal throttling events:", log_data[SCAO_NTTE]);
	printf("  %-40s0x%x\n", "Current throttling status:", log_data[SCAO_CTS]);
	printf("  %-40s%"PRIu64"\n", "PCIe correctable error count:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	printf("  %-40s%"PRIu32"\n", "Incomplete shutdowns:",
		le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	printf("  %-40s%d\n", "Percent free blocks:", log_data[SCAO_PFB]);
	printf("  %-40s%"PRIu16"\n", "Capacitor health:",
		le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  %-40s%"PRIu64"\n", "Unaligned I/O:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	printf("  %-40s%"PRIu64"\n", "Security version number:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	printf("  %-40s%"PRIu64"\n", "Namespace utilization:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	printf("  %-40s%s\n", "PLP start count:",
		uint128_t_to_string(le128_to_cpu(&log_data[SCAO_PSC])));
	printf("  %-40s%s\n", "Endurance estimate:",
		uint128_t_to_string(le128_to_cpu(&log_data[SCAO_EEST])));

	uint16_t smart_log_ver = le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);

	printf("  %-40s%"PRIu16"\n", "Log page version:", smart_log_ver);
	printf("  %-40s0x%"PRIx64"%"PRIx64"\n", "Log page GUID:",
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
		le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));

	if (smart_log_ver > 2) {
		printf("  %-40s%d\n", "Errata version field:", log_data[SCAO_EVF]);
		printf("  %-40s%"PRIu16"\n", "Point version field:", log_data[SCAO_PVF]);
		printf("  %-40s%"PRIu16"\n", "Minor version field:", log_data[SCAO_MIVF]);
		printf("  %-40s%d\n", "Major version field:", log_data[SCAO_MAVF]);
		printf("  %-40s%d\n", "NVMe errata version:", log_data[SCAO_NEV]);
		printf("  %-40s%"PRIu64"\n", "PCIe link retraining count: ",
			le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
		printf("  %-40s%"PRIu64"\n", "Power state change count:",
			le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
	}
}

static int get_c0_log_page(struct nvme_dev *dev, char *format)
{
	__u8 data[C0_SMART_CLOUD_ATTR_LEN] = { 0 };
	int uuid_index = 0;

	// Best effort attempt at uuid. Otherwise, assume no index (i.e. 0)
	// Log GUID check will ensure correctness of returned data
	ocp_get_uuid_index(dev, &uuid_index);

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = &data,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid =  C0_SMART_CLOUD_ATTR_OPCODE,
		.len = sizeof(data),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	int ret = nvme_get_log(&args);

	if (ret)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
			nvme_status_to_string(ret, false), ret);

	if (!ret && !memcmp(scao_guid, &data[SCAO_LPG],
		sizeof(scao_guid)) == 0) {

		fprintf(stderr, "ERROR : OCP : Unknown GUID in C0 Log Page data\n");

		fprintf(stderr, "ERROR : OCP : Expected GUID: 0x%"PRIx64"%"PRIx64"\n",
			le64_to_cpu(*(uint64_t *)&scao_guid[8]),
			le64_to_cpu(*(uint64_t *)&scao_guid[0]));

		fprintf(stderr, "ERROR : OCP : Actual GUID: 0x%"PRIx64"%"PRIx64"\n",
			le64_to_cpu(*(uint64_t *)&data[SCAO_LPG + 8]),
			le64_to_cpu(*(uint64_t *)&data[SCAO_LPG]));

		ret = -1;
	}

	if (!ret) {
		const enum nvme_print_flags print_flag = validate_output_format(format);

		if (print_flag == JSON)
			print_C0_log_json(data);
		else if (print_flag == NORMAL)
			print_C0_log_normal(data);
		else {
			fprintf(stderr, "Error: Failed to parse.\n");
			ret = -EINVAL;
		}
	}

	return ret;
}

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve the SMART health extended data.";
	struct nvme_dev *dev = NULL;
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

	ret = get_c0_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C0 Log Page, ret = %d\n",
			ret);

	dev_close(dev);
	return ret;
}
