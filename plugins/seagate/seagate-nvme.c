// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Do NOT modify or remove this copyright and license
 *
 * Copyright (c) 2017-2018 Seagate Technology LLC and/or its Affiliates, All Rights Reserved
 *
 * ******************************************************************************************
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * \file seagate-nvme.c
 * \brief This file defines the functions and macros to make building a nvme-cli seagate plug-in.
 *
 *   Author: Debabrata Bardhan <debabrata.bardhan@seagate.com>
 */


#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <ctype.h>
#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"
#include <time.h>

#define CREATE_CMD

#include "seagate-nvme.h"
#include "seagate-diag.h"


/***************************************
 * Command for "log-pages-supp"
 ***************************************/
static char *log_pages_supp_print(__u32 pageID)
{
	switch (pageID) {
	case 0x01:
		return "ERROR_INFORMATION";
	case 0x02:
		return "SMART_INFORMATION";
	case 0x03:
		return "FW_SLOT_INFORMATION";
	case 0x04:
		return "CHANGED_NAMESPACE_LIST";
	case 0x05:
		return "COMMANDS_SUPPORTED_AND_EFFECTS";
	case 0x06:
		return "DEVICE_SELF_TEST";
	case 0x07:
		return "TELEMETRY_HOST_INITIATED";
	case 0x08:
		return "TELEMETRY_CONTROLLER_INITIATED";
	case 0xC0:
		return "VS_MEDIA_SMART_LOG";
	case 0xC1:
		return "VS_DEBUG_LOG1";
	case 0xC2:
		return "VS_SEC_ERROR_LOG_PAGE";
	case 0xC3:
		return "VS_LIFE_TIME_DRIVE_HISTORY";
	case 0xC4:
		return "VS_EXTENDED_SMART_INFO";
	case 0xC5:
		return "VS_LIST_SUPPORTED_LOG_PAGE";
	case 0xC6:
		return "VS_POWER_MONITOR_LOG_PAGE";
	case 0xC7:
		return "VS_CRITICAL_EVENT_LOG_PAGE";
	case 0xC8:
		return "VS_RECENT_DRIVE_HISTORY";
	case 0xC9:
		return "VS_SEC_ERROR_LOG_PAGE";
	case 0xCA:
		return "VS_LIFE_TIME_DRIVE_HISTORY";
	case 0xCB:
		return "VS_PCIE_ERROR_LOG_PAGE";
	case 0xCF:
		return "DRAM Supercap SMART Attributes";
	case 0xD6:
		return "VS_OEM2_WORK_LOAD";
	case 0xD7:
		return "VS_OEM2_FW_SECURITY";
	case 0xD8:
		return "VS_OEM2_REVISION";
	default:
		return "UNKNOWN";
	}
}

static int stx_is_jag_pan(char *devMN)
{
	int match_found = 1; /* found = 0, not_found = 1 */

	for (int i = 0; i < STX_NUM_LEGACY_DRV; i++) {
		match_found = strncmp(devMN, stx_jag_pan_mn[i], strlen(stx_jag_pan_mn[i]));
		if (!match_found)
			break;
	}

	return match_found;
}


static void json_log_pages_supp(log_page_map *logPageMap)
{
	struct json_object *root;
	struct json_object *logPages;
	__u32 i = 0;

	root = json_create_object();
	logPages = json_create_array();
	json_object_add_value_array(root, "supported_log_pages", logPages);

	for (i = 0; i < le32_to_cpu(logPageMap->NumLogPages); i++) {
		struct json_object *lbaf = json_create_object();

		json_object_add_value_int(lbaf, "logpage_id",
			le32_to_cpu(logPageMap->LogPageEntry[i].LogPageID));
		json_object_add_value_string(lbaf, "logpage_name",
			log_pages_supp_print(le32_to_cpu(logPageMap->LogPageEntry[i].LogPageID)));

		json_array_add_value_object(logPages, lbaf);
	}
	json_print_object(root, NULL);
	json_free_object(root);
}

static int log_pages_supp(int argc, char **argv, struct command *acmd,
			  struct plugin *plugin)
{
	int err = 0;
	__u32 i = 0;
	log_page_map logPageMap;
	const char *desc = "Retrieve Seagate Supported Log-Page information for the given device ";
	const char *output_format = "output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int fmt;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;
	err = nvme_get_log_simple(hdl, 0xc5, &logPageMap, sizeof(logPageMap));
	if (!err) {
		if (strcmp(cfg.output_format, "json")) {
			printf("Seagate Supported Log-pages count :%d\n",
				le32_to_cpu(logPageMap.NumLogPages));
			printf("%-15s %-30s\n", "LogPage-Id", "LogPage-Name");

			for (fmt = 0; fmt < 45; fmt++)
				printf("-");
			printf("\n");
		} else
			json_log_pages_supp(&logPageMap);

		for (i = 0; i < le32_to_cpu(logPageMap.NumLogPages); i++) {
			if (strcmp(cfg.output_format, "json")) {
				printf("0x%-15X",
					   le32_to_cpu(logPageMap.LogPageEntry[i].LogPageID));
				printf("%-30s\n",
					   log_pages_supp_print(le32_to_cpu(logPageMap.LogPageEntry[i].LogPageID)));
			}
		}
	}

	if (err > 0)
		nvme_show_status(err);

	return err;
}

/* EOF Command for "log-pages-supp" */

/***************************************
 * Extended-SMART Information
 ***************************************/
static char *print_ext_smart_id(__u8 attrId)
{
	switch (attrId) {
	case VS_ATTR_ID_SOFT_READ_ERROR_RATE:
		return "Soft ECC error count";
	case VS_ATTR_ID_REALLOCATED_SECTOR_COUNT:
		return "Bad NAND block count";
	case VS_ATTR_ID_POWER_ON_HOURS:
		return "Power On Hours";
	case VS_ATTR_ID_POWER_FAIL_EVENT_COUNT:
		return "Power Fail Event Count";
	case VS_ATTR_ID_DEVICE_POWER_CYCLE_COUNT:
		return "Device Power Cycle Count";
	case VS_ATTR_ID_RAW_READ_ERROR_RATE:
		return "Raw Read Error Count";
	case VS_ATTR_ID_GROWN_BAD_BLOCK_COUNT:
		return "Bad NAND block count";
	case VS_ATTR_ID_END_2_END_CORRECTION_COUNT:
		return "SSD End to end correction counts";
	case VS_ATTR_ID_MIN_MAX_WEAR_RANGE_COUNT:
		return "User data erase counts";
	case VS_ATTR_ID_REFRESH_COUNT:
		return "Refresh count";
	case VS_ATTR_ID_BAD_BLOCK_COUNT_USER:
		return "User data erase fail count";
	case VS_ATTR_ID_BAD_BLOCK_COUNT_SYSTEM:
		return "System area erase fail count";
	case VS_ATTR_ID_THERMAL_THROTTLING_STATUS:
		return "Thermal throttling status and count";
	case VS_ATTR_ID_ALL_PCIE_CORRECTABLE_ERROR_COUNT:
		return "PCIe Correctable Error count";
	case VS_ATTR_ID_ALL_PCIE_UNCORRECTABLE_ERROR_COUNT:
		return "PCIe Uncorrectable Error count";
	case VS_ATTR_ID_INCOMPLETE_SHUTDOWN_COUNT:
		return "Incomplete shutdowns";
	case VS_ATTR_ID_GB_ERASED_LSB:
		return "LSB of Flash GB erased";
	case VS_ATTR_ID_GB_ERASED_MSB:
		return "MSB of Flash GB erased";
	case VS_ATTR_ID_LIFETIME_DEVSLEEP_EXIT_COUNT:
		return "LIFETIME_DEV_SLEEP_EXIT_COUNT";
	case VS_ATTR_ID_LIFETIME_ENTERING_PS4_COUNT:
		return "LIFETIME_ENTERING_PS4_COUNT";
	case VS_ATTR_ID_LIFETIME_ENTERING_PS3_COUNT:
		return "LIFETIME_ENTERING_PS3_COUNT";
	case VS_ATTR_ID_RETIRED_BLOCK_COUNT:
		return "Retired block count";
	case VS_ATTR_ID_PROGRAM_FAILURE_COUNT:
		return "Program fail count";
	case VS_ATTR_ID_ERASE_FAIL_COUNT:
		return "Erase Fail Count";
	case VS_ATTR_ID_AVG_ERASE_COUNT:
		return "System data % used";
	case VS_ATTR_ID_UNEXPECTED_POWER_LOSS_COUNT:
		return "Unexpected power loss count";
	case VS_ATTR_ID_WEAR_RANGE_DELTA:
		return "Wear range delta";
	case VS_ATTR_ID_SATA_INTERFACE_DOWNSHIFT_COUNT:
		return "PCIE_INTF_DOWNSHIFT_COUNT";
	case VS_ATTR_ID_END_TO_END_CRC_ERROR_COUNT:
		return "E2E_CRC_ERROR_COUNT";
	case VS_ATTR_ID_UNCORRECTABLE_READ_ERRORS:
		return "Uncorrectable Read Error Count";
	case VS_ATTR_ID_MAX_LIFE_TEMPERATURE:
		return "Max lifetime temperature";
	case VS_ATTR_ID_RAISE_ECC_CORRECTABLE_ERROR_COUNT:
		return "RAIS_ECC_CORRECT_ERR_COUNT";
	case VS_ATTR_ID_UNCORRECTABLE_RAISE_ERRORS:
		return "Uncorrectable RAISE error count";
	case VS_ATTR_ID_DRIVE_LIFE_PROTECTION_STATUS:
		return "DRIVE_LIFE_PROTECTION_STATUS";
	case VS_ATTR_ID_REMAINING_SSD_LIFE:
		return "Remaining SSD life";
	case VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB:
		return "LSB of Physical (NAND) bytes written";
	case VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB:
		return "MSB of Physical (NAND) bytes written";
	case VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB:
		return "LSB of Physical (HOST) bytes written";
	case VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB:
		return "MSB of Physical (HOST) bytes written";
	case VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB:
		return "LSB of Physical (NAND) bytes read";
	case VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB:
		return "MSB of Physical (NAND) bytes read";
	case VS_ATTR_ID_FREE_SPACE:
		return "Free Space";
	case VS_ATTR_ID_TRIM_COUNT_LSB:
		return "LSB of Trim count";
	case VS_ATTR_ID_TRIM_COUNT_MSB:
		return "MSB of Trim count";
	case VS_ATTR_ID_OP_PERCENTAGE:
		return "OP percentage";
	case VS_ATTR_ID_MAX_SOC_LIFE_TEMPERATURE:
		return "Max lifetime SOC temperature";
	default:
		return "Un-Known";
	}
}

static __u64 smart_attribute_vs(__u16 verNo, SmartVendorSpecific attr)
{
	__u64 val = 0;
	vendor_smart_attribute_data *attrVendor;

	/**
	 * These are all Vendor A specific attributes.
	 */
	if (verNo >= EXTENDED_SMART_VERSION_VENDOR1) {
		attrVendor = (vendor_smart_attribute_data *)&attr;
		memcpy(&val, &(attrVendor->LSDword), sizeof(val));
		return val;
	} else
		return le32_to_cpu(attr.Raw0_3);
}

static void print_smart_log(__u16 verNo, SmartVendorSpecific attr, int lastAttr)
{
	static __u64 lsbGbErased = 0, msbGbErased = 0, lsbLifWrtToFlash = 0, msbLifWrtToFlash = 0,
		lsbLifWrtFrmHost = 0, msbLifWrtFrmHost = 0, lsbLifRdToHost = 0, msbLifRdToHost = 0, lsbTrimCnt = 0, msbTrimCnt = 0;
	char buf[40] = {0};
	char strBuf[35] = {0};
	int hideAttr = 0;

	if (attr.AttributeNumber == VS_ATTR_ID_GB_ERASED_LSB) {
		lsbGbErased = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_GB_ERASED_MSB) {
		msbGbErased = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB) {
		lsbLifWrtToFlash = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB) {
		msbLifWrtToFlash = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB) {
		lsbLifWrtFrmHost = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB) {
		msbLifWrtFrmHost = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB) {
		lsbLifRdToHost = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB) {
		msbLifRdToHost = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_TRIM_COUNT_LSB) {
		lsbTrimCnt = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if (attr.AttributeNumber == VS_ATTR_ID_TRIM_COUNT_MSB) {
		msbTrimCnt = smart_attribute_vs(verNo, attr);
		hideAttr = 1;
	}

	if ((attr.AttributeNumber) && (hideAttr != 1)) {
		printf("%-40s", print_ext_smart_id(attr.AttributeNumber));
		printf("%-15d", attr.AttributeNumber);
		printf(" 0x%016"PRIx64"\n", (uint64_t)smart_attribute_vs(verNo, attr));
	}

	if (lastAttr == 1) {
		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_GB_ERASED_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_GB_ERASED_MSB << 8 | VS_ATTR_ID_GB_ERASED_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbGbErased, (uint64_t)lsbGbErased);
		printf(" %s\n", buf);

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtToFlash, (uint64_t)lsbLifWrtToFlash);
		printf(" %s\n", buf);

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtFrmHost, (uint64_t)lsbLifWrtFrmHost);
		printf(" %s\n", buf);

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifRdToHost, (uint64_t)lsbLifRdToHost);
		printf(" %s\n", buf);

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_TRIM_COUNT_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_TRIM_COUNT_MSB << 8 | VS_ATTR_ID_TRIM_COUNT_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbTrimCnt, (uint64_t)lsbTrimCnt);
		printf(" %s\n", buf);

	}
}

static void json_print_smart_log(struct json_object *root, EXTENDED_SMART_INFO_T *ExtdSMARTInfo)
{
	struct json_object *lbafs;
	int index = 0;

	static __u64 lsbGbErased = 0, msbGbErased = 0, lsbLifWrtToFlash = 0, msbLifWrtToFlash = 0,
		lsbLifWrtFrmHost = 0, msbLifWrtFrmHost = 0, lsbLifRdToHost = 0, msbLifRdToHost = 0, lsbTrimCnt = 0, msbTrimCnt = 0;
	char buf[40] = {0};

	lbafs = json_create_array();
	json_object_add_value_array(root, "Extended-SMART-Attributes", lbafs);

	for (index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++) {
		struct json_object *lbaf = json_create_object();

		if (ExtdSMARTInfo->vendorData[index].AttributeNumber) {
			json_object_add_value_string(lbaf, "attribute_name", print_ext_smart_id(ExtdSMARTInfo->vendorData[index].AttributeNumber));
			json_object_add_value_int(lbaf, "attribute_id", ExtdSMARTInfo->vendorData[index].AttributeNumber);
			json_object_add_value_int(lbaf, "attribute_value", smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]));
			json_array_add_value_object(lbafs, lbaf);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_GB_ERASED_LSB)
				lsbGbErased = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_GB_ERASED_MSB)
				msbGbErased = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB)
				lsbLifWrtToFlash = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB)
				msbLifWrtToFlash = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB)
				lsbLifWrtFrmHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB)
				msbLifWrtFrmHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB)
				lsbLifRdToHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB)
				msbLifRdToHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_TRIM_COUNT_LSB)
				lsbTrimCnt = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if (ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_TRIM_COUNT_MSB)
				msbTrimCnt = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);
		}
	}

	struct json_object *lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", (print_ext_smart_id(VS_ATTR_ID_GB_ERASED_LSB) + 7));

	json_object_add_value_int(lbaf, "attribute_id", VS_ATTR_ID_GB_ERASED_MSB << 8 | VS_ATTR_ID_GB_ERASED_LSB);

	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbGbErased, (uint64_t)lsbGbErased);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(lbafs, lbaf);


	lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB) + 7));

	json_object_add_value_int(lbaf, "attribute_id", VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB);

	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtToFlash, (uint64_t)lsbLifWrtToFlash);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(lbafs, lbaf);


	lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB) + 7));

	json_object_add_value_int(lbaf, "attribute_id", VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB);

	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtFrmHost, (uint64_t)lsbLifWrtFrmHost);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(lbafs, lbaf);


	lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB) + 7));

	json_object_add_value_int(lbaf, "attribute_id", VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB);

	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifRdToHost, (uint64_t)lsbLifRdToHost);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(lbafs, lbaf);


	lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", (print_ext_smart_id(VS_ATTR_ID_TRIM_COUNT_LSB) + 7));

	json_object_add_value_int(lbaf, "attribute_id", VS_ATTR_ID_TRIM_COUNT_MSB << 8 | VS_ATTR_ID_TRIM_COUNT_LSB);

	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbTrimCnt, (uint64_t)lsbTrimCnt);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(lbafs, lbaf);
}

static void print_smart_log_CF(vendor_log_page_CF *pLogPageCF)
{
	__u64 currentTemp, maxTemp;

	printf("\n\nSeagate DRAM Supercap SMART Attributes :\n");
	printf("%-39s %-19s\n", "Description", "Supercap Attributes");

	printf("%-40s", "Super-cap current temperature");
	currentTemp = pLogPageCF->AttrCF.SuperCapCurrentTemperature;
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(currentTemp));

	maxTemp = pLogPageCF->AttrCF.SuperCapMaximumTemperature;
	printf("%-40s", "Super-cap maximum temperature");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(maxTemp));

	printf("%-40s", "Super-cap status");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageCF->AttrCF.SuperCapStatus));

	printf("%-40s", "Data units read to DRAM namespace");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.MS__u64),
		   le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.LS__u64));

	printf("%-40s", "Data units written to DRAM namespace");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.MS__u64),
		   le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.LS__u64));

	printf("%-40s", "DRAM correctable error count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageCF->AttrCF.DramCorrectableErrorCount));

	printf("%-40s", "DRAM uncorrectable error count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageCF->AttrCF.DramUncorrectableErrorCount));
}

static void json_print_smart_log_CF(struct json_object *root, vendor_log_page_CF *pLogPageCF)
{
	struct json_object *logPages;
	unsigned int currentTemp, maxTemp;
	char buf[40];

	logPages = json_create_array();
	json_object_add_value_array(root, "DRAM Supercap SMART Attributes", logPages);
	struct json_object *lbaf = json_create_object();

	currentTemp = pLogPageCF->AttrCF.SuperCapCurrentTemperature;
	json_object_add_value_string(lbaf, "attribute_name", "Super-cap current temperature");
	json_object_add_value_int(lbaf, "attribute_value", currentTemp);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	maxTemp = pLogPageCF->AttrCF.SuperCapMaximumTemperature;
	json_object_add_value_string(lbaf, "attribute_name", "Super-cap maximum temperature");
	json_object_add_value_int(lbaf, "attribute_value", maxTemp);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Super-cap status");
	json_object_add_value_int(lbaf, "attribute_value", pLogPageCF->AttrCF.SuperCapStatus);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Data units read to DRAM namespace");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.MS__u64),
		le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Data units written to DRAM namespace");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.MS__u64),
		le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "DRAM correctable error count");
	json_object_add_value_int(lbaf, "attribute_value", pLogPageCF->AttrCF.DramCorrectableErrorCount);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "DRAM uncorrectable error count");
	json_object_add_value_int(lbaf, "attribute_value", pLogPageCF->AttrCF.DramUncorrectableErrorCount);
	json_array_add_value_object(logPages, lbaf);
}


static void print_stx_smart_log_C0(STX_EXT_SMART_LOG_PAGE_C0 *pLogPageC0)
{
	printf("\n\nSeagate SMART Health Attributes :\n");
	printf("%-39s %-19s\n", "Description", "Health Attributes");

	printf("%-40s", "Physical Media Units Written");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageC0->phyMediaUnitsWrt.MS__u64),
		   le64_to_cpu(pLogPageC0->phyMediaUnitsWrt.LS__u64));

	printf("%-40s", "Physical Media Units Read");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageC0->phyMediaUnitsRd.MS__u64),
		   le64_to_cpu(pLogPageC0->phyMediaUnitsRd.LS__u64));

	printf("%-40s", "Bad User NAND Blocks");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->badUsrNandBlocks));

	printf("%-40s", "Bad System NAND Blocks");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->badSysNandBlocks));

	printf("%-40s", "XOR Recovery Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->xorRecoveryCnt));

	printf("%-40s", "Uncorrectable Read Error Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->ucRdEc));

	printf("%-40s", "Soft ECC Error Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->softEccEc));

	printf("%-40s", "End to End Correction Counts");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->etoeCrrCnt));

	printf("%-40s", "System Data Used in Parcent");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->sysDataUsed));

	printf("%-40s", "Refresh Counts");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->refreshCount));

	printf("%-40s", "User Data Erase Counts");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->usrDataEraseCnt));

	printf("%-40s", "Thermal Throttling Status and Count");
	printf(" 0x%04x\n", le16_to_cpu(pLogPageC0->thermalThrottling));

	printf("%-40s", "DSSD Specification Version");
	printf(" %d.%d.%d.%d\n", pLogPageC0->dssdSpecVerMajor,
				le16_to_cpu(pLogPageC0->dssdSpecVerMinor),
				le16_to_cpu(pLogPageC0->dssdSpecVerPoint),
				pLogPageC0->dssdSpecVerErrata);

	printf("%-40s", "PCIe Correctable Error Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->pcieCorrEc));

	printf("%-40s", "Incomplete Shutdowns");
	printf(" 0x%08x\n", le32_to_cpu(pLogPageC0->incompleteShutdowns));

	printf("%-40s", "Free Blocks in Percent");
	printf(" %d\n", pLogPageC0->freeBlocks);

	printf("%-40s", "Capacitor Health");
	printf(" 0x%04x\n", le16_to_cpu(pLogPageC0->capHealth));

	printf("%-40s", "NVMe Errata Version");
	printf(" %c\n", pLogPageC0->nvmeErrataVer);

	printf("%-40s", "Unaligned IO");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->unalignedIO));

	printf("%-40s", "Security Version Number");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->secVerNum));

	printf("%-40s", "Total Namespace Utilization");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->totalNUSE));

	printf("%-40s", "PLP Start Count");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageC0->plpStartCnt.MS__u64),
		   le64_to_cpu(pLogPageC0->plpStartCnt.LS__u64));

	printf("%-40s", "Endurance Estimate");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageC0->enduranceEstimate.MS__u64),
		   le64_to_cpu(pLogPageC0->enduranceEstimate.LS__u64));

	printf("%-40s", "PCIe Link Retraining Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->pcieLinkRetCnt));

	printf("%-40s", "Power State Change Count");
	printf(" 0x%016"PRIx64"\n", le64_to_cpu(pLogPageC0->powStateChangeCnt));

	printf("%-40s", "Log Page Version");
	printf(" 0x%04x\n", le16_to_cpu(pLogPageC0->logPageVer));

	printf("%-40s", "Log Page GUID");
	printf(" 0x%016"PRIx64"%016"PRIx64"\n", le64_to_cpu(pLogPageC0->logPageGUID.MS__u64),
				le64_to_cpu(pLogPageC0->logPageGUID.LS__u64));
}

static void json_print_stx_smart_log_C0(struct json_object *root, STX_EXT_SMART_LOG_PAGE_C0 *pLogPageC0)
{
	struct json_object *logPages;
	char buf[40];

	logPages = json_create_array();
	json_object_add_value_array(root, "Seagate SMART Health Attributes", logPages);

	struct json_object *lbaf = json_create_object();

	json_object_add_value_string(lbaf, "attribute_name", "Physical Media Units Written");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageC0->phyMediaUnitsWrt.MS__u64),
		le64_to_cpu(pLogPageC0->phyMediaUnitsWrt.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);


	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Physical Media Units Read");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageC0->phyMediaUnitsRd.MS__u64),
		le64_to_cpu(pLogPageC0->phyMediaUnitsRd.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Bad User NAND Blocks");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->badUsrNandBlocks));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Bad System NAND Blocks");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->badSysNandBlocks));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "XOR Recovery Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->xorRecoveryCnt));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Uncorrectable Read Error Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->ucRdEc));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Soft ECC Error Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->softEccEc));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "End to End Correction Counts");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->etoeCrrCnt));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "System Data Used in Parcent");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->sysDataUsed));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Refresh Counts");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->refreshCount));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "User Data Erase Counts");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->usrDataEraseCnt));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Thermal Throttling Status and Count");
	json_object_add_value_int(lbaf, "attribute_value", le16_to_cpu(pLogPageC0->thermalThrottling));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "DSSD Specification Version");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "%d.%d.%d.%d", pLogPageC0->dssdSpecVerMajor,
					le16_to_cpu(pLogPageC0->dssdSpecVerMinor),
					le16_to_cpu(pLogPageC0->dssdSpecVerPoint),
					pLogPageC0->dssdSpecVerErrata);
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "PCIe Correctable Error Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->pcieCorrEc));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Incomplete Shutdowns");
	json_object_add_value_int(lbaf, "attribute_value", le32_to_cpu(pLogPageC0->incompleteShutdowns));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Free Blocks in Percent");
	json_object_add_value_int(lbaf, "attribute_value", pLogPageC0->freeBlocks);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Capacitor Health");
	json_object_add_value_int(lbaf, "attribute_value", le16_to_cpu(pLogPageC0->capHealth));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "NVMe Errata Version");
	json_object_add_value_int(lbaf, "attribute_value", pLogPageC0->nvmeErrataVer);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Unaligned IO");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->unalignedIO));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Security Version Number");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->secVerNum));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Total Namespace Utilization");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->totalNUSE));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "PLP Start Count");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageC0->plpStartCnt.MS__u64),
		le64_to_cpu(pLogPageC0->plpStartCnt.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Endurance Estimate");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageC0->enduranceEstimate.MS__u64),
		le64_to_cpu(pLogPageC0->enduranceEstimate.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "PCIe Link Retraining Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->pcieLinkRetCnt));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Power State Change Count");
	json_object_add_value_int(lbaf, "attribute_value", le64_to_cpu(pLogPageC0->powStateChangeCnt));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Log Page Version");
	json_object_add_value_int(lbaf, "attribute_value", le16_to_cpu(pLogPageC0->logPageVer));
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	json_object_add_value_string(lbaf, "attribute_name", "Log Page GUID");
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageC0->logPageGUID.MS__u64),
		le64_to_cpu(pLogPageC0->logPageGUID.LS__u64));
	json_object_add_value_string(lbaf, "attribute_value", buf);
	json_array_add_value_object(logPages, lbaf);
}

static int vs_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct nvme_id_ctrl     ctrl;
	char                    modelNo[40];
	STX_EXT_SMART_LOG_PAGE_C0   ehExtSmart;
	EXTENDED_SMART_INFO_T   ExtdSMARTInfo;
	vendor_log_page_CF      logPageCF;
	struct json_object *root = json_create_object();
	struct json_object *lbafs = json_create_array();
	struct json_object *lbafs_ExtSmart, *lbafs_DramSmart;

	const char *desc = "Retrieve the Firmware Activation History for Seagate NVMe drives";
	const char *output_format = "output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err, index = 0;
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("\nDevice not found\n");
		return -1;
	}

	if (strcmp(cfg.output_format, "json"))
		printf("Seagate Extended SMART Information :\n");


	/**
	 * Here we should identify if the drive is a Panthor or Jaguar.
	 * Here we need to extract the model no from ctrl-id abd use it
	 * to determine drive family.
	 */

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (!err) {
		memcpy(modelNo, ctrl.mn, sizeof(modelNo));
	} else {
		nvme_show_status(err);
		return err;
	}

	if (!stx_is_jag_pan(modelNo)) {
		err = nvme_get_log_simple(hdl, 0xC4, &ExtdSMARTInfo, sizeof(ExtdSMARTInfo));
		if (!err) {
			if (strcmp(cfg.output_format, "json")) {
				printf("%-39s %-15s %-19s\n", "Description", "Ext-Smart-Id", "Ext-Smart-Value");
				for (index = 0; index < 80; index++)
					printf("-");
				printf("\n");
				for (index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++)
					print_smart_log(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index], index == (NUMBER_EXTENDED_SMART_ATTRIBUTES - 1));

			} else {
				lbafs_ExtSmart = json_create_object();
				json_print_smart_log(lbafs_ExtSmart, &ExtdSMARTInfo);

				json_object_add_value_array(root, "SMART-Attributes", lbafs);
				json_array_add_value_object(lbafs, lbafs_ExtSmart);
			}

			/**
			 * Next get Log Page 0xCF
			 */

			err = nvme_get_log_simple(hdl, 0xCF, &logPageCF, sizeof(logPageCF));
			if (!err) {
				if (strcmp(cfg.output_format, "json")) {
					print_smart_log_CF(&logPageCF);
				} else {
					lbafs_DramSmart = json_create_object();
					json_print_smart_log_CF(lbafs_DramSmart, &logPageCF);
					json_array_add_value_object(lbafs, lbafs_DramSmart);
					json_print_object(root, NULL);
				}
			} else if (!strcmp(cfg.output_format, "json")) {
				json_print_object(root, NULL);
				json_free_object(root);
			}
		} else if (err > 0) {
			nvme_show_status(err);
		}
	} else {
		err = nvme_get_log_simple(hdl, 0xC0, &ehExtSmart, sizeof(ehExtSmart));

		if (!err) {
			if (strcmp(cfg.output_format, "json")) {
				print_stx_smart_log_C0(&ehExtSmart);
			} else {
				lbafs_ExtSmart = json_create_object();
				json_print_stx_smart_log_C0(lbafs_ExtSmart, &ehExtSmart);

				json_object_add_value_array(root, "SMART-Attributes", lbafs);
				json_array_add_value_object(lbafs, lbafs_ExtSmart);

				json_print_object(root, NULL);
				json_free_object(root);
			}
		}

		if (err > 0)
			nvme_show_status(err);
	}

	err = nvme_get_log_simple(hdl, 0xC4,
				  &ExtdSMARTInfo, sizeof(ExtdSMARTInfo));
	if (!err) {
		if (strcmp(cfg.output_format, "json")) {
			printf("%-39s %-15s %-19s\n", "Description", "Ext-Smart-Id", "Ext-Smart-Value");
			for (index = 0; index < 80; index++)
				printf("-");
			printf("\n");
			for (index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++)
				print_smart_log(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index], index == (NUMBER_EXTENDED_SMART_ATTRIBUTES - 1));

		} else {
			lbafs_ExtSmart = json_create_object();
			json_print_smart_log(lbafs_ExtSmart, &ExtdSMARTInfo);

			json_object_add_value_array(root, "SMART-Attributes", lbafs);
			json_array_add_value_object(lbafs, lbafs_ExtSmart);
		}

		/**
		 * Next get Log Page 0xCF
		 */

		err = nvme_get_log_simple(hdl, 0xCF,
					  &logPageCF, sizeof(logPageCF));
		if (!err) {
			if (strcmp(cfg.output_format, "json")) {
				print_smart_log_CF(&logPageCF);
			} else {
				lbafs_DramSmart = json_create_object();
				json_print_smart_log_CF(lbafs_DramSmart, &logPageCF);
				json_array_add_value_object(lbafs, lbafs_DramSmart);
				json_print_object(root, NULL);
			}
		} else if (!strcmp(cfg.output_format, "json")) {
			json_print_object(root, NULL);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

/*EOF Extended-SMART Information */

/***************************************
 * Temperature-Stats information
 ***************************************/
static void json_temp_stats(__u32 temperature, __u32 PcbTemp, __u32 SocTemp,
			    __u32 maxTemperature, __u32 MaxSocTemp,
			    __u32 cf_err, __u32 scCurrentTemp, __u32 scMaxTem)
{
	struct json_object *root = json_create_object();

	json_object_add_value_int(root, "Current temperature", temperature);
	json_object_add_value_int(root, "Current PCB temperature", PcbTemp);
	json_object_add_value_int(root, "Current SOC temperature", SocTemp);
	json_object_add_value_int(root, "Highest temperature", maxTemperature);
	json_object_add_value_int(root, "Max SOC temperature", MaxSocTemp);
	if (!cf_err) {
		json_object_add_value_int(root, "SuperCap Current temperature", scCurrentTemp);
		json_object_add_value_int(root, "SuperCap Max temperature", scMaxTem);
	}

	json_print_object(root, NULL);
}

static int temp_stats(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	EXTENDED_SMART_INFO_T ExtdSMARTInfo;
	vendor_log_page_CF    logPageCF;

	int err, cf_err;
	int index;
	const char *desc = "Retrieve Seagate Temperature Stats information for the given device ";
	const char *output_format = "output in binary format";
	nvme_print_flags_t flags;
	unsigned int temperature = 0, PcbTemp = 0, SocTemp = 0, scCurrentTemp = 0, scMaxTemp = 0;
	unsigned long long maxTemperature = 0, MaxSocTemp = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("\nDevice not found\n");
		return -1;
	}

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (flags & NORMAL)
		printf("Seagate Temperature Stats Information :\n");
	/*STEP-1 : Get Current Temperature from SMART */
	err = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log);
	if (!err) {
		temperature = ((smart_log.temperature[1] << 8) | smart_log.temperature[0]);
		temperature = temperature ? temperature - 273 : 0;
		PcbTemp = le16_to_cpu(smart_log.temp_sensor[0]);
		PcbTemp = PcbTemp ? PcbTemp - 273 : 0;
		SocTemp = le16_to_cpu(smart_log.temp_sensor[1]);
		SocTemp = SocTemp ? SocTemp - 273 : 0;
		if (flags & NORMAL) {
			printf("%-20s : %u C\n", "Current Temperature", temperature);
			printf("%-20s : %u C\n", "Current PCB Temperature", PcbTemp);
			printf("%-20s : %u C\n", "Current SOC Temperature", SocTemp);
		}
	}

	/* STEP-2 : Get Max temperature form Ext SMART-id 194 */
	err = nvme_get_log_simple(hdl, 0xC4,
				  &ExtdSMARTInfo, sizeof(ExtdSMARTInfo));
	if (!err) {
		for (index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++) {
			if (ExtdSMARTInfo.vendorData[index].AttributeNumber == VS_ATTR_ID_MAX_LIFE_TEMPERATURE) {
				maxTemperature = smart_attribute_vs(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index]);
				maxTemperature = maxTemperature ? maxTemperature - 273 : 0;
				if (flags & NORMAL)
					printf("%-20s : %d C\n", "Highest Temperature", (unsigned int)maxTemperature);
			}

			if (ExtdSMARTInfo.vendorData[index].AttributeNumber == VS_ATTR_ID_MAX_SOC_LIFE_TEMPERATURE) {
				MaxSocTemp = smart_attribute_vs(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index]);
				MaxSocTemp = MaxSocTemp ? MaxSocTemp - 273 : 0;
				if (flags & NORMAL)
					printf("%-20s : %d C\n", "Max SOC Temperature", (unsigned int)MaxSocTemp);
			}
		}
	} else {
		if (err > 0)
			nvme_show_status(err);
	}

	cf_err = nvme_get_log_simple(hdl, 0xCF,
					 &logPageCF, sizeof(ExtdSMARTInfo));

	if (!cf_err) {
		scCurrentTemp = logPageCF.AttrCF.SuperCapCurrentTemperature;
		scCurrentTemp = scCurrentTemp ? scCurrentTemp - 273 : 0;
		printf("%-20s : %d C\n", "Super-cap Current Temperature", scCurrentTemp);

		scMaxTemp = logPageCF.AttrCF.SuperCapMaximumTemperature;
		scMaxTemp = scMaxTemp ? scMaxTemp - 273 : 0;
		printf("%-20s : %d C\n", "Super-cap Max Temperature", scMaxTemp);
	}

	if (flags & JSON)
		json_temp_stats(temperature, PcbTemp, SocTemp, maxTemperature, MaxSocTemp, cf_err, scCurrentTemp, scMaxTemp);

	return err;
}
/* EOF Temperature Stats information */

/***************************************
 * PCIe error-log information
 ***************************************/
static void print_vs_pcie_error_log(pcie_error_log_page pcieErrorLog)
{
	__u32 correctPcieEc = pcieErrorLog.BadDllpErrCnt + pcieErrorLog.BadTlpErrCnt +
			      pcieErrorLog.RcvrErrCnt + pcieErrorLog.ReplayTOErrCnt +
			      pcieErrorLog.ReplayNumRolloverErrCnt;
	__u32 uncorrectPcieEc = pcieErrorLog.FCProtocolErrCnt + pcieErrorLog.DllpProtocolErrCnt +
				pcieErrorLog.CmpltnTOErrCnt + pcieErrorLog.RcvrQOverflowErrCnt +
				pcieErrorLog.UnexpectedCplTlpErrCnt + pcieErrorLog.CplTlpURErrCnt +
				pcieErrorLog.CplTlpCAErrCnt + pcieErrorLog.ReqCAErrCnt +
				pcieErrorLog.ReqURErrCnt + pcieErrorLog.EcrcErrCnt +
				pcieErrorLog.MalformedTlpErrCnt + pcieErrorLog.CplTlpPoisonedErrCnt +
				pcieErrorLog.MemRdTlpPoisonedErrCnt;

	printf("%-45s : %u\n", "PCIe Correctable Error Count", correctPcieEc);
	printf("%-45s : %u\n", "PCIe Un-Correctable Error Count", uncorrectPcieEc);
	printf("%-45s : %u\n", "Unsupported Request Error Status (URES)", pcieErrorLog.ReqURErrCnt);
	printf("%-45s : %u\n", "ECRC Error Status (ECRCES)", pcieErrorLog.EcrcErrCnt);
	printf("%-45s : %u\n", "Malformed TLP Status (MTS)", pcieErrorLog.MalformedTlpErrCnt);
	printf("%-45s : %u\n", "Receiver Overflow Status (ROS)", pcieErrorLog.RcvrQOverflowErrCnt);
	printf("%-45s : %u\n", "Unexpected Completion Status(UCS)", pcieErrorLog.UnexpectedCplTlpErrCnt);
	printf("%-45s : %u\n", "Completion Timeout Status (CTS)", pcieErrorLog.CmpltnTOErrCnt);
	printf("%-45s : %u\n", "Flow Control Protocol Error Status (FCPES)", pcieErrorLog.FCProtocolErrCnt);
	printf("%-45s : %u\n", "Poisoned TLP Status (PTS)", pcieErrorLog.MemRdTlpPoisonedErrCnt);
	printf("%-45s : %u\n", "Data Link Protocol Error Status(DLPES)", pcieErrorLog.DllpProtocolErrCnt);
	printf("%-45s : %u\n", "Replay Timer Timeout Status(RTS)", pcieErrorLog.ReplayTOErrCnt);
	printf("%-45s : %u\n", "Replay_NUM Rollover Status(RRS)", pcieErrorLog.ReplayNumRolloverErrCnt);
	printf("%-45s : %u\n", "Bad DLLP Status (BDS)", pcieErrorLog.BadDllpErrCnt);
	printf("%-45s : %u\n", "Bad TLP Status (BTS)", pcieErrorLog.BadTlpErrCnt);
	printf("%-45s : %u\n", "Receiver Error Status (RES)", pcieErrorLog.RcvrErrCnt);
	printf("%-45s : %u\n", "Cpl TLP Unsupported Request Error Count", pcieErrorLog.CplTlpURErrCnt);
	printf("%-45s : %u\n", "Cpl TLP Completion Abort Error Count", pcieErrorLog.CplTlpCAErrCnt);
	printf("%-45s : %u\n", "Cpl TLP Poisoned Error Count", pcieErrorLog.CplTlpPoisonedErrCnt);
	printf("%-45s : %u\n", "Request Completion Abort Error Count", pcieErrorLog.ReqCAErrCnt);
	printf("%-45s : %s\n", "Advisory Non-Fatal Error Status(ANFES)", "Not Supported");
	printf("%-45s : %s\n", "Completer Abort Status (CAS)", "Not Supported");
}

static void json_vs_pcie_error_log(pcie_error_log_page pcieErrorLog)
{
	struct json_object *root = json_create_object();
	__u32 correctPcieEc = pcieErrorLog.BadDllpErrCnt + pcieErrorLog.BadTlpErrCnt +
			      pcieErrorLog.RcvrErrCnt + pcieErrorLog.ReplayTOErrCnt +
			      pcieErrorLog.ReplayNumRolloverErrCnt;
	__u32 uncorrectPcieEc = pcieErrorLog.FCProtocolErrCnt + pcieErrorLog.DllpProtocolErrCnt +
				pcieErrorLog.CmpltnTOErrCnt + pcieErrorLog.RcvrQOverflowErrCnt +
				pcieErrorLog.UnexpectedCplTlpErrCnt + pcieErrorLog.CplTlpURErrCnt +
				pcieErrorLog.CplTlpCAErrCnt + pcieErrorLog.ReqCAErrCnt +
				pcieErrorLog.ReqURErrCnt + pcieErrorLog.EcrcErrCnt +
				pcieErrorLog.MalformedTlpErrCnt + pcieErrorLog.CplTlpPoisonedErrCnt +
				pcieErrorLog.MemRdTlpPoisonedErrCnt;

	json_object_add_value_int(root, "PCIe Correctable Error Count", correctPcieEc);
	json_object_add_value_int(root, "PCIe Un-Correctable Error Count", uncorrectPcieEc);
	json_object_add_value_int(root, "Unsupported Request Error Status (URES)", pcieErrorLog.ReqURErrCnt);
	json_object_add_value_int(root, "ECRC Error Status (ECRCES)", pcieErrorLog.EcrcErrCnt);
	json_object_add_value_int(root, "Malformed TLP Status (MTS)", pcieErrorLog.MalformedTlpErrCnt);
	json_object_add_value_int(root, "Receiver Overflow Status (ROS)", pcieErrorLog.RcvrQOverflowErrCnt);
	json_object_add_value_int(root, "Unexpected Completion Status(UCS)", pcieErrorLog.UnexpectedCplTlpErrCnt);
	json_object_add_value_int(root, "Completion Timeout Status (CTS)", pcieErrorLog.CmpltnTOErrCnt);
	json_object_add_value_int(root, "Flow Control Protocol Error Status (FCPES)", pcieErrorLog.FCProtocolErrCnt);
	json_object_add_value_int(root, "Poisoned TLP Status (PTS)", pcieErrorLog.MemRdTlpPoisonedErrCnt);
	json_object_add_value_int(root, "Data Link Protocol Error Status(DLPES)", pcieErrorLog.DllpProtocolErrCnt);
	json_object_add_value_int(root, "Replay Timer Timeout Status(RTS)", pcieErrorLog.ReplayTOErrCnt);
	json_object_add_value_int(root, "Replay_NUM Rollover Status(RRS)", pcieErrorLog.ReplayNumRolloverErrCnt);
	json_object_add_value_int(root, "Bad DLLP Status (BDS)", pcieErrorLog.BadDllpErrCnt);
	json_object_add_value_int(root, "Bad TLP Status (BTS)", pcieErrorLog.BadTlpErrCnt);
	json_object_add_value_int(root, "Receiver Error Status (RES)", pcieErrorLog.RcvrErrCnt);
	json_object_add_value_int(root, "Cpl TLP Unsupported Request Error Count", pcieErrorLog.CplTlpURErrCnt);
	json_object_add_value_int(root, "Cpl TLP Completion Abort Error Count", pcieErrorLog.CplTlpCAErrCnt);
	json_object_add_value_int(root, "Cpl TLP Poisoned Error Count", pcieErrorLog.CplTlpPoisonedErrCnt);
	json_object_add_value_int(root, "Request Completion Abort Error Count", pcieErrorLog.ReqCAErrCnt);
	json_print_object(root, NULL);
}

static int vs_pcie_error_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	pcie_error_log_page pcieErrorLog;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	const char *desc = "Retrieve Seagate PCIe error counters for the given device ";
	const char *output_format = "output in binary format";
	int err;
	nvme_print_flags_t flags;
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("\nDevice not found\n");
		return -1;
	}

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (flags & NORMAL)
		printf("Seagate PCIe error counters Information :\n");

	err = nvme_get_log_simple(hdl, 0xCB,
				  &pcieErrorLog, sizeof(pcieErrorLog));
	if (!err) {
		if (flags & NORMAL)
			print_vs_pcie_error_log(pcieErrorLog);
		else
			json_vs_pcie_error_log(pcieErrorLog);

	} else if (err > 0) {
		nvme_show_status(err);
	}


	return err;
}
/* EOF PCIE error-log information */


/***************************************
 * FW Activation History log
 ***************************************/
static void print_stx_vs_fw_activate_history(stx_fw_activ_history_log_page fwActivHis)
{
	__u32 i;
	char prev_fw[9] = {0};
	char new_fw[9] = {0};
	char buf[80];

	if (fwActivHis.numValidFwActHisEnt > 0) {
		printf("\n\nSeagate FW Activation History :\n");
		printf("%-9s %-21s %-7s %-13s %-9s %-5s %-15s %-9s\n", "Counter ", "      Timestamp ", " PCC ", "Previous FW ", "New FW ", "Slot", "Commit Action", "Result");

		for (i = 0; i < fwActivHis.numValidFwActHisEnt; i++) {

			printf("   %-4d   ", fwActivHis.fwActHisEnt[i].fwActivCnt);

			time_t t = fwActivHis.fwActHisEnt[i].timeStamp / 1000;
			struct tm  ts = *localtime(&t);

			strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
			printf(" %-20s   ", buf);
			printf("%-5" PRId64 "   ",
			       (uint64_t)fwActivHis.fwActHisEnt[i].powCycleCnt);

			memset(prev_fw, 0, sizeof(prev_fw));
			memcpy(prev_fw, fwActivHis.fwActHisEnt[i].previousFW, sizeof(fwActivHis.fwActHisEnt[i].previousFW));
			printf("%-8s   ", prev_fw);

			memset(new_fw, 0, sizeof(new_fw));
			memcpy(new_fw, fwActivHis.fwActHisEnt[i].newFW, sizeof(fwActivHis.fwActHisEnt[i].newFW));
			printf("%-8s  ", new_fw);

			printf("  %-2d  ", fwActivHis.fwActHisEnt[i].slotNum);
			printf("      0x%02x      ", fwActivHis.fwActHisEnt[i].commitActionType);
			printf("  0x%02x\n", fwActivHis.fwActHisEnt[i].result);
		}
	} else {
		printf("%s\n", "Do not have valid FW Activation History");
	}
}

static void json_stx_vs_fw_activate_history(stx_fw_activ_history_log_page fwActivHis)
{
	struct json_object *root = json_create_object();
	__u32 i;

	char buf[80];

	struct json_object *historyLogPage = json_create_array();

	json_object_add_value_array(root, "Seagate FW Activation History", historyLogPage);

	if (fwActivHis.numValidFwActHisEnt > 0) {
		for (i = 0; i < fwActivHis.numValidFwActHisEnt; i++) {
			struct json_object *lbaf = json_create_object();
			char prev_fw[8] = { 0 };
			char new_fw[8] = { 0 };

			json_object_add_value_int(lbaf, "Counter", fwActivHis.fwActHisEnt[i].fwActivCnt);

			time_t t = fwActivHis.fwActHisEnt[i].timeStamp / 1000;
			struct tm  ts = *localtime(&t);

			strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
			printf(" %-20s   ", buf);
			json_object_add_value_string(lbaf, "Timestamp", buf);

			json_object_add_value_int(lbaf, "PCC", fwActivHis.fwActHisEnt[i].powCycleCnt);
			sprintf(prev_fw, "%s", fwActivHis.fwActHisEnt[i].previousFW);
			json_object_add_value_string(lbaf, "Previous_FW", prev_fw);

			sprintf(new_fw, "%s", fwActivHis.fwActHisEnt[i].newFW);
			json_object_add_value_string(lbaf, "New_FW", new_fw);

			json_object_add_value_int(lbaf, "Slot", fwActivHis.fwActHisEnt[i].slotNum);
			json_object_add_value_int(lbaf, "Commit_Action", fwActivHis.fwActHisEnt[i].commitActionType);
			json_object_add_value_int(lbaf, "Result", fwActivHis.fwActHisEnt[i].result);

			json_array_add_value_object(historyLogPage, lbaf);
		}
	} else {
		printf("%s\n", "Do not have valid FW Activation History");
	}

	json_print_object(root, NULL);
	json_free_object(root);
}

static int stx_vs_fw_activate_history(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	stx_fw_activ_history_log_page fwActivHis;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	const char *desc = "Retrieve FW Activate History for Seagate device ";
	const char *output_format = "output in binary format";
	int err;
	nvme_print_flags_t flags;
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err < 0) {
		printf("\nDevice not found\n");
		return -1;
	}

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (flags & NORMAL)
		printf("Seagate FW Activation History Information :\n");

	err = nvme_get_log_simple(hdl, 0xC2, &fwActivHis, sizeof(fwActivHis));
	if (!err) {
		if (flags & NORMAL)
			print_stx_vs_fw_activate_history(fwActivHis);
		else
			json_stx_vs_fw_activate_history(fwActivHis);
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}
/* EOF FW Activation History log information */


static int clear_fw_activate_history(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Clear FW Activation History for the given Seagate device ";
	const char *save = "specifies that the controller shall save the attribute";
	int err;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_id_ctrl ctrl;
	char modelNo[40];
	__u32 result;

	struct config {
		bool   save;
	};

	struct config cfg = {
		.save         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err < 0) {
		printf("\nDevice not found\n");
		return -1;
	}

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (!err) {
		memcpy(modelNo, ctrl.mn, sizeof(modelNo));
	} else {
		nvme_show_status(err);
		return err;
	}

	if (!stx_is_jag_pan(modelNo)) {
		printf("\nDevice does not support Clear FW Activation History\n");
	} else {
		err = nvme_set_features(hdl, 0, 0xC1, 0, 0x80000000, 0, 0, 0, 0, NULL,
				0, &result);
		if (err)
			fprintf(stderr, "%s: couldn't clear PCIe correctable errors\n",
				__func__);
	}

	if (err < 0) {
		perror("set-feature");
		return errno;
	}

	return err;
}


static int vs_clr_pcie_correctable_errs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Clear Seagate PCIe Correctable counters for the given device ";
	const char *save = "specifies that the controller shall save the attribute";

	struct nvme_id_ctrl ctrl;
	char modelNo[40];

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	__u32 result;
	int err;

	struct config {
		bool   save;
	};

	struct config cfg = {
		.save         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("\nDevice not found\n");
		return -1;
	}


	err = nvme_identify_ctrl(hdl, &ctrl);
	if (!err) {
		memcpy(modelNo, ctrl.mn, sizeof(modelNo));
	} else {
		nvme_show_status(err);
		return err;
	}

	if (!stx_is_jag_pan(modelNo)) {
		err = nvme_set_features_simple(hdl, 0, 0xE1, cfg.save, 0xCB, &result);
	} else {
		err = nvme_set_features(hdl, 0, 0xC3, 0, 0x80000000, 0, 0, 0, 0, NULL,
				0, &result);
		if (err)
			fprintf(stderr, "%s: couldn't clear PCIe correctable errors\n", __func__);
	}

	err = nvme_set_features_simple(hdl, 0, 0xE1, cfg.save, 0xCB, &result);

	if (err < 0) {
		perror("set-feature");
		return errno;
	}

	return err;
}

static int get_host_tele(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Capture the Telemetry Host-Initiated Data in either hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_specific = "1 - controller shall capture Data representing the internal\n"
		"state of the controller at the time the command is processed.\n"
		"0 - controller shall not update the Telemetry Host Initiated Data.";
	const char *raw = "output in raw format";
	struct nvme_temetry_log_hdr tele_log;
	int blkCnt, maxBlk = 0, blksToGet;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	unsigned char  *log;
	__le64  offset = 0;
	int err, dump_fd;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		bool  raw_binary;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
		.log_id       = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("log_specific", 'i', &cfg.log_id,       log_specific),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	dump_fd = STDOUT_FILENO;
	cfg.log_id = (cfg.log_id << 8) | 0x07;
	err = nvme_get_nsid_log(hdl, cfg.namespace_id, false, cfg.log_id,
				(void *)(&tele_log), sizeof(tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n",
				   nvme_transport_handle_get_name(hdl), cfg.log_id,
				   cfg.namespace_id);
			printf("Data Block 1 Last Block:%d Data Block 2 Last Block:%d Data Block 3 Last Block:%d\n",
				   tele_log.tele_data_area1, tele_log.tele_data_area2, tele_log.tele_data_area3);

			d((unsigned char *)(&tele_log), sizeof(tele_log), 16, 1);
		} else
			seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror("log page");
	}

	blkCnt = 0;

	while (blkCnt < maxBlk) {
		unsigned long long bytesToGet;

		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if (!blksToGet) {

			return err;
		}

		bytesToGet = (unsigned long long)blksToGet * 512;
		log = malloc(bytesToGet);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");

			return -EINVAL;
		}

		memset(log, 0, bytesToGet);

		nvme_init_get_log(&cmd, cfg.namespace_id, cfg.log_id,
				  NVME_CSI_NVM, log, bytesToGet);
		nvme_init_get_log_lpo(&cmd, offset);
		err = nvme_get_log(hdl, &cmd, true,
				   NVME_LOG_PAGE_PDU_SIZE, NULL);
		if (!err) {
			offset += (__le64)bytesToGet;

			if (!cfg.raw_binary) {
				printf("\nBlock # :%d to %d\n", blkCnt + 1, blkCnt + blksToGet);

				d((unsigned char *)log, bytesToGet, 16, 1);
			} else
				seaget_d_raw((unsigned char *)log, bytesToGet, dump_fd);
		} else if (err > 0) {
			nvme_show_status(err);
		} else {
			perror("log page");
		}

		blkCnt += blksToGet;

		free(log);
	}

	return err;
}

static int get_ctrl_tele(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Capture the Telemetry Controller-Initiated Data in either hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *raw = "output in raw format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err, dump_fd;
	struct nvme_temetry_log_hdr tele_log;
	__le64  offset = 0;
	__u16 log_id;
	int blkCnt, maxBlk = 0, blksToGet;
	unsigned char  *log;

	struct config {
		__u32 namespace_id;
		bool  raw_binary;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	dump_fd = STDOUT_FILENO;

	log_id = 0x08;
	err = nvme_get_nsid_log(hdl, cfg.namespace_id, false, log_id,
				(void *)(&tele_log), sizeof(tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		if (!cfg.raw_binary) {
			printf("Device:%s namespace-id:%#x\n",
				   nvme_transport_handle_get_name(hdl), cfg.namespace_id);
			printf("Data Block 1 Last Block:%d Data Block 2 Last Block:%d Data Block 3 Last Block:%d\n",
				   tele_log.tele_data_area1, tele_log.tele_data_area2, tele_log.tele_data_area3);

			d((unsigned char *)(&tele_log), sizeof(tele_log), 16, 1);
		} else
			seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror("log page");
	}

	blkCnt = 0;

	while (blkCnt < maxBlk) {
		unsigned long long bytesToGet;

		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if (!blksToGet)
			return err;

		bytesToGet = (unsigned long long)blksToGet * 512;
		log = malloc(bytesToGet);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			return -EINVAL;
		}

		memset(log, 0, bytesToGet);

		nvme_init_get_log(&cmd, cfg.namespace_id, log_id,
				  NVME_CSI_NVM, log, bytesToGet);
		nvme_init_get_log_lpo(&cmd, offset);
		err = nvme_get_log(hdl, &cmd, true,
				   NVME_LOG_PAGE_PDU_SIZE, NULL);
		if (!err) {
			offset += (__le64)bytesToGet;

			if (!cfg.raw_binary) {
				printf("\nBlock # :%d to %d\n", blkCnt + 1, blkCnt + blksToGet);

				d((unsigned char *)log, bytesToGet, 16, 1);
			} else
				seaget_d_raw((unsigned char *)log, bytesToGet, dump_fd);
		} else if (err > 0) {
			nvme_show_status(err);
		} else {
			perror("log page");
		}

		blkCnt += blksToGet;

		free(log);
	}


	return err;
}

void
seaget_d_raw(unsigned char *buf, int len, int fd)
{
	if (write(fd, (void *)buf, len) <= 0)
		printf("%s: Write Failed\n", __func__);
}


static int vs_internal_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Capture the Telemetry Controller-Initiated Data in binary format";
	const char *namespace_id = "desired namespace";

	const char *file = "dump file";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err, dump_fd;
	int flags = O_WRONLY | O_CREAT;
	int mode = 0664;
	struct nvme_temetry_log_hdr tele_log;
	__le64  offset = 0;
	__u16 log_id;
	int blkCnt, maxBlk = 0, blksToGet;
	unsigned char  *log;

	struct config {
		__u32 namespace_id;
		char  *file;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
		.file         = "",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FILE("dump-file",    'f', &cfg.file,         file),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	dump_fd = STDOUT_FILENO;
	if (strlen(cfg.file)) {
		dump_fd = open(cfg.file, flags, mode);
		if (dump_fd < 0) {
			perror(cfg.file);
			return -EINVAL;
		}
	}

	log_id = 0x08;
	err = nvme_get_nsid_log(hdl, cfg.namespace_id, false, log_id,
				(void *)(&tele_log), sizeof(tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror("log page");
	}

	blkCnt = 0;

	while (blkCnt < maxBlk) {
		unsigned long long bytesToGet;

		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if (!blksToGet)
			goto out;

		bytesToGet = (unsigned long long)blksToGet * 512;
		log = malloc(bytesToGet);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			err = EINVAL;
			goto out;
		}

		memset(log, 0, bytesToGet);

		nvme_init_get_log_lpo(&cmd, offset);
		nvme_init_get_log(&cmd, cfg.namespace_id, log_id,
				  NVME_CSI_NVM, log, bytesToGet);
		nvme_init_get_log_lpo(&cmd, offset);
		err = nvme_get_log(hdl, &cmd, true,
				   NVME_LOG_PAGE_PDU_SIZE, NULL);
		if (!err) {
			offset += (__le64)bytesToGet;

			seaget_d_raw((unsigned char *)log, bytesToGet, dump_fd);

		} else if (err > 0) {
			nvme_show_status(err);
		} else {
			perror("log page");
		}

		blkCnt += blksToGet;

		free(log);
	}
out:
	if (strlen(cfg.file))
		close(dump_fd);

	return err;
}

/*SEAGATE-PLUGIN Version */
static int seagate_plugin_version(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	printf("Seagate-Plugin version : %d.%d\n",
		   SEAGATE_PLUGIN_VERSION_MAJOR,
		   SEAGATE_PLUGIN_VERSION_MINOR);
	return 0;
}
/*EOF SEAGATE-PLUGIN Version */

/*OCP SEAGATE-PLUGIN Version */
static int stx_ocp_plugin_version(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	printf("Seagate-OCP-Plugin version : %d.%d\n",
		SEAGATE_OCP_PLUGIN_VERSION_MAJOR,
		SEAGATE_OCP_PLUGIN_VERSION_MINOR);
	return 0;
}
/*EOF OCP SEAGATE-PLUGIN Version */
