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
 */


#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <ctype.h>
#include "linux/nvme_ioctl.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"
#include "argconfig.h"
#include "suffix.h"
#include "json.h"

#define CREATE_CMD

#include "seagate-nvme.h"
#include "seagate-diag.h"


/***************************************
*Command for "log-pages-supp"
***************************************/
static char *log_pages_supp_print(__u32 pageID)
{
	switch(pageID) {
	case 0x01:
		return "ERROR_INFORMATION";
		break;
	case 0x02:
		return "SMART_INFORMATION";
		break;
	case 0x03:
		return "FW_SLOT_INFORMATION";
		break;
	case 0x04:
		return "CHANGED_NAMESPACE_LIST";
		break;
	case 0x05:
		return "COMMANDS_SUPPORTED_AND_EFFECTS";
		break;
	case 0x06:
		return "DEVICE_SELF_TEST";
		break;
	case 0x07:
		return "TELEMETRY_HOST_INITIATED";
		break;
	case 0x08:
		return "TELEMETRY_CONTROLLER_INITIATED";
		break;
	case 0xC0:
		return "VS_MEDIA_SMART_LOG";
		break;
	case 0xC1:
		return "VS_DEBUG_LOG1";
		break;
	case 0xC2:
		return "VS_SEC_ERROR_LOG_PAGE";
		break;
	case 0xC3:
		return "VS_LIFE_TIME_DRIVE_HISTORY";
		break;
	case 0xC4:
		return "VS_EXTENDED_SMART_INFO";
		break;
	case 0xC5:
		return "VS_LIST_SUPPORTED_LOG_PAGE";
		break;
	case 0xC6:
		return "VS_POWER_MONITOR_LOG_PAGE";
		break;
	case 0xC7:
		return "VS_CRITICAL_EVENT_LOG_PAGE";
		break;
	case 0xC8:
		return "VS_RECENT_DRIVE_HISTORY";
		break;
	case 0xC9:
		return "VS_SEC_ERROR_LOG_PAGE";
		break;
	case 0xCA:
		return "VS_LIFE_TIME_DRIVE_HISTORY";
		break;
	case 0xCB:
		return "VS_PCIE_ERROR_LOG_PAGE";
		break;
	case 0xCF:
		return "DRAM Supercap SMART Attributes";
		break;
	case 0xD6:
		return "VS_OEM2_WORK_LOAD";
		break;
	case 0xD7:
		return "VS_OEM2_FW_SECURITY";
		break;
	case 0xD8:
		return "VS_OEM2_REVISION";
		break;
	default:
		return "UNKNOWN";
		break;
	}
}


static void json_log_pages_supp(log_page_map *logPageMap)
{
	struct json_object *root;
	struct json_array *logPages;
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
	printf("\n");
}

static int log_pages_supp(int argc, char **argv, struct command *cmd,
			  struct plugin *plugin)
{
	int err = 0;
	int fd = 0;
	__u32 i = 0;
	log_page_map logPageMap;
	const char *desc = "Retrieve Seagate Supported Log-Page information for the given device ";
	const char *output_format = "output in binary format";
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

	fd = parse_and_open(argc, argv, desc, opts);
	err = nvme_get_log(fd, 1, 0xc5, false, NVME_NO_LOG_LSP,
		sizeof(logPageMap), &logPageMap);
	if (!err) {
		if (strcmp(cfg.output_format,"json")) {
			printf ("Seagate Supported Log-pages count :%d\n",
				le32_to_cpu(logPageMap.NumLogPages));
			printf ("%-15s %-30s\n", "LogPage-Id", "LogPage-Name");

			for(fmt=0; fmt<45; fmt++)
				printf ("-");
			printf("\n");
		} else
			json_log_pages_supp(&logPageMap);

		for (i = 0; i<le32_to_cpu(logPageMap.NumLogPages); i++) {
			if (strcmp(cfg.output_format,"json")) {
				printf("0x%-15X",
				       le32_to_cpu(logPageMap.LogPageEntry[i].LogPageID));
				printf("%-30s\n",
				       log_pages_supp_print(le32_to_cpu(logPageMap.LogPageEntry[i].LogPageID)));
			}
		}
	}

	if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
	return err;
}

/* EOF Command for "log-pages-supp" */


/***************************************
* Extended-SMART Information
***************************************/
static char *print_ext_smart_id(__u8 attrId)
{
	switch(attrId) {
	case VS_ATTR_ID_SOFT_READ_ERROR_RATE:
		return "Soft ECC error count";
		break;
	case VS_ATTR_ID_REALLOCATED_SECTOR_COUNT:
		return "Bad NAND block count";
		break;
	case VS_ATTR_ID_POWER_ON_HOURS:
		return "Power On Hours";
		break;
	case VS_ATTR_ID_POWER_FAIL_EVENT_COUNT:
		return "Power Fail Event Count";
		break;
	case VS_ATTR_ID_DEVICE_POWER_CYCLE_COUNT:
		return "Device Power Cycle Count";
		break;
	case VS_ATTR_ID_RAW_READ_ERROR_RATE:
		return "Raw Read Error Count";
		break;
	case VS_ATTR_ID_GROWN_BAD_BLOCK_COUNT:
		return "Bad NAND block count";
		break;
	case VS_ATTR_ID_END_2_END_CORRECTION_COUNT:
		return "SSD End to end correction counts";
		break;
	case VS_ATTR_ID_MIN_MAX_WEAR_RANGE_COUNT:
		return "User data erase counts";
		break;
	case VS_ATTR_ID_REFRESH_COUNT:
		return "Refresh count";
		break;
	case VS_ATTR_ID_BAD_BLOCK_COUNT_USER:
		return "User data erase fail count";
		break;
	case VS_ATTR_ID_BAD_BLOCK_COUNT_SYSTEM:
		return "System area erase fail count";
		break;
	case VS_ATTR_ID_THERMAL_THROTTLING_STATUS:
		return "Thermal throttling status and count";
		break;
	case VS_ATTR_ID_ALL_PCIE_CORRECTABLE_ERROR_COUNT:
		return "PCIe Correctable Error count";
		break;
	case VS_ATTR_ID_ALL_PCIE_UNCORRECTABLE_ERROR_COUNT:
		return "PCIe Uncorrectable Error count";
		break;
	case VS_ATTR_ID_INCOMPLETE_SHUTDOWN_COUNT:
		return "Incomplete shutdowns";
		break;
	case VS_ATTR_ID_GB_ERASED_LSB:
		return "LSB of Flash GB erased";
		break;
	case VS_ATTR_ID_GB_ERASED_MSB:
		return "MSB of Flash GB erased";
		break;
	case VS_ATTR_ID_LIFETIME_DEVSLEEP_EXIT_COUNT:
		return "LIFETIME_DEV_SLEEP_EXIT_COUNT";
		break;
	case VS_ATTR_ID_LIFETIME_ENTERING_PS4_COUNT:
		return "LIFETIME_ENTERING_PS4_COUNT";
		break;
	case VS_ATTR_ID_LIFETIME_ENTERING_PS3_COUNT:
		return "LIFETIME_ENTERING_PS3_COUNT";
		break;
	case VS_ATTR_ID_RETIRED_BLOCK_COUNT:
		return "Retired block count"; /*VS_ATTR_ID_RETIRED_BLOCK_COUNT*/
		break;
	case VS_ATTR_ID_PROGRAM_FAILURE_COUNT:
		return "Program fail count";
		break;
	case VS_ATTR_ID_ERASE_FAIL_COUNT:
		return "Erase Fail Count";
		break;
	case VS_ATTR_ID_AVG_ERASE_COUNT:
		return "System data % used";
		break;
	case VS_ATTR_ID_UNEXPECTED_POWER_LOSS_COUNT:
		return "Unexpected power loss count";
		break;
	case VS_ATTR_ID_WEAR_RANGE_DELTA:
		return "Wear range delta";
		break;
	case VS_ATTR_ID_SATA_INTERFACE_DOWNSHIFT_COUNT:
		return "PCIE_INTF_DOWNSHIFT_COUNT";
		break;
	case VS_ATTR_ID_END_TO_END_CRC_ERROR_COUNT:
		return "E2E_CRC_ERROR_COUNT";
		break;
	case VS_ATTR_ID_UNCORRECTABLE_READ_ERRORS:
		return "Uncorrectable Read Error Count";
		break;
	case VS_ATTR_ID_MAX_LIFE_TEMPERATURE:
		return "Max lifetime temperature";/*VS_ATTR_ID_MAX_LIFE_TEMPERATURE for extended*/
		break;
	case VS_ATTR_ID_RAISE_ECC_CORRECTABLE_ERROR_COUNT:
		return "RAIS_ECC_CORRECT_ERR_COUNT";
		break;
	case VS_ATTR_ID_UNCORRECTABLE_RAISE_ERRORS:
		return "Uncorrectable RAISE error count";/*VS_ATTR_ID_UNCORRECTABLE_RAISE_ERRORS*/
		break;
	case VS_ATTR_ID_DRIVE_LIFE_PROTECTION_STATUS:
		return "DRIVE_LIFE_PROTECTION_STATUS";
		break;
	case VS_ATTR_ID_REMAINING_SSD_LIFE:
		return "Remaining SSD life";
		break;
	case VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB:
		return "LSB of Physical (NAND) bytes written";
		break;
	case VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB:
		return "MSB of Physical (NAND) bytes written";
		break;
	case VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB:
		return "LSB of Physical (HOST) bytes written";
		break;
	case VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB:
		return "MSB of Physical (HOST) bytes written";
		break;
	case VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB:
		return "LSB of Physical (NAND) bytes read";
		break;
	case VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB:
		return "MSB of Physical (NAND) bytes read";
		break;
	case VS_ATTR_ID_FREE_SPACE:
		return "Free Space";
		break;
	case VS_ATTR_ID_TRIM_COUNT_LSB:
		return "LSB of Trim count";
		break;
	case VS_ATTR_ID_TRIM_COUNT_MSB:
		return "MSB of Trim count";
		break;
	case VS_ATTR_ID_OP_PERCENTAGE:
		return "OP percentage";
		break;
	case VS_ATTR_ID_MAX_SOC_LIFE_TEMPERATURE:
		return "Max lifetime SOC temperature";
		break;
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

	if ((attr.AttributeNumber != 0) && (hideAttr != 1)) {
		printf("%-40s", print_ext_smart_id(attr.AttributeNumber));
		printf("%-15d", attr.AttributeNumber  );
		printf(" 0x%016"PRIx64"", (uint64_t)smart_attribute_vs(verNo, attr));
		printf("\n");
	}

	if (lastAttr == 1) {

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_GB_ERASED_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_GB_ERASED_MSB << 8 | VS_ATTR_ID_GB_ERASED_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbGbErased, (uint64_t)lsbGbErased);
		printf(" %s", buf);
		printf("\n");

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtToFlash, (uint64_t)lsbLifWrtToFlash);
		printf(" %s", buf);
		printf("\n");

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifWrtFrmHost, (uint64_t)lsbLifWrtFrmHost);
		printf(" %s", buf);
		printf("\n");

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB << 8 | VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbLifRdToHost, (uint64_t)lsbLifRdToHost);
		printf(" %s", buf);
		printf("\n");

		sprintf(strBuf, "%s", (print_ext_smart_id(VS_ATTR_ID_TRIM_COUNT_LSB) + 7));
		printf("%-40s", strBuf);

		printf("%-15d", VS_ATTR_ID_TRIM_COUNT_MSB << 8 | VS_ATTR_ID_TRIM_COUNT_LSB);

		sprintf(buf, "0x%016"PRIx64"%016"PRIx64"", (uint64_t)msbTrimCnt, (uint64_t)lsbTrimCnt);
		printf(" %s", buf);
		printf("\n");

	}
}

static void json_print_smart_log(struct json_object *root,
				 EXTENDED_SMART_INFO_T *ExtdSMARTInfo )
{
	/*struct json_object *root; */
	struct json_array *lbafs;
	int index = 0;

	static __u64 lsbGbErased = 0, msbGbErased = 0, lsbLifWrtToFlash = 0, msbLifWrtToFlash = 0,
		lsbLifWrtFrmHost = 0, msbLifWrtFrmHost = 0, lsbLifRdToHost = 0, msbLifRdToHost = 0, lsbTrimCnt = 0, msbTrimCnt = 0;
	char buf[40] = {0};

	/*root = json_create_object();*/
	lbafs = json_create_array();
	json_object_add_value_array(root, "Extended-SMART-Attributes", lbafs);

	for (index =0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++) {
		struct json_object *lbaf = json_create_object();
		if (ExtdSMARTInfo->vendorData[index].AttributeNumber != 0) {
			json_object_add_value_string(lbaf, "attribute_name", print_ext_smart_id(ExtdSMARTInfo->vendorData[index].AttributeNumber));
			json_object_add_value_int(lbaf, "attribute_id",ExtdSMARTInfo->vendorData[index].AttributeNumber);
			json_object_add_value_int(lbaf, "attribute_value", smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]));
			json_array_add_value_object(lbafs, lbaf);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_GB_ERASED_LSB)
				lsbGbErased = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_GB_ERASED_MSB)
				msbGbErased = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB)
				lsbLifWrtToFlash = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB)
				msbLifWrtToFlash = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB)
				lsbLifWrtFrmHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB)
				msbLifWrtFrmHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB)
				lsbLifRdToHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB)
				msbLifRdToHost = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_TRIM_COUNT_LSB)
				lsbTrimCnt = smart_attribute_vs(ExtdSMARTInfo->Version, ExtdSMARTInfo->vendorData[index]);

			if(ExtdSMARTInfo->vendorData[index].AttributeNumber == VS_ATTR_ID_TRIM_COUNT_MSB)
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

	/*
	  json_print_object(root, NULL);
	  printf("\n");
	*/
}

static void print_smart_log_CF(vendor_log_page_CF *pLogPageCF)
{
	__u64 currentTemp, maxTemp;
	printf("\n\nSeagate DRAM Supercap SMART Attributes :\n");
	printf("%-39s %-19s \n", "Description", "Supercap Attributes");

	printf("%-40s", "Super-cap current temperature");
	currentTemp = pLogPageCF->AttrCF.SuperCapCurrentTemperature;
	/*currentTemp = currentTemp ? currentTemp - 273 : 0;*/
	printf(" 0x%016"PRIx64"", le64_to_cpu(currentTemp));
	printf("\n");

	maxTemp = pLogPageCF->AttrCF.SuperCapMaximumTemperature;
	/*maxTemp = maxTemp ? maxTemp - 273 : 0;*/
	printf("%-40s", "Super-cap maximum temperature");
	printf(" 0x%016"PRIx64"", le64_to_cpu(maxTemp));
	printf("\n");

	printf("%-40s", "Super-cap status");
	printf(" 0x%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.SuperCapStatus));
	printf("\n");

	printf("%-40s", "Data units read to DRAM namespace");
	printf(" 0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.MS__u64),
	       le64_to_cpu(pLogPageCF->AttrCF.DataUnitsReadToDramNamespace.LS__u64));
	printf("\n");

	printf("%-40s", "Data units written to DRAM namespace");
	printf(" 0x%016"PRIx64"%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.MS__u64),
	       le64_to_cpu(pLogPageCF->AttrCF.DataUnitsWrittenToDramNamespace.LS__u64));
	printf("\n");

	printf("%-40s", "DRAM correctable error count");
	printf(" 0x%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DramCorrectableErrorCount));
	printf("\n");

	printf("%-40s", "DRAM uncorrectable error count");
	printf(" 0x%016"PRIx64"", le64_to_cpu(pLogPageCF->AttrCF.DramUncorrectableErrorCount));
	printf("\n");

}

static void json_print_smart_log_CF(struct json_object *root,
				    vendor_log_page_CF *pLogPageCF)
{
	/*struct json_object *root;*/
	struct json_array *logPages;
	unsigned int currentTemp, maxTemp;
	char buf[40];

	/*root = json_create_object(); */

	logPages = json_create_array();
	json_object_add_value_array(root, "DRAM Supercap SMART Attributes", logPages);
	struct json_object *lbaf = json_create_object();

	currentTemp = pLogPageCF->AttrCF.SuperCapCurrentTemperature;
	/*currentTemp = currentTemp ? currentTemp - 273 : 0;*/
	json_object_add_value_string(lbaf, "attribute_name", "Super-cap current temperature");
	json_object_add_value_int(lbaf, "attribute_value", currentTemp);
	json_array_add_value_object(logPages, lbaf);

	lbaf = json_create_object();
	maxTemp = pLogPageCF->AttrCF.SuperCapMaximumTemperature;
	/*maxTemp = maxTemp ? maxTemp - 273 : 0;*/
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

	/*
	  json_print_object(root, NULL);
	  printf("\n");
	*/
}

static int vs_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	EXTENDED_SMART_INFO_T   ExtdSMARTInfo;
	vendor_log_page_CF      logPageCF;
	int fd;
	struct json_object *root;
	struct json_array *lbafs;
	struct json_object *lbafs_ExtSmart, *lbafs_DramSmart;
	root = json_create_object();
	lbafs = json_create_array();

	const char *desc = "Retrieve Seagate Extended SMART information for the given device ";
	const char *output_format = "output in binary format";
	int err, index=0;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if (strcmp(cfg.output_format,"json"))
		printf("Seagate Extended SMART Information :\n");

	err = nvme_get_log(fd, 1, 0xC4, false, NVME_NO_LOG_LSP,
		sizeof(ExtdSMARTInfo), &ExtdSMARTInfo);
	if (!err) {
		if (strcmp(cfg.output_format,"json")) {
			printf("%-39s %-15s %-19s \n", "Description", "Ext-Smart-Id", "Ext-Smart-Value");
			for(index=0; index<80; index++)
				printf("-");
			printf("\n");
			for(index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++)
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

		err = nvme_get_log(fd, 1, 0xCF, false, NVME_NO_LOG_LSP,
			sizeof(logPageCF), &logPageCF);
		if (!err) {
			if(strcmp(cfg.output_format,"json")) {
				/*printf("Seagate DRAM Supercap SMART Attributes :\n");*/

				print_smart_log_CF(&logPageCF);
			} else {
				lbafs_DramSmart = json_create_object();
				json_print_smart_log_CF(lbafs_DramSmart, &logPageCF);
				json_array_add_value_object(lbafs, lbafs_DramSmart);
				json_print_object(root, NULL);
			}
		} else if (!strcmp(cfg.output_format, "json"))
			json_print_object(root, NULL);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);

	return err;
}

/*EOF Extended-SMART Information */

/***************************************
 * Temperature-Stats information
 ***************************************/
static void json_temp_stats(__u32 temperature, __u32 PcbTemp, __u32 SocTemp, __u32 maxTemperature,
			    __u32 MaxSocTemp, __u32 cf_err, __u32 scCurrentTemp, __u32 scMaxTem)
{
	struct json_object *root;
	root = json_create_object();

	json_object_add_value_int(root, "Current temperature", temperature);
	json_object_add_value_int(root, "Current PCB temperature", PcbTemp);
	json_object_add_value_int(root, "Current SOC temperature", SocTemp);
	json_object_add_value_int(root, "Highest temperature", maxTemperature);
	json_object_add_value_int(root, "Max SOC temperature", MaxSocTemp);
	if(!cf_err) {
		json_object_add_value_int(root, "SuperCap Current temperature", scCurrentTemp);
		json_object_add_value_int(root, "SuperCap Max temperature", scMaxTem);
	}

	json_print_object(root, NULL);
	printf("\n");

}
static int temp_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	EXTENDED_SMART_INFO_T ExtdSMARTInfo;
	vendor_log_page_CF    logPageCF;

	int fd;
	int err, cf_err;
	int index;
	const char *desc = "Retrieve Seagate Temperature Stats information for the given device ";
	const char *output_format = "output in binary format";
	unsigned int temperature = 0, PcbTemp = 0, SocTemp = 0, scCurrentTemp = 0, scMaxTemp = 0;
	unsigned long long maxTemperature = 0, MaxSocTemp = 0;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		printf ("\nDevice not found \n");;
		return -1;
	}

	if(strcmp(cfg.output_format,"json"))
		printf("Seagate Temperature Stats Information :\n");
	/*STEP-1 : Get Current Temperature from SMART */
	err = nvme_smart_log(fd, 0xffffffff, &smart_log);
	if (!err) {
		temperature = ((smart_log.temperature[1] << 8) | smart_log.temperature[0]);
		temperature = temperature ? temperature - 273 : 0;
		PcbTemp = le16_to_cpu(smart_log.temp_sensor[0]);
		PcbTemp = PcbTemp ? PcbTemp - 273 : 0;
		SocTemp = le16_to_cpu(smart_log.temp_sensor[1]);
		SocTemp = SocTemp ? SocTemp - 273 : 0;
		if (strcmp(cfg.output_format,"json")) {
			printf("%-20s : %u C\n", "Current Temperature", temperature);
			printf("%-20s : %u C\n", "Current PCB Temperature", PcbTemp);
			printf("%-20s : %u C\n", "Current SOC Temperature", SocTemp);
		}
	}

	/* STEP-2 : Get Max temperature form Ext SMART-id 194 */
	err = nvme_get_log(fd, 1, 0xC4, false, NVME_NO_LOG_LSP,
		sizeof(ExtdSMARTInfo), &ExtdSMARTInfo);
	if (!err) {
		for(index = 0; index < NUMBER_EXTENDED_SMART_ATTRIBUTES; index++) {
			if (ExtdSMARTInfo.vendorData[index].AttributeNumber == VS_ATTR_ID_MAX_LIFE_TEMPERATURE) {
				maxTemperature = smart_attribute_vs(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index]);
				maxTemperature = maxTemperature ? maxTemperature - 273 : 0;
				if (strcmp(cfg.output_format,"json"))
					printf("%-20s : %d C\n", "Highest Temperature", (unsigned int)maxTemperature);
			}

			if (ExtdSMARTInfo.vendorData[index].AttributeNumber == VS_ATTR_ID_MAX_SOC_LIFE_TEMPERATURE) {
				MaxSocTemp = smart_attribute_vs(ExtdSMARTInfo.Version, ExtdSMARTInfo.vendorData[index]);
				MaxSocTemp = MaxSocTemp ? MaxSocTemp - 273 : 0;
				if (strcmp(cfg.output_format,"json"))
					printf("%-20s : %d C\n", "Max SOC Temperature", (unsigned int)MaxSocTemp);
			}
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);

	cf_err = nvme_get_log(fd, 1, 0xCF, false, NVME_NO_LOG_LSP,
		sizeof(ExtdSMARTInfo), &logPageCF);

	if(!cf_err) {
		scCurrentTemp = logPageCF.AttrCF.SuperCapCurrentTemperature;
		scCurrentTemp = scCurrentTemp ? scCurrentTemp - 273 : 0;
		printf("%-20s : %d C\n", "Super-cap Current Temperature", scCurrentTemp);

		scMaxTemp = logPageCF.AttrCF.SuperCapMaximumTemperature;
		scMaxTemp = scMaxTemp ? scMaxTemp - 273 : 0;
		printf("%-20s : %d C\n", "Super-cap Max Temperature", scMaxTemp);
	}

	if(!strcmp(cfg.output_format,"json"))
		json_temp_stats(temperature, PcbTemp, SocTemp, maxTemperature, MaxSocTemp, cf_err, scCurrentTemp, scMaxTemp);

	return err;
}
/* EOF Temperature Stats information */

/***************************************
 * PCIe error-log information
 ***************************************/
static void print_vs_pcie_error_log(pcie_error_log_page  pcieErrorLog)
{
	__u32 correctPcieEc = 0;
	__u32 uncorrectPcieEc = 0;
	correctPcieEc = pcieErrorLog.BadDllpErrCnt + pcieErrorLog.BadTlpErrCnt
		+ pcieErrorLog.RcvrErrCnt + pcieErrorLog.ReplayTOErrCnt
		+ pcieErrorLog.ReplayNumRolloverErrCnt;

	uncorrectPcieEc = pcieErrorLog.FCProtocolErrCnt + pcieErrorLog.DllpProtocolErrCnt
		+ pcieErrorLog.CmpltnTOErrCnt + pcieErrorLog.RcvrQOverflowErrCnt
		+ pcieErrorLog.UnexpectedCplTlpErrCnt + pcieErrorLog.CplTlpURErrCnt
		+ pcieErrorLog.CplTlpCAErrCnt + pcieErrorLog.ReqCAErrCnt
		+ pcieErrorLog.ReqURErrCnt + pcieErrorLog.EcrcErrCnt
		+ pcieErrorLog.MalformedTlpErrCnt + pcieErrorLog.CplTlpPoisonedErrCnt
		+ pcieErrorLog.MemRdTlpPoisonedErrCnt;

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
	struct json_object *root;
	root = json_create_object();
	__u32 correctPcieEc = 0;
	__u32 uncorrectPcieEc = 0;
	correctPcieEc = pcieErrorLog.BadDllpErrCnt + pcieErrorLog.BadTlpErrCnt
		+ pcieErrorLog.RcvrErrCnt + pcieErrorLog.ReplayTOErrCnt
		+ pcieErrorLog.ReplayNumRolloverErrCnt;

	uncorrectPcieEc = pcieErrorLog.FCProtocolErrCnt + pcieErrorLog.DllpProtocolErrCnt
		+ pcieErrorLog.CmpltnTOErrCnt + pcieErrorLog.RcvrQOverflowErrCnt
		+ pcieErrorLog.UnexpectedCplTlpErrCnt + pcieErrorLog.CplTlpURErrCnt
		+ pcieErrorLog.CplTlpCAErrCnt + pcieErrorLog.ReqCAErrCnt
		+ pcieErrorLog.ReqURErrCnt + pcieErrorLog.EcrcErrCnt
		+ pcieErrorLog.MalformedTlpErrCnt + pcieErrorLog.CplTlpPoisonedErrCnt
		+ pcieErrorLog.MemRdTlpPoisonedErrCnt;

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
	printf("\n");
}

static int vs_pcie_error_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	pcie_error_log_page pcieErrorLog;
	int fd;

	const char *desc = "Retrieve Seagate PCIe error counters for the given device ";
	const char *output_format = "output in binary format";
	int err;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if(strcmp(cfg.output_format,"json"))
		printf("Seagate PCIe error counters Information :\n");

	err = nvme_get_log(fd, 1, 0xCB, false, NVME_NO_LOG_LSP,
		sizeof(pcieErrorLog), &pcieErrorLog);
	if (!err) {
		if(strcmp(cfg.output_format,"json")) {
			print_vs_pcie_error_log(pcieErrorLog);
		} else
			json_vs_pcie_error_log(pcieErrorLog);

	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err), err);

	return err;
}
/* EOF PCIE error-log information */

static int vs_clr_pcie_correctable_errs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Clear Seagate PCIe Correctable counters for the given device ";
	const char *save = "specifies that the controller shall save the attribute";
	int err, fd;
	__u32 result;
	void *buf = NULL;

	struct config {
		int   save;
	};

	struct config cfg = {
		.save         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	err = nvme_set_feature(fd, 0, 0xE1, 0xCB, 0, cfg.save, 0, buf, &result);

	if (err < 0) {
		perror("set-feature");
		return errno;
	}

	return err;

}

static int get_host_tele(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Capture the Telemetry Host-Initiated Data in either " \
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_specific = "1 - controller shall capture Data representing the internal " \
		"state of the controller at the time the command is processed. " \
		"0 - controller shall not update the Telemetry Host Initiated Data.";
	const char *raw = "output in raw format";
	int err, fd, dump_fd;
	struct nvme_temetry_log_hdr tele_log;
	__le64  offset = 0;
	int blkCnt, maxBlk = 0, blksToGet;
	unsigned char  *log;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		int   raw_binary;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	dump_fd = STDOUT_FILENO;
	cfg.log_id = (cfg.log_id << 8) | 0x07;
	err = nvme_get_log13(fd, cfg.namespace_id, cfg.log_id,
			     NVME_NO_LOG_LSP, offset, 0, false,
			     sizeof(tele_log), (void *)(&tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n",
			       devicename, cfg.log_id,
			       cfg.namespace_id);
			printf("Data Block 1 Last Block:%d Data Block 2 Last Block:%d Data Block 3 Last Block:%d\n",
			       tele_log.tele_data_area1, tele_log.tele_data_area2, tele_log.tele_data_area3);

			d((unsigned char *)(&tele_log), sizeof(tele_log), 16, 1);
		} else
			seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
	else
		perror("log page");

	blkCnt = 0;

	while(blkCnt < maxBlk) {
		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if(blksToGet == 0)
			return err;

		log = malloc(blksToGet * 512);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			return EINVAL;
		}

		memset(log, 0, blksToGet * 512);

		err = nvme_get_log13(fd, cfg.namespace_id, cfg.log_id,
				     NVME_NO_LOG_LSP, offset, 0, false,
				     blksToGet * 512, (void *)log);
		if (!err) {
			offset += blksToGet * 512;

			if (!cfg.raw_binary) {
				printf("\nBlock # :%d to %d\n", blkCnt + 1, blkCnt + blksToGet);

				d((unsigned char *)log, blksToGet * 512, 16, 1);
			} else
				seaget_d_raw((unsigned char *)log, blksToGet * 512, dump_fd);
		} else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
		else
			perror("log page");

		blkCnt += blksToGet;

		free(log);
	}

	return err;
}

static int get_ctrl_tele(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Capture the Telemetry Controller-Initiated Data in either "	\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *raw = "output in raw format";
	int err, fd, dump_fd;
	struct nvme_temetry_log_hdr tele_log;
	__le64  offset = 0;
	__u16 log_id;
	int blkCnt, maxBlk = 0, blksToGet;
	unsigned char  *log;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	dump_fd = STDOUT_FILENO;

	log_id = 0x08;
	err = nvme_get_log13(fd, cfg.namespace_id, log_id,
			     NVME_NO_LOG_LSP, offset, 0, false,
			     sizeof(tele_log), (void *)(&tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		if (!cfg.raw_binary) {
			printf("Device:%s namespace-id:%#x\n",
			       devicename, cfg.namespace_id);
			printf("Data Block 1 Last Block:%d Data Block 2 Last Block:%d Data Block 3 Last Block:%d\n",
			       tele_log.tele_data_area1, tele_log.tele_data_area2, tele_log.tele_data_area3);

			d((unsigned char *)(&tele_log), sizeof(tele_log), 16, 1);
		} else
			seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
	else
		perror("log page");

	blkCnt = 0;

	while(blkCnt < maxBlk) {
		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if(blksToGet == 0)
			return err;

		log = malloc(blksToGet * 512);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			return EINVAL;
		}

		memset(log, 0, blksToGet * 512);

		err = nvme_get_log13(fd, cfg.namespace_id, log_id,
				     NVME_NO_LOG_LSP, offset, 0, false,
				     blksToGet * 512, (void *)log);
		if (!err) {
			offset += blksToGet * 512;

			if (!cfg.raw_binary) {
				printf("\nBlock # :%d to %d\n", blkCnt + 1, blkCnt + blksToGet);

				d((unsigned char *)log, blksToGet * 512, 16, 1);
			} else
				seaget_d_raw((unsigned char *)log, blksToGet * 512, dump_fd);
		} else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
		else
			perror("log page");

		blkCnt += blksToGet;

		free(log);
	}
	return err;

}

void seaget_d_raw(unsigned char *buf, int len, int fd)
{
	/*********************
	int i;
	fflush(stdout);
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
	*********************/

	if (write(fd, (void *)buf, len) <= 0)
		printf("%s: Write Failed\n",__FUNCTION__);
}


static int vs_internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Capture the Telemetry Controller-Initiated Data in " \
		"binary format";
	const char *namespace_id = "desired namespace";

	const char *file = "dump file";
	int err, fd, dump_fd;
	int flags = O_WRONLY | O_CREAT;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	dump_fd = STDOUT_FILENO;
	if(strlen(cfg.file)) {
		dump_fd = open(cfg.file, flags, mode);
		if (dump_fd < 0) {
			perror(cfg.file);
			return EINVAL;
		}
	}

	log_id = 0x08;
	err = nvme_get_log13(fd, cfg.namespace_id, log_id,
			     NVME_NO_LOG_LSP, offset, 0, false,
			     sizeof(tele_log), (void *)(&tele_log));
	if (!err) {
		maxBlk = tele_log.tele_data_area3;
		offset += 512;

		/*
		printf("Data Block 1 Last Block:%d Data Block 2 Last Block:%d Data Block 3 Last Block:%d\n",
			tele_log.tele_data_area1, tele_log.tele_data_area2, tele_log.tele_data_area3);
		*/
		seaget_d_raw((unsigned char *)(&tele_log), sizeof(tele_log), dump_fd);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
	else
		perror("log page");

	blkCnt = 0;

	while(blkCnt < maxBlk) {
		blksToGet = ((maxBlk - blkCnt) >= TELEMETRY_BLOCKS_TO_READ) ? TELEMETRY_BLOCKS_TO_READ : (maxBlk - blkCnt);

		if(blksToGet == 0) {
			return err;
		}

		log = malloc(blksToGet * 512);

		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			return EINVAL;
		}

		memset(log, 0, blksToGet * 512);

		err = nvme_get_log13(fd, cfg.namespace_id, log_id,
				     NVME_NO_LOG_LSP, offset, 0, false,
				     blksToGet * 512, (void *)log);
		if (!err) {
			offset += blksToGet * 512;

			seaget_d_raw((unsigned char *)log, blksToGet * 512, dump_fd);

		} else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
		else
			perror("log page");

		blkCnt += blksToGet;

		free(log);
	}

	if(strlen(cfg.file))
		close(dump_fd);

	return err;
}

/*SEAGATE-PLUGIN Version */
static int seagate_plugin_version(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin)
{
	printf("Seagate-Plugin version : %d.%d \n",
		SEAGATE_PLUGIN_VERSION_MAJOR,
		SEAGATE_PLUGIN_VERSION_MINOR);
	return 0;
}
/*EOF SEAGATE-PLUGIN Version */
