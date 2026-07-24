// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 YMTC Corporation or its affiliates.
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
 *   Author:  Bin Zhang<robin_zhang3@ymtc.com>
 */
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "ymtc-nvme.h"
#include "ymtc-utils.h"

 /* sysfs paths for vendor ID and device ID */
static char *vendor_id_path1 = "/sys/class/nvme/nvme%d/device/vendor";
static char *vendor_id_path2 = "/sys/class/misc/nvme%d/device/vendor";
static char *device_id_path1 = "/sys/class/nvme/nvme%d/device/device";
static char *device_id_path2 = "/sys/class/misc/nvme%d/device/device";
static unsigned short vendor_id;
static unsigned short device_id;

/**
 * ReadSysFile - Read a hexadecimal ID value from a sysfs file
 * @file:  Path to the sysfs file
 * @id:    Output parameter to store the read ID value
 * Return: Number of bytes read on success, -1 on failure
 */
static int ReadSysFile(const char *file, unsigned short *id)
{
	int ret = 0;
	char idstr[32] = { '\0' };
	int fd = open(file, O_RDONLY);

	if (fd < 0) {
		perror(file);
		return fd;
	}

	ret = read(fd, idstr, sizeof(idstr));
	close(fd);
	if (ret < 0)
		perror("read");
	else
		*id = strtol(idstr, NULL, 16);

	return ret;
}

/**
 * GetSSDModel - Identify YMTC SSD model by NVMe controller index
 * @idx: NVMe controller index (e.g., idx=0 for nvme0)
 * Return: ySSDModel enum value indicating the SSD model
 */
static enum ySSDModel GetSSDModel(int idx)
{
	enum ySSDModel model = UNKNOWN_SSD;
	char path[512];

	sprintf(path, vendor_id_path1, idx);
	if (ReadSysFile(path, &vendor_id) < 0) {
		sprintf(path, vendor_id_path2, idx);
		ReadSysFile(path, &vendor_id);
	}
	sprintf(path, device_id_path1, idx);
	if (ReadSysFile(path, &device_id) < 0) {
		sprintf(path, device_id_path2, idx);
		ReadSysFile(path, &device_id);
	}
	if (vendor_id == YMTC_VENDOR_ID) {
		switch (device_id) {
		case 0x1058:
			model = PE310;
			break;
		case 0x1078:
			model = PE321;
			break;
		case 0x1a28:
			model = PE511;
			break;
		case 0x1a38:
			model = PE501;
			break;
		case 0x1a48:
			model = PE522;
			break;
		default:
			model = UNKNOWN_SSD;
			break;
		}
	}
	return model;
}

/**
 * ymtc_parse_options - Parse command line arguments
 * @dev:   Output parameter, NVMe device pointer
 * @argc:  Number of command line arguments
 * @argv:  Command line argument array
 * @desc:  Command description string
 * @opts:  Command line options configuration
 * @model: Output parameter, detected SSD model (can be NULL)
 * Return: 0 on success, -1 on failure
 */
static int ymtc_parse_options(struct nvme_dev **dev, int argc, char **argv,
				const char *desc,
				struct argconfig_commandline_options *opts,
				enum ySSDModel *model)
{
	int idx;
	int err = parse_and_open(dev, argc, argv, desc, opts);

	if (err) {
		perror("open");
		return -1;
	}

	if (model) {
		if (sscanf(argv[optind], "/dev/nvme%d", &idx) != 1)
			idx = 0;
		*model = GetSSDModel(idx);
	}

	return 0;
}

/**
 * print_ymtc_smart_item - Print a single YMTC SMART log entry
 * @it:    Pointer to YMTC SMART log item
 * @model: SSD model (different models interpret the same feature_id differently)
 *
 * Note: feature_id (it->id[0]) determines the metric type.
 *       normalized value (it->nmVal[0]) represents a percentage (0-100).
 *       raw value (it->rawVal) contains the raw counter value (format varies by type).
 */
static void print_ymtc_smart_item(const struct nvme_ymtc_smart_log_item *it,
								  enum ySSDModel model)
{
	const u8 *nm = it->nmVal;
	const u8 *raw = it->rawVal;
	u8 feature_id = it->id[0];

	switch (feature_id) {
	case SI_VD_PROGRAM_FAIL_ID:
		printf("program_fail_count              : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_ERASE_FAIL_ID:
		printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_WEARLEVELING_COUNT_ID:
		printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
			   *nm, *(uint16_t *)raw, *(uint16_t *)(raw + 2), *(uint16_t *)(raw + 4));
		break;

	case SI_VD_TEMPT_SINCE_BOOTUP_ID:
		printf("tempt_since_bootup              : %3d%%       max: %u, min: %u, curr: %u\n",
			   *nm, *(uint16_t *)raw - 273, *(uint16_t *)(raw + 2) - 273,
			   *(uint16_t *)(raw + 4) - 273);
		break;

	case SI_VD_E2E_DECTECTION_COUNT_ID:
		printf("e2e_error_count                 : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_PCIE_CRC_ERR_COUNT_ID:
		printf("crc_error_count                 : %3d%%       %"PRIu32"\n",
			   *nm, *(uint32_t *)raw);
		break;

	case SI_VD_TIMED_WORKLOAD_MEDIA_WEAR_ID:
		printf("timed_workload_media_wear       : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_TIMED_WORKLOAD_HOST_READ_ID:
		printf("timed_workload_host_read        : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_TIMED_WORKLOAD_TIMER_ID:
		printf("timed_workload_timer            : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_IN_FLIGHT_READ_IO_COUNT_ID:
		printf("in_flight_read_IO_count         : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_IN_FLIGHT_WRITE_IO_COUNT_ID:
		printf("in_flight_write_IO_count        : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_TEMPT_SINCE_BORN_ID:
		printf("tempt_since_born                : %3d%%       max: %u, min: %u, curr: %u\n",
			   *nm, *(uint16_t *)raw - 273, *(uint16_t *)(raw + 2) - 273,
			   *(int16_t *)(raw + 4) - 273);
		break;

	case SI_VD_POWER_CONSUMPTION_ID:
		printf("power_consumption               : %3d%%       max: %u, min: %u, curr: %u\n",
			   *nm, *(uint16_t *)raw, *(uint16_t *)(raw + 2), *(uint16_t *)(raw + 4));
		break;

	case SI_VD_THERMAL_THROTTLE_STATUS_ID:
		printf("thermal_throttle_status         : %3d%%       %d%%, cnt: %"PRIu32"\n",
			   *nm, *raw, *(uint32_t *)(raw + 1));
		break;

	case SI_VD_THERMAL_THROTTLE_TIME_ID:
		printf("thermal_throttle_time           : %3d%%       %u, time: %"PRIu32"\n",
			   *nm, *raw, *(uint32_t *)(raw + 1));
		break;

	case SI_VD_FEATURE_EC_ID:
		if (model == PE511 || model == PE310)
			printf("power_loss_protection           : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		else if (model == PE501 || model == PE522)
			printf("capacitor_capacitance           : %3d%%       current: %u, nominal: %u, threshold: %u\n",
				   *nm, *(uint16_t *)raw, *(uint16_t *)(raw + 2), *(uint16_t *)(raw + 4));
		break;

	case SI_VD_FEATURE_ED_ID:
		if ((model == PE511) || (model == PE310))
			printf("flash_error_media_count         : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		else if (model == PE501 || model == PE522)
			printf("free_xblock_status              : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		break;

	case SI_VD_FEATURE_F0_ID:
		if (model == PE511 || model == PE501 || model == PE522)
			printf("lifetime_write_aplification     : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		else if (model == PE310 || model == PE321)
			printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		break;

	case SI_VD_READ_FAIL_ID:
		printf("read_fail                       : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_PLL_LOCK_LOSS_COUNT_ID:
		printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_TOTAL_WRITE_ID:
		printf("nand_bytes_written              : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_HOST_WRITE_ID:
		printf("host_bytes_written              : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_SYSTEM_AREA_LIFE_LEFT_ID:
		printf("system_area_life_remaining      : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_NAND_BYTES_READ_ID:
		printf("nand_bytes_read                 : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_FIRMWARE_UPDATE_COUNT_ID:
		printf("firmware_update_count           : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_FEATURE_FA_ID:
		if (model == PE511 || model == PE501 || model == PE522)
			printf("dram_CECC_count                 : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		else if (model == PE310)
			printf("nand_bytes_read                 : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		break;

	case SI_VD_DRAM_UECC_COUNT_ID:
		printf("dram_UECC_count                 : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_XOR_PASS_COUNT_ID:
		printf("xor_pass_count                  : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_XOR_FAIL_COUNT_ID:
		printf("xor_fail_count                  : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_XOR_INVOKED_COUNT_ID:
		printf("xor_invoked_count               : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	default:
		// skip
		break;
	}
}

/**
 * show_ymtc_smart_log - Format and display YMTC additional SMART log
 * @dev:   NVMe device
 * @nsid:  Namespace ID
 * @smart: Pointer to YMTC SMART log data
 * @model: SSD model (used for model-specific field interpretation)
 * Return: 0 on success, error code on failure
 */
static int show_ymtc_smart_log(struct nvme_dev *dev, __u32 nsid,
							   struct nvme_ymtc_smart_log *smart, enum ySSDModel model)
{
	struct nvme_id_ctrl ctrl;
	char fw_ver[10];
	int err = 0;
	const u8 *base = (const u8 *)smart;
	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err)
		return err;

	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
			 ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
			 ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		   dev->name, nsid);
	printf("key                               normalized raw\n");

	for (int i = 0; i < YMTC_MAX_ITEMS; i++) {
		const struct nvme_ymtc_smart_log_item *it =
			(const struct nvme_ymtc_smart_log_item *)(base + (size_t)i * YMTC_SMART_ITEM_SIZE);

		if (it->id[0] == 0x00 || it->id[0] == 0xFF )
			continue;
		print_ymtc_smart_item(it, model);
	}

	return 0;
}

/**
 * get_additional_smart_log - Main command function: Retrieve YMTC additional SMART log
 * @argc:   Number of arguments
 * @argv:   Argument array
 * @cmd:    Command structure (NVMe CLI framework)
 * @plugin: Plugin structure
 * Return: 0 on success, error code on failure
 *
 * Command description: Retrieves YMTC additional SMART information (Log ID 0xCA)
 *                      and prints formatted output or raw binary data.
 * Options: -n/--namespace-id  Specify namespace (default: all)
 *          -b/--raw-binary    Output raw binary format
 */
static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_ymtc_smart_log smart_log;
	memset(&smart_log, 0 , sizeof(smart_log));
	char *desc =
		"Get Ymtc vendor specific additional smart log (optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct nvme_dev *dev;
	enum ySSDModel model = UNKNOWN_SSD;
	struct config {
		__u32 namespace_id;
		bool  raw_binary;
	};
	int err;

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",  'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = ymtc_parse_options(&dev, argc, argv, desc, opts,&model);
	if (err)
		return err;
	err = nvme_get_nsid_log(dev_fd(dev), false, 0xca, cfg.namespace_id,
				sizeof(smart_log), &smart_log);
	if (!err) {
		if (model == UNKNOWN_SSD){
			printf("Not support for parsing current product log!\n");
		}
		else{
			if (!cfg.raw_binary){
				err = show_ymtc_smart_log(dev, cfg.namespace_id, &smart_log, model);
			}
			else
				d_raw((unsigned char *)&smart_log, sizeof(smart_log));
		}
	}
	if (err > 0)
		nvme_show_status(err);

	dev_close(dev);
	return err;
}
