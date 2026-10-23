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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/int-util.h>
#include <shared/unaligned-util.h>

#include "global-ctx.h"
#include "nvme-pci-ids.h"
#include "nvme-print.h"
#include "plugin.h"
#include "src/cleanup.h"
#include "ymtc-utils.h"

/**
 * GetSSDModel - Identify the YMTC SSD model of a controller
 * @ctx: NVMe global context
 * @hdl: transport handle of the controller or one of its namespaces
 * Return: ySSDModel enum value indicating the SSD model
 */
static enum ySSDModel GetSSDModel(struct libnvme_global_ctx *ctx,
				  struct libnvme_transport_handle *hdl)
{
	enum ySSDModel model = UNKNOWN_SSD;
	__u32 vendor_id = 0, device_id = 0;

	if (nvme_get_pci_ids(ctx, hdl, &vendor_id, &device_id,
			     NULL, NULL, NULL))
		return model;

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
 * @ctx:   Output parameter, pointer to NVMe global context
 * @hdl:   Output parameter, pointer to NVMe transport handle
 * @argc:  Number of command line arguments
 * @argv:  Command line argument array
 * @desc:  Command description string
 * @opts:  Command line options configuration
 * @model: Output parameter, detected SSD model (can be NULL)
 * Return: 0 on success, -1 on failure
 */
static int ymtc_parse_options(struct libnvme_global_ctx **ctx,
		struct libnvme_transport_handle **hdl,
		int argc, char **argv, const char *desc,
		struct argconfig_commandline_options *opts,
		enum ySSDModel *model)
{
	int err;

	err = parse_and_open(ctx, hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (model)
		*model = GetSSDModel(*ctx, *hdl);

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
			   *nm,
			   shr_get_unaligned_le16(raw),
			   shr_get_unaligned_le16(raw + 2),
			   shr_get_unaligned_le16(raw + 4));
		break;

	case SI_VD_TEMPT_SINCE_BOOTUP_ID:
		printf("tempt_since_bootup              : %3d%%       max: %u, min: %u, curr: %u\n",
			   *nm,
			   shr_get_unaligned_le16(raw) - 273,
			   shr_get_unaligned_le16(raw + 2) - 273,
			   shr_get_unaligned_le16(raw + 4) - 273);
		break;

	case SI_VD_E2E_DECTECTION_COUNT_ID:
		printf("e2e_error_count                 : %3d%%       %"PRIu64"\n",
			   *nm, int48_to_long(raw));
		break;

	case SI_VD_PCIE_CRC_ERR_COUNT_ID:
		printf("crc_error_count                 : %3d%%       %"PRIu32"\n",
			   *nm, shr_get_unaligned_le32(raw));
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
			   *nm,
			   shr_get_unaligned_le16(raw) - 273,
			   shr_get_unaligned_le16(raw + 2) - 273,
			   (int16_t)shr_get_unaligned_le16(raw + 4) - 273);
		break;

	case SI_VD_POWER_CONSUMPTION_ID:
		printf("power_consumption               : %3d%%       max: %u, min: %u, curr: %u\n",
			   *nm,
			   shr_get_unaligned_le16(raw),
			   shr_get_unaligned_le16(raw + 2),
			   shr_get_unaligned_le16(raw + 4));
		break;

	case SI_VD_THERMAL_THROTTLE_STATUS_ID:
		printf("thermal_throttle_status         : %3d%%       %d%%, cnt: %"PRIu32"\n",
			   *nm, *raw, shr_get_unaligned_le32(raw + 1));
		break;

	case SI_VD_THERMAL_THROTTLE_TIME_ID:
		printf("thermal_throttle_time           : %3d%%       %u, time: %"PRIu32"\n",
			   *nm, *raw, shr_get_unaligned_le32(raw + 1));
		break;

	case SI_VD_FEATURE_EC_ID:
		if (model == PE511 || model == PE310)
			printf("power_loss_protection           : %3d%%       %"PRIu64"\n",
				   *nm, int48_to_long(raw));
		else if (model == PE501 || model == PE522)
			printf("capacitor_capacitance           : %3d%%       current: %u, nominal: %u, threshold: %u\n",
				   *nm,
				   shr_get_unaligned_le16(raw),
				   shr_get_unaligned_le16(raw + 2),
				   shr_get_unaligned_le16(raw + 4));
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
 * @hdl:   Output parameter, pointer to NVMe transport handle
 * @nsid:  Namespace ID
 * @smart: Pointer to YMTC SMART log data
 * @model: SSD model (used for model-specific field interpretation)
 * Return: 0 on success, error code on failure
 */
static int show_ymtc_smart_log(struct libnvme_transport_handle *hdl, __u32 nsid,
		struct nvme_ymtc_smart_log *smart, enum ySSDModel model)
{
	struct nvme_id_ctrl ctrl;
	struct libnvme_passthru_cmd cmd;
	char fw_ver[10];
	int err = 0;
	const u8 *base = (const u8 *)smart;
	nvme_init_identify_ctrl(&cmd, &ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		return err;
	}

	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
		ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
		ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
	       libnvme_transport_handle_get_name(hdl), nsid);
	printf("key                               normalized raw\n");

	for (int i = 0; i < YMTC_MAX_ITEMS; i++) {
		const struct nvme_ymtc_smart_log_item *it =
			(const struct nvme_ymtc_smart_log_item *)
				(base + (size_t)i * YMTC_SMART_ITEM_SIZE);

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
 * @acmd:   Command structure (NVMe CLI framework)
 * @plugin: Plugin structure
 * Return: 0 on success, error code on failure
 *
 * Command description: Retrieves YMTC additional SMART information (Log ID 0xCA)
 *                      and prints formatted output or raw binary data.
 * Options: -n/--namespace-id  Specify namespace (default: all)
 *          -b/--raw-binary    Output raw binary format
 */
static int get_additional_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	char *desc = "Get YMTC vendor specific additional smart log (optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct nvme_ymtc_smart_log smart_log = { 0 };
	struct libnvme_passthru_cmd cmd;
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
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace,
			 nvme_nsid_values),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = ymtc_parse_options(&ctx, &hdl, argc, argv, desc, opts,&model);
	if (err)
		return err;
	nvme_init_get_log(&cmd, cfg.namespace_id, 0xca, NVME_CSI_NVM,
			  &smart_log, sizeof(smart_log));
	err = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (!err) {
		if (model == UNKNOWN_SSD){
			printf("Not support for parsing current product log!\n");
		}
		else{
			if (!cfg.raw_binary){
				err = show_ymtc_smart_log(hdl, cfg.namespace_id, &smart_log, model);
			}
			else
				d_raw((unsigned char *)&smart_log, sizeof(smart_log));
		}
	}
	if (err > 0)
		nvme_show_status(err);

	return err;
}

static struct command get_additional_smart_log_cmd = {
	.name = "smart-log-add",
	.help = "Retrieve YMTC SMART Log, show it",
	.fn = get_additional_smart_log,
};

static struct command *commands[] = {
	&get_additional_smart_log_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "ymtc",
	.desc = "YMTC vendor specific extensions",
	.version = NVME_VERSION,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
