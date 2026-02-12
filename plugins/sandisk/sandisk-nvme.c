// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@sandisk.com>
 *           Brandon Paupore <brandon.paupore@sandisk.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/cleanup.h"
#include "util/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "sandisk-nvme.h"
#include "sandisk-utils.h"
#include "plugins/wdc/wdc-nvme-cmds.h"

static __u8 ocp_C2_guid[SNDK_GUID_LENGTH] = {
	0x6D, 0x79, 0x9A, 0x76, 0xB4, 0xDA, 0xF6, 0xA3,
	0xE2, 0x4D, 0xB2, 0x8A, 0xAC, 0xF3, 0x1C, 0xD1
};

static int sndk_do_cap_telemetry_log(struct nvme_global_ctx *ctx,
				     struct nvme_transport_handle *hdl,
				     const char *file, __u32 bs, int type,
				     int data_area)
{
	struct nvme_telemetry_log *log;
	size_t full_size = 0;
	int err = 0, output;
	__u32 host_gen = 1;
	int ctrl_init = 0;
	__u8 *data_ptr = NULL;
	int data_written = 0, data_remaining = 0;
	struct nvme_id_ctrl ctrl;
	__u64 capabilities = 0;
	bool host_behavior_changed = false;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err) {
		fprintf(stderr, "ERROR: WDC: nvme_identify_ctrl() failed 0x%x\n", err);
		return err;
	}

	if (!(ctrl.lpa & 0x8)) {
		fprintf(stderr, "Telemetry log pages not supported by device\n");
		return -EINVAL;
	}

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err)
		return err;
	capabilities = sndk_get_drive_capabilities(ctx, hdl);

	if (data_area == 4) {
		if (!(ctrl.lpa & 0x40)) {
			fprintf(stderr, "%s: Telemetry data area 4 not supported by device\n",
				__func__);
			return -EINVAL;
		}

		err = nvme_set_etdas(hdl, &host_behavior_changed);
		if (err) {
			fprintf(stderr, "%s: Failed to set ETDAS bit\n", __func__);
			return err;
		}
	}

	if (type == SNDK_TELEMETRY_TYPE_HOST) {
		host_gen = 1;
		ctrl_init = 0;
	} else if (type == SNDK_TELEMETRY_TYPE_CONTROLLER) {
		if (capabilities & SNDK_DRIVE_CAP_INTERNAL_LOG) {
			err = sndk_check_ctrl_telemetry_option_disabled(hdl);
			if (err)
				return err;
		}
		host_gen = 0;
		ctrl_init = 1;
	} else {
		fprintf(stderr, "%s: Invalid type parameter; type = %d\n", __func__, type);
		return -EINVAL;
	}

	if (!file) {
		fprintf(stderr, "%s: Please provide an output file!\n", __func__);
		return -EINVAL;
	}

	output = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "%s: Failed to open output file %s: %s!\n",
				__func__, file, strerror(errno));
		return output;
	}

	if (ctrl_init)
		err = nvme_get_ctrl_telemetry(hdl, true, &log,
					  data_area, &full_size);
	else if (host_gen)
		err = nvme_get_new_host_telemetry(hdl, &log,
						  data_area, &full_size);
	else
		err = nvme_get_host_telemetry(hdl, &log, data_area,
					  &full_size);

	if (err < 0) {
		perror("get-telemetry-log");
		goto close_output;
	} else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "%s: Failed to acquire telemetry header!\n", __func__);
		goto close_output;
	}

	/*
	 *Continuously pull data until the offset hits the end of the last
	 *block.
	 */
	data_written = 0;
	data_remaining = full_size;
	data_ptr = (__u8 *)log;

	while (data_remaining) {
		data_written = write(output, data_ptr, data_remaining);

		if (data_written < 0) {
			data_remaining = data_written;
			break;
		} else if (data_written <= data_remaining) {
			data_remaining -= data_written;
			data_ptr += data_written;
		} else {
			/* Unexpected overwrite */
			fprintf(stderr, "Failure: Unexpected telemetry log overwrite\n" \
				"- data_remaining = 0x%x, data_written = 0x%x\n",
				data_remaining, data_written);
			break;
		}
	}

	if (fsync(output) < 0) {
		fprintf(stderr, "ERROR: %s: fsync: %s\n", __func__, strerror(errno));
		err = -1;
	}

	if (host_behavior_changed) {
		host_behavior_changed = false;
		err = nvme_clear_etdas(hdl, &host_behavior_changed);
		if (err) {
			fprintf(stderr, "%s: Failed to clear ETDAS bit\n", __func__);
			return err;
		}
	}

	free(log);
close_output:
	close(output);
	return err;
}

static __u32 sndk_dump_udui_data(struct nvme_transport_handle *hdl,
				 __u32 dataLen, __u32 offset, __u8 *dump_data)
{
	int ret;
	struct nvme_passthru_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof(struct nvme_passthru_cmd));
	admin_cmd.opcode = SNDK_NVME_CAP_UDUI_OPCODE;
	admin_cmd.nsid = 0xFFFFFFFF;
	admin_cmd.addr = (__u64)(uintptr_t)dump_data;
	admin_cmd.data_len = dataLen;
	admin_cmd.cdw10 = ((dataLen >> 2) - 1);
	admin_cmd.cdw12 = offset;
	ret = nvme_submit_admin_passthru(hdl, &admin_cmd);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: reading DUI data failed\n");
		nvme_show_status(ret);
	}

	return ret;
}

static int sndk_do_cap_udui(struct nvme_transport_handle *hdl, char *file,
			    __u32 xfer_size, int verbose, __u64 file_size,
			    __u64 offset)
{
	int ret = 0;
	int output;
	ssize_t written = 0;
	struct nvme_telemetry_log *log;
	__u32 udui_log_hdr_size = sizeof(struct nvme_telemetry_log);
	__u32 chunk_size = xfer_size;
	__u64 total_size;

	log = (struct nvme_telemetry_log *)malloc(udui_log_hdr_size);
	if (!log) {
		fprintf(stderr,
			"%s: ERROR: log header malloc failed : status %s, size 0x%x\n",
			__func__, strerror(errno), udui_log_hdr_size);
		return -1;
	}
	memset(log, 0, udui_log_hdr_size);

	/* get the udui telemetry and log headers */
	ret = sndk_dump_udui_data(hdl, udui_log_hdr_size, 0, (__u8 *)log);
	if (ret) {
		fprintf(stderr, "%s: ERROR: SNDK: Get UDUI header failed\n", __func__);
		nvme_show_status(ret);
		goto out;
	}

	total_size = (le32_to_cpu(log->dalb4) + 1) * 512;
	if (offset > total_size) {
		fprintf(stderr, "%s: ERROR: SNDK: offset larger than log length = 0x%"PRIx64"\n",
			__func__, (uint64_t)total_size);
		goto out;
	}

	if (file_size && (total_size - offset) > file_size)
		total_size = offset + file_size;

	log = (struct nvme_telemetry_log *)realloc(log, chunk_size);

	output = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "%s: Failed to open output file %s: %s!\n", __func__, file,
			strerror(errno));
		goto out;
	}

	while (offset < total_size) {
		if (chunk_size > total_size - offset)
			chunk_size = total_size - offset;
		ret = sndk_dump_udui_data(hdl, chunk_size, offset,
					  ((__u8 *)log));
		if (ret) {
			fprintf(stderr,
				"%s: ERROR: Get UDUI failed, offset = 0x%"PRIx64", size = %u\n",
				__func__, (uint64_t)offset, chunk_size);
			break;
		}

		/* write the dump data into the file */
		written = write(output, (void *)log, chunk_size);
		if (written != chunk_size) {
			fprintf(stderr,
				"%s: ERROR: SNDK: Failed to flush DUI data to file!\n" \
				"- written = %zd, offset = 0x%"PRIx64", chunk_size = %u\n",
				__func__, written, (uint64_t)offset, chunk_size);
			ret = errno;
			break;
		}

		offset += chunk_size;
	}

	close(output);
	nvme_show_status(ret);
	if (verbose)
		fprintf(stderr,
			"INFO: SNDK: Capture Device Unit Info log length = 0x%"PRIx64"\n",
			(uint64_t)total_size);

out:
	free(log);
	return ret;
}

static int sndk_get_default_telemetry_da(struct nvme_transport_handle *hdl,
					 int *data_area)
{
	struct nvme_id_ctrl ctrl;
	int err;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err) {
		fprintf(stderr, "ERROR: SNDK: nvme_identify_ctrl() failed 0x%x\n", err);
		return err;
	}

	if (ctrl.lpa & 0x40)
		*data_area = 4;
	else
		*data_area = 3;

	return 0;
}

static int sndk_vs_internal_fw_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Internal Firmware Log.";
	const char *file = "Output file pathname.";
	const char *size = "Data retrieval transfer size.";
	const char *data_area =
		"Data area to retrieve up to. Supported for telemetry, see man page for other use cases.";
	const char *file_size =
		"Output file size. Deprecated, see man page for supported devices.";
	const char *offset =
		"Output file data offset. Deprecated, see man page for supported devices.";
	const char *type =
		"Telemetry type - NONE, HOST, or CONTROLLER:\n" \
		"  NONE - Default, capture without using NVMe telemetry.\n" \
		"  HOST - Host-initiated telemetry.\n" \
		"  CONTROLLER - Controller-initiated telemetry.";
	char f[PATH_MAX] = {0};
	char fileSuffix[PATH_MAX] = {0};
	__u32 xfer_size = 0;
	int telemetry_type = 0, telemetry_data_area = 0;
	struct SNDK_UtilsTimeInfo timeInfo;
	__u8 timeStamp[SNDK_MAX_PATH_LEN];
	__u64 capabilities = 0;
	__u32 device_id, read_vendor_id;
	int ret = -1;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	struct config {
		char *file;
		__u32 xfer_size;
		int data_area;
		__u64 file_size;
		__u64 offset;
		char *type;
	};

	struct config cfg = {
		.file = NULL,
		.xfer_size = 0x10000,
		.data_area = 0,
		.file_size = 0,
		.offset = 0,
		.type = NULL,
	};

	NVME_ARGS(opts,
		OPT_FILE("output-file",   'o', &cfg.file,      file),
		OPT_UINT("transfer-size", 's', &cfg.xfer_size, size),
		OPT_UINT("data-area",     'd', &cfg.data_area, data_area),
		OPT_LONG("file-size",     'f', &cfg.file_size, file_size),
		OPT_LONG("offset",        'e', &cfg.offset,    offset),
		OPT_FILE("type",          't', &cfg.type,      type));

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret || !sndk_check_device(ctx, hdl))
		goto out;

	if (cfg.xfer_size) {
		xfer_size = cfg.xfer_size;
	} else {
		fprintf(stderr, "ERROR: SNDK: Invalid length\n");
		goto out;
	}

	ret = sndk_get_pci_ids(ctx, hdl, &device_id, &read_vendor_id);

	if (cfg.file) {
		int verify_file;

		/* verify file name and path is valid before getting dump data */
		verify_file = open(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (verify_file < 0) {
			fprintf(stderr, "ERROR: SNDK: open: %s\n", strerror(errno));
			goto out;
		}
		close(verify_file);
		strncpy(f, cfg.file, PATH_MAX - 1);
	} else {
		sndk_UtilsGetTime(&timeInfo);
		memset(timeStamp, 0, sizeof(timeStamp));
		sndk_UtilsSnprintf((char *)timeStamp, SNDK_MAX_PATH_LEN,
			"%02u%02u%02u_%02u%02u%02u", timeInfo.year,
			timeInfo.month, timeInfo.dayOfMonth,
			timeInfo.hour, timeInfo.minute,
			timeInfo.second);
		snprintf(fileSuffix, PATH_MAX, "_internal_fw_log_%s", (char *)timeStamp);

		ret = sndk_get_serial_name(hdl, f, PATH_MAX, fileSuffix);
		if (ret) {
			fprintf(stderr, "ERROR: SNDK: failed to generate file name\n");
			goto out;
		}
	}

	if (!cfg.file) {
		if (strlen(f) > PATH_MAX - 5) {
			fprintf(stderr, "ERROR: SNDK: file name overflow\n");
			ret = -1;
			goto out;
		}
		strcat(f, ".bin");
	}
	fprintf(stderr, "%s: filename = %s\n", __func__, f);

	if (cfg.data_area) {
		if (cfg.data_area > 5 || cfg.data_area < 1) {
			fprintf(stderr, "ERROR: SNDK: Data area must be 1-5\n");
			ret = -1;
			goto out;
		}
	}

	if (!cfg.type || !strcmp(cfg.type, "NONE") || !strcmp(cfg.type, "none")) {
		telemetry_type = SNDK_TELEMETRY_TYPE_NONE;
		data_area = 0;
	} else if (!strcmp(cfg.type, "HOST") || !strcmp(cfg.type, "host")) {
		telemetry_type = SNDK_TELEMETRY_TYPE_HOST;
		telemetry_data_area = cfg.data_area;
	} else if (!strcmp(cfg.type, "CONTROLLER") || !strcmp(cfg.type, "controller")) {
		telemetry_type = SNDK_TELEMETRY_TYPE_CONTROLLER;
		telemetry_data_area = cfg.data_area;
	} else {
		fprintf(stderr,
			"ERROR: SNDK: Invalid type - Must be NONE, HOST or CONTROLLER\n");
		ret = -1;
		goto out;
	}

	capabilities = sndk_get_drive_capabilities(ctx, hdl);

	/* Supported through WDC plugin for non-telemetry */
	if ((capabilities & SNDK_DRIVE_CAP_INTERNAL_LOG) &&
	    (telemetry_type != SNDK_TELEMETRY_TYPE_NONE)) {
		if (sndk_get_default_telemetry_da(hdl, &telemetry_data_area)) {
			fprintf(stderr, "%s: Error determining default telemetry data area\n",
				__func__);
			return -EINVAL;
		}

		ret = sndk_do_cap_telemetry_log(ctx, hdl, f, xfer_size,
				telemetry_type, telemetry_data_area);
		goto out;
	}

	if (capabilities & SNDK_DRIVE_CAP_UDUI) {
		if ((telemetry_type == SNDK_TELEMETRY_TYPE_HOST) ||
		    (telemetry_type == SNDK_TELEMETRY_TYPE_CONTROLLER)) {
			if (sndk_get_default_telemetry_da(hdl, &telemetry_data_area)) {
				fprintf(stderr, "%s: Error determining default telemetry data area\n",
					__func__);
				return -EINVAL;
			}

			ret = sndk_do_cap_telemetry_log(ctx, hdl, f, xfer_size,
					telemetry_type, telemetry_data_area);
			goto out;
		} else {
			ret = sndk_do_cap_udui(hdl, f, xfer_size,
					 nvme_args.verbose, cfg.file_size,
					 cfg.offset);
			goto out;
		}
	}

	/* Fallback to WDC plugin if otherwise not supported */
	return run_wdc_vs_internal_fw_log(argc, argv, command, plugin);

out:
	return ret;
}

static int sndk_vs_nand_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_nand_stats(argc, argv, command, plugin);
}

static int sndk_vs_smart_add_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_smart_add_log(argc, argv, command, plugin);
}

static int sndk_clear_pcie_correctable_errors(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_clear_pcie_correctable_errors(argc, argv, command, plugin);
}

static int sndk_drive_status(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_drive_status(argc, argv, command, plugin);
}

static int sndk_clear_assert_dump(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_clear_assert_dump(argc, argv, command, plugin);
}

#define SNDK_NVME_SN861_DRIVE_RESIZE_OPCODE  0xD1
#define SNDK_NVME_SN861_DRIVE_RESIZE_BUFFER_SIZE  0x1000

static int sndk_do_sn861_drive_resize(struct nvme_transport_handle *hdl,
		uint64_t new_size,
		__u64 *result)
{
	uint8_t buffer[SNDK_NVME_SN861_DRIVE_RESIZE_BUFFER_SIZE] = {0};
	struct nvme_passthru_cmd admin_cmd;
	int ret;

	memset(&admin_cmd, 0, sizeof(struct nvme_passthru_cmd));
	admin_cmd.opcode = SNDK_NVME_SN861_DRIVE_RESIZE_OPCODE;
	admin_cmd.cdw10 = 0x00000040;
	admin_cmd.cdw12 = 0x00000103;
	admin_cmd.cdw13 = 0x00000001;

	memcpy(buffer, &new_size, sizeof(new_size));
	admin_cmd.addr = (__u64)(uintptr_t)buffer;
	admin_cmd.data_len = SNDK_NVME_SN861_DRIVE_RESIZE_BUFFER_SIZE;

	ret = nvme_submit_admin_passthru(hdl, &admin_cmd);
	if (result)
		*result = admin_cmd.result;
	return ret;
}

static int sndk_drive_resize(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Send a Resize command.";
	const char *size = "The new size (in GB) to resize the drive to.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	uint64_t capabilities = 0;
	int ret;
	uint32_t device_id = -1, vendor_id = -1;
	__u64 result;

	struct config {
		uint64_t size;
	};

	struct config cfg = {
		.size = 0,
	};

	NVME_ARGS(opts,
		OPT_UINT("size", 's', &cfg.size, size));

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret)
		return ret;
	sndk_check_device(ctx, hdl);
	capabilities = sndk_get_drive_capabilities(ctx, hdl);
	ret = sndk_get_pci_ids(ctx, hdl, &device_id, &vendor_id);

	if ((capabilities & SNDK_DRIVE_CAP_RESIZE_SN861) == SNDK_DRIVE_CAP_RESIZE_SN861) {
		ret = sndk_do_sn861_drive_resize(hdl, cfg.size, &result);

		if (!ret) {
			fprintf(stderr, "The drive-resize command was successful.  A system ");
			fprintf(stderr, "shutdown is required to complete the operation.\n");
		} else
			fprintf(stderr, "ERROR: SNDK: %s failure, ret: %d, result: 0x%"PRIx64"\n",
					__func__, ret, (uint64_t)result);
	} else {
		/* Fallback to WDC plugin command if otherwise not supported */
		return run_wdc_drive_resize(argc, argv, command, plugin);
	}

	nvme_show_status(ret);
	return ret;
}

static void sndk_print_fw_act_history_log_normal(__u8 *data, int num_entries)
{
	int i, j;
	char previous_fw[9];
	char new_fw[9];
	char commit_action_bin[8];
	char time_str[100];
	__u16 oldestEntryIdx = 0, entryIdx = 0;
	uint64_t timestamp;
	int fw_vers_len = 0;
	const char *null_fw = "--------";

	memset((void *)time_str, '\0', 100);

	if (data[0] == SNDK_NVME_GET_FW_ACT_HISTORY_C2_LOG_ID) {
		printf("  Firmware Activate History Log\n");
		printf("                               Power Cycle     ");
		printf("Previous    New\n");
		printf("  Entry      Timestamp            Count        ");
		printf("Firmware    Firmware    Slot   Action  Result\n");
		printf("  -----  -----------------  -----------------  ");
		printf("---------   ---------   -----  ------  -------\n");

		struct sndk_fw_act_history_log_format_c2 *fw_act_hist_log =
			(struct sndk_fw_act_history_log_format_c2 *)(data);

		oldestEntryIdx = SNDK_MAX_NUM_ACT_HIST_ENTRIES;
		if (num_entries == SNDK_MAX_NUM_ACT_HIST_ENTRIES) {
			/* find lowest/oldest entry */
			for (i = 0; i < num_entries; i++) {
				j = (i+1 == SNDK_MAX_NUM_ACT_HIST_ENTRIES) ? 0 : i+1;
				if (le16_to_cpu(
						fw_act_hist_log->entry[i].fw_act_hist_entries) >
					le16_to_cpu(
						fw_act_hist_log->entry[j].fw_act_hist_entries)) {
					oldestEntryIdx = j;
					break;
				}
			}
		}
		if (oldestEntryIdx == SNDK_MAX_NUM_ACT_HIST_ENTRIES)
			entryIdx = 0;
		else
			entryIdx = oldestEntryIdx;

		for (i = 0; i < num_entries; i++) {
			memset((void *)previous_fw, 0, 9);
			memset((void *)new_fw, 0, 9);
			memset((void *)commit_action_bin, 0, 8);

			memcpy(previous_fw,
				(char *)&
					(fw_act_hist_log->entry[entryIdx].previous_fw_version),
				8);
			fw_vers_len = strlen((char *)
				&(fw_act_hist_log->entry[entryIdx].current_fw_version));
			if (fw_vers_len > 1)
				memcpy(new_fw,
					(char *)&
					(fw_act_hist_log->entry[entryIdx].current_fw_version),
					8);
			else
				memcpy(new_fw, null_fw, 8);

			printf("%5"PRIu16"",
				(uint16_t)le16_to_cpu(
					fw_act_hist_log->entry[entryIdx].fw_act_hist_entries));

			timestamp = (0x0000FFFFFFFFFFFF &
				le64_to_cpu(
					fw_act_hist_log->entry[entryIdx].timestamp));
			printf("   ");
			printf("%16"PRIu64"", timestamp);
			printf("   ");

			printf("%16"PRIu64"",
				(uint64_t)le64_to_cpu(
					fw_act_hist_log->entry[entryIdx].power_cycle_count));
			printf("     ");
			printf("%s", (char *)previous_fw);
			printf("    ");
			printf("%s", (char *)new_fw);
			printf("     ");
			printf("%2"PRIu8"",
				(uint8_t)fw_act_hist_log->entry[entryIdx].slot_number);
			printf("   ");
			sndk_get_commit_action_bin(
			    fw_act_hist_log->entry[entryIdx].commit_action_type,
			    (char *)&commit_action_bin);
			printf("  %s", (char *)commit_action_bin);
			printf("  ");
			if (!le16_to_cpu(fw_act_hist_log->entry[entryIdx].result))
				printf("pass");
			else
				printf("fail #%d",
					(uint16_t)le16_to_cpu(
						fw_act_hist_log->entry[entryIdx].result));
			printf("\n");

			entryIdx++;
			if (entryIdx >= SNDK_MAX_NUM_ACT_HIST_ENTRIES)
				entryIdx = 0;
		}
	} else
		fprintf(stderr, "ERROR: SNDK: %s: Unknown log page\n", __func__);
}

static void sndk_print_fw_act_history_log_json(__u8 *data, int num_entries)
{
	struct json_object *root = json_create_object();
	int i, j;
	char previous_fw[9];
	char new_fw[9];
	char commit_action_bin[8];
	char fail_str[32];
	char time_str[100];
	char ext_time_str[20];
	uint64_t timestamp;
	int fw_vers_len = 0;

	memset((void *)previous_fw, 0, 9);
	memset((void *)new_fw, 0, 9);
	memset((void *)commit_action_bin, 0, 8);
	memset((void *)time_str, '\0', 100);
	memset((void *)ext_time_str, 0, 20);
	memset((void *)fail_str, 0, 11);
	char *null_fw = "--------";
	__u16 oldestEntryIdx = 0, entryIdx = 0;

	if (data[0] == SNDK_NVME_GET_FW_ACT_HISTORY_C2_LOG_ID) {
		struct sndk_fw_act_history_log_format_c2 *fw_act_hist_log =
			(struct sndk_fw_act_history_log_format_c2 *)(data);

		oldestEntryIdx = SNDK_MAX_NUM_ACT_HIST_ENTRIES;
		if (num_entries == SNDK_MAX_NUM_ACT_HIST_ENTRIES) {
			/* find lowest/oldest entry */
			for (i = 0; i < num_entries; i++) {
				j = (i+1 == SNDK_MAX_NUM_ACT_HIST_ENTRIES) ? 0 : i+1;
				if (le16_to_cpu(
						fw_act_hist_log->entry[i].fw_act_hist_entries) >
					le16_to_cpu(
						fw_act_hist_log->entry[j].fw_act_hist_entries)) {
					oldestEntryIdx = j;
					break;
				}
			}
		}
		if (oldestEntryIdx == SNDK_MAX_NUM_ACT_HIST_ENTRIES)
			entryIdx = 0;
		else
			entryIdx = oldestEntryIdx;

		for (i = 0; i < num_entries; i++) {
			memcpy(previous_fw,
				(char *)&
				(fw_act_hist_log->entry[entryIdx].previous_fw_version),
				8);
			fw_vers_len = strlen((char *)
				&(fw_act_hist_log->entry[entryIdx].current_fw_version));
			if (fw_vers_len > 1)
				memcpy(new_fw,
					(char *)&
					(fw_act_hist_log->entry[entryIdx].current_fw_version),
					8);
			else
				memcpy(new_fw, null_fw, 8);

			json_object_add_value_int(root, "Entry",
			    le16_to_cpu(fw_act_hist_log->entry[entryIdx].fw_act_hist_entries));

			timestamp = (0x0000FFFFFFFFFFFF &
				le64_to_cpu(
					fw_act_hist_log->entry[entryIdx].timestamp));
			json_object_add_value_uint64(root, "Timestamp", timestamp);

			json_object_add_value_int(root, "Power Cycle Count",
				le64_to_cpu(
					fw_act_hist_log->entry[entryIdx].power_cycle_count));
			json_object_add_value_string(root, "Previous Firmware",
					previous_fw);
			json_object_add_value_string(root, "New Firmware",
					new_fw);
			json_object_add_value_int(root, "Slot",
				fw_act_hist_log->entry[entryIdx].slot_number);

			sndk_get_commit_action_bin(
			    fw_act_hist_log->entry[entryIdx].commit_action_type,
			    (char *)&commit_action_bin);
			json_object_add_value_string(root, "Action", commit_action_bin);

			if (!le16_to_cpu(fw_act_hist_log->entry[entryIdx].result)) {
				json_object_add_value_string(root, "Result", "pass");
			} else {
				sprintf((char *)fail_str, "fail #%d",
					(int)(le16_to_cpu(
						fw_act_hist_log->entry[entryIdx].result)));
				json_object_add_value_string(root, "Result", fail_str);
			}

			json_print_object(root, NULL);
			printf("\n");

			entryIdx++;
			if (entryIdx >= SNDK_MAX_NUM_ACT_HIST_ENTRIES)
				entryIdx = 0;
		}
	} else
		fprintf(stderr, "ERROR: SNDK: %s: Unknown log page\n", __func__);

	json_free_object(root);
}

static int sndk_print_fw_act_history_log(__u8 *data, int num_entries, int fmt)
{
	if (!data) {
		fprintf(stderr, "ERROR: SNDK: Invalid buffer in print_fw act_history_log\n");
		return -1;
	}

	switch (fmt) {
	case NORMAL:
		sndk_print_fw_act_history_log_normal(data, num_entries);
		break;
	case JSON:
		sndk_print_fw_act_history_log_json(data, num_entries);
		break;
	}
	return 0;
}

static int sndk_get_fw_act_history_C2(struct nvme_global_ctx *ctx, struct nvme_transport_handle *hdl,
				     char *format)
{
	struct sndk_fw_act_history_log_format_c2 *fw_act_history_log;
	__u32 tot_entries = 0, num_entries = 0;
	nvme_print_flags_t fmt;
	__u8 *data;
	int ret;
	bool c2GuidMatch = false;

	if (!sndk_check_device(ctx, hdl))
		return -1;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR: SNDK: invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * SNDK_FW_ACT_HISTORY_C2_LOG_BUF_LEN);
	if (!data) {
		fprintf(stderr, "ERROR: SNDK: malloc: %s\n", strerror(errno));
		return -1;
	}

	memset(data, 0, sizeof(__u8) * SNDK_FW_ACT_HISTORY_C2_LOG_BUF_LEN);

	ret = nvme_get_log_simple(hdl,
				  SNDK_NVME_GET_FW_ACT_HISTORY_C2_LOG_ID,
				  data, SNDK_FW_ACT_HISTORY_C2_LOG_BUF_LEN);

	if (strcmp(format, "json"))
		nvme_show_status(ret);

	if (!ret) {
		/* Get the log page data and verify the GUID */
		fw_act_history_log = (struct sndk_fw_act_history_log_format_c2 *)(data);

		c2GuidMatch = !memcmp(ocp_C2_guid,
				fw_act_history_log->log_page_guid,
				SNDK_GUID_LENGTH);

		if (c2GuidMatch) {
			/* parse the data */
			tot_entries = le32_to_cpu(fw_act_history_log->num_entries);

			if (tot_entries > 0) {
				num_entries = (tot_entries < SNDK_MAX_NUM_ACT_HIST_ENTRIES) ?
						tot_entries : SNDK_MAX_NUM_ACT_HIST_ENTRIES;
				ret = sndk_print_fw_act_history_log(data, num_entries,
					fmt);
			} else  {
				fprintf(stderr, "INFO: SNDK: No entries found.\n");
				ret = 0;
			}
		} else {
			fprintf(stderr, "ERROR: SNDK: Invalid C2 log page GUID\n");
			ret = -1;
		}
	} else {
		fprintf(stderr, "ERROR: SNDK: Unable to read FW Activate History Log Page data\n");
		ret = -1;
	}

	free(data);
	return ret;
}


static int sndk_vs_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Retrieve FW activate history table.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	uint64_t capabilities = 0;
	int ret;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	NVME_ARGS(opts);

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret)
		return ret;
	capabilities = sndk_get_drive_capabilities(ctx, hdl);

	if (capabilities & SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2) {
		ret = sndk_get_fw_act_history_C2(ctx, hdl, cfg.output_format);

		if (ret) {
			fprintf(stderr, "ERROR: SNDK: Failure reading the FW ");
			fprintf(stderr, "Activate History, ret = %d\n", ret);
		}
	} else
		/* Fall back to the wdc plugin command */
		ret = run_wdc_vs_fw_activate_history(argc, argv, command, plugin);

	return ret;
}

static int sndk_do_clear_fw_activate_history_fid(struct nvme_transport_handle *hdl)
{
	int ret = -1;
	__u64 result;
	__u32 value = 1 << 31; /* Bit 31 - Clear Firmware Update History Log */

	ret = nvme_set_features_simple(hdl, SNDK_NVME_CLEAR_FW_ACT_HIST_VU_FID, 0, value,
				false, &result);

	nvme_show_status(ret);
	return ret;
}

static int sndk_clear_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Clear FW activate history table.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u64 capabilities = 0;
	int ret;

	NVME_ARGS(opts);

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret)
		return ret;
 	capabilities = sndk_get_drive_capabilities(ctx, hdl);

	if (capabilities & SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY) {
		ret = sndk_do_clear_fw_activate_history_fid(hdl);

		if (ret) {
			fprintf(stderr, "ERROR: SNDK: Failure clearing the FW ");
			fprintf(stderr, "Activate History, ret = %d\n", ret);
		}
	} else
		/* Fall back to the wdc plugin command */
		ret = run_wdc_clear_fw_activate_history(argc, argv, command, plugin);

	return ret;
}

static int sndk_vs_telemetry_controller_option(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_telemetry_controller_option(argc, argv, command, plugin);
}

static int sndk_reason_identifier(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_reason_identifier(argc, argv, command, plugin);
}

static int sndk_log_page_directory(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_log_page_directory(argc, argv, command, plugin);
}

static int sndk_namespace_resize(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_namespace_resize(argc, argv, command, plugin);
}

static int sndk_vs_drive_info(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_drive_info(argc, argv, command, plugin);
}

static int sndk_capabilities(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Send a capabilities command.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	uint64_t capabilities = 0;
	int ret;

	NVME_ARGS(opts);

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	/* get capabilities */
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret || !sndk_check_device(ctx, hdl))
		return -1;

	capabilities = sndk_get_drive_capabilities(ctx, hdl);

	/* print command and supported status */
	printf("Sandisk Plugin Capabilities for NVME device:%s\n", nvme_transport_handle_get_name(hdl));
	printf("vs-internal-log               : %s\n",
	       capabilities & SNDK_DRIVE_CAP_INTERNAL_LOG_MASK ? "Supported" : "Not Supported");
	printf("vs-nand-stats                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_NAND_STATS ? "Supported" : "Not Supported");
	printf("vs-smart-add-log              : %s\n",
	       capabilities & SNDK_DRIVE_CAP_SMART_LOG_MASK ? "Supported" : "Not Supported");
	printf("--C0 Log Page                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_C0_LOG_PAGE ? "Supported" : "Not Supported");
	printf("--C1 Log Page                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_C1_LOG_PAGE ? "Supported" : "Not Supported");
	printf("--C3 Log Page                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_C3_LOG_PAGE ? "Supported" : "Not Supported");
	printf("--CA Log Page                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CA_LOG_PAGE ? "Supported" : "Not Supported");
	printf("--D0 Log Page                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_D0_LOG_PAGE ? "Supported" : "Not Supported");
	printf("clear-pcie-correctable-errors : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLEAR_PCIE_MASK ? "Supported" : "Not Supported");
	printf("get-drive-status              : %s\n",
	       capabilities & SNDK_DRIVE_CAP_DRIVE_STATUS ? "Supported" : "Not Supported");
	printf("clear-assert-dump             : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLEAR_ASSERT ? "Supported" : "Not Supported");
	printf("drive-resize                  : %s\n",
	       capabilities & SNDK_DRIVE_CAP_RESIZE_MASK ? "Supported" : "Not Supported");
	printf("vs-fw-activate-history        : %s\n",
	       capabilities & SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_MASK ? "Supported" :
	       "Not Supported");
	printf("clear-fw-activate-history     : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY_MASK ? "Supported" :
	       "Not Supported");
	printf("vs-telemetry-controller-option: %s\n",
	       capabilities & SNDK_DRIVE_CAP_DISABLE_CTLR_TELE_LOG ? "Supported" : "Not Supported");
	printf("vs-error-reason-identifier    : %s\n",
	       capabilities & SNDK_DRIVE_CAP_REASON_ID ? "Supported" : "Not Supported");
	printf("log-page-directory            : %s\n",
	       capabilities & SNDK_DRIVE_CAP_LOG_PAGE_DIR ? "Supported" : "Not Supported");
	printf("namespace-resize              : %s\n",
	       capabilities & SNDK_DRIVE_CAP_NS_RESIZE ? "Supported" : "Not Supported");
	printf("vs-drive-info                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_INFO ? "Supported" : "Not Supported");
	printf("vs-temperature-stats          : %s\n",
	       capabilities & SNDK_DRIVE_CAP_TEMP_STATS ? "Supported" : "Not Supported");
	printf("cloud-SSD-plugin-version      : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLOUD_SSD_VERSION ? "Supported" : "Not Supported");
	printf("vs-pcie-stats                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_PCIE_STATS ? "Supported" : "Not Supported");
	printf("get-error-recovery-log        : %s\n",
	       capabilities & SNDK_DRIVE_CAP_OCP_C1_LOG_PAGE ? "Supported" : "Not Supported");
	printf("get-dev-capabilities-log      : %s\n",
	       capabilities & SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE ? "Supported" : "Not Supported");
	printf("get-unsupported-reqs-log      : %s\n",
	       capabilities & SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE ? "Supported" : "Not Supported");
	printf("get-latency-monitor-log       : %s\n",
	       capabilities & SNDK_DRIVE_CAP_C3_LOG_PAGE ? "Supported" : "Not Supported");
	printf("cloud-boot-SSD-version        : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLOUD_BOOT_SSD_VERSION ? "Supported" :
	       "Not Supported");
	printf("vs-cloud-log                  : %s\n",
	       capabilities & SNDK_DRIVE_CAP_CLOUD_LOG_PAGE ? "Supported" : "Not Supported");
	printf("vs-hw-rev-log                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_HW_REV_LOG_PAGE ? "Supported" : "Not Supported");
	printf("vs-device_waf                 : %s\n",
	       capabilities & SNDK_DRIVE_CAP_DEVICE_WAF ? "Supported" : "Not Supported");
	printf("set-latency-monitor-feature   : %s\n",
	       capabilities & SNDK_DRIVE_CAP_SET_LATENCY_MONITOR ? "Supported" : "Not Supported");
	printf("capabilities                  : Supported\n");

	return 0;
}

static int sndk_cloud_ssd_plugin_version(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_cloud_ssd_plugin_version(argc, argv, command, plugin);
}

static int sndk_vs_pcie_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_pcie_stats(argc, argv, command, plugin);
}

static int sndk_get_latency_monitor_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_get_latency_monitor_log(argc, argv, command, plugin);
}

static int sndk_get_error_recovery_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_get_error_recovery_log(argc, argv, command, plugin);
}

static int sndk_get_dev_capabilities_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_get_dev_capabilities_log(argc, argv, command, plugin);
}

static int sndk_get_unsupported_reqs_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_get_unsupported_reqs_log(argc, argv, command, plugin);
}

static int sndk_cloud_boot_SSD_version(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_cloud_boot_SSD_version(argc, argv, command, plugin);
}

static int sndk_vs_cloud_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_cloud_log(argc, argv, command, plugin);
}

static int sndk_vs_hw_rev_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_hw_rev_log(argc, argv, command, plugin);
}

static int sndk_vs_device_waf(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_device_waf(argc, argv, command, plugin);
}

static int sndk_set_latency_monitor_feature(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_set_latency_monitor_feature(argc, argv, command, plugin);
}

static int sndk_vs_temperature_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_temperature_stats(argc, argv, command, plugin);
}

static int sndk_cu_smart_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_cu_smart_log(argc, argv, command, plugin);
}
