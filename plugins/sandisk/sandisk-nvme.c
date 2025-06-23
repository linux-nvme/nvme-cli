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

static int sndk_do_cap_telemetry_log(struct nvme_dev *dev, const char *file,
				     __u32 bs, int type, int data_area)
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
	nvme_root_t r;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err) {
		fprintf(stderr, "ERROR: WDC: nvme_identify_ctrl() failed 0x%x\n", err);
		return err;
	}

	if (!(ctrl.lpa & 0x8)) {
		fprintf(stderr, "Telemetry log pages not supported by device\n");
		return -EINVAL;
	}

	r = nvme_scan(NULL);
	capabilities = sndk_get_drive_capabilities(r, dev);

	if (type == SNDK_TELEMETRY_TYPE_HOST) {
		host_gen = 1;
		ctrl_init = 0;
	} else if (type == SNDK_TELEMETRY_TYPE_CONTROLLER) {
		if (capabilities & SNDK_DRIVE_CAP_INTERNAL_LOG) {
			err = sndk_check_ctrl_telemetry_option_disabled(dev);
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
		err = nvme_get_ctrl_telemetry(dev_fd(dev), true, &log,
					  data_area, &full_size);
	else if (host_gen)
		err = nvme_get_new_host_telemetry(dev_fd(dev), &log,
						  data_area, &full_size);
	else
		err = nvme_get_host_telemetry(dev_fd(dev), &log, data_area,
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

	free(log);
close_output:
	close(output);
	return err;
}

static __u32 sndk_dump_udui_data(int fd, __u32 dataLen, __u32 offset,
				 __u8 *dump_data)
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
	ret = nvme_submit_admin_passthru(fd, &admin_cmd, NULL);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: reading DUI data failed\n");
		nvme_show_status(ret);
	}

	return ret;
}

static int sndk_do_cap_udui(int fd, char *file, __u32 xfer_size, int verbose,
			    __u64 file_size, __u64 offset)
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
	ret = sndk_dump_udui_data(fd, udui_log_hdr_size, 0, (__u8 *)log);
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
		ret = sndk_dump_udui_data(fd, chunk_size, offset,
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

static int sndk_vs_internal_fw_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Internal Firmware Log.";
	const char *file = "Output file pathname.";
	const char *size = "Data retrieval transfer size.";
	const char *data_area =
		"Data area to retrieve up to. Currently only supported on the SN340, SN640, SN730, and SN840 devices.";
	const char *file_size = "Output file size. Currently only supported on the SN340 device.";
	const char *offset =
		"Output file data offset. Currently only supported on the SN340 device.";
	const char *type =
		"Telemetry type - NONE, HOST, or CONTROLLER Currently only supported on the SN530, SN640, SN730, SN740, SN810, SN840 and ZN350 devices.";
	const char *verbose = "Display more debug messages.";
	char f[PATH_MAX] = {0};
	char fileSuffix[PATH_MAX] = {0};
	struct nvme_dev *dev;
	nvme_root_t r;
	__u32 xfer_size = 0;
	int telemetry_type = 0, telemetry_data_area = 0;
	struct SNDK_UtilsTimeInfo timeInfo;
	__u8 timeStamp[SNDK_MAX_PATH_LEN];
	__u64 capabilities = 0;
	__u32 device_id, read_vendor_id;
	int ret = -1;

	struct config {
		char *file;
		__u32 xfer_size;
		int data_area;
		__u64 file_size;
		__u64 offset;
		char *type;
		bool verbose;
	};

	struct config cfg = {
		.file = NULL,
		.xfer_size = 0x10000,
		.data_area = 0,
		.file_size = 0,
		.offset = 0,
		.type = NULL,
		.verbose = false,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("output-file",   'o', &cfg.file,      file),
		OPT_UINT("transfer-size", 's', &cfg.xfer_size, size),
		OPT_UINT("data-area",     'd', &cfg.data_area, data_area),
		OPT_LONG("file-size",     'f', &cfg.file_size, file_size),
		OPT_LONG("offset",        'e', &cfg.offset,    offset),
		OPT_FILE("type",          't', &cfg.type,      type),
		OPT_FLAG("verbose",       'v', &cfg.verbose,   verbose),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	r = nvme_scan(NULL);
	if (!sndk_check_device(r, dev))
		goto out;

	if (cfg.xfer_size) {
		xfer_size = cfg.xfer_size;
	} else {
		fprintf(stderr, "ERROR: SNDK: Invalid length\n");
		goto out;
	}

	ret = sndk_get_pci_ids(r, dev, &device_id, &read_vendor_id);

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

		ret = sndk_get_serial_name(dev, f, PATH_MAX, fileSuffix);
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

	capabilities = sndk_get_drive_capabilities(r, dev);

	/* Supported through WDC plugin for non-telemetry */
	if ((capabilities & SNDK_DRIVE_CAP_INTERNAL_LOG) &&
	    (telemetry_type != SNDK_TELEMETRY_TYPE_NONE)) {
		/* Set the default DA to 3 if not specified */
		if (!telemetry_data_area)
			telemetry_data_area = 3;

		ret = sndk_do_cap_telemetry_log(dev, f, xfer_size,
				telemetry_type, telemetry_data_area);
		goto out;
	}

	if (capabilities & SNDK_DRIVE_CAP_UDUI) {
		if ((telemetry_type == SNDK_TELEMETRY_TYPE_HOST) ||
		    (telemetry_type == SNDK_TELEMETRY_TYPE_CONTROLLER)) {
			/* Set the default DA to 3 if not specified */
			if (!telemetry_data_area)
				telemetry_data_area = 3;

			ret = sndk_do_cap_telemetry_log(dev, f, xfer_size,
					telemetry_type, telemetry_data_area);
			goto out;
		} else {
			ret = sndk_do_cap_udui(dev_fd(dev), f, xfer_size,
					 cfg.verbose, cfg.file_size,
					 cfg.offset);
			goto out;
		}
	}

	/* Fallback to WDC plugin if otherwise not supported */
	nvme_free_tree(r);
	dev_close(dev);
	return run_wdc_vs_internal_fw_log(argc, argv, command, plugin);

out:
	nvme_free_tree(r);
	dev_close(dev);
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

static int sndk_drive_resize(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_drive_resize(argc, argv, command, plugin);
}

static int sndk_vs_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_fw_activate_history(argc, argv, command, plugin);
}

static int sndk_clear_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_clear_fw_activate_history(argc, argv, command, plugin);
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
	uint64_t capabilities = 0;
	struct nvme_dev *dev;
	nvme_root_t r;
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	/* get capabilities */
	r = nvme_scan(NULL);
	sndk_check_device(r, dev);
	capabilities = sndk_get_drive_capabilities(r, dev);

	/* print command and supported status */
	printf("Sandisk Plugin Capabilities for NVME device:%s\n", dev->name);
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
	       capabilities & SNDK_DRIVE_CAP_RESIZE ? "Supported" : "Not Supported");
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
	nvme_free_tree(r);
	dev_close(dev);

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
