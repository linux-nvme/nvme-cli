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


static int sndk_vs_internal_fw_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	return run_wdc_vs_internal_fw_log(argc, argv, command, plugin);
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
