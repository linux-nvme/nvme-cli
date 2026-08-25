// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <shared/compiler-attributes-util.h>

#include "plugin.h"

#define SOLIDIGM_PLUGIN_VERSION "1.24"

#include "plugins/ocp/ocp-clear-features.h"
#include "plugins/ocp/ocp-fw-activation-history.h"
#include "plugins/ocp/ocp-smart-extended-log.h"
#include "solidigm-garbage-collection.h"
#include "solidigm-get-drive-info.h"
#include "solidigm-id-ctrl.h"
#include "solidigm-internal-logs.h"
#include "solidigm-latency-tracking.h"
#include "solidigm-log-page-dir.h"
#include "solidigm-market-log.h"
#include "solidigm-ocp-version.h"
#include "solidigm-smart.h"
#include "solidigm-telemetry.h"
#include "solidigm-temp-stats.h"
#include "solidigm-workload-tracker.h"

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, sldgm_id_ctrl);
}

static int get_additional_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return solidigm_get_additional_smart_log(argc, argv, acmd, plugin);
}

static int get_internal_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return solidigm_get_internal_log(argc, argv, acmd, plugin);
}

static int get_garbage_collection_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return solidigm_get_garbage_collection_log(argc, argv, acmd, plugin);
}

static int get_latency_tracking_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return solidigm_get_latency_tracking_log(argc, argv, acmd, plugin);
}

static int get_telemetry_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return solidigm_get_telemetry_log(argc, argv, acmd, plugin);
}

static int clear_fw_update_history(int argc, char **argv, struct command *acmd,
				   struct plugin *plugin)
{
	return ocp_clear_fw_update_history(argc, argv, acmd, plugin);
}

static int clear_pcie_correctable_error_counters(int argc, char **argv, struct command *acmd,
						struct plugin *plugin)
{
	return ocp_clear_pcie_correctable_errors(argc, argv, acmd, plugin);
}

static int smart_cloud(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	return ocp_smart_add_log(argc, argv, acmd, plugin);
}

static int fw_activation_history(int argc, char **argv, struct command *acmd,
				 struct plugin *plugin)
{
	return ocp_fw_activation_history_log(argc, argv, acmd, plugin);
}

static int get_log_page_directory_log(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	return solidigm_get_log_page_directory_log(argc, argv, acmd, plugin);
}

static int get_market_log(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	return sldgm_get_market_log(argc, argv, acmd, plugin);
}

static int get_temp_stats_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return sldgm_get_temp_stats_log(argc, argv, acmd, plugin);
}

static int get_drive_info(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return sldgm_get_drive_info(argc, argv, acmd, plugin);
}

static int get_cloud_SSDplugin_version(int argc, char **argv, struct command *acmd,
				       struct plugin *plugin)
{
	return sldgm_ocp_version(argc, argv, acmd, plugin);
}

static int get_workload_tracker(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	return sldgm_get_workload_tracker(argc, argv, acmd, plugin);
}

static struct command id_ctrl_cmd = {
	.name = "id-ctrl",
	.help = "Send NVMe Identify Controller",
	.fn = id_ctrl,
};

static struct command get_additional_smart_log_cmd = {
	.name = "smart-log-add",
	.help = "Retrieve Solidigm SMART Log",
	.fn = get_additional_smart_log,
};

static struct command smart_cloud_cmd = {
	.name = "vs-smart-add-log",
	.help = "Get SMART / health extended log (redirects to ocp plug-in)",
	.fn = smart_cloud,
};

static struct command get_internal_log_cmd = {
	.name = "vs-internal-log",
	.help = "Retrieve Debug log binaries",
	.fn = get_internal_log,
};

static struct command get_garbage_collection_log_cmd = {
	.name = "garbage-collect-log",
	.help = "Retrieve Garbage Collection Log",
	.fn = get_garbage_collection_log,
};

static struct command get_market_log_cmd = {
	.name = "market-log",
	.help = "Retrieve Market Log",
	.fn = get_market_log,
};

static struct command get_latency_tracking_log_cmd = {
	.name = "latency-tracking-log",
	.help = "Enable/Retrieve Latency tracking Log",
	.fn = get_latency_tracking_log,
};

static struct command get_telemetry_log_cmd = {
	.name = "parse-telemetry-log",
	.help = "Parse Telemetry Log binary",
	.fn = get_telemetry_log,
};

static struct command clear_pcie_correctable_error_counters_cmd = {
	.name = "clear-pcie-correctable-errors",
	.help = "Clear PCIe Correctable Error Counters (redirects to ocp plug-in)",
	.fn = clear_pcie_correctable_error_counters,
};

static struct command clear_fw_update_history_cmd = {
	.name = "clear-fw-activate-history",
	.help = "Clear firmware update history log (redirects to ocp plug-in)",
	.fn = clear_fw_update_history,
};

static struct command fw_activation_history_cmd = {
	.name = "vs-fw-activate-history",
	.help = "Get firmware activation history log (redirects to ocp plug-in)",
	.fn = fw_activation_history,
};

static struct command get_log_page_directory_log_cmd = {
	.name = "log-page-directory",
	.help = "Retrieve log page directory",
	.fn = get_log_page_directory_log,
};

static struct command get_temp_stats_log_cmd = {
	.name = "temp-stats",
	.help = "Retrieve Temperature Statistics log",
	.fn = get_temp_stats_log,
};

static struct command get_drive_info_cmd = {
	.name = "vs-drive-info",
	.help = "Retrieve drive information",
	.fn = get_drive_info,
};

static struct command get_cloud_SSDplugin_version_cmd = {
	.name = "cloud-SSDplugin-version",
	.help = "Prints plug-in OCP version",
	.fn = get_cloud_SSDplugin_version,
	.no_device = true,
};

static struct command get_workload_tracker_cmd = {
	.name = "workload-tracker",
	.help = "Real Time capture Workload Tracker samples",
	.fn = get_workload_tracker,
};

static struct command *commands[] = {
	&id_ctrl_cmd,
	&get_additional_smart_log_cmd,
	&smart_cloud_cmd,
	&get_internal_log_cmd,
	&get_garbage_collection_log_cmd,
	&get_market_log_cmd,
	&get_latency_tracking_log_cmd,
	&get_telemetry_log_cmd,
	&clear_pcie_correctable_error_counters_cmd,
	&clear_fw_update_history_cmd,
	&fw_activation_history_cmd,
	&get_log_page_directory_log_cmd,
	&get_temp_stats_log_cmd,
	&get_drive_info_cmd,
	&get_cloud_SSDplugin_version_cmd,
	&get_workload_tracker_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "solidigm",
	.desc = "Solidigm vendor specific extensions",
	.version = SOLIDIGM_PLUGIN_VERSION,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
