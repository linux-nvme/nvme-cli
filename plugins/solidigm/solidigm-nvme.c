// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

#define CREATE_CMD
#include "solidigm-nvme.h"

#include "solidigm-id-ctrl.h"
#include "solidigm-smart.h"
#include "solidigm-internal-logs.h"
#include "solidigm-garbage-collection.h"
#include "solidigm-latency-tracking.h"
#include "solidigm-telemetry.h"
#include "solidigm-log-page-dir.h"
#include "solidigm-market-log.h"
#include "solidigm-temp-stats.h"
#include "solidigm-get-drive-info.h"
#include "solidigm-ocp-version.h"

#include "plugins/ocp/ocp-clear-features.h"
#include "plugins/ocp/ocp-smart-extended-log.h"
#include "plugins/ocp/ocp-fw-activation-history.h"

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, sldgm_id_ctrl);
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_additional_smart_log(argc, argv, cmd, plugin);
}

static int get_internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_internal_log(argc, argv, cmd, plugin);
}

static int get_garbage_collection_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_garbage_collection_log(argc, argv, cmd, plugin);
}

static int get_latency_tracking_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_latency_tracking_log(argc, argv, cmd, plugin);
}

static int get_telemetry_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_telemetry_log(argc, argv, cmd, plugin);
}

static int clear_fw_update_history(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	return ocp_clear_fw_update_history(argc, argv, cmd, plugin);
}

static int clear_pcie_correctable_error_counters(int argc, char **argv, struct command *cmd,
						struct plugin *plugin)
{
	return ocp_clear_pcie_correctable_errors(argc, argv, cmd, plugin);
}

static int smart_cloud(int argc, char **argv, struct command *cmd,
		       struct plugin *plugin)
{
	return ocp_smart_add_log(argc, argv, cmd, plugin);
}

static int fw_activation_history(int argc, char **argv, struct command *cmd,
				 struct plugin *plugin)
{
	return ocp_fw_activation_history_log(argc, argv, cmd, plugin);
}

static int get_log_page_directory_log(int argc, char **argv, struct command *cmd,
				      struct plugin *plugin)
{
	return solidigm_get_log_page_directory_log(argc, argv, cmd, plugin);
}

static int get_market_log(int argc, char **argv, struct command *cmd,
				      struct plugin *plugin)
{
	return sldgm_get_market_log(argc, argv, cmd, plugin);
}

static int get_temp_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sldgm_get_temp_stats_log(argc, argv, cmd, plugin);
}

static int get_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sldgm_get_drive_info(argc, argv, cmd, plugin);
}

static int get_cloud_SSDplugin_version(int argc, char **argv, struct command *cmd,
				       struct plugin *plugin)
{
	return sldgm_ocp_version(argc, argv, cmd, plugin);
}
