// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

#define CREATE_CMD
#include "solidigm-nvme.h"

#include "solidigm-smart.h"
#include "solidigm-garbage-collection.h"
#include "solidigm-latency-tracking.h"
#include "solidigm-telemetry.h"

#include "plugins/ocp/ocp-clear-fw-update-history.h"
#include "plugins/ocp/ocp-smart-extended-log.h"
#include "plugins/ocp/ocp-fw-activation-history.h"

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return solidigm_get_additional_smart_log(argc, argv, cmd, plugin);
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
