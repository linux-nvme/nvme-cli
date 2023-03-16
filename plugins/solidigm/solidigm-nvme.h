// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/solidigm/solidigm-nvme

#if !defined(SOLIDIGM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SOLIDIGM_NVME

#include "cmd.h"

#define SOLIDIGM_PLUGIN_VERSION "0.10"

PLUGIN(NAME("solidigm", "Solidigm vendor specific extensions", SOLIDIGM_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Solidigm SMART Log", get_additional_smart_log)
		ENTRY("vs-smart-add-log", "Get SMART / health extended log (redirects to ocp plug-in)", smart_cloud)
		ENTRY("garbage-collect-log", "Retrieve Garbage Collection Log", get_garbage_collection_log)
		ENTRY("latency-tracking-log", "Enable/Retrieve Latency tracking Log", get_latency_tracking_log)
		ENTRY("parse-telemetry-log", "Parse Telemetry Log binary", get_telemetry_log)
		ENTRY("clear-fw-activate-history", "Clear firmware update history log (redirects to ocp plug-in)", clear_fw_update_history)
		ENTRY("vs-fw-activate-history", "Get firmware activation history log (redirects to ocp plug-in)", fw_activation_history)
	)
);

#endif

#include "define_cmd.h"
