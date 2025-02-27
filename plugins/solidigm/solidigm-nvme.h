// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/solidigm/solidigm-nvme

#if !defined(SOLIDIGM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SOLIDIGM_NVME

#include "cmd.h"

#define SOLIDIGM_PLUGIN_VERSION "1.12"

PLUGIN(NAME("solidigm", "Solidigm vendor specific extensions", SOLIDIGM_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
		ENTRY("smart-log-add", "Retrieve Solidigm SMART Log", get_additional_smart_log)
		ENTRY("vs-smart-add-log", "Get SMART / health extended log (redirects to ocp plug-in)", smart_cloud)
		ENTRY("vs-internal-log", "Retrieve Debug log binaries", get_internal_log)
		ENTRY("garbage-collect-log", "Retrieve Garbage Collection Log", get_garbage_collection_log)
		ENTRY("market-log", "Retrieve Market Log", get_market_log)
		ENTRY("latency-tracking-log", "Enable/Retrieve Latency tracking Log", get_latency_tracking_log)
		ENTRY("parse-telemetry-log", "Parse Telemetry Log binary", get_telemetry_log)
		ENTRY("clear-pcie-correctable-errors ", "Clear PCIe Correctable Error Counters (redirects to ocp plug-in)", clear_pcie_correctable_error_counters)
		ENTRY("clear-fw-activate-history", "Clear firmware update history log (redirects to ocp plug-in)", clear_fw_update_history)
		ENTRY("vs-fw-activate-history", "Get firmware activation history log (redirects to ocp plug-in)", fw_activation_history)
		ENTRY("log-page-directory", "Retrieve log page directory", get_log_page_directory_log)
		ENTRY("temp-stats", "Retrieve Temperature Statistics log", get_temp_stats_log)
		ENTRY("vs-drive-info", "Retrieve drive information", get_drive_info)
		ENTRY("cloud-SSDplugin-version", "Prints plug-in OCP version", get_cloud_SSDplugin_version)
		ENTRY("workload-tracker", "Real Time capture Workload Tracker samples",
		      get_workload_tracker)
	)
);

#endif

#include "define_cmd.h"
