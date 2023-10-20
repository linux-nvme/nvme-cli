/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ocp/ocp-nvme

#if !defined(OCP_NVME) || defined(CMD_HEADER_MULTI_READ)
#define OCP_NVME

#include "cmd.h"

PLUGIN(NAME("ocp", "OCP cloud SSD extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-add-log", "Retrieve extended SMART Information", smart_add_log)
		ENTRY("latency-monitor-log", "Get Latency Monitor Log Page", ocp_latency_monitor_log)
		ENTRY("set-latency-monitor-feature", "Set Latency Monitor feature", ocp_set_latency_monitor_feature)
		ENTRY("internal-log", "Retrieve and save internal device telemetry log", ocp_telemetry_log)
		ENTRY("clear-fw-activate-history", "Clear firmware update history log", clear_fw_update_history)
		ENTRY("eol-plp-failure-mode", "Define EOL or PLP circuitry failure mode.", eol_plp_failure_mode)
		ENTRY("clear-pcie-correctable-error-counters", "Clear PCIe correctable error counters", clear_pcie_corectable_error_counters)
		ENTRY("fw-activate-history", "Get firmware activation history log", fw_activation_history_log)
		ENTRY("unsupported-reqs-log", "Get Unsupported Requirements Log Page", ocp_unsupported_requirements_log)
		ENTRY("error-recovery-log", "Retrieve Error Recovery Log Page", ocp_error_recovery_log)
		ENTRY("device-capability-log", "Get Device capabilities Requirements Log Page", ocp_device_capabilities_log)
		ENTRY("set-dssd-power-state-feature", "Get Device capabilities Requirements Log Page", set_dssd_power_state_feature)
		ENTRY("set-plp-health-check-interval", "Set PLP Health Check Interval", set_plp_health_check_interval)
		ENTRY("get-plp-health-check-interval", "Get PLP Health Check Interval", get_plp_health_check_interval)
	)
);

#endif

#include "define_cmd.h"
