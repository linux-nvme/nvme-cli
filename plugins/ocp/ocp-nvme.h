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
		ENTRY("clear-fw-activate-history", "Clear firmware update history log", clear_fw_update_history)
		ENTRY("eol-plp-failure-mode", "Define EOL or PLP circuitry failure mode.", eol_plp_failure_mode)
		ENTRY("clear-pcie-correctable-error-counters", "Clear PCIe correctable error counters", clear_pcie_corectable_error_counters)
		ENTRY("vs-fw-activate-history", "Get firmware activation history log", fw_activation_history_log)
	)
);

#endif

#include "define_cmd.h"
