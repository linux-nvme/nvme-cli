/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/micron/micron-nvme

#if !defined(MICRON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MICRON_NVME

#include "cmd.h"

PLUGIN(NAME("micron", "Micron vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("select-download", "Selective Firmware Download", micron_selective_download)
		ENTRY("vs-temperature-stats", "Retrieve Micron temperature statistics ", micron_temp_stats)
		ENTRY("vs-pcie-stats", "Retrieve Micron PCIe error stats", micron_pcie_stats)
		ENTRY("clear-pcie-correctable-errors", "Clear correctable PCIe errors", micron_clear_pcie_correctable_errors)
		ENTRY("vs-internal-log", "Retrieve Micron logs", micron_internal_logs)
		ENTRY("vs-telemetry-controller-option", "Enable/Disable controller telemetry log generation", micron_telemetry_cntrl_option)
		ENTRY("vs-nand-stats", "Retrieve NAND Stats", micron_nand_stats)
		ENTRY("vs-smart-ext-log", "Retrieve extended SMART logs", micron_smart_ext_log)
		ENTRY("vs-drive-info", "Retrieve Drive information", micron_drive_info)
		ENTRY("plugin-version", "Display plugin version info", micron_plugin_version)
		ENTRY("cloud-SSD-plugin-version", "Display plugin version info", micron_cloud_ssd_plugin_version)
		ENTRY("log-page-directory", "Retrieve log page directory", micron_logpage_dir)
		ENTRY("vs-fw-activate-history", "Display FW activation history", micron_fw_activation_history)
		ENTRY("latency-tracking", "Latency monitoring feature control", micron_latency_stats_track)
		ENTRY("latency-stats", "Latency information for tracked commands", micron_latency_stats_info)
		ENTRY("latency-logs", "Latency log details tracked by drive", micron_latency_stats_logs)
		ENTRY("vs-smart-add-log", "Retrieve extended SMART data", micron_ocp_smart_health_logs)
		ENTRY("clear-fw-activate-history", "Clear FW activation history", micron_clr_fw_activation_history)
		ENTRY("vs-smbus-option", "Enable/Disable SMBUS on the drive", micron_smbus_option)
	)
);

#endif

#include "define_cmd.h"
