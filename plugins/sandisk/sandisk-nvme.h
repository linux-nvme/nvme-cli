/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/sandisk/sandisk-nvme

#if !defined(SANDISK_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SANDISK_NVME

#define SANDISK_PLUGIN_VERSION   "3.0.0"
#include "cmd.h"

PLUGIN(NAME("sndk", "Sandisk vendor specific extensions", SANDISK_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("vs-internal-log", "Sandisk Internal Firmware Log",
			sndk_vs_internal_fw_log)
		ENTRY("vs-nand-stats", "Sandisk NAND Statistics", sndk_vs_nand_stats)
		ENTRY("vs-smart-add-log", "Sandisk Additional Smart Log",
			sndk_vs_smart_add_log)
		ENTRY("clear-pcie-correctable-errors",
			"Sandisk Clear PCIe Correctable Error Count",
			sndk_clear_pcie_correctable_errors)
		ENTRY("get-drive-status", "Sandisk Get Drive Status",
			sndk_drive_status)
		ENTRY("clear-assert-dump", "Sandisk Clear Assert Dump",
			sndk_clear_assert_dump)
		ENTRY("drive-resize", "Sandisk Drive Resize", sndk_drive_resize)
		ENTRY("vs-fw-activate-history", "Sandisk Get FW Activate History",
			sndk_vs_fw_activate_history)
		ENTRY("clear-fw-activate-history",
			"Sandisk Clear FW Activate History",
			sndk_clear_fw_activate_history)
		ENTRY("vs-telemetry-controller-option",
			"Sandisk Enable/Disable Controller Initiated Telemetry Log",
			sndk_vs_telemetry_controller_option)
		ENTRY("vs-error-reason-identifier",
			"Sandisk Telemetry Reason Identifier",
			sndk_reason_identifier)
		ENTRY("log-page-directory", "Sandisk Get Log Page Directory",
			sndk_log_page_directory)
		ENTRY("namespace-resize", "Sandisk NamespaceDrive Resize",
			sndk_namespace_resize)
		ENTRY("vs-drive-info", "Sandisk Get Drive Info", sndk_vs_drive_info)
		ENTRY("vs-temperature-stats", "Sandisk Get Temperature Stats",
			sndk_vs_temperature_stats)
		ENTRY("capabilities", "Sandisk Device Capabilities",
			sndk_capabilities)
		ENTRY("cloud-SSD-plugin-version",
			"Sandisk Cloud SSD Plugin Version",
			sndk_cloud_ssd_plugin_version)
		ENTRY("vs-pcie-stats", "Sandisk VS PCIE Statistics",
			sndk_vs_pcie_stats)
		ENTRY("get-latency-monitor-log",
			"Sandisk Get Latency Monitor Log Page",
			sndk_get_latency_monitor_log)
		ENTRY("get-error-recovery-log",
			"Sandisk Get Error Recovery Log Page",
			sndk_get_error_recovery_log)
		ENTRY("get-dev-capabilities-log",
			"Sandisk Get Device Capabilities Log Page",
			sndk_get_dev_capabilities_log)
		ENTRY("get-unsupported-reqs-log",
			"Sandisk Get Unsupported Requirements Log Page",
			sndk_get_unsupported_reqs_log)
		ENTRY("cloud-boot-SSD-version",
			"Sandisk Get the Cloud Boot SSD Version",
			sndk_cloud_boot_SSD_version)
		ENTRY("vs-cloud-log", "Sandisk Get the Cloud Log Page",
			sndk_vs_cloud_log)
		ENTRY("vs-hw-rev-log", "Sandisk Get the Hardware Revision Log Page",
			sndk_vs_hw_rev_log)
		ENTRY("vs-device-waf",
			"Sandisk Calculate Device Write Amplication Factor",
			sndk_vs_device_waf)
		ENTRY("set-latency-monitor-feature",
			"Sandisk set Latency Monitor feature",
			sndk_set_latency_monitor_feature)
		ENTRY("cu-smart-log",
			"Sandisk Get Customer Unique Smart Log",
			sndk_cu_smart_log)

	)
);

#endif

#include "define_cmd.h"
