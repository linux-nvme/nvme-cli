#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/wdc/wdc-nvme

#if !defined(WDC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define WDC_NVME

#include "cmd.h"

PLUGIN(NAME("wdc", "Western Digital vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("cap-diag", "WDC Capture-Diagnostics", wdc_cap_diag)
		ENTRY("drive-log", "WDC Drive Log", wdc_drive_log)
		ENTRY("get-crash-dump", "WDC Crash Dump", wdc_get_crash_dump)
		ENTRY("get-pfail-dump", "WDC Pfail Dump", wdc_get_pfail_dump)
		ENTRY("id-ctrl", "WDC identify controller", wdc_id_ctrl)
		ENTRY("purge", "WDC Purge", wdc_purge)
		ENTRY("purge-monitor", "WDC Purge Monitor", wdc_purge_monitor)
		ENTRY("vs-internal-log", "WDC Internal Firmware Log", wdc_vs_internal_fw_log)
		ENTRY("vs-nand-stats", "WDC NAND Statistics", wdc_vs_nand_stats)
		ENTRY("vs-smart-add-log", "WDC Additional Smart Log", wdc_vs_smart_add_log)
		ENTRY("clear-pcie-correctable-errors", "WDC Clear PCIe Correctable Error Count", wdc_clear_pcie_correctable_errors)
		ENTRY("drive-essentials", "WDC Drive Essentials", wdc_drive_essentials)
		ENTRY("get-drive-status", "WDC Get Drive Status", wdc_drive_status)
		ENTRY("clear-assert-dump", "WDC Clear Assert Dump", wdc_clear_assert_dump)
		ENTRY("drive-resize", "WDC Drive Resize", wdc_drive_resize)
		ENTRY("vs-fw-activate-history", "WDC Get FW Activate History", wdc_vs_fw_activate_history)
		ENTRY("clear-fw-activate-history", "WDC Clear FW Activate History", wdc_clear_fw_activate_history)
		ENTRY("enc-get-log", "WDC Get Enclosure Log", wdc_enc_get_log)
		ENTRY("vs-telemetry-controller-option", "WDC Enable/Disable Controller Initiated Telemetry Log", wdc_vs_telemetry_controller_option)
		ENTRY("vs-error-reason-identifier", "WDC Telemetry Reason Identifier", wdc_reason_identifier)
		ENTRY("log-page-directory", "WDC Get Log Page Directory", wdc_log_page_directory)
		ENTRY("namespace-resize", "WDC NamespaceDrive Resize", wdc_namespace_resize)
		ENTRY("vs-drive-info", "WDC Get Drive Info", wdc_vs_drive_info)
		ENTRY("vs-temperature-stats", "WDC Get Temperature Stats", wdc_vs_temperature_stats)
		ENTRY("capabilities", "WDC Device Capabilities", wdc_capabilities)
		ENTRY("cloud-SSD-plugin-version", "WDC Cloud SSD Plugin Version", wdc_cloud_ssd_plugin_version)
		ENTRY("vs-pcie-stats", "WDC VS PCIE Statistics", wdc_vs_pcie_stats)
	)
);

#endif

#include "define_cmd.h"
