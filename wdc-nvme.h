#undef CMD_INC_FILE
#define CMD_INC_FILE wdc-nvme

#if !defined(WDC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define WDC_NVME

#include "cmd.h"

PLUGIN(NAME("wdc", "Western Digital vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("cap-diag", "WDC Capture-Diagnostics", wdc_cap_diag)
		ENTRY("drive-log", "WDC Drive Log", wdc_drive_log)
		ENTRY("get-crash-dump", "WDC Crash Dump", wdc_get_crash_dump)
		ENTRY("id-ctrl", "WDC identify controller", wdc_id_ctrl)
		ENTRY("purge", "WDC Purge", wdc_purge)
		ENTRY("purge-monitor", "WDC Purge Monitor", wdc_purge_monitor)
		ENTRY("smart-log-add", "WDC Additional Smart Log", wdc_smart_log_add)
	)
);

#endif

#include "define_cmd.h"
