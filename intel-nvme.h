#undef CMD_INC_FILE
#define CMD_INC_FILE intel-nvme

#if !defined(INTEL_NVME) || defined(CMD_HEADER_MULTI_READ)
#define INTEL_NVME

#include "cmd.h"

PLUGIN(NAME("intel", "Intel vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
		ENTRY("smart-log-add", "Retrieve Intel SMART Log, show it", get_additional_smart_log)
		ENTRY("market-name", "Retrieve Intel Marketing Name log, show it", get_market_log)
		ENTRY("temp-stats", "Retrieve Intel Temperature Statistics log, show it", get_temp_stats_log)
		ENTRY("lat-stats", "Retrieve Intel IO Latancy Statistics log, show it", get_lat_stats_log)
		ENTRY("internal-log", "Retrieve Intel internal firmware log, save it", get_internal_log)
	)
);

#endif

#include "define_cmd.h"
