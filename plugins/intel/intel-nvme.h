#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/intel/intel-nvme

#if !defined(INTEL_NVME) || defined(CMD_HEADER_MULTI_READ)
#define INTEL_NVME

#include "cmd.h"

PLUGIN(NAME("intel", "Intel vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
		ENTRY("internal-log", "Retrieve Intel internal firmware log, save it", get_internal_log)
		ENTRY("lat-stats", "Retrieve Intel IO Latency Statistics log, show it", get_lat_stats_log)
		ENTRY("set-bucket-thresholds", "Set Latency Stats Bucket Values, save it", set_lat_stats_thresholds)
		ENTRY("lat-stats-tracking", "Enable and disable Latency Statistics logging.", enable_lat_stats_tracking)
		ENTRY("market-name", "Retrieve Intel Marketing Name log, show it", get_market_log)
		ENTRY("smart-log-add", "Retrieve Intel SMART Log, show it", get_additional_smart_log)
		ENTRY("temp-stats", "Retrieve Intel Temperature Statistics log, show it", get_temp_stats_log)
	)
);

#endif

#include "define_cmd.h"
