#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/memblaze/memblaze-nvme

#if !defined(MEMBLAZE_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MEMBLAZE_NVME

#include "cmd.h"
#include "common.h"

#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

PLUGIN(NAME("memblaze", "Memblaze vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Memblaze SMART Log, show it", mb_get_additional_smart_log)
		ENTRY("get-pm-status", "Get Memblaze Power Manager Status", mb_get_powermanager_status)
		ENTRY("set-pm-status", "Set Memblaze Power Manager Status", mb_set_powermanager_status)
		ENTRY("select-download", "Selective Firmware Download", mb_selective_download)
		ENTRY("lat-stats", "Enable and disable Latency Statistics logging", mb_set_lat_stats)
		ENTRY("lat-stats-print", "Retrieve IO Latency Statistics log, show it", mb_lat_stats_log_print)
		ENTRY("lat-log", "Set Memblaze High Latency Log", mb_set_high_latency_log)
		ENTRY("lat-log-print", "Output Memblaze High Latency Log", mb_high_latency_log_print)
		ENTRY("clear-error-log", "Clear error log", memblaze_clear_error_log)
	)
);

#endif

#include "define_cmd.h"

