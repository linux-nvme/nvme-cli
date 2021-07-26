#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/scaleflux/sfx-nvme

#if !defined(SFX_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SFX_NVME

#include "cmd.h"

PLUGIN(NAME("sfx", "ScaleFlux vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve ScaleFlux SMART Log, show it", get_additional_smart_log)
		ENTRY("lat-stats", "Retrieve ScaleFlux IO Latency Statistics log, show it", get_lat_stats_log)
		ENTRY("get-bad-block", "Retrieve bad block table of block device, show it", sfx_get_bad_block)
		ENTRY("query-cap", "Query current capacity info", query_cap_info)
		ENTRY("change-cap", "Dynamic change capacity", change_cap)
		ENTRY("set-feature", "Set a feature", sfx_set_feature)
		ENTRY("get-feature", "Get a feature", sfx_get_feature)
	)
);

#endif

#include "define_cmd.h"
