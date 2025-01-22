/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/fdp/fdp

#if !defined(FDP_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FDP_NVME

#include "cmd.h"

PLUGIN(NAME("fdp", "Manage Flexible Data Placement enabled devices", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("configs", "List configurations", fdp_configs)
		ENTRY("usage", "Show reclaim unit handle usage", fdp_usage)
		ENTRY("stats", "Show statistics", fdp_stats)
		ENTRY("events", "List events affecting reclaim units and media usage", fdp_events)
		ENTRY("status", "Show reclaim unit handle status", fdp_status)
		ENTRY("update", "Update a reclaim unit handle", fdp_update)
		ENTRY("set-events", "Enable or disable events", fdp_set_events)
		ENTRY("feature", "Show, enable or disable FDP configuration", fdp_feature)
	)
);

#endif

#include "define_cmd.h"
