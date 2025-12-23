/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/twsc/twsc-nvme

#if !defined(TWSC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define TWSC_NVME

#include "cmd.h"

PLUGIN(NAME("twsc", "TWSC vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve TWSC SMART Log, show it", twsc_get_additional_smart_log)
		ENTRY("query-cap", "Query current capacity info", twsc_query_cap_info)
		ENTRY("dump-evtlog", "Dump evtlog into file and parse warning & error log", twsc_dump_evtlog)
		ENTRY("exit-write-reject", "Exit write reject mode", twsc_exit_write_reject)
		ENTRY("status", "Retrieve the TWSC status output, show it", twsc_status)
	)
);

#endif

#include "define_cmd.h"
