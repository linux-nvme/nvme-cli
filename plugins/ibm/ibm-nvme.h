/* SPDX-License-Identifier: GPL-2.0-or-later*/
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ibm/ibm-nvme

#if !defined(IBM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define IBM_NVME

#include "cmd.h"

#define PLUGIN_VERSION "nvme ibm plugin version 0.1"

PLUGIN(NAME("ibm", "IBM vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("crit-log", "Display IBM Smart Log Information", get_ibm_addi_smart_log)
		ENTRY("vpd", "Display IBM VPD Information", get_ibm_vpd_log)
		ENTRY("persist-event-log", "IBM specific Persistent Event Log",
				get_ibm_persistent_event_log)
	)
);
#endif

#include "define_cmd.h"
