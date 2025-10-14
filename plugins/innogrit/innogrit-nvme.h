/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/innogrit/innogrit-nvme

#if !defined(INNOGRIT_NVME) || defined(CMD_HEADER_MULTI_READ)
#define INNOGRIT_NVME

#include "cmd.h"

PLUGIN(NAME("innogrit", "innogrit vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("get-eventlog",  "get event log", innogrit_geteventlog)
		ENTRY("get-cdump",     "get cdump data", innogrit_vsc_getcdump)
	)
);

#endif

#include "define_cmd.h"
