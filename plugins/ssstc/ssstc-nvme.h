/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ssstc/ssstc-nvme

#if !defined(SSSTC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SSSTC_NVME

#include "cmd.h"
PLUGIN(NAME("ssstc", "SSSTC vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve ssstc SMART Log, show it", ssstc_get_add_smart_log)
	)
);
#endif

#include "define_cmd.h"
