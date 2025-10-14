/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/inspur/inspur-nvme

#if !defined(INSPUR_NVME) || defined(CMD_HEADER_MULTI_READ)
#define INSPUR_NVME

#include "cmd.h"

PLUGIN(NAME("inspur", "Inspur vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("nvme-vendor-log", "Retrieve Inspur Vendor Log, show it", nvme_get_vendor_log)
	)
);

#endif

#include "define_cmd.h"
