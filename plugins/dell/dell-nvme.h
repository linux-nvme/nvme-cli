/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/dell/dell-nvme

#if !defined(DELL_NVME) || defined(CMD_HEADER_MULTI_READ)
#define DELL_NVME

#include "cmd.h"

PLUGIN(NAME("dell", "DELL vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
	)
);

#endif

#include "define_cmd.h"
