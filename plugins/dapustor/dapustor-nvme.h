/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/dapustor/dapustor-nvme

#if !defined(DAPUSTOR_NVME) || defined(CMD_HEADER_MULTI_READ)
#define DAPUSTOR_NVME

#include "cmd.h"

PLUGIN(NAME("dapustor", "DapuStor vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve DapuStor SMART Log, show it", dapustor_additional_smart_log)
	)
);

#endif

#include "define_cmd.h"
