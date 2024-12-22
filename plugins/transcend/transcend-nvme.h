/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/transcend/transcend-nvme

#if !defined(TRANSCEND_NVME) || defined(CMD_HEADER_MULTI_READ)
#define TRANSCEND_NVME

#include "cmd.h"
PLUGIN(NAME("transcend", "Transcend vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("healthvalue", "NVME health percentage", get_health_value)
		ENTRY("badblock", "Get NVME bad block number", get_bad_block)
		ENTRY("plphealthvalue", "Get NVME PLP Health.", get_plp_health)
	)
);

#endif /* TRANSCEND_NVME */

#include "define_cmd.h"
